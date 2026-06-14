"""
Copy Fail — CVE-2026-31431 Linux Kernel LPE + Container Escape Detection
Skill #53 — CopyFailLPE

Research basis:
  Xint Code Research Team (Juno Im / Taeyang Lee of Theori)
  "Copy Fail: 732 Bytes to Root on Every Major Linux Distribution"
  https://xint.io/blog/copy-fail-linux-distributions
  Published: April 29, 2026 | CVE assigned: April 22, 2026
  Disclosure timeline: Reported 2026-03-23 → Patched 2026-04-01 → Public 2026-04-29

Vulnerability summary:
  Logic bug in Linux kernel authencesn cryptographic template.
  Unprivileged local user → controlled 4-byte page cache write →
  overwrite setuid binary in memory → root (no race condition, no recompile).
  732-byte Python PoC works on Ubuntu / Amazon Linux / RHEL / SUSE.
  Kernel versions: ~4.9 (2017 in-place AF_ALG optimization) through patched kernels.
  Also crosses container/K8s boundaries (page cache is host-wide).

Root cause chain (three commits, ~decade apart):
  [2011] authencesn added — uses dst scatterlist as ESN scratch space
  [2015] AF_ALG AEAD support + new AEAD interface (assoclen+cryptlen offset past output)
  [2017] algif_aead in-place optimization: req->src = req->dst
         → page cache pages from splice() now in WRITABLE destination scatterlist
         → authencesn's write at dst[assoclen+cryptlen] lands in page cache

Attack chain:
  ① AF_ALG socket (authencesn template) — no privileges required
  ② splice() target setuid binary (/usr/bin/su) into socket TX scatterlist
  ③ sendmsg() AAD bytes[4:7] = desired 4-byte shellcode chunk (seqno_lo controlled)
  ④ recvmsg() → authencesn writes seqno_lo to page cache of target file
  ⑤ HMAC fails → recvmsg returns error, but 4-byte write persists
  ⑥ Repeat for each 4-byte chunk of shellcode
  ⑦ execve("/usr/bin/su") → loads corrupted page cache → root

Stealth properties:
  - On-disk file unchanged → MD5/SHA256 file integrity checks MISS the modification
  - Page cache is host-wide → crosses container boundaries
  - No races, no retries, no crash-prone timing windows

bingo integration scope:
  This module operates in POST-EXPLOITATION context:
  - After webshell / RCE is confirmed, probe the target server
  - Fingerprint Linux kernel version via HTTP headers, /proc/version exposure, webshell
  - Check algif_aead module availability via webshell command execution
  - Detect K8s/container environment for escalation path assessment
  - AI auto-trigger: Linux server + post-RCE context OR kernel version leak detected

Evidence levels:
  VERIFIED   — kernel version confirmed vulnerable + algif_aead loaded + webshell exec confirmed
  LIKELY     — kernel version in vulnerable range (2017~patch) from HTTP headers/banner
  INFERRED   — Linux server detected, version unknown, module status unknown
  AI_ANALYSIS — OS banner suggests Linux, no further confirmation
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.exceptions import RequestException

# ── Vulnerable kernel version range ─────────────────────────────────────────
# Introduced: commit 72548b093ee3 (2017, Linux ~4.9)
# Fixed:      commit a664bf3d603d (April 1, 2026)
# Approximate version range: 4.9 <= kernel < 6.x (distro-dependent patch)
VULN_INTRODUCED_VERSION = (4, 9, 0)

# Distro-specific patched kernels (from disclosure article + NVD)
PATCHED_KERNELS = {
    "ubuntu":  "6.17.0-1008",          # Ubuntu patched after 6.17.0-1007-aws (tested as vulnerable)
    "amzn":    "6.18.8-10",            # Amazon Linux 2023 patched after 6.18.8-9
    "rhel":    "6.12.0-125",           # RHEL 10.1 patched after 6.12.0-124
    "suse":    "6.12.0-160001",        # SUSE 16 patched after 6.12.0-160000
}

# ── HTTP headers that may leak kernel version ────────────────────────────────
KERNEL_LEAK_HEADERS = ["Server", "X-Powered-By", "X-Server-Info", "Via"]

# Patterns to extract Linux kernel version from strings
KERNEL_VERSION_RE = re.compile(
    r"Linux[/ ](\d+\.\d+[\.\d]*)",
    re.IGNORECASE,
)
UNAME_RE = re.compile(
    r"(\d+\.\d+\.\d+[-\w.]*)",
)

# ── Webshell command probes ──────────────────────────────────────────────────
WEBSHELL_KERNEL_CMD    = "uname -r"
WEBSHELL_MODULE_CMD    = "lsmod | grep algif_aead"
WEBSHELL_PYTHON_CMD    = "python3 --version"
WEBSHELL_CONTAINER_CMD = "cat /proc/1/cgroup | head -3"
WEBSHELL_PROC_VERSION  = "cat /proc/version"

# ── Common webshell URL patterns ─────────────────────────────────────────────
WEBSHELL_EXEC_PARAMS = [
    ("cmd",     "GET"),
    ("c",       "GET"),
    ("command", "GET"),
    ("exec",    "GET"),
    ("shell",   "GET"),
    ("cmd",     "POST"),
    ("c",       "POST"),
]

# ── Container/K8s indicators in cgroup output ───────────────────────────────
CONTAINER_PATTERNS = [
    r"docker",
    r"kubepod",
    r"kubernetes",
    r"containerd",
    r"k8s",
    r"/system\.slice/docker",
]

# ── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass
class CopyFailFinding:
    finding_type: str       # "kernel_version_vuln" | "algif_aead_loaded" | "container_escape_path"
                            # | "kernel_banner_leak" | "python310_available"
    description: str
    url: str = ""
    kernel_version: str = ""
    distro_hint: str = ""
    algif_aead_loaded: bool = False
    python310_available: bool = False
    container_environment: bool = False
    k8s_environment: bool = False
    evidence_level: str = "AI_ANALYSIS"
    severity: str = "high"
    curl_poc: str = ""
    remediation_hint: str = ""


@dataclass
class CopyFailResult:
    target: str
    findings: list[CopyFailFinding] = field(default_factory=list)
    kernel_version: str = ""
    distro_hint: str = ""
    kernel_vulnerable: bool = False
    algif_aead_loaded: bool = False
    python310_available: bool = False
    container_environment: bool = False
    k8s_environment: bool = False
    container_escape_possible: bool = False
    lpe_path_confirmed: bool = False
    webshell_exec_available: bool = False
    webshell_url: str = ""
    severity: str = "none"
    evidence_level: str = "AI_ANALYSIS"
    error: str = ""
    summary: str = ""


# ── Scanner ───────────────────────────────────────────────────────────────────

class CopyFailScanner:
    """
    Detects CVE-2026-31431 applicability via:
      1. HTTP header kernel version leak (passive)
      2. /proc/version path exposure check
      3. Webshell command execution (if available from prior exploitation)
      4. Container/K8s environment detection for escape-path assessment
    """

    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/124.0.0.0 Safari/537.36",
    }
    TIMEOUT = 8

    def __init__(
        self,
        target: str,
        webshell_url: Optional[str] = None,
        proxies: Optional[dict] = None,
    ):
        self.target = target.rstrip("/")
        self.webshell_url = webshell_url
        self.proxies = proxies or {}
        self.session = requests.Session()
        self.session.headers.update(self.HEADERS)
        self.session.verify = False

    # ── Public entry ──────────────────────────────────────────────────────────

    def scan(self) -> CopyFailResult:
        result = CopyFailResult(target=self.target)
        try:
            self._check_http_headers(result)
            self._check_proc_version_exposure(result)
            if self.webshell_url:
                self._probe_via_webshell(result)
            self._assess_vulnerability(result)
            self._build_summary(result)
        except Exception as exc:
            result.error = str(exc)
        return result

    # ── HTTP header kernel leak ───────────────────────────────────────────────

    def _check_http_headers(self, result: CopyFailResult) -> None:
        try:
            resp = self.session.get(
                self.target, timeout=self.TIMEOUT, proxies=self.proxies,
                allow_redirects=True,
            )
        except RequestException:
            return

        for header in KERNEL_LEAK_HEADERS:
            value = resp.headers.get(header, "")
            if not value:
                continue
            m = KERNEL_VERSION_RE.search(value)
            if m:
                kver = m.group(1)
                result.kernel_version = kver
                distro = self._guess_distro(value + " " + resp.headers.get("Server", ""))
                result.distro_hint = distro
                finding = CopyFailFinding(
                    finding_type="kernel_banner_leak",
                    description=(
                        f"HTTP header '{header}' leaks Linux kernel version: {kver} — "
                        f"check if in vulnerable range (4.9 ~ distro-patch)"
                    ),
                    url=self.target,
                    kernel_version=kver,
                    distro_hint=distro,
                    evidence_level="LIKELY",
                    severity="high",
                    remediation_hint=(
                        "Remove kernel version from HTTP response headers. "
                        "Patch kernel to post-CVE-2026-31431 version."
                    ),
                )
                result.findings.append(finding)
                break

        # OS hint from Server header even without version
        server = resp.headers.get("Server", "").lower()
        if "linux" in server or "ubuntu" in server or "centos" in server or "debian" in server:
            if not result.kernel_version:
                result.distro_hint = self._guess_distro(server)

    # ── /proc/version direct exposure ────────────────────────────────────────

    def _check_proc_version_exposure(self, result: CopyFailResult) -> None:
        for path in ["/proc/version", "/server-info", "/phpinfo.php"]:
            url = self.target + path
            try:
                resp = self.session.get(url, timeout=self.TIMEOUT, proxies=self.proxies)
                if resp.status_code != 200:
                    continue
                m = UNAME_RE.search(resp.text[:500])
                if m and "Linux" in resp.text:
                    kver = m.group(1)
                    result.kernel_version = kver
                    result.distro_hint = self._guess_distro(resp.text[:200])
                    finding = CopyFailFinding(
                        finding_type="kernel_banner_leak",
                        description=(
                            f"/proc/version exposed at {url}: kernel {kver}"
                        ),
                        url=url,
                        kernel_version=kver,
                        evidence_level="VERIFIED",
                        severity="high",
                        curl_poc=f"curl -sk '{url}' | head -1",
                        remediation_hint=(
                            "Block direct access to /proc/* via web server config. "
                            "Patch to post-CVE-2026-31431 kernel."
                        ),
                    )
                    result.findings.append(finding)
                    break
            except RequestException:
                continue

    # ── Webshell-based deep probe ─────────────────────────────────────────────

    def _probe_via_webshell(self, result: CopyFailResult) -> None:
        """Execute diagnostic commands via webshell to assess LPE feasibility."""
        if not self.webshell_url:
            return

        probes = [
            (WEBSHELL_PROC_VERSION,  self._handle_proc_version),
            (WEBSHELL_KERNEL_CMD,    self._handle_uname),
            (WEBSHELL_MODULE_CMD,    self._handle_algif_module),
            (WEBSHELL_PYTHON_CMD,    self._handle_python_version),
            (WEBSHELL_CONTAINER_CMD, self._handle_cgroup),
        ]
        for cmd, handler in probes:
            output = self._exec_webshell(cmd)
            if output:
                handler(result, output)

        result.webshell_exec_available = True
        result.webshell_url = self.webshell_url

    def _exec_webshell(self, cmd: str) -> str:
        """Try common webshell parameter patterns to execute a command."""
        for param, method in WEBSHELL_EXEC_PARAMS:
            try:
                if method == "GET":
                    resp = self.session.get(
                        self.webshell_url,
                        params={param: cmd},
                        timeout=self.TIMEOUT,
                        proxies=self.proxies,
                    )
                else:
                    resp = self.session.post(
                        self.webshell_url,
                        data={param: cmd},
                        timeout=self.TIMEOUT,
                        proxies=self.proxies,
                    )
                text = resp.text.strip()
                if text and len(text) < 2000 and "\n" in text or len(text) > 5:
                    return text
            except RequestException:
                continue
        return ""

    def _handle_proc_version(self, result: CopyFailResult, output: str) -> None:
        m = UNAME_RE.search(output)
        if m:
            result.kernel_version = m.group(1)
            result.distro_hint = self._guess_distro(output)

    def _handle_uname(self, result: CopyFailResult, output: str) -> None:
        kver = output.strip().split()[0] if output.strip() else ""
        if kver and re.match(r"\d+\.\d+", kver):
            result.kernel_version = kver

    def _handle_algif_module(self, result: CopyFailResult, output: str) -> None:
        if "algif_aead" in output:
            result.algif_aead_loaded = True
            finding = CopyFailFinding(
                finding_type="algif_aead_loaded",
                description=(
                    "algif_aead kernel module is LOADED — "
                    "CVE-2026-31431 exploit primitive available"
                ),
                url=self.webshell_url or self.target,
                algif_aead_loaded=True,
                evidence_level="VERIFIED",
                severity="critical",
                curl_poc=(
                    f"# Via webshell:\n"
                    f"curl -s '{self.webshell_url}?cmd=lsmod+|+grep+algif_aead'"
                ),
                remediation_hint=(
                    "Immediately: rmmod algif_aead; "
                    "echo 'install algif_aead /bin/false' "
                    "> /etc/modprobe.d/disable-algif-aead.conf"
                ),
            )
            result.findings.append(finding)

    def _handle_python_version(self, result: CopyFailResult, output: str) -> None:
        m = re.search(r"Python (\d+)\.(\d+)", output)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            if major >= 3 and minor >= 10:
                result.python310_available = True
                finding = CopyFailFinding(
                    finding_type="python310_available",
                    description=(
                        f"Python {major}.{minor} available — "
                        "732-byte PoC script can run directly (uses os.splice, Python 3.10+)"
                    ),
                    url=self.webshell_url or self.target,
                    python310_available=True,
                    evidence_level="VERIFIED",
                    severity="high",
                )
                result.findings.append(finding)

    def _handle_cgroup(self, result: CopyFailResult, output: str) -> None:
        for pattern in CONTAINER_PATTERNS:
            if re.search(pattern, output, re.IGNORECASE):
                result.container_environment = True
                is_k8s = bool(re.search(r"kube|k8s", output, re.IGNORECASE))
                result.k8s_environment = is_k8s
                finding = CopyFailFinding(
                    finding_type="container_escape_path",
                    description=(
                        f"{'Kubernetes' if is_k8s else 'Container'} environment detected — "
                        "CVE-2026-31431 page cache is HOST-WIDE: "
                        "container escape to node root possible (Part 2 attack chain)"
                    ),
                    url=self.webshell_url or self.target,
                    container_environment=True,
                    k8s_environment=is_k8s,
                    evidence_level="VERIFIED",
                    severity="critical",
                    remediation_hint=(
                        "Patch host kernel. "
                        "Block AF_ALG on host: disable algif_aead module. "
                        "See: https://xint.io/blog/copy-fail-linux-distributions (Part 2)"
                    ),
                )
                result.findings.append(finding)
                break

    # ── Vulnerability assessment ──────────────────────────────────────────────

    def _assess_vulnerability(self, result: CopyFailResult) -> None:
        """Determine if kernel version is in the vulnerable range."""
        if not result.kernel_version:
            return

        parsed = self._parse_kernel_version(result.kernel_version)
        if parsed < VULN_INTRODUCED_VERSION:
            # Too old to be affected (pre-2017 in-place AF_ALG)
            return

        # Check if distro-specific patch applies
        patched = self._is_distro_patched(result.kernel_version, result.distro_hint)
        result.kernel_vulnerable = not patched

        if result.kernel_vulnerable:
            ev = "VERIFIED" if result.webshell_exec_available else "LIKELY"
            finding = CopyFailFinding(
                finding_type="kernel_version_vuln",
                description=(
                    f"Kernel {result.kernel_version} is in CVE-2026-31431 vulnerable range "
                    f"(introduced 2017 in-place AF_ALG, patched 2026-04-01). "
                    f"LPE via AF_ALG + splice() + authencesn scratch write."
                ),
                url=self.target,
                kernel_version=result.kernel_version,
                distro_hint=result.distro_hint,
                evidence_level=ev,
                severity="critical",
                curl_poc=(
                    "# Check kernel version:\n"
                    "uname -r\n"
                    "# Check algif_aead module:\n"
                    "lsmod | grep algif_aead\n"
                    "# Immediate mitigation:\n"
                    "sudo rmmod algif_aead\n"
                    "echo 'install algif_aead /bin/false' | sudo tee "
                    "/etc/modprobe.d/disable-algif-aead.conf"
                ),
                remediation_hint="Patch kernel to post-CVE-2026-31431 version (Apr 2026+).",
            )
            result.findings.append(finding)
            result.evidence_level = ev

        # Assess container escape
        if result.kernel_vulnerable and result.container_environment:
            result.container_escape_possible = True

        # Assess full LPE confirmation
        if (result.kernel_vulnerable and
                result.algif_aead_loaded and
                result.webshell_exec_available):
            result.lpe_path_confirmed = True
            result.evidence_level = "VERIFIED"

        # Severity
        if result.lpe_path_confirmed:
            result.severity = "critical"
        elif result.kernel_vulnerable:
            result.severity = "high"
        elif result.findings:
            result.severity = "medium"

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_kernel_version(kver: str) -> tuple:
        """Parse kernel version string into comparable tuple."""
        m = re.match(r"(\d+)\.(\d+)\.?(\d*)", kver)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))
        return (0, 0, 0)

    @staticmethod
    def _is_distro_patched(kver: str, distro_hint: str) -> bool:
        """Check if this specific distro kernel version includes the fix."""
        hint = distro_hint.lower()
        for distro_key, patch_ver in PATCHED_KERNELS.items():
            if distro_key in hint:
                # Compare version strings lexicographically (works for semver-like)
                return kver >= patch_ver
        # Unknown distro: be conservative, mark as potentially vulnerable
        return False

    @staticmethod
    def _guess_distro(text: str) -> str:
        text_lower = text.lower()
        if "ubuntu" in text_lower:       return "ubuntu"
        if "amzn" in text_lower or "amazon" in text_lower: return "amzn"
        if "rhel" in text_lower or "red hat" in text_lower: return "rhel"
        if "suse" in text_lower:         return "suse"
        if "debian" in text_lower:       return "debian"
        if "centos" in text_lower:       return "centos"
        if "alpine" in text_lower:       return "alpine"
        return "linux"

    def _build_summary(self, result: CopyFailResult) -> None:
        result.summary = (
            f"CopyFailLPE CVE-2026-31431: {len(result.findings)} findings | "
            f"kernel:{result.kernel_version or 'unknown'} | "
            f"vuln:{result.kernel_vulnerable} | "
            f"algif_aead:{result.algif_aead_loaded} | "
            f"container:{result.container_environment} | "
            f"k8s:{result.k8s_environment} | "
            f"lpe_confirmed:{result.lpe_path_confirmed} | "
            f"severity:{result.severity}"
        )
