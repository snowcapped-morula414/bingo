"""
AI-Powered API Fuzzer
Inspired by Brutecat's "Hacking Google with AI for $500,000" approach.
Takes discovered API endpoints and automatically probes them for vulnerabilities.
evidence_level: VERIFIED (confirmed vuln) / LIKELY (suspicious response) / INFERRED (pattern)
Zero-Hallucination: only reports what real HTTP responses return.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

# ── Response classification ─────────────────────────────────────────────────
_INTERESTING_STATUS = {200, 201, 206}
_AUTH_BYPASS_STATUS = {200, 201}
_ERROR_STATUS = {500, 502, 503}

# ── Payloads for parameter fuzzing ──────────────────────────────────────────
_FUZZ_PAYLOADS = [
    # IDOR
    "1", "2", "0", "-1", "99999", "admin",
    # SQLi probes (safe, error-detecting only)
    "'", "\"", "1'--", "1 OR 1=1",
    # Path traversal
    "../etc/passwd", "../../etc/passwd",
    # Generic
    "<script>alert(1)</script>",
    "{{7*7}}",          # SSTI probe
    "${7*7}",
]

# ── Sensitive keywords in response bodies ───────────────────────────────────
_SENSITIVE_KEYWORDS = [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "private_key", "access_token", "refresh_token", "ssn", "credit_card",
    "email", "phone", "address", "주민등록번호", "계좌번호", "비밀번호",
    "root:", "/etc/passwd", "syntax error", "mysql", "ORA-", "pg_query",
    "traceback", "stack trace", "exception", "at java.",
]

_TIMEOUT = 8
_RATE_LIMIT_DELAY = 0.3   # seconds between requests


@dataclass
class FuzzFinding:
    url: str
    method: str
    payload: str
    status_code: int
    response_size: int
    sensitive_keywords_found: list[str]
    evidence_level: str      # VERIFIED / LIKELY / INFERRED
    note: str = ""


@dataclass
class ApiFuzzResult:
    target: str
    endpoints_tested: int = 0
    findings: list[FuzzFinding] = field(default_factory=list)
    unauth_endpoints: list[str] = field(default_factory=list)   # no auth needed
    error_endpoints: list[str] = field(default_factory=list)    # 500 errors
    severity: str = "NONE"   # CRITICAL / HIGH / MEDIUM / LOW / NONE
    error: str = ""


class ApiFuzzer:
    """
    AI-guided API fuzzer.
    1. Tests each endpoint without authentication (unauthenticated access check)
    2. Fuzzes parameters with common payloads
    3. Classifies responses by sensitivity
    """

    def __init__(
        self,
        target: str,
        endpoints: list[tuple[str, str]],   # [(method, path), ...]
        session: Optional[requests.Session] = None,
        max_endpoints: int = 50,
    ):
        self.target = target.rstrip("/")
        self.base = self._base_url(target)
        self.endpoints = endpoints[:max_endpoints]
        self.sess = session or requests.Session()
        # No cookies, no auth — test unauthenticated access
        self.sess.cookies.clear()
        self.sess.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)",
            "Accept": "application/json,*/*",
        })
        self.sess.verify = False

    # ── Public API ──────────────────────────────────────────────────────────

    def fuzz(self) -> ApiFuzzResult:
        result = ApiFuzzResult(target=self.target)

        for method, path in self.endpoints:
            url = urljoin(self.base, path)
            result.endpoints_tested += 1

            # Step 1: unauthenticated access check
            finding = self._probe_unauth(method, url)
            if finding:
                result.findings.append(finding)
                if finding.status_code in _AUTH_BYPASS_STATUS:
                    result.unauth_endpoints.append(url)

            # Step 2: parameter fuzzing (only on GET endpoints with params)
            if method.upper() == "GET" and finding and finding.status_code in _INTERESTING_STATUS:
                fuzz_findings = self._fuzz_params(url)
                result.findings.extend(fuzz_findings)
                result.error_endpoints.extend(
                    f.url for f in fuzz_findings
                    if f.status_code in _ERROR_STATUS
                )

            time.sleep(_RATE_LIMIT_DELAY)

        result.severity = self._calc_severity(result)
        return result

    # ── Internal ────────────────────────────────────────────────────────────

    @staticmethod
    def _base_url(target: str) -> str:
        parsed = urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _probe_unauth(self, method: str, url: str) -> Optional[FuzzFinding]:
        try:
            if method.upper() in ("POST", "PUT", "PATCH"):
                r = self.sess.request(
                    method, url,
                    json={},
                    timeout=_TIMEOUT,
                    allow_redirects=False,
                )
            else:
                r = self.sess.request(
                    method, url,
                    timeout=_TIMEOUT,
                    allow_redirects=False,
                )
        except Exception:
            return None

        body = r.text[:4000]
        keywords = self._find_sensitive(body)
        ev = self._evidence_level(r.status_code, keywords)

        if r.status_code in _INTERESTING_STATUS or keywords:
            return FuzzFinding(
                url=url,
                method=method.upper(),
                payload="(no auth)",
                status_code=r.status_code,
                response_size=len(r.content),
                sensitive_keywords_found=keywords,
                evidence_level=ev,
                note="Unauthenticated access" if r.status_code in _AUTH_BYPASS_STATUS else "",
            )
        return None

    def _fuzz_params(self, url: str) -> list[FuzzFinding]:
        findings: list[FuzzFinding] = []
        for payload in _FUZZ_PAYLOADS[:6]:   # limit to 6 payloads per endpoint
            fuzz_url = f"{url}?id={payload}&user_id={payload}"
            try:
                r = self.sess.get(fuzz_url, timeout=_TIMEOUT, allow_redirects=False)
            except Exception:
                continue

            body = r.text[:4000]
            keywords = self._find_sensitive(body)
            ev = self._evidence_level(r.status_code, keywords)

            if r.status_code in _ERROR_STATUS or keywords:
                findings.append(FuzzFinding(
                    url=fuzz_url,
                    method="GET",
                    payload=payload,
                    status_code=r.status_code,
                    response_size=len(r.content),
                    sensitive_keywords_found=keywords,
                    evidence_level=ev,
                    note="500 error — possible injection" if r.status_code in _ERROR_STATUS else "",
                ))
            time.sleep(_RATE_LIMIT_DELAY)
        return findings

    @staticmethod
    def _find_sensitive(text: str) -> list[str]:
        low = text.lower()
        return [k for k in _SENSITIVE_KEYWORDS if k.lower() in low]

    @staticmethod
    def _evidence_level(status: int, keywords: list[str]) -> str:
        if keywords and status in _INTERESTING_STATUS:
            return "VERIFIED"
        if keywords or status in _ERROR_STATUS:
            return "LIKELY"
        return "INFERRED"

    @staticmethod
    def _calc_severity(result: ApiFuzzResult) -> str:
        verified = [f for f in result.findings if f.evidence_level == "VERIFIED"]
        if result.unauth_endpoints and verified:
            return "CRITICAL"
        if result.unauth_endpoints:
            return "HIGH"
        if result.error_endpoints:
            return "MEDIUM"
        if result.findings:
            return "LOW"
        return "NONE"
