"""
login_executor.py — 범용 웹 로그인 실행기
/login <url> <username> <password> 명령어의 백엔드

지원:
  - HTML form 자동 탐지 (action, method, hidden fields)
  - ASP/IIS (ASPSESSIONID), PHP (PHPSESSID), Java (JSESSIONID)
  - Baseline 비교로 False Positive 방지 (auth_tools 로직 재사용)
  - 로그인 성공 시 쿠키 딕셔너리 반환
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, urlencode

import httpx


# ── 공통 로그인 폼 필드 이름 패턴 ─────────────────────────────────────
_USER_FIELDS = [
    "userid", "user_id", "username", "user_name", "loginid", "login_id",
    "id", "email", "uid", "account", "adminid", "admin_id",
    "mb_id", "mem_id", "member_id", "아이디",
]
_PASS_FIELDS = [
    "password", "passwd", "pass", "pw", "userpasswd", "user_pw",
    "pwd", "loginpassword", "loginpw", "login_pw",
    "mb_password", "mem_pw", "비밀번호",
]
_SUCCESS_KEYWORDS = [
    "logout", "signout", "sign_out", "로그아웃", "注销",
    "dashboard", "mypage", "마이페이지", "개인정보", "관리자",
    "welcome", "로그인 성공",
]
_FAIL_KEYWORDS = [
    "incorrect", "invalid", "wrong password", "wrong id",
    "아이디 또는 비밀번호", "id 또는 비밀번호", "비밀번호가 틀",
    "아이디가 존재하지", "존재하지 않는", "로그인 실패", "로그인에 실패",
    "login failed", "authentication failed", "잘못된 아이디",
    "密码错误", "用户不存在", "登录失败",
]
_GENERIC_COOKIES = {"aspsessionid", "phpsessid", "jsessionid", "_ga", "_gid"}


@dataclass
class LoginResult:
    success: bool
    evidence: str          # VERIFIED / LIKELY / FAILED
    message: str
    cookies: dict[str, str] = field(default_factory=dict)
    login_url: str = ""
    redirect_url: str = ""
    username: str = ""
    password: str = ""


class LoginExecutor:
    """실제 HTTP 로그인을 수행하고 세션 쿠키를 반환한다."""

    def __init__(self, timeout: int = 15, on_log=None):
        self.timeout = timeout
        self._log = on_log or (lambda m: None)

    # ── 공개 API ──────────────────────────────────────────────────────

    def login(self, target_url: str, username: str, password: str) -> LoginResult:
        """
        target_url 의 로그인 폼을 자동으로 탐지하여 username/password 로 로그인한다.
        성공하면 LoginResult(success=True, cookies=...) 를 반환.
        """
        self._log(f"🔑 로그인 시도 → {target_url}")
        self._log(f"   ID: {username}  PW: {'*' * len(password)}")

        # 1) 로그인 페이지 가져오기 + 폼 분석
        try:
            form_info = self._detect_form(target_url)
        except Exception as e:
            return LoginResult(
                success=False, evidence="FAILED",
                message=f"로그인 페이지 접근 실패: {e}",
            )

        if not form_info:
            self._log("  ⚠  폼을 찾지 못함 — POST 직접 시도")
            form_info = {"action": target_url, "method": "POST", "fields": {}}

        login_url = form_info["action"]
        self._log(f"  → 폼 action: {login_url}")
        self._log(f"  → 필드: {list(form_info['fields'].keys())}")

        # 2) Baseline — 가짜 자격증명으로 실패 응답 기록
        fake_data = self._build_post_data(
            form_info["fields"], "BINGO_NO_SUCH_USER_xXx9", "BINGO_WRONG_PW_xXx9"
        )
        baseline_len, baseline_cookies = self._do_post(login_url, fake_data)
        self._log(f"  → baseline 응답 크기: {baseline_len} bytes")

        # 3) 실제 자격증명으로 로그인
        real_data = self._build_post_data(form_info["fields"], username, password)
        actual_len, actual_cookies = self._do_post(login_url, real_data, follow_redirects=False)
        self._log(f"  → 실제 응답 크기: {actual_len} bytes")

        # 4) 성공 판정
        result = self._judge(
            login_url=login_url,
            actual_len=actual_len,
            baseline_len=baseline_len,
            cookies=actual_cookies,
            username=username,
            password=password,
        )
        return result

    # ── 폼 자동 탐지 ──────────────────────────────────────────────────

    def _detect_form(self, url: str) -> dict | None:
        """HTML에서 로그인 폼을 탐지 → action, method, hidden fields 반환"""
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.8",
        }
        with httpx.Client(
            verify=False,
            timeout=self.timeout,
            follow_redirects=True,
            headers=headers,
        ) as client:
            resp = client.get(url)
            html = resp.text

        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        forms = re.findall(
            r"<form[^>]*>(.*?)</form>", html, re.DOTALL | re.IGNORECASE
        )

        best_form = None
        best_score = -1

        for form_html in forms:
            score = 0
            # 비밀번호 필드 있으면 로그인 폼일 확률 높음
            if re.search(r'type\s*=\s*["\']?password', form_html, re.IGNORECASE):
                score += 10

            # action 추출
            action_match = re.search(
                r"<form[^>]+action\s*=\s*[\"']([^\"']*)[\"']", form_html, re.IGNORECASE
            )
            if not action_match:
                # form 태그 자체에서 다시 시도 (forms 는 내부 html만 담겨있어서)
                idx = html.find(form_html[:50])
                if idx > 0:
                    surrounding = html[max(0, idx - 200):idx + 200]
                    action_match = re.search(
                        r"<form[^>]+action\s*=\s*[\"']([^\"']*)[\"']",
                        surrounding,
                        re.IGNORECASE,
                    )

            action = action_match.group(1) if action_match else url
            if not action.startswith("http"):
                action = urljoin(base + "/", action.lstrip("/"))

            # method 추출
            method_match = re.search(
                r"<form[^>]+method\s*=\s*[\"'](\w+)[\"']", form_html, re.IGNORECASE
            )
            method = (method_match.group(1).upper() if method_match else "POST")

            # 모든 input 필드 추출
            fields: dict[str, str] = {}
            for m in re.finditer(
                r"<input[^>]+>", form_html, re.IGNORECASE
            ):
                inp = m.group(0)
                name_m = re.search(r'name\s*=\s*["\']([^"\']+)["\']', inp, re.IGNORECASE)
                val_m = re.search(r'value\s*=\s*["\']([^"\']*)["\']', inp, re.IGNORECASE)
                if name_m:
                    fields[name_m.group(1)] = val_m.group(1) if val_m else ""

            if score > best_score:
                best_score = score
                best_form = {"action": action, "method": method, "fields": fields}

        return best_form

    # ── POST 데이터 구성 ──────────────────────────────────────────────

    def _build_post_data(
        self, known_fields: dict, username: str, password: str
    ) -> dict:
        """
        폼의 숨겨진 필드를 그대로 유지하고, ID/PW 필드에 자격증명 삽입.
        필드명을 찾지 못하면 공통 이름 후보로 폴백.
        """
        data = dict(known_fields)  # hidden fields 포함

        user_key = None
        pass_key = None

        for k in data:
            kl = k.lower()
            if any(f in kl for f in _USER_FIELDS) and user_key is None:
                user_key = k
            if any(f in kl for f in _PASS_FIELDS) and pass_key is None:
                pass_key = k

        if user_key is None:
            user_key = "id"
        if pass_key is None:
            pass_key = "password"

        data[user_key] = username
        data[pass_key] = password
        return data

    # ── HTTP POST 실행 ────────────────────────────────────────────────

    def _do_post(
        self,
        url: str,
        data: dict,
        follow_redirects: bool = True,
    ) -> tuple[int, dict[str, str]]:
        """POST 전송 → (응답 body 길이, 쿠키 dict)"""
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.8",
        }
        try:
            with httpx.Client(
                verify=False,
                timeout=self.timeout,
                follow_redirects=follow_redirects,
                headers=headers,
            ) as client:
                resp = client.post(url, data=data)
                cookies = dict(resp.cookies)
                return len(resp.text), cookies
        except Exception:
            return 0, {}

    # ── 성공 판정 ─────────────────────────────────────────────────────

    def _judge(
        self,
        login_url: str,
        actual_len: int,
        baseline_len: int,
        cookies: dict[str, str],
        username: str,
        password: str,
    ) -> LoginResult:
        """응답 길이·쿠키·키워드를 종합하여 로그인 성공 여부 판단"""

        # 성공/실패 키워드 확인을 위해 실제 응답 본문 다시 가져오기
        body = self._fetch_after_login(login_url, cookies)

        has_success = any(kw.lower() in body.lower() for kw in _SUCCESS_KEYWORDS)
        has_fail = any(kw.lower() in body.lower() for kw in _FAIL_KEYWORDS)

        # 의미있는 쿠키 (generic 제외)
        meaningful_cookie = {
            k: v for k, v in cookies.items()
            if k.lower() not in _GENERIC_COOKIES
        }

        len_diff = abs(actual_len - baseline_len)

        # ── 판정 로직 ───────────────────────────────────────────────
        if has_fail:
            return LoginResult(
                success=False, evidence="FAILED",
                message=f"🔴 로그인 실패 — 실패 키워드 감지: {[kw for kw in _FAIL_KEYWORDS if kw.lower() in body.lower()][:2]}",
                cookies={}, login_url=login_url,
                username=username, password=password,
            )

        if has_success and (meaningful_cookie or len_diff > 300):
            return LoginResult(
                success=True, evidence="VERIFIED",
                message=f"✅ 로그인 성공 [VERIFIED] — 성공 키워드 확인, 세션 쿠키 저장",
                cookies=cookies, login_url=login_url,
                username=username, password=password,
            )

        if has_success:
            return LoginResult(
                success=True, evidence="LIKELY",
                message=f"🟡 로그인 성공 추정 [LIKELY] — 성공 키워드 확인 (쿠키 미확인)",
                cookies=cookies, login_url=login_url,
                username=username, password=password,
            )

        if meaningful_cookie and len_diff > 300:
            return LoginResult(
                success=True, evidence="LIKELY",
                message=f"🟡 로그인 성공 추정 [LIKELY] — 의미 있는 쿠키 + 응답 크기 변화({len_diff}bytes)",
                cookies=cookies, login_url=login_url,
                username=username, password=password,
            )

        if len_diff > 500:
            return LoginResult(
                success=True, evidence="INFERRED",
                message=f"🔵 로그인 가능성 있음 [INFERRED] — 응답 크기 변화 {len_diff}bytes (키워드 없음)",
                cookies=cookies, login_url=login_url,
                username=username, password=password,
            )

        return LoginResult(
            success=False, evidence="FAILED",
            message=f"🔴 로그인 실패 — 변화 없음 (응답차이 {len_diff}bytes, 쿠키 없음)",
            cookies={}, login_url=login_url,
            username=username, password=password,
        )

    def _fetch_after_login(self, login_url: str, cookies: dict) -> str:
        """로그인 후 메인 페이지에서 성공/실패 키워드 확인"""
        if not cookies:
            return ""
        try:
            with httpx.Client(
                verify=False,
                timeout=self.timeout,
                follow_redirects=True,
                cookies=cookies,
            ) as client:
                # 로그인 페이지의 부모 디렉토리에 접근 (보통 관리자 대시보드)
                base = "/".join(login_url.split("/")[:-1]) + "/"
                resp = client.get(base)
                return resp.text
        except Exception:
            return ""
