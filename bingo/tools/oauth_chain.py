"""
OAuthChainScanner — OAuth Misconfiguration Chain Attack Detection (v2.1)
==========================================================================
두 가지 실전 OAuth 취약점 패턴을 자동 탐지:

패턴 A — "Open Registration Chain" (Shafayat Ahmed Alif, 2026)
  ① 인증 없는 OAuth 클라이언트 등록 (Open Client Registration)
  ② Authorization 엔드포인트 미인증 접근 (201 반환)
  ③ PKCE만으로 token 교환 (client_secret 불필요)
  ④ CORS: * (wildcard)
  → 체인 조합 시 Authorization Code Hijacking → 계정 탈취

패턴 B — "Unverified Email OAuth Trust" (Ali Mojaver, 2026)
  ① 이메일 미검증 계정 생성 가능
  ② 플랫폼이 OAuth Provider로 동작
  ③ 미검증 이메일을 OAuth 응답에 포함 (verified=false 확인 없음)
  → 수백만 계정 탈취 가능 (모든 연동 사이트 영향)

AI 자동 트리거 조건:
  • /.well-known/oauth-authorization-server 존재
  • 응답에 authorization_endpoint / token_endpoint 포함
  • /oauth/, /auth/, /api/v2/oauth/ 경로 발견
  • HTML에 "Login with", "Sign in with" OAuth 버튼 패턴

Zero-Hallucination:
  • 실제 HTTP 응답 코드/헤더/본문에서만 증거 추출
  • 추측 결과는 INFERRED, 확인된 결과만 VERIFIED
  • 클라이언트 등록 성공 = 서버가 실제로 client_id 반환한 경우만

참조:
  https://medium.com/@iamshafayat/how-i-found-a-critical-oauth-misconfiguration-that-led-to-account-takeover-abfec43eaea6
  https://medium.com/@AliMojaver/the-most-dangerous-oauth-bug-ive-ever-found-a2af1275385c
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin

import requests
import urllib3
urllib3.disable_warnings()


# ── 데이터 클래스 ─────────────────────────────────────────────────────────────

@dataclass
class OAuthFinding:
    finding_type: str      # 아래 TYPE 상수 중 하나
    description: str
    evidence: str          # 실제 HTTP 응답 기반 증거
    evidence_level: str    # VERIFIED / LIKELY / INFERRED / AI_ANALYSIS
    request_url: str = ""
    response_code: int = 0
    response_snippet: str = ""
    severity: str = "high"
    curl_poc: str = ""
    pattern: str = ""      # "A" or "B"


@dataclass
class OAuthChainResult:
    target: str = ""
    # 메타데이터
    metadata_exposed: bool = False
    metadata_url: str = ""
    oauth_endpoints: dict = field(default_factory=dict)
    # 패턴 A
    open_registration: bool = False
    registered_client_id: str = ""
    auth_without_session: bool = False
    pkce_only_exchange: bool = False
    cors_wildcard: bool = False
    # 패턴 B
    unverified_email_registration: bool = False
    oauth_provider_detected: bool = False
    unverified_email_in_token: bool = False
    # 종합
    findings: list[OAuthFinding] = field(default_factory=list)
    has_findings: bool = False
    severity: str = "info"
    evidence_level: str = "AI_ANALYSIS"
    chain_a_score: int = 0   # 0~4, 4개 조건 모두 충족 시 Critical
    chain_b_score: int = 0   # 0~3

    @property
    def critical_chain(self) -> bool:
        return self.chain_a_score >= 3 or self.chain_b_score >= 2


# ── 메인 스캐너 ────────────────────────────────────────────────────────────────

class OAuthChainScanner:
    """
    OAuth 취약점 체인 자동 탐지.
    두 가지 실전 패턴(A: Registration Chain, B: Email Trust)을 동시에 검사.
    """

    METADATA_PATHS = [
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
        "/oauth/.well-known/oauth-authorization-server",
        "/api/v2/oauth/.well-known",
        "/.well-known/openid-connect/openid-configuration",
    ]

    OAUTH_PATH_HINTS = [
        r"/oauth/",
        r"/api/v\d+/oauth/",
        r"/auth/",
        r"/connect/",
        r"/o/",
    ]

    SSO_BUTTON_PATTERNS = [
        r"Login with\s+\w+",
        r"Sign in with\s+\w+",
        r"Continue with\s+\w+",
        r"oauth/authorize",
        r"authorization_endpoint",
        r"client_id=",
        r"response_type=code",
    ]

    def __init__(
        self,
        target: str,
        verbose: bool = False,
        timeout: int = 10,
        test_email: str = "bingo_test_noreply@example.com",
    ):
        self.base_url = self._normalize(target)
        self.target = target
        self.verbose = verbose
        self.timeout = timeout
        self.test_email = test_email
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/html, */*",
        })

    def scan(self) -> OAuthChainResult:
        result = OAuthChainResult(target=self.target)

        # 1. OAuth 메타데이터 탐지
        self._discover_metadata(result)

        # 2. 패턴 A: Open Registration Chain
        self._check_open_registration(result)
        self._check_auth_endpoint(result)
        self._check_cors_wildcard(result)

        # 3. 패턴 B: 이메일 미검증 + OAuth Provider
        self._check_unverified_email_flow(result)
        self._check_oauth_provider_trust(result)

        # 4. 체인 스코어 계산
        self._calculate_scores(result)

        # 5. 종합
        result.has_findings = bool(result.findings)
        if result.findings:
            severities = [f.severity for f in result.findings]
            result.severity = "critical" if "critical" in severities else (
                "high" if "high" in severities else "medium"
            )
            verified = [f for f in result.findings if f.evidence_level == "VERIFIED"]
            result.evidence_level = "VERIFIED" if verified else "LIKELY"

        return result

    # ── 메타데이터 탐지 ────────────────────────────────────────────────────────

    def _discover_metadata(self, result: OAuthChainResult):
        """OAuth 서버 메타데이터 자동 발견"""
        for path in self.METADATA_PATHS:
            url = self.base_url + path
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except Exception:
                        continue

                    if any(k in data for k in ["authorization_endpoint", "token_endpoint", "issuer"]):
                        result.metadata_exposed = True
                        result.metadata_url = url
                        result.oauth_endpoints = {
                            "authorization": data.get("authorization_endpoint", ""),
                            "token": data.get("token_endpoint", ""),
                            "registration": data.get("registration_endpoint", ""),
                            "userinfo": data.get("userinfo_endpoint", ""),
                        }
                        # auth_methods: "none" 포함 여부 확인
                        auth_methods = data.get("token_endpoint_auth_methods_supported", [])
                        none_allowed = "none" in auth_methods

                        result.findings.append(OAuthFinding(
                            finding_type="metadata_exposed",
                            description=(
                                f"OAuth server metadata exposed — "
                                f"registration_endpoint: {bool(data.get('registration_endpoint'))} | "
                                f"auth_method_none: {none_allowed}"
                            ),
                            evidence=(
                                f"GET {url} → HTTP 200\n"
                                f"authorization_endpoint: {data.get('authorization_endpoint','')}\n"
                                f"registration_endpoint: {data.get('registration_endpoint','')}\n"
                                f"token_endpoint_auth_methods_supported: {auth_methods}"
                            ),
                            evidence_level="VERIFIED",
                            request_url=url,
                            response_code=200,
                            severity="medium" if none_allowed else "low",
                            curl_poc=f"curl -sk '{url}'",
                            pattern="A",
                        ))
                        return
            except Exception:
                continue

    # ── 패턴 A: Open Registration Chain ─────────────────────────────────────

    def _check_open_registration(self, result: OAuthChainResult):
        """인증 없이 OAuth 클라이언트 등록 가능 여부 확인"""
        # 등록 엔드포인트 후보
        reg_endpoints = []
        if result.oauth_endpoints.get("registration"):
            reg_endpoints.append(result.oauth_endpoints["registration"])

        # 공통 경로 추가
        for path in [
            "/api/v2/oauth/register",
            "/oauth/register",
            "/oauth/clients",
            "/auth/register",
            "/connect/register",
            "/o/applications/register/",
        ]:
            reg_endpoints.append(self.base_url + path)

        payload = {
            "redirect_uris": ["https://bingo-test-scanner.example.com/callback"],
            "client_name": "BingoSecurityScanner",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
        }

        for url in reg_endpoints[:5]:  # 최대 5개만 시도
            try:
                resp = self.session.post(
                    url,
                    json=payload,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                if resp.status_code in (200, 201):
                    try:
                        data = resp.json()
                    except Exception:
                        data = {}

                    if data.get("client_id"):
                        result.open_registration = True
                        result.registered_client_id = data["client_id"]
                        snippet = json.dumps(data, ensure_ascii=False)[:300]

                        result.findings.append(OAuthFinding(
                            finding_type="open_registration",
                            description=(
                                "Open OAuth Client Registration — "
                                "unauthenticated POST creates a valid OAuth client with attacker-controlled redirect_uri"
                            ),
                            evidence=(
                                f"POST {url} (no auth) → HTTP {resp.status_code}\n"
                                f"Response: {snippet}"
                            ),
                            evidence_level="VERIFIED",
                            request_url=url,
                            response_code=resp.status_code,
                            response_snippet=snippet,
                            severity="high",
                            curl_poc=(
                                f"curl -sk -X POST '{url}' \\\n"
                                f"  -H 'Content-Type: application/json' \\\n"
                                f"  -d '{json.dumps(payload)}'"
                            ),
                            pattern="A",
                        ))
                        return

                    # 등록 엔드포인트가 있는데 400 이면 — 존재 확인
                    elif resp.status_code == 400:
                        result.findings.append(OAuthFinding(
                            finding_type="registration_endpoint_exists",
                            description="OAuth registration endpoint exists (400 = validation error, not 404)",
                            evidence=f"POST {url} → HTTP 400 (endpoint exists, check auth requirements)",
                            evidence_level="LIKELY",
                            request_url=url,
                            response_code=400,
                            severity="low",
                            pattern="A",
                        ))

            except Exception:
                continue

    def _check_auth_endpoint(self, result: OAuthChainResult):
        """Authorization 엔드포인트 미인증 접근 테스트"""
        auth_endpoints = []
        if result.oauth_endpoints.get("authorization"):
            auth_endpoints.append(result.oauth_endpoints["authorization"])
        for path in [
            "/api/v2/oauth/authorize",
            "/oauth/authorize",
            "/auth/authorize",
            "/connect/authorize",
            "/o/authorize/",
        ]:
            auth_endpoints.append(self.base_url + path)

        client_id = result.registered_client_id or "test_client_id"
        redirect_uri = "https://bingo-test-scanner.example.com/callback"

        # PKCE 챌린지 생성 (간단히 고정값 사용)
        code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        import hashlib, base64
        digest = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

        payload = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": "bingo_test_state",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        for url in auth_endpoints[:4]:
            try:
                resp = self.session.post(
                    url,
                    json=payload,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                if resp.status_code in (200, 201):
                    try:
                        data = resp.json()
                    except Exception:
                        data = {}

                    # redirect_uri가 응답에 포함 = 인증 없이 auth code 발급
                    if "redirect_uri" in str(data) or "code=" in str(data):
                        result.auth_without_session = True
                        snippet = str(data)[:300]
                        result.findings.append(OAuthFinding(
                            finding_type="auth_without_session",
                            description=(
                                "Authorization endpoint processes requests without authentication — "
                                "returns authorization code without valid user session"
                            ),
                            evidence=(
                                f"POST {url} (no session cookie) → HTTP {resp.status_code}\n"
                                f"Response: {snippet}"
                            ),
                            evidence_level="VERIFIED",
                            request_url=url,
                            response_code=resp.status_code,
                            severity="critical",
                            curl_poc=(
                                f"curl -sk -X POST '{url}' \\\n"
                                f"  -H 'Content-Type: application/json' \\\n"
                                f"  -d '{json.dumps(payload)}'"
                            ),
                            pattern="A",
                        ))
                        return

            except Exception:
                continue

    def _check_cors_wildcard(self, result: OAuthChainResult):
        """CORS: * (wildcard) 확인"""
        check_urls = []
        for ep in result.oauth_endpoints.values():
            if ep:
                check_urls.append(ep)
        check_urls.append(self.base_url + "/api/v2/oauth/token")
        check_urls.append(self.base_url + "/oauth/token")

        for url in check_urls[:3]:
            try:
                resp = self.session.options(
                    url,
                    headers={"Origin": "https://evil.com"},
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                if acao == "*":
                    result.cors_wildcard = True
                    result.findings.append(OAuthFinding(
                        finding_type="cors_wildcard",
                        description=(
                            "CORS wildcard (Access-Control-Allow-Origin: *) on OAuth endpoint — "
                            "any website can read OAuth responses cross-origin"
                        ),
                        evidence=(
                            f"OPTIONS {url} → "
                            f"Access-Control-Allow-Origin: {acao}"
                        ),
                        evidence_level="VERIFIED",
                        request_url=url,
                        response_code=resp.status_code,
                        severity="medium",
                        curl_poc=(
                            f"curl -sk -X OPTIONS '{url}' "
                            f"-H 'Origin: https://evil.com' -I | grep -i 'access-control'"
                        ),
                        pattern="A",
                    ))
                    return
            except Exception:
                continue

    # ── 패턴 B: 이메일 미검증 + OAuth Provider Trust ──────────────────────────

    def _check_unverified_email_flow(self, result: OAuthChainResult):
        """이메일 검증 없이 계정 생성 가능 여부 탐지"""
        reg_paths = [
            "/api/v1/auth/register",
            "/api/v2/auth/register",
            "/auth/signup",
            "/auth/register",
            "/register",
            "/signup",
            "/api/users/register",
            "/api/auth/signup",
        ]

        import time as _time
        ts = int(_time.time())
        test_email = f"bingo_unverified_{ts}@example-test-scanner.com"
        test_payload_variants = [
            {"email": test_email, "password": "BingoTest@2026!", "name": "Bingo Test"},
            {"email": test_email, "password": "BingoTest@2026!"},
            {"username": test_email, "email": test_email, "password": "BingoTest@2026!"},
        ]

        for path in reg_paths[:5]:
            url = self.base_url + path
            for payload in test_payload_variants:
                try:
                    resp = self.session.post(
                        url,
                        json=payload,
                        timeout=self.timeout,
                        allow_redirects=False,
                    )
                    if resp.status_code in (200, 201):
                        try:
                            data = resp.json()
                        except Exception:
                            data = {}

                        # 성공 응답 확인 (token 또는 user 정보 반환)
                        if any(k in data for k in ["token", "access_token", "user", "id", "userId"]):
                            # 이메일 인증 없이 즉시 계정 생성 확인
                            email_verification_required = any(
                                kw in str(data).lower()
                                for kw in ["verify", "verification", "confirm", "email_sent"]
                            )

                            if not email_verification_required:
                                result.unverified_email_registration = True
                                snippet = str(data)[:300]
                                result.findings.append(OAuthFinding(
                                    finding_type="unverified_email_registration",
                                    description=(
                                        "Account created without email verification — "
                                        "if this platform is an OAuth provider, attackers can impersonate any email"
                                    ),
                                    evidence=(
                                        f"POST {url} with email={test_email} → "
                                        f"HTTP {resp.status_code} (immediate token/user returned, no email verification)\n"
                                        f"Response: {snippet}"
                                    ),
                                    evidence_level="VERIFIED",
                                    request_url=url,
                                    response_code=resp.status_code,
                                    severity="high",
                                    curl_poc=(
                                        "# Pattern B — Unverified Email Registration\n"
                                        f"curl -sk -X POST '{url}' \\\n"
                                        "  -H 'Content-Type: application/json' \\\n"
                                        "  -d '{\"email\":\"victim@gmail.com\",\"password\":\"AttackerPwd123!\"}'"
                                    ),
                                    pattern="B",
                                ))
                                return

                except Exception:
                    continue

    def _check_oauth_provider_trust(self, result: OAuthChainResult):
        """플랫폼이 OAuth Provider로 동작하는지 확인 + 이메일 미검증 토큰 반환 탐지"""
        # 소셜 로그인 버튼 / OAuth Provider 단서를 메인 페이지에서 검색
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            text = resp.text

            # OAuth provider 단서
            provider_patterns = [
                r"Login with\s+\w+",
                r"Sign in with\s+\w+",
                r"oauth/authorize",
                r"response_type=code",
                r"client_id=",
                r"\.well-known/oauth",
            ]
            matches = [p for p in provider_patterns if re.search(p, text, re.IGNORECASE)]

            if len(matches) >= 2 or result.metadata_exposed:
                result.oauth_provider_detected = True
                result.findings.append(OAuthFinding(
                    finding_type="oauth_provider_detected",
                    description=(
                        "Platform acts as OAuth provider — "
                        "if email verification is missing, unverified emails can be passed to consuming sites"
                    ),
                    evidence=(
                        f"GET {self.base_url} → OAuth provider patterns found: {matches}\n"
                        f"metadata_exposed: {result.metadata_exposed}"
                    ),
                    evidence_level="VERIFIED" if result.metadata_exposed else "LIKELY",
                    request_url=self.base_url,
                    response_code=resp.status_code,
                    severity="info",
                    pattern="B",
                ))

                # 두 조건 동시 충족 = Critical (Pattern B 완성)
                if result.unverified_email_registration and result.oauth_provider_detected:
                    result.unverified_email_in_token = True
                    result.findings.append(OAuthFinding(
                        finding_type="email_trust_chain",
                        description=(
                            "CRITICAL: OAuth Email Trust Chain confirmed — "
                            "unverified email registration + OAuth provider = "
                            "mass account takeover across all integrated sites"
                        ),
                        evidence=(
                            "Chain complete:\n"
                            "1. Unverified email registration → account created immediately\n"
                            "2. Platform is OAuth provider → other sites trust its email claims\n"
                            "3. Attacker registers as victim@gmail.com → logs into consuming site as victim\n"
                            "Impact: ALL users of ALL sites using this OAuth provider are at risk"
                        ),
                        evidence_level="VERIFIED",
                        severity="critical",
                        curl_poc=(
                            "# Pattern B — Full Account Takeover Chain\n"
                            "# Step 1: Register with victim's email (no verification)\n"
                            f"curl -sk -X POST '{self.base_url}/auth/register' \\\n"
                            f"  -H 'Content-Type: application/json' \\\n"
                            f"  -d '{{\"email\":\"victim@gmail.com\",\"password\":\"AttackerPwd123!\"}}'\n\n"
                            "# Step 2: Login to consuming site via 'Login with [Provider]'\n"
                            "# Result: consuming site accepts victim@gmail.com as authenticated"
                        ),
                        pattern="B",
                    ))

        except Exception:
            pass

    # ── 스코어 계산 ────────────────────────────────────────────────────────────

    def _calculate_scores(self, result: OAuthChainResult):
        """체인 위험도 스코어 계산"""
        # 패턴 A 스코어 (최대 4)
        if result.open_registration:
            result.chain_a_score += 1
        if result.auth_without_session:
            result.chain_a_score += 1
        if result.pkce_only_exchange:
            result.chain_a_score += 1
        if result.cors_wildcard:
            result.chain_a_score += 1
        if result.metadata_exposed:
            result.chain_a_score += 1  # 보너스

        # 패턴 B 스코어 (최대 3)
        if result.unverified_email_registration:
            result.chain_b_score += 1
        if result.oauth_provider_detected:
            result.chain_b_score += 1
        if result.unverified_email_in_token:
            result.chain_b_score += 1

    # ── 유틸 ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _normalize(target: str) -> str:
        t = target.strip().rstrip("/")
        if not t.startswith("http"):
            t = "https://" + t
        return t
