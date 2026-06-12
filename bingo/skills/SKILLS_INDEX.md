# BINGO SKILLS INDEX

bingo 에이전트가 자동으로 로드하는 전문 스킬 라이브러리.
Cursor의 SKILL.md 시스템과 동일한 방식으로 동작.

## 스킬 자동 로드 규칙

| 키워드/컨텍스트 | 자동 로드 스킬 |
|---|---|
| `sqli`, `sql injection`, `?id=`, `union`, `blind` | sqli/SKILL.md |
| `waf`, `cloudflare`, `blocked`, `403` | waf_bypass/SKILL.md |
| `api`, `/v1/`, `/graphql`, `jwt`, `oauth` | api_security/SKILL.md |
| `login`, `auth`, `session`, `password`, `sso` | auth_attack/SKILL.md |
| `subdomain`, `recon`, `scan`, `fingerprint` | recon/SKILL.md |
| `xss`, `ssrf`, `lfi`, `ssti`, `rce` | web_vuln/SKILL.md |

## 수동 로드

```
/skill load sqli
/skill load waf_bypass
/skill list
```
