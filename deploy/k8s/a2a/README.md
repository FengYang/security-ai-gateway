> 中文版 ｜ [English](./README.en.md)

# A2A K3S 部署（L1 Guardrail + a2aproxy + testagent）

本目录提供 P2-2 A2A 的 K3S 局域网验证清单。**不依赖本机 Docker**：静态交叉编译后生成 Docker-save tar，再通过临时特权 Pod 导入 K3S containerd。

> 适用边界：LAN 预生产验证。生产入口应改为 ClusterIP + Higress，注册快照应由控制面生成，审计应落 WORM，Guardrail 生产档位应接入 L2/ML（本目录仅 L1 规则版）。

## 1. 组件

| 文件 | 内容 |
|---|---|
| `guardrail.yaml` | `a2a-guardrail` Deployment + ClusterIP；加载镜像内 `/app/policy` |
| `testagent.yaml` | `a2a-testagent` Deployment + ClusterIP；`hello_world` 测试 Agent |
| `a2aproxy.yaml` | `a2aproxy` Deployment + NodePort `30086`；静态快照、签名 ACL、静态 bearer、JSONL 审计、内容安全检查接线 |
| `kustomization.yaml` | 统一命名空间 `otpmask` |

前置资源（由部署命令创建，不放入 Git）：

- ConfigMap `a2a-snapshot`：`snapshot.json`。
- Secret `a2a-proxy-secrets`：`acl.json`、`acl-key`、`auth-tokens`、`guardrail-token`。
- 镜像：`docker.io/security-ai-gateway/a2aproxy:lan-20261021`、`a2a-guardrail:lan-20261021`、`a2a-testagent:lan-20261021`。

## 2. 构建静态二进制与镜像 tar

要求 Go 1.26（系统 Go 1.20 不满足 `go 1.26.0`）。示例：

```powershell
$env:GOTOOLCHAIN = "local"
$env:GOOS = "linux"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
New-Item -ItemType Directory -Force .tools/a2a-deploy | Out-Null

go build -trimpath -ldflags="-s -w" -o .tools/a2a-deploy/a2aproxy ./gateway/a2aproxy/cmd
go build -trimpath -ldflags="-s -w" -o .tools/a2a-deploy/a2aguardrail ./gateway/a2aguardrail/cmd/a2aguardrail
go build -trimpath -ldflags="-s -w" -o .tools/a2a-deploy/a2a-testagent ./gateway/a2a/testagent/cmd
```

本次 LAN 验证使用一次性 `mkimage` 生成 Docker-save tar（scratch 静态镜像）。生产构建优先使用各目录 `Dockerfile`：

```text
gateway/a2aproxy/Dockerfile
gateway/a2aguardrail/Dockerfile
gateway/a2a/testagent/Dockerfile
```

Dockerfile 路径需要 Docker/BuildKit；本机无 Docker 时使用上面的静态二进制导入流程。

## 3. 导入 K3S containerd（无 Docker）

K3S 的 `kubectl` 不能直接导入镜像。使用临时特权 Pod 挂载宿主根目录，调用节点上的 `k3s ctr`：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: a2a-image-loader
  namespace: kube-system
spec:
  restartPolicy: Never
  hostPID: true
  containers:
    - name: loader
      image: busybox:1.36
      command: ["sh", "-c", "sleep 600"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: host
          mountPath: /host
  volumes:
    - name: host
      hostPath:
        path: /
```

```powershell
$kc = ".tools/k3s-kubeconfig-73.yaml"
kubectl --kubeconfig $kc apply -f loader-pod.yaml
kubectl --kubeconfig $kc -n kube-system wait --for=condition=Ready pod/a2a-image-loader --timeout=90s

foreach ($f in "a2aproxy","a2a-guardrail","a2a-testagent") {
  kubectl --kubeconfig $kc -n kube-system cp ".tools/a2a-deploy/$f.tar" "a2a-image-loader:/host/tmp/$f.tar"
  kubectl --kubeconfig $kc -n kube-system exec a2a-image-loader -- `
    chroot /host /usr/local/bin/k3s ctr `
      --address /run/k3s/containerd/containerd.sock `
      --namespace k8s.io images import "/tmp/$f.tar"
}

kubectl --kubeconfig $kc -n kube-system delete pod a2a-image-loader
```

`/usr/local/bin/k3s ctr` 的版本应与集群一致；本集群为 `v2.3.4-k3s1.36`。

## 4. 生成部署夹具

本次 LAN 验证的夹具（签名 ACL、随机 bearer、testagent 静态快照）在 `.tools/a2a-deploy/`，该目录已被 `.gitignore` 忽略：

```text
acl.json
acl-key.txt
auth-tokens.txt
auth-token.txt
guardrail-token.txt
snapshot.json
```

生产环境不应使用一次性夹具：ACL 由控制面签名并轮换，bearer 由密钥管理下发，snapshot 由注册中心生成。

## 5. 创建 ConfigMap / Secret

先创建资源，再 apply 工作负载，避免 Pod 短暂 `CreateContainerConfigError`。

```powershell
$kc = ".tools/k3s-kubeconfig-73.yaml"
$key    = (Get-Content .tools/a2a-deploy/acl-key.txt -Raw).Trim()
$tokens = (Get-Content .tools/a2a-deploy/auth-tokens.txt -Raw).Trim()
$gtoken = (Get-Content .tools/a2a-deploy/guardrail-token.txt -Raw).Trim()

kubectl --kubeconfig $kc -n otpmask create configmap a2a-snapshot `
  --from-file=snapshot.json=.tools/a2a-deploy/snapshot.json

kubectl --kubeconfig $kc -n otpmask create secret generic a2a-proxy-secrets `
  --from-file=acl.json=.tools/a2a-deploy/acl.json `
  --from-literal=acl-key=$key `
  --from-literal=auth-tokens=$tokens `
  --from-literal=guardrail-token=$gtoken
```

重复执行前先删除旧资源，或在 `kubectl create` 后接 `kubectl apply -f -` 的 YAML 流程。`a2aproxy` 以只读方式挂载 Secret，`guardrail-token` 与 Guardrail 的 `GUARDRAIL_AUTH_TOKEN` 必须一致。

## 6. 部署与探针

```powershell
$kc = ".tools/k3s-kubeconfig-73.yaml"
kubectl --kubeconfig $kc apply -k deploy/k8s/a2a
kubectl --kubeconfig $kc -n otpmask rollout status deployment/a2a-guardrail --timeout=120s
kubectl --kubeconfig $kc -n otpmask rollout status deployment/a2a-testagent --timeout=120s
kubectl --kubeconfig $kc -n otpmask rollout status deployment/a2aproxy --timeout=120s
kubectl --kubeconfig $kc -n otpmask get pods -l app.kubernetes.io/part-of=a2a -o wide
```

预期：

- `a2aproxy`：`/readyz` 返回 `ready`；日志出现快照加载、治理 wired、内容安全 wired。
- `a2a-guardrail`：`/readyz` 200；启动日志含规则数（本策略为 10,068 total / 1,466 active）。
- `a2a-testagent`：TCP 9001 就绪。

## 7. 端到端检查

```powershell
$base  = "http://192.168.31.73:30086"
$token = (Get-Content .tools/a2a-deploy/auth-token.txt -Raw).Trim()

curl.exe -sS "$base/readyz"
curl.exe -sS "$base/a2a/tenant-a/testagent/.well-known/agent-card.json"
```

`SendMessage` 请求需带：

```text
Authorization: Bearer <token>
A2A-Version: 1.0
X-GA-A2A-Skill: hello_world
Content-Type: application/json
```

请求体示例：

```json
{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"kind":"text","text":"hello"}]}}}
```

验证点：

1. 普通文本 → `result.task.status.state=TASK_STATE_COMPLETED`。
2. 命中 L1 block 类目 → `-32010` / `content_blocked`，后端不收到请求。
3. 命中 mask 类目（如手机号）→ 响应 Part 变为 `[REDACTED]`，结构字段保留。
4. 无 token → `-31401` / `unauthenticated`。
5. 临时把 `a2a-guardrail` 缩容到 0 → 请求返回 `-32010`（`A2A_CONTENT_SAFETY_FAIL_CLOSED=true`）；恢复后放行。

审计：

```powershell
$kc = ".tools/k3s-kubeconfig-73.yaml"
$pod = kubectl --kubeconfig $kc -n otpmask get pods -l app=a2aproxy -o jsonpath="{.items[0].metadata.name}"
kubectl --kubeconfig $kc -n otpmask logs $pod --tail=50
```

`a2aproxy` 为 scratch 镜像，无 `cat`/`sh`；审计文件在 emptyDir，需通过节点 hostPath 临时读取，或改为 sidecar/持久卷。生产建议接 `policyaudit`/WORM。

## 8. 生产前必须替换

1. **入口**：删除 NodePort `30086`，改 ClusterIP + Higress 路由；修复 `higress-gateway` 的 hostPort 冲突副本。
2. **注册快照**：改为控制面签名快照/注册中心拉取，不使用静态 ConfigMap。
3. **ACL/token**：接密钥管理与轮换；禁止把夹具写入仓库或长期使用静态 bearer。
4. **审计**：emptyDir JSONL → WORM/集中审计，补完整性校验与保留策略。
5. **Guardrail**：按业务分级接 L2/ML（qwen3guard 可选）；本目录只验证 L1 规则版。
6. **镜像**：生产 Dockerfile 构建并扫描；本地 scratch 镜像不含 CA bundle。
7. **Tracing**：确认 Collector → Tempo 链路可查询，再宣称 tracing 验收通过。
