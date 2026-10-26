# P2-4 T-4.3（接收侧）· PRE-A-4：中央 remote-write 的 mTLS 终止代理

> 配套：发送侧 [`../remote-write-mtls/`](../remote-write-mtls/README.md)（各集群 Prometheus 挂客户端证书）。
> 本文解决的是**另一半**：中央接收侧如何真的校验「你是谁」。
>
> **缺口背景**：Prometheus 的 `--web.config.file` 只能做「服务端 TLS + basic_auth」，
> **没有 `ssl_verify_client` 语义** ⇒ 客户端证书在 Prometheus 这里形同虚设。
> 不发客户端证书也能写，等于 mTLS 只做了单向 —— 这正是 `PRE-A-4` 的核心缺口。

## 1. 数据路径

```
各集群 Prometheus ──[客户端证书]──► 9443 本代理 ──[明文，同命名空间]──► prometheus-central:9090
                     TLS 双向校验                  仅 /api/v1/write
```

- **9443**：唯一对外写入入口，双向 TLS（`ssl_verify_client on`）。
- **9090**：中央 Prometheus 本体，收紧后**只允许代理与 Grafana 访问**（见 §3 第 ② 步）。
- **8080**：代理自身 `/healthz`、`/stub_status`，**不放行跨集群来源**。

## 2. 资产

| 文件 | 内容 | 是否在 `resources` |
|------|------|:---:|
| `nginx-mtls-proxy.yaml` | ConfigMap(`nginx.conf`) + Deployment + Service(9443/8080) | ✅ |
| `kustomization.yaml` | overlay 入口；`images:` 可改内网镜像源 | — |
| `secret-mtls-server.example.yaml` | 服务端证书 + 客户端 CA 的 Secret 模板 | ❌ 模板勿 apply |
| `replace-central-write-np.tighten.yaml` | **同名替换**中央 NP：9090 只留代理 + Grafana | ❌ 需手工执行 |
| `networkpolicy-mtls-gateway-ingress.yaml` | 9443 的跨集群来源放行（按出口 IP） | ❌ 需填 CIDR 后执行 |

代理容器口径：非 root（UID 101）、`readOnlyRootFilesystem`、drop ALL capabilities、
`automountServiceAccountToken: false`、`seccompProfile: RuntimeDefault`。

## 3. 启用（三步，顺序不可颠倒）

```bash
# ⓪ 证书：与发送侧同一 CA（gen-ca.sh 一次出齐 CA / server / client）
(cd deploy/monitoring-overlays/remote-write-mtls && ./gen-ca.sh --out ./certs)

# ① 注入服务端证书 Secret（注意用 generic：kubernetes.io/tls 只装两键，放不下 ca.crt）
kubectl -n otpmask create secret generic otpmask-remote-write-mtls-server \
  --from-file=tls.crt=./certs/server.crt \
  --from-file=tls.key=./certs/server.key \
  --from-file=ca.crt=./certs/ca.crt \
  --dry-run=client -o yaml | kubectl apply -f -

# ② 起代理
kubectl apply -k deploy/monitoring-overlays/remote-write-mtls-server
kubectl -n otpmask rollout status deploy/remote-write-mtls-gateway

# ③ 打通后再收紧 9090（NP 加性 ⇒ 只能整对象替换，不能叠加）
kubectl apply -f deploy/monitoring-overlays/remote-write-mtls-server/replace-central-write-np.tighten.yaml

# ④ 填好各集群出口 IP 后再放行 9443
kubectl apply -f deploy/monitoring-overlays/remote-write-mtls-server/networkpolicy-mtls-gateway-ingress.yaml
```

> **为什么 ③ 必须放在 ② 之后**：收紧后 9090 对同命名空间全关，
> 若代理还没通，写入会**没有任何替代路径**。先通后收，故障时才有对照。

## 4. 验证

**本机已实测（无集群，仅静态与证书层）**

| 项 | 方法 | 状态 |
|---|---|---|
| 证书链 / EKU / SAN | `gen-ca.sh` 自校验 + `openssl verify` | ✅ 见发送侧 README §4 |
| 双向握手（证书层） | `openssl s_server -Verify 1` + `s_client -cert` | ✅ 客户端 `verify return:1`；无证书被拒 |
| YAML / 配置断言 | `python3 scripts/check-central-aggregation-assets.py`＋`scripts/check-mtls-proxy-assets.py` | ✅（`ssl_verify_client on`、CA 绑定、仅 write 路径等逐项断言） |
| kustomize 构建 | `kubectl kustomize deploy/monitoring-overlays/remote-write-mtls-server` | ✅（本机 kubectl v1.14 内置 kustomize v2） |

**待环境就绪（未做即未做，不得填 PASS）—— 登记 `PRE-B-9` + `PRE-A-11`**

- ❌ `nginx -t` 语法校验：本机无 nginx、Docker 引擎未启 ⇒ 静态断言通过**不等于**语法通过。
- ❌ 代理真实转发：未做「带证书写入成功 / 不带证书被拒 / 错误 CA 被拒」三组实测。
- ❌ Secret 卷 `0440` + `fsGroup: 101` 与 `readOnlyRootFilesystem` 的实机行为。
- ❌ 收紧 NP 后中央 Grafana 查询是否受影响（依赖 Grafana 真实 Pod 标签核对）。

## 5. 排障对照表（nginx 侧状态码）

| 现象 | 含义 | 处置 |
|---|---|---|
| 连接被直接断开 / `400 No required SSL certificate was sent` | 客户端未带证书 | 发送侧 `tls_config.cert_file/key_file` 是否挂上、卷是否可读 |
| `495` | 客户端证书校验失败（非本 CA / 链不全 / 过期） | 两端是否同一 CA；`openssl verify -CAfile ca.crt client.crt` |
| `496` | 未提供客户端证书（`ssl_verify_client on` 下等同拒绝） | 同上，先查发送侧配置 |
| `497`（HTTP 打 HTTPS 口） | 明文打 9443 | url 必须是 `https://…:9443/api/v1/write` |
| `404` | 路径不是精确的 `/api/v1/write` | 检查 url 尾部是否多了斜杠或用了 `/api/v1/push` |
| `405` | 非 POST | remote_write 只发 POST；GET 是手工探测打错了 |
| `502 / 504` | 代理→上游不通 | 中央 Prometheus 是否 Running；9090 是否被自己的 NP 拦了 |

## 6. 与端口矩阵 / NP 三档的关系

- `9443` 已登记为**唯一** mTLS 写入入口（[端口矩阵](../../k8s-overlays/trust/networkpolicy-tiers/README.md) §1）。
- `9443` 不出现在 NP 三档模板中：三档管的是**各集群侧数据面入站**（8085/19090），
  而 9443 在**中央集群侧**。两处不重叠，勿混填。
- 中央侧 9090 的收紧由 `replace-central-write-np.tighten.yaml` 负责，**不是**三档模板的职责。

## 7. 证书轮换（不引入 CRL，靠短周期 + 换签）

当前口径：**不做 CRL/OCSP**，靠 90 天有效期。因此「吊销」= 换 CA 或换签，步骤：

1. **同 CA 重签客户端证书**（最常见）：只更新发送侧 Secret，本代理无需重启（`ssl_client_certificate` 仍是同一 CA）。
2. **换 CA**（客户端证书泄露时的唯一手段）：
   - 先把**新旧两个 CA PEM 拼接**写入本 Secret 的 `ca.crt`（nginx 视作信任集合）→ `kubectl apply` → 重启代理；
   - 再逐集群换发新 CA 签的客户端证书；
   - 全部切完后，把 Secret 的 `ca.crt` 收敛回新 CA 单张 → 重启。
   - ⚠️ 顺序颠倒会**全集群写入瞬间中断**（旧证书已不被信任）。
3. 服务端证书轮换：只想改本 Secret 的 `tls.crt/tls.key` 并重启代理；
   发送侧 `server_name` 由证书 SAN 决定，若换 SAN 须同步改各集群 `server_name`。

## 8. 已知边界（写进设计而不是留给现场发现）

- **不做请求级鉴权**：代理只证明「这个客户端持有合法证书」，不区分集群身份 ⇒
  某个已认证客户端可以伪造 `external_labels.cluster` 写脏数据。
  精确到集群的写入准入需要按证书 CN 做 map（`map $ssl_client_s_dn`）→ 当前**未做**，
  属后续增强项（与 T-2.1 registry 的 cluster_id 对齐才有意义）。
- **单副本**：代理挂掉期间各集群在队列里重试（发送侧 `max_backoff=60s`、`capacity=10000`），
  不丢但会延迟；高可用需扩容 + 前置 L4 LB。
- **HTTP/2**：`http2 on` 需 nginx ≥ 1.25.1；镜像固定 `1.27-alpine`，换镜像须核对版本。
- **Grafana 放行是按标签猜的**：`app: grafana` 取自 `deploy/monitoring/grafana.yaml:545`，
  中央集群若用别的标签必须在 ③ 之前改，否则收紧后看板直接断。
