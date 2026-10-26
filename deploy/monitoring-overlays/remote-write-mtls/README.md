# P2-4 T-4.3：remote-write mTLS 发送侧（per-cluster Prometheus）

> 与 `deploy/monitoring/central/trust/README.md`（中央侧）配套。
> 本 overlay 只挂载客户端证书；**目标地址与 tls_config 片段由运维合并进 prometheus.yml**。
>
> **证书来源两条路径（不再"等客户 CA"）**：
> - **路径 1 内置自签 CA（默认，离线可用）**：`gen-ca.sh --out <dir>` 一次生成 CA + 服务端 + 客户端证书，
>   POC/内网/MVP 直接可用；
> - **路径 2 企业 CA 注入（可选）**：`gen-ca.sh --out <dir> --mode csr` 只生成私钥与 CSR，
>   交客户 CA 签发后放回 `server.crt` / `client.crt` / `ca.crt`。
>
> 两条路径的**发送侧配置完全相同**（都读 `/etc/prometheus/mtls/{ca.crt,tls.crt,tls.key}`），
> 换 CA 不改配置。

## 1. 资产

| 文件 | 内容 |
|------|------|
| `kustomization.yaml` | overlay 入口（`bases: ../../monitoring`） |
| `patch-prometheus-tls-volume.yaml` | Prometheus Deployment：挂载 `otpmask-remote-write-mtls` → `/etc/prometheus/mtls`（0400, readOnly） |
| `prometheus-remote-write-snippet.yml` | 待合并进 prometheus.yml 的片段：`external_labels.cluster` + `remote_write`（url/tls_config/authorization） |
| `secret-remote-write-mtls.example.yaml` | 客户端证书 Secret 模板（**不在 resources 内，勿 apply**） |
| `gen-ca.sh` | **证书生成器**：`self-signed`（自签 CA）／`csr`（企业 CA）两模式；含链、EKU、SAN、私钥权限自校验 |

## 2. 启用步骤

```bash
# ① 生成证书（二选一）
#    路径 1 · 内置自签 CA（离线，POC 即用）
./gen-ca.sh --out ./certs
#    路径 2 · 企业 CA（只出 CSR，交客户 CA 签发）
./gen-ca.sh --out ./certs --mode csr
#      → 签发后放回 ./certs/{server.crt,client.crt,ca.crt}，再跑：
#        openssl verify -CAfile ./certs/ca.crt ./certs/server.crt ./certs/client.crt

# ② 注入客户端证书 Secret（禁止入库）
#    必须三键 `--from-file`：`create secret tls` 装不下 ca.crt，
#    `create secret generic` 又没有 --cert/--key/--ca-file 这些 flag
kubectl -n otpmask create secret generic otpmask-remote-write-mtls \
  --from-file=tls.crt=./certs/client.crt \
  --from-file=tls.key=./certs/client.key \
  --from-file=ca.crt=./certs/ca.crt \
  --dry-run=client -o yaml | kubectl apply -f -

# ③ 挂载证书卷
kubectl apply -k deploy/monitoring-overlays/remote-write-mtls

# ④ 合并配置片段（ConfigMap 数据是字符串，strategic merge 无法安全改写 → 人工/流程合并）
#    - global.external_labels.cluster: <本集群唯一 ID>
#    - remote_write: url / tls_config / authorization（见 snippet，含占位符）
#    合并后：kubectl -n otpmask rollout restart deployment/prometheus
```

## 3. 关键口径

- **目标地址可配置**：snippet 中 `url: REPLACE_WITH_CENTRAL_WRITE_ENDPOINT` 为占位符，
  **不写死任何内网地址**。形态 B（我方中央栈）**必须指向 mTLS 终止代理 9443**：
  `https://remote-write-mtls-gateway.<ns>.svc.cluster.local:9443/api/v1/write`，
  代理只放行精确路径 `/api/v1/write` 并强制客户端证书；直连 `prometheus-central:9090` 仅限
  「尚未收紧 NP 的内网/专线临时态」，不得作为交付形态。
  代理侧资产见 [`../remote-write-mtls-server/`](../remote-write-mtls-server/README.md)。
  形态 A 的四种接收端（原生 Prometheus / Thanos / Mimir / VM）见
  [`deploy/monitoring/central/receivers/`](../../monitoring/central/receivers/README.md)。
- **cluster 标签口径**：`external_labels.cluster` 是中央侧 `by (cluster)`、看板变量、
  Alertmanager `equal: [cluster]` 的唯一来源，每集群必须唯一（建议 = registry cluster_id）。
- **mTLS 校验**：`server_name` 必须与接收端证书 SAN 一致，`insecure_skip_verify: false` 固定。
- **证书用途分离**：服务端 `EKU=serverAuth`、客户端 `EKU=clientAuth`，**不签双用途证书**
  （双用途会让"客户端证书"可用于冒充服务端）。
- **租户头不是认证**：Mimir 的 `X-Scope-OrgID`、Thanos 的 `THANOS-TENANT` 是**路由**语义，
  可被伪造；真正的"谁在写"由 mTLS 客户端证书保证。
- **鉴权**：Bearer 令牌走 `credentials_file`（Secret 挂载），**禁止明文写进 prometheus.yml**。
- **有效期**：默认 90 天（轮换周期口径）；`gen-ca.sh --days` 可改，>90 会告警。
- **私钥权限**：脚本在 POSIX 上断言 `600`，不满足即判失败；Windows 文件系统无 POSIX 权限语义
  → 脚本明确告警并要求在 Linux 上重生成（**不假装通过**）。

## 4. 验证状态（区分"本机已实测"与"待环境"）

**已实测（本机，OpenSSL 3.5.7、ECDSA P-256、2026-10-26）**

| 项 | 方法 | 结果 |
|---|---|---|
| 证书链 | `openssl verify -CAfile ca.crt server.crt client.crt` | ✅ 两者均 OK |
| 服务端 SAN | `openssl x509 -noout -ext subjectAltName` | ✅ 覆盖 `prometheus-central.otpmask.svc.cluster.local` / `.svc` / `localhost` |
| EKU 分离 | `-ext extendedKeyUsage` | ✅ 服务端 `serverAuth`、客户端 `clientAuth` |
| **双向 mTLS 握手** | `openssl s_server -Verify 1` + `s_client -cert` | ✅ 客户端证书 `verify return:1`（CN=otpmask-prometheus-writer） |
| **无证书被拒** | 同上，`s_client` 不带 `-cert` | ✅ 服务端 `peer did not return a certificate` |
| 覆盖保护 | 二次运行不带 `--force` | ✅ 退出码 3（拒绝覆盖 CA 私钥） |
| `--force` 备份 | 二次运行带 `--force` | ✅ 旧产物移到 `.bak-<时间戳>` |
| 企业 CA 模式 | `--mode csr` | ✅ 只产 `server.csr`/`client.csr`，不签发 |
| 私钥权限 | `stat -c %a` | ⚠️ Windows 下为 644（无 POSIX 语义）→ 脚本已告警；**Linux 上须复核为 600** |

**待环境就绪（未做即未做）**

- ❌ **K8s 证书卷挂载未实测**：本机无 K8s，Secret 创建与 `/etc/prometheus/mtls` 挂载均未执行。
- ❌ **Prometheus 实际写入未实测**：片段合并后的 `prometheus.yml` 语法与真实 remote-write 连通性未验证。
- ⚠️ `defaultMode: 0400` 与 Prometheus 以 `nobody(65534)` 运行 → Secret 卷对该用户可读性需实测
  （K8s Secret 卷默认属主 root:root，0400 时 nobody 读不到 → 需按 CNI/运行时调整，
  或改用 CSI Secret Store）。**此项必须在环境就绪后立即验证。**
- ⚠️ **真实握手只覆盖证书层**：`s_server` 验证的是"证书链与用途正确"，不等于
  "接收端代理（nginx/envoy）配置正确"——代理侧 `ssl_verify_client on` 与 CA 绑定仍需现场核对。
