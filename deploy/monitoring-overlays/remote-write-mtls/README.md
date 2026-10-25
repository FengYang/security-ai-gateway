# P2-4 T-4.3：remote-write mTLS 发送侧（per-cluster Prometheus）

> 与 `deploy/monitoring/central/trust/README.md`（中央侧）配套。
> 本 overlay 只挂载客户端证书；**目标地址与 tls_config 片段由运维合并进 prometheus.yml**。

## 1. 资产

| 文件 | 内容 |
|------|------|
| `kustomization.yaml` | overlay 入口（`bases: ../../monitoring`） |
| `patch-prometheus-tls-volume.yaml` | Prometheus Deployment：挂载 `otpmask-remote-write-mtls` → `/etc/prometheus/mtls`（0400, readOnly） |
| `prometheus-remote-write-snippet.yml` | 待合并进 prometheus.yml 的片段：`external_labels.cluster` + `remote_write`（url/tls_config/authorization） |
| `secret-remote-write-mtls.example.yaml` | 客户端证书 Secret 模板（**不在 resources 内，勿 apply**） |

## 2. 启用步骤

```bash
# ① 签发并注入证书（禁止入库；同一 CA 与接收侧共用）
kubectl -n otpmask create secret tls otpmask-remote-write-mtls \
  --cert=/path/client.crt --key=/path/client.key --ca-file=/path/ca.crt

# ② 挂载证书卷
kubectl apply -k deploy/monitoring-overlays/remote-write-mtls

# ③ 合并配置片段（ConfigMap 数据是字符串，strategic merge 无法安全改写 → 人工/流程合并）
#    - global.external_labels.cluster: <本集群唯一 ID>
#    - remote_write: url / tls_config / authorization（见 snippet，含占位符）
#    合并后：kubectl -n otpmask rollout restart deployment/prometheus
```

## 3. 关键口径

- **目标地址可配置**：snippet 中 `url: REPLACE_WITH_CENTRAL_WRITE_ENDPOINT` 为占位符，
  **不写死任何内网地址**；中央侧形态二选一（客户既有 Prometheus / 我方 central 栈）
  的启用步骤差异见 `deploy/monitoring/central/trust/README.md` 第 1 节。
- **cluster 标签口径**：`external_labels.cluster` 是中央侧 `by (cluster)`、看板变量、
  Alertmanager `equal: [cluster]` 的唯一来源，每集群必须唯一（建议 = registry cluster_id）。
- **mTLS 校验**：`server_name` 必须与接收端证书 SAN 一致，`insecure_skip_verify: false` 固定。
- **鉴权**：Bearer 令牌走 `credentials_file`（Secret 挂载），**禁止明文写进 prometheus.yml**。

## 4. 待环境就绪

- ❌ 未做集群验证（本机无 K8s）：证书挂载、Prometheus 重启、写入连通性未实测。
- ❌ 未验证 `REPLACE_WITH_CENTRAL_WRITE_ENDPOINT` 可达性与证书 SAN 匹配。
- ❌ 未验证片段合并后的 prometheus.yml 语法（合并由运维流程完成，本机未生成实际文件）。
- ⚠️ `defaultMode: 0400` 与 Prometheus 以 `nobody(65534)` 运行 → Secret 卷对该用户可读性需实测
  （K8s Secret 卷默认属主 root:root，0400 时 nobody 读不到 → 需按 CNI/运行时调整，
  或改用 CSI Secret Store）。**此项必须在环境就绪后立即验证。**
