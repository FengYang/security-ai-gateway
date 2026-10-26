# 中央侧接收端：四种目标形态的发送片段

> **本目录不在 `kustomization.yaml` 的 `resources` 内** → 对默认部署**零影响**，
> 也不参与 `kubectl apply -k deploy/monitoring/central`。它是**发送侧片段库**：
> 按中央侧实际采用哪种接收端，取对应的一份合并进各集群 `prometheus.yml`。
>
> **口径变化（2026-10-26）**：原文档写"形态 A / 形态 B **二选一**"，把"换接收端"说成了
> "产品路线分叉"。实际上**发送端是同一个**（Prometheus remote-write），只有目标地址、
> 路径、认证头、租户头不同 —— 因此改为：**默认形态 B（我方 central 栈）＋ 四种受支持接收端**，
> 客户已有监控栈时按对应片段替换三个值（url / 认证 / 租户头）即可，**不存在"选边"**。

## 1. 选型矩阵

| 接收端 | 片段文件 | 写入路径 | 认证（原生） | 租户 / 多租隔离 | 典型场景 |
|---|---|---|---|---|---|
| **原生 Prometheus** | `remote-write-target-prometheus.example.yaml` | `/api/v1/write` | **无**（必须前置代理做 mTLS/鉴权） | 无租户概念，靠 `external_labels.cluster` 区分来源 | 我方 central 栈（形态 B 默认）、客户已有单实例 Prometheus |
| **Thanos Receive** | `remote-write-target-thanos.example.yaml` | `/api/v1/receive` | **无**（前置代理） | 请求头 `THANOS-TENANT`（默认租户 `default-tenant`） | 客户已有 Thanos 长期存储 / 全局视图 |
| **Grafana Mimir** | `remote-write-target-mimir.example.yaml` | `/api/v1/push` | **无**（前置网关注入租户头） | **必须** 请求头 `X-Scope-OrgID`，缺失即被拒 | 客户用 Grafana 栈（Loki/Mimir/Tempo） |
| **VictoriaMetrics** | `remote-write-target-victoriametrics.example.yaml` | 单机 `/api/v1/write`；集群版 `vminsert` `/insert/<accountID>/prometheus/api/v1/write` | 可选 `-httpAuth.*` 或前置 `vmauth` | `?extra_label=cluster=<id>` 或 accountID 路径 | 客户用 VM 做低成本长期存储 |

> **共性**：四种接收端**都不解决"谁在写"的鉴权**（Mimir/Thanos 的租户头是**路由**不是**认证**，
> 可被任意伪造）。故**跨公网必须 mTLS**，`cluster` 标签仍由发送侧 `external_labels.cluster` 唯一提供。

## 2. 三个必须替换的值（逐集群）

| 占位符 | 替换为 | 缺失后果 |
|---|---|---|
| `REPLACE_WITH_CENTRAL_WRITE_ENDPOINT` | 接收端完整 URL（含路径） | 配置校验拒绝启动（不静默丢指标） |
| `REPLACE_WITH_CLUSTER_ID` | 本集群唯一 ID（建议 = registry `cluster_id`） | 落 `cluster=""`，看板/告警去重失效 |
| `REPLACE_WITH_CENTRAL_SERVER_NAME` | 接收端证书 SAN（mTLS 时必填） | 握手校验失败，写入全断 |
| `REPLACE_WITH_TENANT`（仅 Thanos/Mimir/VM） | 租户标识 | Mimir：请求被拒；Thanos：落到默认租户；VM：标签污染 |

## 3. 冒烟校验（合并前先验通道）

```bash
# ① 通道可写（用最小样本，不污染正式序列；接收端支持 remote-write 即可）
printf '# TYPE rw_probe gauge\nrw_probe 1\n' | curl -sS -o /dev/null -w '%{http_code}\n' \
  --data-binary @- -H 'Content-Type: text/plain' \
  -H 'X-Scope-OrgID: REPLACE_WITH_TENANT' \
  --cert client.crt --key client.key --cacert ca.crt \
  'https://<host>/api/v1/push'

# ② 配置语法（Prometheus 本体）
promtool check config prometheus.yml

# ③ 写入是否真的到达（在接收端查）
#    原生/Mimir/Thanos/VM 均可查：count by (cluster) ({__name__="rw_probe"})
```

**期望**：① `200`（或 Mimir `200`／Thanos `200`／VM `204`）；② `SUCCESS`；③ 能查到 `cluster=<id>` 的样本。
任一不满足即**不得**进入切流演练 —— 通道没通就切流，会把"看不见"误判成"没故障"。

## 4. 各片段的结构（为什么长得几乎一样）

四份片段只在 `url`、`headers`、`query` 三处不同，其余（`queue_config` / `write_relabel_configs` /
`tls_config`）完全一致 —— 这样可以**用 diff 对照审阅**，避免"复制粘贴时改错一处"。

```bash
# 审阅时只看差异
diff -u remote-write-target-prometheus.example.yaml remote-write-target-mimir.example.yaml
```

## 5. 与 mTLS overlay 的关系

- 证书挂载：`deploy/monitoring-overlays/remote-write-mtls/`（Secret 三键 + 只读卷）
- 证书生成：同目录 `gen-ca.sh`（自签）或企业 CA 签发（`--mode csr`）
- **不要**在本目录片段里写死证书路径以外的凭据；Bearer/密码一律走 `credentials_file`（Secret 挂载）

## 6. 待环境就绪（如实标注）

- ❌ **四种接收端均未做真机连通验证**：本机无 K8s、无 Thanos/Mimir/VM 实例，
  上面 §3 的冒烟步骤是**待执行清单**，不是已通过结论。
- ⚠️ **Mimir 的 `X-Scope-OrgID` 语义**按 Mimir 官方 multi-tenancy 口径编写；
  **单租户模式**（`-multitenancy_enabled=false`）下该头可省，但**不要**因此关掉认证代理。
- ⚠️ **Thanos 的租户头名**取决于接收端 `--receive.tenant-header` 配置（默认 `THANOS-TENANT`）；
  客户侧若改过该参数，片段里的头名须同步。
- ⚠️ **VM 集群版的 accountID 路径**与单机版路径不同，片段内两种都给了注释，**按实际版本择一**。
