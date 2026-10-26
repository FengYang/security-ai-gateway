# 跨集群网络边界：三档 NetworkPolicy ＋ 端口矩阵

> **默认不启用**。本目录不在 `deploy/k8s-overlays/trust/kustomization.yaml` 的 `resources` 内，
> 需显式 `kubectl apply -f networkpolicy-tiers/<档位>.yaml` 单档应用。
>
> **为什么需要"档"而不是一份策略**：导出端点与业务端点**同端口**（gateway-core `8085`、
> tee-infer `19090`），NetworkPolicy 属 L3/L4，**无法按 URL 路径**放行导出而放行业务 ⇒
> 只能整体收敛来源。而"要放行谁"随部署形态变化（单集群 / 多集群 / 采集器在集群外），
> 一刀切会**误伤数据面**（插件拉表失败 → 沿用旧表；配额/抓取失败 → 可观测性缺口）。

## 1. 端口矩阵（唯一口径，勿另起别名）

| 端口 | 组件 | 用途 | 方向 | 跨集群 |
|---|---|---|---|---|
| **8085** | `gateway-core`（`OTP_CORE_ADDR`，默认 `:8085`） | 业务 API、策略拉取、**审计链导出** `/v1/internal/audit/chain/export`、`/metrics` | 入站 | ✅ 中央采集器 |
| **19090** | `tee-infer-service`（helm `port`，默认 `19090`） | 推理转发、TEE 配额下发、**审计链导出（tee）**、`/metrics` | 入站 | ✅ 中央采集器 |
| **9443** | `remote-write-mtls-gateway`（中央） | **remote-write 唯一跨集群写入入口**：双向 TLS + 客户端证书强制校验，仅 `/api/v1/write` | 入站 | ✅ **各集群 Prometheus**（唯一对公网可开的口） |
| **9090** | `prometheus-central`（中央） | remote-write 接收（**收紧后仅代理可直连**）、查询 API（Grafana） | 入站 | ❌ **不再直接跨集群**（一律经 9443） |
| **9090** | per-cluster `prometheus` | 本地抓取与查询 | 本地 | ❌ **不跨集群**（写入中央是**出站**到中央 9443） |
| **8080** | `remote-write-mtls-gateway`（中央） | 代理自身 `/healthz`、`/stub_status` | 入站 | ❌ 仅 kubelet / 同命名空间 |
| 19099 | `alert-relay`（示例占位） | 告警 webhook 转发 | 出站 | 可选 |

**流量方向（谁连谁）**

| 源 | 目标 | 端口 / 路径 | 说明 |
|---|---|---|---|
| 各集群 Prometheus | 中央 `remote-write-mtls-gateway` | `9443/api/v1/write` | 出站；**双向 TLS**（发送侧带客户端证书）；形态 A 客户接收端见 `central/receivers/` |
| 中央 `remote-write-mtls-gateway` | 中央 `prometheus-central` | `9090/api/v1/write` | 集群内明文回环（TLS 已在前一跳终止）；由收紧后的 NP 限定为**仅代理可入** |
| 中央采集器 | 各集群 `gateway-core` | `8085/v1/internal/audit/chain/export?schema=admin|core` | 入站到被采集集群；Bearer + 来源 CIDR 白名单 |
| 中央采集器 | 各集群 `tee-infer-service` | `19090/…?schema=tee` | 同上 |
| Grafana（中央） | 中央 `prometheus-central` | `9090/api/v1/query` | 集群内（收紧 NP 时必须保留这条，否则看板断） |
| Prometheus（各集群） | 本地 `gateway-core` / `tee-infer` | `8085/metrics`、`19090/metrics` | 集群内抓取 |

> **注意**：`8085`/`19090` 的**业务流量与导出流量同端口**——这就是为什么网段放行会连带放行业务面。
> 应用层的路径级边界在 T-4.2（来源 CIDR 白名单 + Bearer 令牌，**空即 deny**），网络策略只是第二道网。

> **`9443` 为什么不在这三个文件里**：9443 属**中央集群侧**的入站边界
> （`deploy/monitoring-overlays/remote-write-mtls-server/networkpolicy-mtls-gateway-ingress.yaml`），
> 而本目录三档管的是**各集群侧数据面入站**（8085/19090）。两处职责不重叠，
> 不要为了"统一"把 9443 塞进三档模板，否则会在每个集群上留一条指向不存在端口的空放行。

## 2. 三档对比

| 档 | 文件 | 放行的来源 | 适用 | 漏放行的后果 | 多放行的代价 |
|---|---|---|---|---|---|
| **1 minimal** | `tier1-minimal.yaml` | 仅同命名空间：Prometheus 抓取、admin→core、core→tee、envoy→tee | 单集群、未接中央聚合、插件与网关同命名空间 | 无（该形态下这些就是全部） | 无 |
| **2 standard**（推荐） | `tier2-standard.yaml` | 档 1 ＋ 插件命名空间（`REPLACE_WITH_HIGRESS_NAMESPACE`）＋ 中央采集器（`otpmask.io/role=central-collector`） | 多集群 + 中央审计聚合 | 插件拉表失败（沿用旧表）、审计导出不通 | 插件命名空间内任意 pod 可连 core:8085 |
| **3 permissive** | `tier3-permissive.yaml` | 档 2 ＋ **来源 CIDR 网段**（`10.20.0.0/16` 示例） | 采集器无 pod 标签 / 在集群外 / 经 SNAT 后来源为固定网段 | 采集器连不上，导出全断 | **同网段任意主机可连 8085/19090**（L3 层，不区分 pod 身份） |

**选择判据（按顺序问）**

1. 只部署单集群、不接中央审计聚合？→ **档 1**
2. 中央采集器以 Pod 形式部署、且有 `otpmask.io/role=central-collector` 标签？→ **档 2**
3. 采集器在集群外 / 无标签 / 来源只剩网段？→ **档 3**（并把 CIDR 收到 /32 或最小段）
4. 拿不准 → **先不启用**。应用层的 CIDR + 令牌默认已 deny（空即拒），网络策略是纵深防御，不是必需层。

## 3. 启用与回滚

```bash
# ① 启用前核对（档 2/3 必做，缺一不得 apply）
#    a) 插件真实命名空间（属 P1-8 域，本任务不臆造 pod 标签）
kubectl get pods -A --show-labels | grep -i higress | head
#    b) 中央采集器标签是否存在
kubectl -n otpmask get pods -l otpmask.io/role=central-collector
#    c) 应用层白名单与本策略放行项是否一致（不一致 = 两道网互相打架）
kubectl -n otpmask get configmap gateway-core-audit-export -o jsonpath='{.data.cidrs}'

# ② 单档应用（一次只应用一档）
kubectl apply -f deploy/k8s-overlays/trust/networkpolicy-tiers/tier2-standard.yaml

# ③ 观察 15 分钟（这四项任一异常立即回滚）
#    - 插件拉表：插件日志无 "table fetch failed"；限流/路由未沿用旧表
#    - TEE 配额：配额下发成功、推理无 5xx 飙升
#    - 抓取：Prometheus 目标 up 数未下降
#    - 审计导出：中央侧能查到新增 chain 记录

# ④ 回滚（label 定位，秒级恢复放通）
kubectl delete networkpolicy -n otpmask -l otpmask.io/netpol-tier=2-standard
```

**验证连通性（从目标集群内起临时 pod）**

```bash
kubectl -n otpmask run netpol-probe --rm -it --restart=Never --image=curlimages/curl -- \
  curl -sS -o /dev/null -w '%{http_code}\n' --max-time 5 http://gateway-core.otpmask.svc:8085/metrics
# 期望 200；连不上要区分"策略挡了"与"服务本身不可达"：
#   kubectl -n otpmask get endpoints gateway-core
```

## 4. 与旧版单文件策略的关系

`deploy/k8s-overlays/trust/networkpolicy-audit-export-ingress.yaml` 是**档 2 的前身**
（内容近似，但只有一份、无档位标签）。二者**二选一，不要同时 apply**：
K8s NetworkPolicy 是**加性**的（多策略取并集），同时生效等于取较宽的那档，"档位"就失去意义。

- 新部署 → 直接用三档（本目录）
- 已在用旧文件 → 可继续用；迁移时先 `kubectl delete -f` 旧文件再 apply 档 2

## 5. 验证状态（未做即未做）

- ❌ **三档均未在真实 K8s 集群应用**：本机无 K8s；`kubectl apply` / server-side dry-run 未执行。
- ❌ **未做连通性实测**：上面的 probe 命令是**待执行清单**，不是已通过结论。
- ⚠️ **`REPLACE_WITH_HIGRESS_NAMESPACE` 必须替换**：未替换时 `namespaceSelector` 匹配不到任何命名空间
  → 等价于**不放行插件**（fail-closed，方向正确但会误伤数据面）。
- ⚠️ **档 3 的 `10.20.0.0/16` 是示例值**：`ipBlock.cidr` 由 API 校验格式，不能写占位符；
  直接 apply 等于放行一个**你可能并不拥有**的网段。替换前先确认采集器 SNAT 后的实际出口 IP。
- ⚠️ **CNI 差异**：部分 CNI（如 Calico 的部分模式）对 `namespaceSelector` + `podSelector` 组合、
  以及对 hostNetwork pod 的处理不一致；策略语义以目标集群 CNI 为准，需现场核对。
