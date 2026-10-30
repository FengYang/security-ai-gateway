> 中文版 ｜ [English](./README.en.md)

# P2-4 T-4.4：中央聚合部署资产

> **只在承担跨集群聚合的中央集群部署**，与 per-集群栈（`deploy/monitoring/**`）并列、互不干扰。
> 本目录**不在** `deploy/monitoring/kustomization.yaml` 内 → `kubectl apply -k deploy/monitoring`
> 的产物与本次提交前**完全一致**（默认部署零影响）。

## 1. 资产清单

| 文件 | 内容 |
|------|------|
| `kustomization.yaml` | 中央资产入口：`kubectl apply -k deploy/monitoring/central` |
| `prometheus-central.yaml` | 中央 Prometheus（`--web.enable-remote-write-receiver`，90d 保留）+ 中央告警规则 + NetworkPolicy + PVC |
| `alertmanager-central.yaml` | 中央 Alertmanager：按 `cluster` 维度 group_by / inhibit 去重 |
| `grafana-central-dashboards.yaml` | 统一看板：① 跨集群总览 overview ② 单集群下钻 per-cluster（`cluster` 变量） |
| `grafana-central-datasources.yaml` | Grafana 中央数据源 `Prometheus-Central`（uid 同名，看板按 uid 引用） |
| `remote-write-sender.example.yaml` | **各集群侧** remote-write 发送片段模板（含 mTLS 配置位），不在 kustomization 内（权威版本见 `deploy/monitoring-overlays/remote-write-mtls/`） |
| `receivers/` | **四种接收端的发送片段库**（原生 Prometheus / Thanos Receive / Grafana Mimir / VictoriaMetrics）＋选型矩阵；不在 kustomization 内，按中央侧实际形态取一份 |
| `trust/` | **T-4.3 通道信任**子目录：中央侧证书引用示例 + 采集器出站默认拒绝策略 + 落地形态说明 |

## 2. `cluster` 标签口径（统一口径，勿另起别名）

- **来源**：各集群 Prometheus 的 `global.external_labels.cluster=<cluster-id>`；remote-write
  发送时该 external label 附加到**每条样本**，中央侧因此天然带 `cluster` 维度。
  既有锚点：`deploy/monitoring/prometheus.yaml:41-43`（注释「多集群聚合与告警去重（M12）」）。
- **中央侧不做重写/重命名**，故 `label_values(cluster)`、`by (cluster)`、
  `cluster=~"$cluster"`、Alertmanager `equal: [cluster]` 全部直接可用。
- **不使用** `cluster_id` / `k8s_cluster` 等别名。
- **与 T-4.1/T-4.2 的 `schema=admin|tee|core` 是不同维度**：
  `cluster` = 指标来源集群（本目录），`schema` = 审计链类型（审计侧，
  `GET /v1/adminext/audit-chain/query?cluster=<id>&schema=<admin|tee|core>`）。
  两者可组合并列使用，互不替代。
- ⚠️ 某集群漏配 `external_labels.cluster` → 其告警落到 `cluster=""` 分组，看板/去重失效。
  上线前须**逐集群核对**。

## 3. 告警去重设计（避免 N 集群重复轰炸）

| # | 手段 | 位置 | 语义 |
|---|------|------|------|
| ① | **fleet 级聚合（主手段）** | 默认路由 `group_by: [alertname, severity, service]`（**不含 cluster**） | 同一 alertname 在 N 个集群同时触发 → 合并为 **1 条**通知，正文用 `{{ range .Alerts }}` 列出受影响集群 |
| ② | 安全告警按集群分组 | `category=security` 路由 `group_by: [alertname, cluster, service]` | 安全事件需按集群定位处置，**可追溯性优先于去重** |
| ③ | 抑制 | `inhibit_rules`：critical 抑制同 `cluster` 的 warning；`CentralClusterTargetsDown` 抑制该集群下游 warning | 避免级联轰炸 |

通知接收人：`ops-fleet`（默认）/ `ops-critical` / `sec-oncall` / `ops-multicluster`。
⚠️ webhook URL 为占位地址（`alert-relay.otpmask.svc.cluster.local:19099`），
上线前替换为实际值班系统（与既有 `deploy/monitoring/alertmanager.yaml` 约定一致）。

## 4. 部署与接线步骤

```bash
# ① 中央集群：部署中央资产
kubectl apply -k deploy/monitoring/central

# ② 中央集群：Grafana 挂载中央数据源（一次性；未挂载时看板报 datasource not found）
kubectl -n otpmask patch deployment grafana --type=json -p '[
  {"op":"add","path":"/spec/template/spec/volumes/-",
   "value":{"name":"grafana-central-datasources",
            "configMap":{"name":"grafana-central-datasources"}}},
  {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-",
   "value":{"name":"grafana-central-datasources",
            "mountPath":"/etc/grafana/provisioning/datasources/central","readOnly":true}}
]'
kubectl -n otpmask rollout restart deployment/grafana

# ③ 中央集群：导入看板（把 grafana-central-dashboards 的两个 JSON 落到 Grafana
#    provisioning dashboards 目录，或在 UI 中 import）

# ④ 各集群：合并 remote-write 发送片段
#    权威资产：deploy/monitoring-overlays/remote-write-mtls/
#      （证书挂载 overlay + prometheus-remote-write-snippet.yml，含 mTLS 配置位）
#    必须设置唯一的 external_labels.cluster，然后重启该集群 Prometheus
```

## 4.1 中央侧接收端：**默认形态 B ＋ 四种受支持目标**（不是"二选一"）

> **口径修正（2026-10-26）**：原表述「形态 A / 形态 B **二选一**」把"换接收端"说成了
> "产品路线分叉"。实际**发送端是同一个**（Prometheus remote-write），差异只在
> 目标地址 / 路径 / 认证头 / 租户头 —— 因此改为：**默认形态 B，形态 A 为受支持拓扑**，
> 客户已有监控栈时按对应片段替换三个值即可，**不存在选边，也不需要改我方资产**。

本项目**不自建**中央接收端（GSLB / 自研采集均不采用）。

| | **形态 B（默认）**：我方交付 central 栈 | **形态 A**：客户既有监控栈（四种之一） |
|---|---|---|
| 部署动作 | `kubectl apply -k deploy/monitoring/central` + Grafana 挂载数据源 + 导入看板 | 不部署我方 central 资产，只合并发送片段 |
| remote_write 目标 | `https://<代理地址>:9443/api/v1/write`（**经 mTLS 终止代理，不直连 9090**） | 按接收端取片段（见下） |
| 片段来源 | `remote-write-sender.example.yaml` | `receivers/remote-write-target-<target>.example.yaml` |
| mTLS 终止 | **我方已交付**：`deploy/monitoring-overlays/remote-write-mtls-server/`（双向 TLS + `ssl_verify_client on`；收紧后 9090 仅代理可入） | 客户侧或客户网关承担（四种接收端同理，Prometheus 原生同样不校验客户端证书） |
| 告警去重 | 本目录 `alertmanager-central.yaml` 已实现 §3 口径 | 客户 Alertmanager 须采用本文档 §3 口径（否则 N 集群重复轰炸） |

**四种受支持接收端**（`receivers/` 目录，差异见其 README 选型矩阵）：

| 接收端 | 路径 | 必须的额外配置 |
|---|---|---|
| 原生 Prometheus | `/api/v1/write` | 启动须带 `--web.enable-remote-write-receiver` |
| Thanos Receive | `/api/v1/receive` | 请求头 `THANOS-TENANT`（头名随 `--receive.tenant-header`） |
| Grafana Mimir | `/api/v1/push` | 请求头 `X-Scope-OrgID`（多租户启用时**必填**，缺失即拒） |
| VictoriaMetrics | `/api/v1/write`（单机）／`/insert/<accountID>/prometheus/api/v1/write`（集群版） | 成功码为 **204**；`extra_label` 与 `external_labels` 二选一，勿重复 |

> **remote_write 目标地址一律为占位符**（`REPLACE_WITH_CENTRAL_WRITE_ENDPOINT`），
> 我方资产中**不写死任何内网地址**。占位符未替换时，Prometheus 配置校验会**拒绝启动**
> （`promtool check config` 报错），不会静默丢指标。

## 5. T-4.3 通道信任（**接收侧代理已交付，取证待环境**）

remote-write 通道的 mTLS 分两半，本目录只负责「中央 Prometheus 本体」，另两半在 overlay 与发送侧：

- **接收侧（本次补齐）**：`deploy/monitoring-overlays/remote-write-mtls-server/` ——
  Prometheus 原生**不校验客户端证书**（`--web.config.file` 只能做服务端 TLS + basic_auth，
  没有 `ssl_verify_client` 语义），因此在其前面放一层 nginx 做 TLS 终止与客户端证书强制校验：
  对外 `9443`（仅 `/api/v1/write`）→ 集群内明文回环 `9090`。
  配套 `replace-central-write-np.tighten.yaml` 把 9090 从「同命名空间全开」收紧为「仅代理 + Grafana」。
- **发送侧**：`deploy/monitoring-overlays/remote-write-mtls/`（客户端证书挂载 + `tls_config`）。
- **证书**：`gen-ca.sh` 一次出 CA / 服务端 / 客户端，两端同一 CA。
- **仍未做的事**（如实标注）：代理**未在真集群跑过** —— `nginx -t`、真实双向握手经代理、
  Secret 卷 `0440`+`fsGroup:101` 实机行为、收紧 NP 后 Grafana 是否仍通，全部待环境取证
  （登记 `PRE-B-9` / `PRE-A-11`）。**收紧 NP 之前必须先在真集群打通一次写入**，否则无法区分
  「策略拦了」与「代理没通」。
- **未收紧前的口径不变**：9090 仍对 `otpmask` 命名空间全开，只适合内网/专线；
  跨公网写入必须先做上面的三步（起代理 → 打通 → 收紧）。

## 6. 自检脚本

```bash
python3 scripts/check-central-aggregation-assets.py            # 默认检查两个资产目录
python3 scripts/check-central-aggregation-assets.py -v         # 输出 PASS 明细
python3 scripts/check-central-aggregation-assets.py --promtool /path/to/promtool
python3 scripts/check-mtls-proxy-assets.py                     # mTLS 终止代理专项断言（§5）
```

检查项：① YAML 可解析（含 ConfigMap 内嵌 YAML）② 明文凭据扫描（模板/占位符白名单）
③ 看板 JSON 合法 + `cluster` 变量 + 表达式含 cluster 维度 ④ Alertmanager 含 cluster 维度
⑤ 中央 Prometheus 开启 remote-write 接收 ⑥ promtool 规则语法（**无 promtool 则明确 SKIP，不假装通过**）
⑦（专项脚本）代理 `ssl_verify_client on` / 客户端 CA 绑定 / 仅 `/api/v1/write` 可达 / 非 root + 只读根。

退出码：`0` = 全部通过（SKIP 会显式列出）/ `1` = 存在 FAIL / `2` = 环境或输入错误。

## 7. 校验结果（本机，2026-10）

| 项 | 方式 | 结果 |
|----|------|------|
| YAML 语法 | 逐文件 + 内嵌 YAML `yaml.safe_load_all` | ✅ PASS |
| kustomize 构建 | `kubectl kustomize deploy/monitoring/central`（kubectl v1.14 内置 kustomize v2） | ✅ 通过，11 个文档 |
| 看板 JSON | `json.loads` + 变量/维度断言（2 个看板） | ✅ PASS |
| Alertmanager cluster 维度 | 解析内嵌配置断言 group_by/inhibit equal 含 cluster | ✅ PASS |
| remote-write 接收开关 | 断言 Deployment args 含 `--web.enable-remote-write-receiver` | ✅ PASS |
| 明文凭据扫描 | 正则扫描（模板/REPLACE_ 占位符白名单） | ✅ PASS |
| 默认栈零影响 | `git status deploy/monitoring` 仅新增 `central/`；既有文件未改动 | ✅ PASS |
| 汇总 | `PASS=42 FAIL=0 SKIP=5` | ✅ 退出码 0 |

**待环境就绪（如实标注，未做即未做）：**

- ❌ **promtool 规则语法校验未执行**：本机无 promtool，脚本输出 SKIP（不视为通过）。
  中央规则沿用既有 promtool 校验惯例（参照 `billing-prometheusrule-promtool-test.yaml`），
  环境就绪后重跑脚本即可自动补验。
- ❌ **未做集群验证**：本机无 Kubernetes/PG，未执行 `kubectl apply` / server-side dry-run；
  中央 Prometheus 能否真实接收各集群写入、看板能否取到数，均未实测。
- ❌ **未做 kustomize v4/v5 构建验证**：本机仅 kubectl v1.14（kustomize v2）。
- 🖥 **T-4.3 mTLS 接收侧已编码交付、未在集群取证**：代理资产
  （`deploy/monitoring-overlays/remote-write-mtls-server/`）已交付并通过静态断言 +
  kustomize 构建，但 `nginx -t`、真实双向握手、Secret 卷权限组合、收紧 NP 后 Grafana 连通性
  **均未实测** → 登记 `PRE-B-9` / `PRE-A-11`，**未取证不得填 PASS**。
  未执行「起代理 → 打通 → 收紧」三步前，9090 仍为内网明文通道，跨公网启用属违规。
- ❌ **各集群 `external_labels.cluster` 未逐集群核对**：漏配将导致 `cluster=""` 分组。
- ❌ **Grafana 数据源挂载未实测**：`kubectl patch` 命令为静态给出，未在集群执行过。
- ⚠️ **规则精度限制**：`CentralRemoteWriteStalled` 用的
  `prometheus_remote_storage_highest_timestamp_in_seconds` 是接收侧**全局量，无 cluster 维度**，
  只能发现「有集群停写」，不能定位到具体集群；精确到单集群的判据依赖集群期望清单
  （T-2.1 registry），本期不臆造，暂以看板 per-cluster 页人工核对。
