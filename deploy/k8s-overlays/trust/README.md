# P2-4 T-4.3：跨集群通道信任——**审计链导出端点**（per-cluster 侧）

> 为 T-4.2 已实现的审计链导出端点提供部署侧装配：开关、凭证引用、来源白名单、
> 可选的网络边界。**默认部署零影响**：`deploy/k8s/**` 未改动，本 overlay 需显式应用。

## 1. 与 T-4.2 导出端点开关的对应关系（逐条对齐代码口径）

| 组件 | T-4.2 开关 | 语义（T-4.2 代码原文口径） | 本 overlay 的取值来源 |
|------|------------|----------------------------|----------------------|
| gateway-core | `GATEWAY_CORE_AUDIT_EXPORT_ENABLED` | `1\|true\|yes\|on` 才启用；其余 = 路由不注册 → 404 | 置 `"1"`（主动启用） |
| gateway-core | `GATEWAY_CORE_AUDIT_EXPORT_CIDRS` | 来源 IP CIDR 白名单；**启用时为空 → 拒绝启动**（fail-closed） | ConfigMap `gateway-core-audit-export/cidrs` |
| gateway-core | `GATEWAY_CORE_AUDIT_EXPORT_TOKEN` | 静态 Bearer 令牌；**空 = deny-all（全部 403）** | Secret `otpmask-audit-export/export-token` |
| gateway-core | `GATEWAY_CORE_AUDIT_EXPORT_MAX` | 单次导出行数上限（保护推理面） | 置 `10000` |
| tee-infer-service | `-audit-export-enabled` | 未设 = 路由不注册 → 404（默认关闭） | args 追加 `"-audit-export-enabled"` |
| tee-infer-service | `-audit-export-cidrs` | 来源 CIDR 白名单；**启用时为空 → 拒绝启动** | args 追加 `$(AUDIT_EXPORT_CIDRS)` ← ConfigMap |
| tee-infer-service | `-audit-export-token` | 静态 Bearer 令牌；**空 = deny-all** | args 追加 `$(AUDIT_EXPORT_TOKEN)` ← Secret（**不出现在 ps 命令行**） |
| tee-infer-service | `-audit-export-max` | 单次导出行数上限 | args 追加 `"10000"` |

**T-2.3 依赖**：`TokenAuthorizer` 为**临时联调口径**。T-2.3「集群身份凭证（签发/校验/轮换/吊销）」
落地后，应以其替换令牌鉴权，届时本 overlay 的 TOKEN 引用随之替换/删除。

**为什么 tee 用 JSON6902 而不是 strategic merge**：容器 `args` 是**无 merge key 的字符串列表**，
strategic merge 会**整体替换** args → 既有参数（`-sig-key`/`-attest-token`/`-output-guard`/
`-cmaas-url`/`-cmaas-model`/`-dev-mode`）被清空 → 服务无法启动。故补丁只做「追加」。

## 2. 启用步骤

```bash
# ① 注入来源白名单（占位值必须替换；未替换 → CIDR 非法 → 应用层拒绝启动）
kubectl -n otpmask apply -f deploy/k8s-overlays/trust/configmap-audit-export-cidrs.yaml
kubectl -n otpmask patch configmap gateway-core-audit-export \
  --type=merge -p '{"data":{"cidrs":"10.20.0.0/16"}}'
kubectl -n otpmask patch configmap tee-infer-audit-export \
  --type=merge -p '{"data":{"cidrs":"10.20.0.0/16"}}'

# ② 注入令牌（禁止明文入库；模板见 secret-audit-export.example.yaml，勿 apply）
kubectl -n otpmask create secret generic otpmask-audit-export \
  --from-literal=export-token="$(vault kv get -field=export-token secret/otpmask/audit-export)"

# ③ 应用 overlay（打开端点 + 引用凭证）
kubectl apply -k deploy/k8s-overlays/trust
```

## 3. 默认拒绝口径（分三层，任一层缺失即拒绝）

| 层 | 机制 | 缺省行为 |
|----|------|----------|
| 应用层：开关 | `*_AUDIT_EXPORT_ENABLED` 未设 → **路由不注册** → 404 | 端点不存在（零新增攻击面） |
| 应用层：来源 | CIDR 白名单为空 → **拒绝启动**；不匹配的来源 → 403 | 不存在「启用即全开」 |
| 应用层：授权 | 令牌为空 → **deny-all**（全部 403） | 无令牌即全拒 |
| 网络层（可选） | `networkpolicy-audit-export-ingress.yaml` 入站默认拒绝 + 白名单 | **默认不启用**（见 §4） |

## 4. 网络边界：为什么「默认不启用」那份 NetworkPolicy

- 导出端点与业务端点**同端口**（gateway-core `8085`、tee-infer `19090`），NetworkPolicy 属
  L3/L4，**无法按 URL 路径**放行导出而放行业务 → 只能整体收敛来源；
- 收敛整端口会同时约束：插件拉表（经 Higress McpBridge DNS registry）、admin-service 策略下发、
  gateway-core→tee 配额下发、envoy→tee 推理转发、Prometheus 抓取；
- **放行项若不全会误伤数据面**（插件拉表失败 → 保留旧表；配额/抓取失败 → 可观测性缺口）；
- 而 Higress 侧 Pod 的真实命名空间/标签属 **P1-8 域**，本任务不得改动 `deploy/higress/**`
  → 不臆造标签。

因此：`networkpolicy-audit-export-ingress.yaml` 作为**可选纵深防御**单独交付，
启用前必须逐条完成其文件头「启用前核对清单」（7 项），建议先在测试集群 apply 并观察 15 分钟，
异常立即 `kubectl delete networkpolicy` 撤销。

## 5. 集群侧的通道边界放在中央侧

跨集群采集是**新增信任面**，故其网络边界收敛在**中央侧**
（`deploy/monitoring/central/trust/networkpolicy-central-collector-egress.yaml`：
采集器出站默认拒绝 + 白名单放行各集群导出端口），**不触碰各集群既有数据面策略**。

## 6. 待环境就绪（本目录资产无法本机验证）

- ❌ 未做集群验证（本机无 K8s/PG）：端点实际启用、403/404 行为未实测。
- ❌ 未验证各集群来源 CIDR（客户/中央采集器实际出口 IP）与 NetworkPolicy ipBlock 的匹配关系。
- ❌ 未验证 Higress 插件来源放行项（P1-8 域，需现场核对）。
- ❌ 未验证令牌轮换流程（T-2.3 前为手工轮换）。
- ⚠️ 本 overlay 属**主动打开新端点**的应用，若未启用导出需求，**不要 apply**。
