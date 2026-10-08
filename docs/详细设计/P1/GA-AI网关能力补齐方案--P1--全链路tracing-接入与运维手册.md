# GA-AI 网关 P1-2 全链路 tracing —— 接入与运维手册

> 对应《GA-AI网关能力补齐方案--P1--全链路tracing.md》§7.10 收尾交付物。
> 覆盖：灰度开关（租户级开启 / 一键关闭）、各服务接入、排障与 SLO API、性能基线（V-3）、安全审计（V-2）。

## 1. 开关模型（灰度与一键关闭，C-4）

tracing **默认关闭**；关闭时零开销、`/metrics` 逐字节不变（C-8）。三层开关：

| 层级 | 载体 | 默认 | 效果 |
|---|---|---|---|
| 全局 | 环境变量 `TRACING_ENABLED` | `false` | `false` 时各服务使用 NoOpTracer（零 span、零导出） |
| 全局（紧急） | 同上，置回 `false` 并滚动重启 | — | **一键关闭**：语义等同未接入；已产生数据由 Tempo 保留期管理 |
| 租户级（灰度） | `POST /v1/adminext/tracing/tenant` → Collector `tail_sampling` allow-list | 空（全拒绝） | 仅 allow-list 内 `tenant.id` 的 trace 进入采样；其余默认拒绝 |

> **执行点说明（§6.4）**：租户级开闭的**执行点**在 Collector `tail_sampling` 的显式 allow-list（deny-by-default）。
> 本 API 维护「期望 allow-list」并落审计链；Collector 侧热更为运维动作（见 §6 待实机验证项）。

## 2. 各服务接入（环境变量）

| 服务 | 变量 | 默认 | 说明 |
|---|---|---|---|
| tee-infer-service | `TRACING_ENABLED` | `false` | 全局开关 |
| | `TRACING_OTLP_ENDPOINT` | `otel-collector:4317` | OTLP/gRPC 出口 |
| | `TRACING_TLS_INSECURE` | `false` | 开发形态置 `true`；生产用 mTLS |
| gateway-core | `TRACING_ENABLED` / `TRACING_OTLP_ENDPOINT` / `TRACING_TLS_INSECURE` | 同上 | 控制面 `core.route.change` span |
| gateway-admin-service | 同上 | 同上 | 管理面 `admin.request` span |
| gateway-admin-service | `ADMIN_TEMPO_URL` | 空 | 排障查询 Tempo 地址；空 → `/trace/*` 返回 503 |
| | `ADMIN_PROMETHEUS_URL` | 空 | SLA/SLO 聚合；空 → 相关端点 503 |
| | `ADMIN_SLO_FILE` | 空 | SLO/allow-list 持久化文件；空 = 内存模式（重启丢失） |

Envoy/Higress 侧：HCM `tracing` 块（OTel provider，根采样 100%）+ `otel-collector` 集群；
Wasm 插件**不生成 span**，仅透传 `traceparent`（默认行为）+ 统一 `X-Request-Id`。

**部署顺序**：OTel Collector / Tempo（`deploy/monitoring/`）→ 各服务（置 `TRACING_ENABLED=true`）→ Envoy/Higress 配置生效。

## 3. Span 语义（§7.4）

| Span | 服务 | 关键属性（§6.2 白名单） |
|---|---|---|
| `envoy.ingress` | Envoy/Higress | `http.status_code` |
| `tee.infer` | tee-infer | `tenant.id`/`request.id`/`model.id`/`engine.type`/`result`/`tokens.in`/`tokens.out`/`ttft.ms` |
| `cache.lookup` | tee-infer | `cache.hit`/`cache.mode`（event: `cache.hit`/`cache.miss`） |
| `guardrail.check` | tee-infer | `og.category`/`og.mode`/`result`/`deny.reason`（event: `guardrail.denied`） |
| `upstream.model.call` | tee-infer | `tokens.in`/`tokens.out`/`ttft.ms`/`http.status_code`/`input.digest`/`output.digest`/`is.retry`（event: `retry.start`） |
| `core.route.change` | gateway-core | `route.name`/`change.type`/`tenant.id`/`result`/`http.status_code` |
| `admin.request` | gateway-admin-service | `http.method`/`http.route`/`tenant.id`/`user.role`/`result`/`http.status_code` |

出站安全：tee-infer 对上游模型厂商的 HTTP 客户端**剥离** `traceparent`/`tracestate`/`x-request-id`（§6.4）。
审计关联：`AuditEvent.TraceID`（`trace_id`，omitempty、**不进 hash**，WORM 旧链逐字节不变，D-5）。

## 4. 排障与报表 API（§6.3）

统一前缀 `/v1/adminext`，鉴权 `authMiddleware`（admin/auditor），错误遵循 503 fail-closed（不静默返回空）。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/trace/{request_id}` | 单请求全链路聚合（span 树 + 审计 + 耗时分解）；租户内校验 |
| GET | `/trace/search` | 多维检索 `tenant/from/to/model/status/category/limit/offset`；`status` ∈ `ok`/`client_error`/`server_error`/`denied`，枚举外 → 400 |
| GET | `/trace/{request_id}/report` | 导出报告（`?format=json\|csv`）；CSV 防公式注入 |
| GET | `/sla/summary` | SLA：可用性 / P50/P95/P99 / 错误率（Prometheus） |
| GET | `/slo` | SLO 定义 + 错误预算余量 |
| POST | `/slo` | 创建/更新 SLO（admin，落审计链） |
| POST | `/tracing/tenant` | 租户级 tracing 灰度开关（admin，落审计链） |

**租户隔离**：非 admin 仅可访问本声明租户（跨租户/缺省 tenant → 403，fail-closed）；admin 可跨租户。

### SLO 配置（§7.9 冻结 schema）

```json
POST /v1/adminext/slo
{
  "name": "infer-availability",
  "description": "推理服务可用性",
  "sli": { "type": "availability", "metric": "otpmask_inference_requests_total", "filter": "route=\"/v1/infer\"" },
  "target": 0.999,
  "window": "30d",
  "alerting": { "fast_burn_rate": 14.4, "slow_burn_rate": 6, "enabled": true },
  "tenant_id": "t-001",
  "enabled": true
}
```

- 支持类型：`availability`、`latency_p99`；`target` ∈ (0,1)；`window` 非空（如 `30d`）。
- 告警规则：`deploy/monitoring/slo-prometheusrule.yaml`（默认目标 99.9%，燃尽 14.4/6，含 `AISLOTTFTp99Slow`）。
- 看板：`deploy/monitoring/grafana.yaml` 的 `otpmask-ai`（TTFT/Token/拦截率/缓存命中）与 `otpmask-slo`（可用性/P99/错误率/错误预算/燃尽率）。

## 5. 性能基线（V-3：tracing 开启后 p99 延迟增加 < 5%）

固定压测条件（并发/QPS/时长/样本量），对比 `TRACING_ENABLED=false/true`：

1. 关闭态跑基线（`/metrics` 与延迟分位逐字节基线）；
2. 开启态（根采样 100%，Collector `tail_sampling` 1% 落存）同条件压测；
3. **通过判据**：`p99(开) ≤ 1.05 × p99(关)`；测量点 = 网关端到端总延迟；
4. 记录并随报告留证（条件、样本量、统计方法）。

> 关闭态零开销由实现保证：未启用时各服务使用 `noop.Tracer`，span 辅助函数直接返回（单测覆盖）。

## 6. 安全审计清单（V-2 / C-1）

- [x] span 属性仅白名单（§6.2）；禁止 `prompt`/`response`/`messages`/`content`/`embedding`/`vector`/`key`/`secret`/`authorization`。
- [x] tee-infer `SanitizingSpanProcessor` 强制白名单（strict 模式 fail-fast）；Collector `attributes` processor 兜底裁剪（纵深防御，D-4）。
- [x] 上游出站剥离 `traceparent`/`tracestate`/`x-request-id`（单测断言）。
- [x] 审计 `TraceID` 为证据字段（omitempty、不进 hash；WORM 旧链 verify 仍通过）。
- [x] 排障响应仅含白名单属性与审计元数据，无原文、无金额（C-1/C-5）。
- [x] CSV 导出防公式注入（`= + - @ \t \r` 前置单引号）。
- [x] 租户隔离：跨租户/缺省 tenant 的非 admin 访问 → 403（fail-closed）。
- [ ] **待实机验证**：Collector/Tempo/Envoy（Higress）镜像与 tracer 编入、`config_dump` 属性核对（§6.4 待确认项 1/2/4/5/6）。

## 7. 待实机验证项（不阻塞交付，闭环前不得视为已具备）

| # | 项 | 说明 |
|---|---|---|
| 1 | Envoy OTel tracer 编入 | `higress/gateway` 镜像 `envoy --version` + Admin `config_dump` |
| 2 | `http.status_code` 键名 | Envoy span 属性键名与 semconv 版本核对（已用 Collector `http.response.status_code` 兼容映射兜底） |
| 3 | Tempo 分层冻结 | 单实例 30d 保留 + 查询默认 7d 窗口（已落地配置） |
| 4 | Higress `tracing.*` schema | chart 实机核对 |
| 5 | Wasm 对 traceparent 可见性 | 插件实测 |
| 6 | Envoy OTel 默认 tags 清单 | 确认无敏感 fields（`http.url` 不带 query） |
| 7 | Collector 租户 allow-list 热更 | `POST /tracing/tenant` 与 Collector 侧同步的自动化 wiring |
| 8 | 性能基线实测 | §5 方法在实机负载下执行并留证 |
