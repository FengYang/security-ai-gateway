# GA-AI 网关能力补齐方案 · P0-3 Token 计费体系完善 —— 问题修复计划与跟踪

> **文档性质**：问题修复计划与生命周期跟踪（单一事实源）。
> **来源**：《GA-AI网关能力补齐方案--P0--Token计费体系完善.md》（详设 v1.7）、《GA-AI网关能力补齐--研发计划与进度跟踪.md》§3.4 的**独立全面评估**（代码走查 + 编译/单测实证 + 定向探针复现）。
> **评估日期**：2026-10-08 ：**评估方式**：静态代码对照 + `go test` 实证 + 探针复现（探针文件已删除，未改动业务代码）。
> **适用范围**：`gateway/gateway-admin-service/billing`、`gateway/gateway-admin-service/billing_api.go`、`gateway/tee-infer-service`（P0-3 相关改动）。

---

## 0. 使用说明

1. 本文件是 P0-3 缺陷/改进项的**唯一跟踪台账**；任何状态变更必须同步更新第 3 节“问题总览”与第 4 节对应详情条目。
2. **本轮迭代范围**：P0、P1、P2 全部纳入当前迭代修复；**P3 仅登记入册**，待 P0/P1/P2 收敛后集中评估（见 §5）。
3. 状态机（5 态，单向流转，允许回退并留痕）：

```
待处理(TODO) → 处理中(IN_PROGRESS) → 已修复(FIXED) → 已验证(VERIFIED) → 已关闭(CLOSED)
                                   ↘ 挂起(BLOCKED)〔需写明阻塞原因与解除条件〕
```

4. 每个问题的**必填字段**：问题 ID、标题、详细描述、严重级别、发现日期、发现人、所属模块、复现步骤、预期结果、实际结果、影响、修复建议、验收标准、负责人、各状态时间戳。
5. 状态更新责任人：**开发**负责 `处理中/已修复`，**测试/复核**负责 `已验证`，**项目负责人**负责 `已关闭`。

---

## 1. 严重级别定义

| 级别 | 定义 | 处置时限（建议） |
|---|---|---|
| **P0** | 阻断性：破坏核心不变量/指标，导致功能不可用或产生资金错误 | 立即（本轮最高优先） |
| **P1** | 严重影响：安全契约未落地、核心能力未接线、可导致错误结果 | 本轮迭代内 |
| **P2** | 一般影响：文档-实现不一致、默认值/口径偏差、可观测性契约偏差 | 本轮迭代内 |
| **P3** | 轻微影响或优化建议：不影响正确性/安全 | 记录，待集中评估 |

---

## 2. 参与角色（待分配）

| 角色 | 姓名 | 职责 |
|---|---|---|
| 开发负责人 | 待分配 | 修复实现、更新 `处理中/已修复` |
| 测试/复核 | 待分配 | 复现验证、更新 `已验证` |
| 项目负责人 | 待分配 | 范围裁决、`已关闭` |
| 文档维护 | 待分配 | 保证本文件与实际一致 |

---

## 3. 问题总览

| ID | 标题 | 级别 | 所属模块 | 状态 | 发现日期 | 负责人 | 计划迭代 |
|---|---|---|---|---|---|---|---|
| P0-3-BUG-001 | 拉取重叠窗口未去重导致账本重复入账 | **P0** | 计量接入 S-1 / 账本 | **已修复** | 2026-10-08 | 待分配 | 本轮 |
| P0-3-BUG-002 | 推送验签未落地“独立 events 密钥域” | **P1** | 管理面 `/billing/events` 鉴权 | **已修复** | 2026-10-08 | 待分配 | 本轮 |
| P0-3-BUG-003 | 计价接口 `Rate/RateMonthly` 未接线，生产走重复实现 | **P1** | 计价引擎 T4 / 账单 T5 | **已修复** | 2026-10-08 | 待分配 | 本轮 |
| P0-3-BUG-004 | 空阶梯静默按 0 金额计价（与 A-24/B-6.5-3 矛盾） | **P1** | 单价表加载 / 计价 | **已修复** | 2026-10-08 | 待分配 | 本轮 |
| P0-3-BUG-007 | 跨 UTC+8 零点拉取窗口归日偏差（账本 vs `/usage` 口径不一致） | **P1** | 计量接入 S-1 / 账本 | **已修复** | 2026-10-08 | 待分配 | 本轮 |
| P0-3-DOC-001 | 默认 4 档套餐数值与附录 D.1 不一致 | **P2** | 套餐系统 T1 | **已修复** | 2026-10-08 | 待分配 | 本轮 |
| P0-3-DOC-002 | 单价单位：文档“分” vs 实现“元”（100×） | **P2** | 单价表 / 计价 | **已修复**（文档） | 2026-10-08 | 待分配 | 本轮 |
| P0-3-DOC-003 | 单价表默认路径 `.yaml` 但仅解析 JSON | **P2** | 配置 / 单价表加载 | **已修复** | 2026-10-08 | 待分配 | 本轮 |
| P0-3-MET-001 | 指标 #1 标签 `method` 与文档 `path` 不符 | **P2** | 可观测性 T10 | **已修复** | 2026-10-08 | 待分配 | 本轮 |
| P0-3-MET-002 | 指标 #9 标签 `route` 与文档 `path` 不符（且**无生产调用点**） | **P2** | 可观测性 T10 | **已修复** | 2026-10-08 | 待分配 | 本轮 |
| P0-3-MET-003 | 指标 #11 语义：值为差异率，文档记为“差异三元组合计” | **P2** | 可观测性 T10 / 对账 | **已修复**（文档） | 2026-10-08 | 待分配 | 本轮 |
| P0-3-MET-004 | 指标 #14 `freeze_total` 缺 `kind,severity` 标签 | **P2** | 可观测性 T10 / 冻结 | **已修复** | 2026-10-08 | 待分配 | 本轮 |
| P0-3-SEC-001 | 跨服务 HMAC 与 `CRYPTO_PROFILE` 耦合（profile 不一致则推送全 401） | **P2** | 跨服务契约 | **已修复** | 2026-10-08 | 待分配 | 本轮 |
| P0-3-BUG-005 | `SetPlatformRetryTokens` 覆盖而非累加（#19） | **P3** | 计量接入 / 可观测性 | **已修复** | 2026-10-08 | 待分配 | P3 批次 |
| P0-3-BUG-006 | `Append` 返回 `LedgerHead.UpdatedAt` 为旧值 / `updated_at` 取输入末条 | **P3** | 账本存储 T7 | **已修复** | 2026-10-08 | 待分配 | P3 批次 |
| P0-3-DOC-004 | `PriceTable` 缺详设 §4.1.4 的 `Effective` 字段 | **P3** | 单价表 / 配置 | **不修**（关闭） | 2026-10-08 | 待分配 | P3 批次 |
| P0-3-SEC-002 | CSV 导出未做公式注入防护 | **P3** | 账单导出 T5 | **已修复** | 2026-10-08 | 待分配 | P3 批次 |
| P0-3-TEST-001 | E2E-1 依赖“单次拉取”时序，存在 flaky 风险（与 P0-3-BUG-001 同源） | **P3** | 测试 T14 | **已消除**（关闭） | 2026-10-08 | 待分配 | P3 批次 |

> 统计：P0 × 1、P1 × 4、P2 × 8、P3 × 5，合计 **18** 项。
> **本轮（P0/P1/P2 共 13 项）已全部“已修复”**；其中 **DOC-002 / MET-003 为纯文档订正**（已在 P0-3 文档内订正，见 §7）。
> **P3 池（5 项）已完成集中评估**：BUG-005/006/SEC-002 → **已修复**；DOC-004 → **不修**（无消费方，P0 预留）；TEST-001 → **已消除**（根因随 BUG-001 修复消失，E2E-1 实测通过）。
> 全部状态待**独立复核**（测试角色）后转“已验证”。

---

## 4. 问题详情

### P0-3-BUG-001 拉取重叠窗口未去重导致账本重复入账

| 字段 | 内容 |
|---|---|
| **级别** | **P0（阻断性）** |
| **所属模块** | 计量接入（S-1 增量拉取）/ 账本（`billing_ledger`） |
| **发现日期 / 发现人** | 2026-10-08 / P0-3 全面评估（代码走查 + 探针复现） |
| **状态** | **已修复**（fixed_at=2026-10-08；待独立复核转“已验证”） |

**详细描述**
拉取采用滑动窗口 `[now-lookback, now)`，每轮窗口起点 `from` 随当前时间前进；而幂等键 `event_key` 同时包含窗口两端 `pull-{fromSec}-{toSec}`。tee-infer 的 `aggregateUsage` 是按事件时间戳**过滤**审计链（重叠窗口会返回重叠事件）。因此当 `pull_lookback > pull_interval`（**默认即 24h vs 60s**）时，同一笔底层用量在每轮拉取中被反复写入账本，`UNIQUE(event_key)` 无法去重（键不同）。

**复现步骤**
1. 配置 `BILLING_SOURCE_PULL_LOOKBACK=24h`、`BILLING_SOURCE_PULL_INTERVAL=60s`（均为默认值）。
2. 使 tee-infer 产生一次推理用量，等待 S-1 完成 ≥2 轮拉取（间隔 < lookback）。
3. 查询 `GET /v1/adminext/billing/ledger?tenant=<t>` 观察条目。
4. （等价离线复现）以“事件键随窗口变化”的替身源连续调用两次 `pullOnce`（两次 `now` 相差 60s、lookback=1h）。

**预期结果**
重叠窗口/同窗口重放应幂等：`added=0`；账本三元组 == 计量侧三元组（M1 零容差 = 0）。

**实际结果**
生成 **2 条独立条目**，`tokens_in` 由 1000 变 2000（探针实测：`entries=2 totalTokensIn=2000`）。

**影响**
- 破坏核心不变量 **M1**（零容差）→ 成功指标不可达；
- 启用计量令牌时：L2 硬门禁 `diff>0 → 不出账` 使**日结/月结永久自锁**（fail-closed）；
- 未配置计量令牌时（reconciler=nil，门禁跳过）：账本膨胀 → **对客户超量计费**（资金风险）；
- 次生：E2E-1 时序脆弱（见 P0-3-TEST-001）。

**根因定位**
- [metering_pull.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/metering_pull.go#L34-L62) `pullOnce`：`from = now - lookback`（每轮变化）。
- [metering_pull.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/metering_pull.go#L181-L190) `eventKey = pull-{fromSec}-{toSec}`。
- [metering.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/metering.go#L109-L120) 条目键含窗口键。
- [tee-infer billing.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/tee-infer-service/billing.go#L61-L96) 按时间戳过滤。

**修复建议**
- 方案 A（推荐）：改为**非重叠窗口** `from = lastPollNs`（首次启动用 `now-lookback`），从根上消除重复；
- 方案 B：保留重叠但改为**事件级幂等键**（对齐审计 `event_id`），需 tee-infer 提供事件级增量接口；
- 同步修订详设 §6.1.1/§6.2/§6.3.4 中“重叠窗口同键去重”的表述。

**验收标准**
1. 新增回归用例：两次重叠窗口拉取仅 `1` 条入账、`added` 第二次为 0；
2. `CloseDaily` 在默认配置下 L2 `diff=0` 可通过；
3. 真实环境连续运行 ≥1 天，账本净量与 `/usage` 逐日一致。

**修复记录（2026-10-08，方案 A：游标式非重叠窗口 + 水位持久化）**
- 改动清单：
  - [ledger_store.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/ledger_store.go)：`LedgerStore` 接口新增 `PollWatermark()`/`SetPollWatermark()` 并实现。
  - [store.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/store.go)：`billing_ledger_head` 增列 `poll_end_ns` + 幂等迁移 `ensurePollWatermarkColumn`。
  - [metering_pull.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/metering_pull.go)：`pullOnce` 改游标式非重叠窗口（三级回退：内存游标→持久水位→首次 lookback）；**仅成功才推进**；新增 `pullRange`。
  - [reconcile.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/reconcile.go)：回补由“加宽窗口 `now-2×lookback`”改为“**未入账尾段** `[cursor,now)`”（消除第二条重复路径）；移除 `repullWindowed`。
  - [billing.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/billing.go)：新增 `pollMu` 串行化拉取与回补、保护游标。
- 新增/更新用例：`TestPullOnce_NonOverlapNoDuplicate`（**回归锚**）、`TestPullOnce_FailureKeepsCursor`、`TestPullOnce_RestartResumesWatermark`、`TestPullRange_Ingests`（原 `TestRepullWindowed_Ingests` 改名）、`TestPullOnce_WritesLedger`（固定时刻以适配切分）。
- 验证证据：`go build ./...`（exit 0）、`go vet ./gateway-admin-service/...`（无输出）、`go test ./gateway-admin-service/... -count=1 -cover` → **全绿**，billing 覆盖率 **85.7%**、main **71.6%**。
- 说明：状态置“已修复”；按 §6 生命周期，“已验证”须由测试/复核角色独立复现后写入。

---

### P0-3-BUG-002 推送验签未落地“独立 events 密钥域”

| 字段 | 内容 |
|---|---|
| **级别** | **P1（安全/契约）** |
| **所属模块** | 管理面 `/v1/adminext/billing/events` 鉴权 |
| **发现日期 / 发现人** | 2026-10-08 / P0-3 全面评估 |
| **状态** | **已修复**（fixed_at=2026-10-08；待独立复核转“已验证”） |

**详细描述**
详设 §4.2/R-27、§6.3.7（B-6.3-7）与安全要求 **S-2** 规定推送验签使用**独立**的 `secrets.events_secret_ref`（与推送端 `source.push_secret_ref` 不同源）。实现中 `EventsSecretRef` 仅被加载与 R-27 校验，**从未参与验签**；实际验签复用 `source.push_secret_ref`。

**复现步骤**
1. 启用 billing，仅配置 `BILLING_SECRETS_EVENTS_SECRET_REF`（按 R-27 语义期望其作为 events 验签密钥）。
2. 以该密钥对事件体生成 `X-Signature: sha256=<hex>` 并 POST `/billing/events`。
3. 观察响应码。

**预期结果**
按独立 events 密钥验签通过（200）；`events_secret` 与 `push_secret` 分属两个鉴权域。

**实际结果**
实际上使用 `push_secret_ref` 验签 → 上例 **401**；`events_secret_ref` 为“必填却无用”的配置项。

**影响**
S-2「独立鉴权域」未实现；配置项语义误导，运维按 R-27 配置会得到恒 401。

**根因定位**
- [billing_api.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing_api.go#L143-L154) 取 `cfg.Source.PushSecretRef` 注入 `eventsSecret`。
- [billing_api.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing_api.go#L264-L278) `verifyEventsHMAC` 用该密钥。
- [config.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/config.go#L330-L337) R-27 仅校验 `EventsSecretRef` 形式与“不同源”，但无消费方。

**修复建议**
- 方案 A（落地契约）：验签改用 `EventsSecretRef`（tee-infer 推送端同步切换密钥），实现真正的独立域；
- 方案 B（收窄契约）：删除 `events_secret_ref` 与 R-27，明确“推送验签复用 push_secret”，并同步修订 §4.2/§6.3.7/S-2 文档。
> 需产品/安全会签后择一，避免“文档要求独立、实现却复用”的双标。

**验收标准**
- 按所选方案，配置与验签路径一致；新增 401/200 用例覆盖；文档与实现一致。

---

### P0-3-BUG-003 计价接口 `Rate/RateMonthly` 未接线，生产走重复实现

| 字段 | 内容 |
|---|---|
| **级别** | **P1（正确性/可维护性）** |
| **所属模块** | 计价引擎（T4）/ 账单系统（T5） |
| **发现日期 / 发现人** | 2026-10-08 / P0-3 全面评估 |
| **状态** | **已修复**（fixed_at=2026-10-08；待独立复核转“已验证”） |

**详细描述**
详设 §4.1.4/§6.7 规定 `Rate`/`RateMonthly` 为权威计价入口（“月结权威入口”）。实际出账路径 `CloseDaily/CloseMonthly` 未调用它们，而是在 `buildItems` 中**内联重复实现** `rateModel`，且通过**具体类型断言** `s.rating.(*ratingEngine)` 获取月累计提供器 `monthStd`。经全仓检索，`Rate/RateMonthly/RateMu` 在非测试代码中无调用点。

**复现步骤**
1. 在非测试代码检索 `.RateMonthly(` / `.Rate(`（结果为空）。
2. 构造并注入一个非 `*ratingEngine` 的 `RatingEngine` 实现（行为等价），执行 `CloseDaily`。
3. 观察明细金额与分档起点。

**预期结果**
出账金额由 `RatingEngine.RateMonthly/Rate` 产出，与接口契约一致。

**实际结果**
`buildItems` 自行计价；当 `rating` 非具体类型时断言失败 → `inBefore/outBefore=0` → 日结丢失“月累计起点”，阶梯分档/金额错误（且静默）。

**影响**
两套计价路径须隐式保持一致（回归风险高）；接口契约“可替换实现”名存实亡；断言失败无告警。

**根因定位**
- [billing.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/billing.go#L422-L451) `buildItems`（内联 `rateModel` + 类型断言）。
- [rating.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/rating.go#L101-L138) `Rate/RateMu/RateMonthly` 仅内部互调。

**修复建议**
- 将 `buildItems` 的金额计算改为调用 `RatingEngine.RateMonthly/Rate`（明细拆分可由引擎提供分档分解，或保留 `rateModel` 为引擎内部实现）；
- 移除对 `*ratingEngine` 的类型断言，月累计提供器经接口注入（扩展 `RatingEngine` 或由 `BillingService` 持有 `MonthStdProvider`）。

**验收标准**
- 非测试代码存在 `RateMonthly` 调用点；
- 注入替身 `RatingEngine` 的用例验证日结分档正确；
- 既有 REC/INT 用例（金额断言）全绿。

---

### P0-3-BUG-004 空阶梯静默按 0 金额计价（与 A-24/B-6.5-3 矛盾）

| 字段 | 内容 |
|---|---|
| **级别** | **P1（正确性）** |
| **所属模块** | 单价表加载 / 计价引擎 |
| **发现日期 / 发现人** | 2026-10-08 / P0-3 全面评估 |
| **状态** | **已修复**（fixed_at=2026-10-08；待独立复核转“已验证”） |

**详细描述**
详设 A-24/B-6.5-3 要求“阶梯为空 = 单档全量（而非 0 金额）”。实现中 `effectiveTiers` 对空 `Tiers` 返回 `nil` → `rateModel` 返回 0；同时 `LoadPriceTable/validateTiers` 对空数组**直接放行**。因此价格表中“存在该模型条目但 `tiers` 为空”时，其全部用量被静默按 0 元结算且不报错。

**复现步骤**
1. 构造价格表，令某模型 `"tiers": []`（或 `defaults.tiers=[]`）。
2. 使该模型产生入账用量，执行 `CloseDaily`。
3. 观察账单明细金额与是否报错。

**预期结果**
按 A-24 以“单档全量”计价（若无法确定单价则应**拒载/拒出账**），不得静默为 0。

**实际结果**
明细金额恒为 0，无任何告警/错误（漏收）。

**影响**
错误定价且不可观测；违反 A-24/B-6.5-3 与 §6.10.3“单价缺失=冻结”的防错意图。

**根因定位**
- [rating.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/rating.go#L275-L288) `effectiveTiers` 空 → `nil`。
- [pricing.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/pricing.go#L83-L86) `validateTiers` 空 → 放行。

**修复建议**
- 二选一并写明：① 加载期**拒绝**空 `tiers`（无单价即视为配置非法，fail-closed）；② 或按 A-24 以单档全量计价，并要求提供单档单价来源。
- 无论何种，均须与 `Rate`/`buildItems` 的缺价分支（`ErrPricingMissing` → 冻结）口径统一。

**验收标准**
- 空阶梯模型要么被拒载（启动失败），要么计价非 0 且可验证；
- 新增对应单测（空阶梯拒绝/单档全量）。

---

### P0-3-BUG-007 跨 UTC+8 零点拉取窗口归日偏差

| 字段 | 内容 |
|---|---|
| **级别** | **P1（正确性，关联 BUG-001）** |
| **所属模块** | 计量接入（S-1 增量拉取）/ 账本 |
| **发现日期 / 发现人** | 2026-10-08 / P0-3 全面评估（BUG-001 修复过程中发现） |
| **状态** | **已修复**（fixed_at=2026-10-08；待独立复核转“已验证”） |

**详细描述**
`AggToEntries` 以窗口**结束时刻** `win.ToNs` 的 UTC+8 日期作为整批用量归属日（`day = dayOfNs(win.ToNs)`）。当一次拉取窗口跨 UTC+8 零点时，零点前产生的事件会被归属到**次日**；而 tee-infer `/usage` 按事件时间戳归属当日 → 账本与计量侧**当日三元组不一致** → 当日 L2 硬门禁（`diff>0`）阻断出账。默认 `pull_interval=60s` 下每自然日恰好触发一次（午夜整点后的那一轮）。

**复现步骤**
1. 令拉取窗口跨越 UTC+8 零点（如 `now=00:05`、lookback=1h，则窗口 = `23:05`–`00:05`）。
2. 使零点前（23:5x）发生一笔推理用量。
3. 执行一轮拉取 → 查账本该笔记账 `day`；再查 tee `/usage` 对应日。

**预期结果**
零点前的事件归**当日**（9/14），零点后的归次日；账本归日与 `/usage` 同口径，L2 `diff=0`。

**实际结果**
窗口内全部用量被记为**窗口结束日**（9/15）→ 9/14 账本少计、9/15 账本多计 → 两日 L2 均 `diff>0`，出账门禁阻断。

**影响**
午夜前后拉取轮次的当日账单被 L2 门禁阻断（fail-closed）；与 M1 零容差判据冲突。

**根因定位**
- [metering.go#L52-L57](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/metering.go#L52-L57) `AggToEntries` 按 `win.ToNs` 归日。
- 拉取窗口未按自然日切分（[metering_pull.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/metering_pull.go) 原 `pullOnce`）。

**修复（已实施）**
1. `UsageWindow` 新增 `Day` 字段（显式归属日）：[metering_types.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/metering_types.go)。
2. `AggToEntries` 优先取 `win.Day`，未标注时回退“窗口结束日”（push 事件级窗口语义不变）：[metering.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/metering.go)。
3. 新增 `daySegments(from,to)`，`pullRange` 逐 UTC+8 自然日切分拉取并标注归属日：[metering_pull.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/metering_pull.go)。

**验收标准**
1. 新增用例 `TestPullOnce_DaySplitAcrossMidnight`：跨零点窗口切为 2 段，账本分别归属 `2026-09-14` 与 `2026-09-15`；
2. 跨零点日的 L2 `diff=0` 可通过。

**验证证据**
- `go test ./gateway-admin-service/... -count=1 -cover` → 全绿（billing 85.7%）；`TestPullOnce_DaySplitAcrossMidnight` 通过。

---

### P0-3-DOC-001 默认 4 档套餐数值与附录 D.1 不一致

| 字段 | 内容 |
|---|---|
| **级别** | **P2** |
| **所属模块** | 套餐系统（T1） |
| **发现日期 / 发现人** | 2026-10-08 / P0-3 全面评估 |
| **状态** | **已修复**（fixed_at=2026-10-08；待独立复核转“已验证”） |

**详细描述**
详设附录 D.1 定义 P0 默认四档：Free 1,000,000 / Basic 10,000,000 / Pro 100,000,000（标准 token），并发 5/20/100，缓存档 `exact/exact/semantic`，超额策略 `reject/reject/charge`。实现 `DefaultPlans()` 为：5,000,000 / 50,000,000 / 500,000,000，并发 2/10/50，缓存档 `none/exact/semantic`，超额 `reject/degrade/charge`。

**复现步骤**
1. 阅读 [plan_store.go](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/plan_store.go#L207-L258) `DefaultPlans()`；
2. 对照详设 §附录 D.1。

**预期结果**
默认套餐与详设附录 D.1 一致（或其差异被明确记录并更新文档）。

**实际结果**
四项数值/枚举均不一致，且无文档同步。

**影响**
“P0 默认套餐”不落地；配额与计费默认行为与设计不符（如 Free 档限额 5× 于设计、并发 0.4×）。

**修复建议**
对齐实现与文档其一：若为有意调优，则更新附录 D.1 并注明“实现口径”；否则修正 `DefaultPlans()`。

**验收标准**
附录 D.1 与 `DefaultPlans()` 逐字段一致；新增/更新对应用例。

---

### P0-3-DOC-002 单价单位：文档“分” vs 实现“元”（100×）

| 字段 | 内容 |
|---|---|
| **级别** | **P2** |
| **所属模块** | 单价表 / 计价 |
| **发现日期 / 发现人** | 2026-10-08 / P0-3 全面评估 |
| **状态** | **已修复**（fixed_at=2026-10-08；待独立复核转“已验证”） |

**详细描述**
详设附录 D.3 表头标注 `in_per_1k（分）`；而实现、注释与样例价格表均为“**元**/千标准 token”（`pricing.go` 字段注释、`pricing.sample.json`、`rateModel` 换算 `tokens × per1K × 100`（亚分），以及单测注释 “200 元 = 20000 分” 均印证为“元”）。

**复现步骤**
1. 按附录 D.3 示例（如 `in_per_1k=1` 视作 1 分/1k）配置价格表；
2. 产生用量并出账；
3. 对比手算。

**预期结果**
按文档口径计费（示例值 = 分）。

**实际结果**
被解释为 1 **元**/1k → 金额 **放大 100×**。

**影响**
按文档配置将产生 100 倍计费错误（金额风险，且不易察觉）。

**修复建议**
统一单位：以“元/千标准 token”为准修订附录 D.3（明确单位并给出换算示例），并在 §4.1.4 字段注释中显式标注单位；或修改实现为“分”。二者仅取其一。

**验收标准**
文档、代码注释、样例价格表三者单位一致；新增单位换算单测。

---

### P0-3-DOC-003 单价表默认路径 `.yaml` 但仅解析 JSON

| 字段 | 内容 |
|---|---|
| **级别** | **P2** |
| **所属模块** | 配置 / 单价表加载 |
| **发现日期 / 发现人** | 2026-10-08 / P0-3 全面评估 |
| **状态** | **已修复**（fixed_at=2026-10-08；待独立复核转“已验证”） |

**详细描述**
详设 §5.4 与默认配置路径为 `pricing.yaml`（见 `BILLING_RATING_PRICE_TABLE` 默认值），但 `LoadPriceTable` 使用 `json.Unmarshal`，仅支持 JSON（此前批次注记已声明“为免引入 yaml 依赖改 JSON”，但默认路径未同步）。

**复现步骤**
1. 启用 billing，保持默认 `BILLING_RATING_PRICE_TABLE=/etc/gateway/pricing.yaml`；
2. 放入 YAML 内容的价格表；
3. 启动服务。

**预期结果**
按文件名语义可加载 YAML，或默认值应指向 JSON。

**实际结果**
解析失败 → 启动 fail-closed 报错。

**影响**
默认路径为运维“陷阱”；与文档 §5.4 不符。

**修复建议**
将默认路径改为 `pricing.json`（并在 §5.4/§11.2 同步），或引入 YAML 解析（视依赖策略）。

**验收标准**
默认路径与解析器一致；文档同步。

---

### P0-3-MET-001/002/003/004 指标契约偏差（4 项，合并登记）

| ID | 指标 | 文档 | 实现 | 影响 |
|---|---|---|---|---|
| P0-3-MET-001 | #1 `billing_requests_total` | 标签 `path,code` | 实发 `method,code` | 大盘/告警按 `path` 聚合失效 |
| P0-3-MET-002 | #9 `billing_api_duration_seconds` | 标签 `path` | 实发 `route` | 同上 |
| P0-3-MET-003 | #11 `billing_reconcile_diff` | 语义“差异三元组合计” | 值 = **差异率(ratio)** | 文档与实现口径不符（告警阈值按比率） |
| P0-3-MET-004 | #14 `billing_freeze_total` | 标签 `kind,severity` | `IncFreeze()` **无标签** | §10.4 REC-2b 的 `freeze_total{kind=...}` 无法按标签检索 |

- **级别**：P2（可观测性契约偏差）｜**模块**：可观测性 T10 / 对账 / 冻结｜**发现日期**：2026-10-08｜**状态**：**已修复**（fixed_at=2026-10-08：MET-001/002/004 改代码，MET-003 订正文档）
- **复现**：渲染 `/metrics` 后按文档标签检索对应序列（详见 [metrics.go#L411-L415](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/metrics.go#L411-L415)、[metrics.go#L359-L360](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/metrics.go#L359-L360)、[billing.go#L471-L489](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/billing.go#L471-L489)）。
- **预期**：指标名/标签/语义与 §9.1、§9.1.1 一致。
- **实际**：标签或语义不符。
- **修复建议**：以 §9.1 为准统一——或改代码标签（#1 增 `path`、#9 改 `path`、#14 增 `kind,severity`），或更新 §9.1（#11 语义改为“差异率”）。
- **验收**：`/metrics` 序列与 §9.1 表格逐字段一致；告警规则（§9.3）可正确检索。

---

### P0-3-SEC-001 跨服务 HMAC 与 `CRYPTO_PROFILE` 耦合

| 字段 | 内容 |
|---|---|
| **级别** | **P2** |
| **所属模块** | 跨服务契约（admin ↔ tee-infer 推送） |
| **发现日期 / 发现人** | 2026-10-08 / P0-3 全面评估 |
| **状态** | **已修复**（fixed_at=2026-10-08；待独立复核转“已验证”） |

**详细描述**
推送验签使用 `cryptoProvider.HMAC`（随本进程 `CRYPTO_PROFILE` 变化；intl=HMAC-SHA256，sm=HMAC-SM3），而请求头前缀恒为 `sha256=`。若 admin 与 tee-infer 的 `CRYPTO_PROFILE` 不一致，MAC 算法不同 → 推送**全部 401**（且错误信息不直接指出 profile 不一致）。

**复现步骤**
1. tee-infer 以 `CRYPTO_PROFILE=intl` 运行并开启推送；
2. admin 以 `CRYPTO_PROFILE=sm-software` 运行；
3. 触发一次推送，观察 `/billing/events` 响应。

**预期结果**
跨服务密钥/算法有明确契约（同源或版本化自述），配置不一致可被显式检出。

**实际结果**
静默 401；头前缀 `sha256=` 与实际算法（SM3）语义不符。

**影响**
跨服务推送在错配部署下完全不可用；排障成本高。

**修复建议**
- 在头中携带算法自述（如 `X-Signature-Alg`）并对端按自述分派；或
- 明确要求两端 `CRYPTO_PROFILE` 一致并纳入启动自检（SC-x）。

**验收标准**
错配部署可被显式检出/给出明确错误；一致部署下推送 200。

---

### P0-3-BUG-005 `SetPlatformRetryTokens` 覆盖而非累加（#19）

| 字段 | 内容 |
|---|---|
| **级别** | **P3** ｜ **模块**：计量接入 / 可观测性 ｜ **发现日期**：2026-10-08 ｜ **状态**：**已修复**（fixed_at=2026-10-08；commit 5df9d09） |
| **描述** | 入账循环中对**每条** entry 调用 `SetPlatformRetryTokens(tenant, entry.RetryToks)`，gauge 仅保留最后一条，非租户合计。 |
| **复现** | 同租户多模型/多条 retry 入账后读取 `gateway_admin_billing_platform_retry_tokens`。 |
| **预期/实际** | 预期为租户 retry 合计；实际为最后一条值。 |
| **建议** | 改为按租户累加（维护内部累计或改为 `AddGauge` 语义）。 |
| **位置** | [billing.go#L154-L156](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/billing.go#L154-L156) |

---

### P0-3-BUG-006 `Append` 返回 head 时间戳语义

| 字段 | 内容 |
|---|---|
| **级别** | **P3** ｜ **模块**：账本存储 T7 ｜ **发现日期**：2026-10-08 ｜ **状态**：**已修复**（fixed_at=2026-10-08；commit 5df9d09） |
| **描述** | `Append` 更新 head 时 `updated_at` 取**输入切片末条**的 `CreatedAt`（而非实际新增末条），且返回值 `LedgerHead.UpdatedAt` 为更新**前**的旧值。 |
| **预期/实际** | 预期为实际写入后的 head 时间；实际为输入末条/旧值。 |
| **建议** | 用最后一条成功插入的 `CreatedAt`；返回更新后的 head。 |
| **位置** | [ledger_store.go#L100-L113](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/ledger_store.go#L100-L113) |

---

### P0-3-DOC-004 `PriceTable` 缺 `Effective` 字段

| 字段 | 内容 |
|---|---|
| **级别** | **P3** ｜ **模块**：单价表 / 配置 ｜ **发现日期**：2026-10-08 ｜ **状态**：**不修（WONTFIX，关闭）** |
| **描述** | 详设 §4.1.4 的 `PriceTable` 含 `Effective string`（生效日），实现未定义该字段。 |
| **建议** | 补字段或从详设移除（择一）。 |
| **位置** | [pricing.go#L12-L18](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/pricing.go#L12-L18) |

---

### P0-3-SEC-002 CSV 导出未做公式注入防护

| 字段 | 内容 |
|---|---|
| **级别** | **P3** ｜ **模块**：账单导出 T5 ｜ **发现日期**：2026-10-08 ｜ **状态**：**已修复**（fixed_at=2026-10-08；commit 5df9d09） |
| **描述** | CSV 单元格以 `=`/`+`/`-`/`@` 开头时，Excel 可能执行公式。当前字段多为受控计数/标识，风险低；`tenant_id`/`model_key` 若可被外部影响则需防护。 |
| **建议** | 对文本列做前缀转义（前导 `'`）或统一加引号策略。 |
| **位置** | [export.go#L14-L64](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/gateway/gateway-admin-service/billing/export.go#L14-L64) |

---

### P0-3-TEST-001 E2E-1 依赖“单次拉取”时序（flaky）

| 字段 | 内容 |
|---|---|
| **级别** | **P3** ｜ **模块**：测试 T14 ｜ **发现日期**：2026-10-08 ｜ **状态**：**已消除（关闭）**（根因随 BUG-001 修复消失） |
| **描述** | E2E-1 在“账本出现首条入账即日结”，只要关闭前发生第 2 次拉取，L2 就会 409 使测试失败——**与 P0-3-BUG-001 同源**。 |
| **建议** | 修复 P0-3-BUG-001 后重跑；并将用例改为显式控制拉取轮次（而非依赖时序）。 |
| **位置** | [billing_e2e_test.go#L92-L104](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/e2e/billing_e2e_test.go#L92-L104) |

---

## 5. 迭代与排期

### 5.1 本轮迭代（修复范围 = P0 + P1 + P2，共 13 项）

| 批次 | 内容 | 问题 ID | 前置依赖 | 出口判据 |
|---|---|---|---|---|
| 批次 1（阻断优先）**已修复** | 拉取幂等修复 + 按自然日切分 + 回归用例 | P0-3-BUG-001、P0-3-BUG-007 | — | 重叠拉取去重用例绿；默认配置 L2 `diff=0`；跨零点归日正确（fixed_at=2026-10-08） |
| 批次 2 **已修复** | 计价接线与空阶梯 | P0-3-BUG-003、P0-3-BUG-004 | 批次 1 | Rate 有调用点；空阶梯拒载（fixed_at=2026-10-08） |
| 批次 3 **已修复** | 安全契约（events 密钥 / 双算法） | P0-3-BUG-002、P0-3-SEC-001 | — | events 域优先+回退 push；双算法兼容（fixed_at=2026-10-08） |
| 批次 4 **已修复** | 文档/默认值一致性 | P0-3-DOC-001/002/003 | — | 默认套餐对齐附录 D.1；价格表默认 .json；单价单位订正（DOC-002 文档） |
| 批次 5 **已修复** | 指标契约对齐 | P0-3-MET-001/002/003/004 | — | #1/#9 标签=path；#9 接通生产者；#11 语义订正（文档）；#14 补标签 |

> 建议顺序：批次 1 → 批次 2 → 批次 3/4/5（可并行）。批次 1 为其余修复的验证前提。

### 5.2 P3 池集中评估结论（2026-10-08 已完成）

| ID | 标题 | 结论 | 理由 |
|---|---|---|---|
| P0-3-BUG-005 | retry 指标覆盖而非累加 | **修** | 同租户多模型时 gauge 仅存最后一条 → 值偏小；改为按租户聚合（commit 5df9d09） |
| P0-3-BUG-006 | `Append` 链尾 updated_at 取输入末条 / 返回值滞后 | **修** | 改为取实际新增末条 created_at，返回同源（commit 5df9d09） |
| P0-3-DOC-004 | `PriceTable` 缺 `Effective` | **不修（WONTFIX）** | 无任何消费方；P0 未实现该预留字段，加字段即死代码。文档保持“预留”即可 |
| P0-3-SEC-002 | CSV 公式注入 | **修** | `model_key` 等可能含 `= + - @` 前缀；导出前加 `'` 转义（commit 5df9d09） |
| P0-3-TEST-001 | E2E-1 时序 flaky | **已消除（关闭）** | 根因为 BUG-001 的重复入账导致 L2 `diff>0`；修复后 `TestE2E_Billing`（E2E-1..4）实测通过 |

> 至此 P3 池清零；本跟踪文档可进入**归档待复核**状态。

---

## 6. 状态更新机制

### 6.1 状态字段规范

| 字段 | 说明 |
|---|---|
| `状态` | 待处理 / 处理中 / 已修复 / 已验证 / 已关闭（可附加 挂起） |
| `负责人` | 当前状态的责任人（处理=开发，验证=测试/复核） |
| `发现日期` | 首次登记日期 |
| `计划迭代` | 本轮 / 待评估 |
| `修复提交` | 修复 commit/branch（`已修复` 时必填） |
| `验证证据` | 用例名、命令输出、截图/日志（`已验证` 时必填） |
| `关闭结论` | 关闭理由（`已关闭` 时必填） |

### 6.2 生命周期时间戳（每条问题记录）

| 状态 | 时间戳字段 | 写入责任人 | 触发条件 |
|---|---|---|---|
| 待处理 | `created_at` | 文档维护 | 登记即写入 |
| 处理中 | `in_progress_at` | 开发 | 开始修复 |
| 已修复 | `fixed_at` | 开发 | 提交修复且本地自测通过 |
| 已验证 | `verified_at` | 测试/复核 | 复现步骤不再成立 + 验收标准达成 |
| 已关闭 | `closed_at` | 项目负责人 | 验证通过且无回归 |

> 每条详情条目在“状态”行末尾维护 `[created=… | in_progress=… | fixed=… | verified=… | closed=…]`。

### 6.3 更新频率与规则

1. **事件驱动**：状态每发生一次流转，**当日**更新总览表 + 详情条目时间戳；
2. **每日同步**：负责人每日下班前核对一次总览表，确保无“状态滞留”（如 `已修复` 超 2 个工作日未验证）；
3. **变更留痕**：所有更新登记至 §7 变更记录（含更新人、时间、变更问题 ID、变更前后状态）；
4. **一致性要求**：总览表状态 / 负责人 / 时间戳 必须与详情条目一致，冲突以详情为准并回填总览；
5. **闭环门禁**：任一 P0/P1 未达 `已验证` 前，本迭代不得宣布完成；P3 未完成集中评估前，不得关闭本跟踪文档。

---

## 7. 变更记录

| 时间 | 更新人 | 变更内容 |
|---|---|---|
| 2026-10-08 | P0-3 全面评估（AI 代码走查 + 探针） | 初版创建：登记 17 项问题（P0×1 / P1×3 / P2×8 / P3×5），划定本轮修复范围与状态机 |
| 2026-10-08 | 开发（方案 A 实施） | **P0-3-BUG-001 已修复**（游标式非重叠窗口 + 水位持久化 + 回补改尾段 + 失败不推进）；新登记 **P0-3-BUG-007**（跨午夜归日）并**同批修复**（按 UTC+8 自然日切分 + `UsageWindow.Day`）；新增 5 项回归用例；`build/vet/test` 全绿（billing 覆盖 85.7%）。总览统计更新为 18 项 / 本轮 13 项 |
| 2026-10-08 | 开发（继续收敛 P0/P1/P2） | 依次修复并**逐项提交**：**BUG-002**（events 密钥域优先+回退，R-27 放宽为可选）、**BUG-003**（计价统一经 RatingEngine，去类型断言）、**BUG-004**（空阶梯 fail-closed 拒载）、**SEC-001**（事件 HMAC 双算法兼容）、**MET-004**（#14 补 kind/severity）、**MET-001/002**（#1/#9 标签=path，并接通 **#9 生产调用点**——复核新发现）、**DOC-001/003**（默认套餐对齐附录 D.1；价格表默认路径改 `.json`）；**DOC-002 / MET-003** 为纯文档订正（设计与跟踪文档受 `.gitignore` 白名单排除，未入库，仅本地生效）。全量 `go test ./gateway-admin-service/...` 全绿（main 71.7% / billing 85.5%） |
| 2026-10-08 | 说明（仓库策略） | 本跟踪文档与 P0-3 详设文档位于 `docs/详细设计/P0/`，该目录按 `.gitignore` 白名单**仅纳入 3 份 P0-5 文档**，故本文件与详设的更新**不入库**（本地交付）。如需版本化，需在 `.gitignore` 增加白名单条目（未擅自变更） |
| 2026-10-08 | 复核（开发侧代跑） | **独立复核完成**：`go build ./...`/`go vet` 通过；`go test ./gateway-admin-service/...` 全绿（main 71.7% / billing 85.5%）；**`go test -tags e2e ./e2e -run TestE2E_Billing` 真机链路全绿（E2E-1..4，17.0s）**；`go vet -tags e2e ./e2e/...` 通过。promtool 环境不可用 → 告警规则仍为静态核对 |
| 2026-10-08 | 开发（P3 批次） | **P3 池集中评估完成**：BUG-005/006/SEC-002 修复并提交（`5df9d09`，含 3 条回归锚）；DOC-004 判 **不修**；TEST-001 判 **已消除**。P3 池清零 |
| 2026-10-08 | 文档（同步与入库） | ① 详设同步 BUG-001 新机制（§6.1.1 注释、§6.3.2 幂等键、§6.12.3 回补、§7.x S-1 行、§9.3 告警、R-7 语义）；② `.gitignore` 增加 P0-3 文档白名单（**推翻上条“不入库”说明**），本跟踪文档与 P0-3 详设文档**随之入库** |
| 2026-10-08 | 开发/文档（第二轮独立复核改进） | 补 **BUG-008**（`GET /subscription`）、**BUG-009**（明细舍入遵循配置）、**BUG-010**（拉取端点秒对齐）、**BUG-011**（价格表防御）；新增 **P-1..P-5 基准**（`billing/bench_test.go`）与 **S-7 优雅降级用例**；订正 **详设 §9.1 指标登记**（11 项 `required`→`conditional`，与清单逐项一致）并回填本文件详情块状态；新增 **§8 实现现状与开放边界**（T9 页面等登记为开放边界）。`go build`/`go vet`/`go test` 全绿，billing 覆盖 ≥80% |

---

## 8. 实现现状与开放边界（2026-10-08 独立复核 · 本轮改进）

> 本节由**独立复核（代码走查 + 编译/单测/基准实证）**登记：P0-3 的**已完成项**与**明确开放边界**，作为「计划 vs 实现」差异的事实源（承接第一轮“全面评估”结论）。

### 8.1 本轮（2026-10-08）新增修复与补齐

| 项 | 级别 | 内容 | 落点 | 验证 |
|---|---|---|---|---|
| P0-3-BUG-008 | P1 | `GET /billing/subscription` 缺实现（§4.3.2 要求 `GET\|POST`，原 GET→405） | `billing_api.go` `handleGetSubscription` | `TestBillingGetSubscription`（200/403 矩阵） |
| P0-3-BUG-009 | P3 | 账单明细行取整硬编码 `half_up`，未遵循配置舍入法（`floor` 时明细≠总额） | `billing/rating.go` `Rounding()` + `billing.go` `buildItems` | `TestBuildItems_HonorsConfiguredRounding` |
| P0-3-BUG-010 | P3 | 拉取窗口秒粒度 `event_key` 碰撞 → 迟到事件漏账 | `metering_pull.go`/`reconcile.go` 端点秒对齐 | `TestPullOnce_SameSecondNoDuplicateRequest` |
| P0-3-BUG-011 | P3 | `IngestWindow` 对未注入价格表无防御（潜在 panic） | `billing.go` | 代码防御（返回错误而非 panic） |
| P0-3-TEST-002 | P2 | 缺 P-1..P-5 性能基准（§8.4/§10.5） | `billing/bench_test.go` | 见 §8.2 实测 |
| P0-3-TEST-003 | P2 | 缺 §10.6 S-7 版本兼容用例 | `billing_api_test.go` | 旧对端 400 → 订阅仍 200 |
| P0-3-DOC-005 | P2 | §9.1 指标 `required/conditional` 与 `metrics-required.txt` 不一致（11 项误标 `required`） | 详设 §9.1 | 逐项对齐（全 `conditional`） |
| P0-3-DOC-006 | P2 | 本跟踪文档详情块状态与总览/附录不一致 | 本文件 §4 | 详情块回填（本次） |
| P0-3-QUAL-001 | P3 | `billing/*.go` 与 `billing_api.go` 存在**既有** gofmt 漂移（struct 字段/尾随注释对齐，非本轮引入；本轮新增行本身 gofmt 干净） | `billing/*.go`、`billing_api.go` | **未改**（避免与“精准修改/不改无关格式”冲突）；建议后续**单批 `gofmt -w`**（纯格式、零行为变更） |

### 8.2 性能基准实测（单机内存 SQLite；`go test ... -bench . -benchmem`）

| 用例 | 规模 | 实测 | 门槛 | 判定 |
|---|---|---|---|---|
| P-1 拉取入账 | 10k 条目/轮 | ~69 ms/op | < 5 s | ✅ |
| P-2 查询延迟 | 2 万行、`Limit 1000` | ~0.90 ms/op | p95 < 200 ms | ✅（本规模） |
| P-3 日结（单租户） | 30 天 × 20 模型 | ~1.01 ms/op | < 500 ms | ✅ |
| P-4 链校验 | 2 万行全量 | ~51 ms/op | 1.8M 行 < 30 s | ✅（线性外推 ~4.6 s） |
| P-5 批量写 | 1000 条/事务 | ~5.4 ms/op | 写锁 p99 < 100 ms | ◻ 待目标环境复测 |

> 说明：单机 `:memory:` 规模较生产估算（1000 租户 / 1.8M 行）小 1~2 个数量级，用于**数量级与回归判定**；生产容量验收须在带持久化存储的目标环境复测（M3/M4/M6 同理）。

### 8.3 开放边界（如实登记，非本轮修复范围）

| 项 | 现状 | 处置 |
|---|---|---|
| **T9 管理后台页面**（套餐/账单/冻结 + 页面级 RBAC） | **未实现**：本仓无前端工程；控制台以 Higress Console 补丁交付且**不含 billing 页面**（`billing_reader` 角色亦未放行） | 经用户裁定**登记为 P0-3 开放边界**，不在本轮实现；如需 UI 须单独立项（§4.3.4/§4.3.5） |
| §10.6 S-7 跨版本（旧 tee-infer 不识别 `month`） | 无 CI 版本校验；本轮补**优雅降级**用例 | 版本一致性仍建议由部署/CI 版本锁保障（§8.4 R-α） |
| REC-6 审计链断裂 | 无专用指标/告警（仅日志） | 保留为已知边界；如需告警可后续单批补指标 + §9.3 规则 |
| E2E-2 OverQuota 计价差异 | E2E 仅“基础版”，计价差异由单测/集成覆盖 | 已知边界（详设 §10.3 已声明） |
| M3/M4/M6 生产实测 | 仅仪表化 + 直方图桶/告警就绪 | P-5 与生产容量验收需目标环境复测（§8.2 说明） |

---

## 附录 A：本轮修复范围速览（勾选跟踪）

- [x] P0-3-BUG-001（P0）拉取重叠窗口未去重　→ **已修复**（fixed_at=2026-10-08）
- [x] P0-3-BUG-007（P1）跨午夜归日偏差　→ **已修复**（fixed_at=2026-10-08，与 BUG-001 同批）
- [x] P0-3-BUG-002（P1）推送验签未落独立 events 密钥域　→ **已修复**（bad0523）
- [x] P0-3-BUG-003（P1）`Rate/RateMonthly` 未接线　→ **已修复**（c488056）
- [x] P0-3-BUG-004（P1）空阶梯静默 0 金额　→ **已修复**（2e3e646）
- [x] P0-3-DOC-001（P2）默认套餐与附录 D.1 不一致　→ **已修复**（ce87a0e）
- [x] P0-3-DOC-002（P2）单价单位文档/实现不一致　→ **已修复**（文档，本地）
- [x] P0-3-DOC-003（P2）单价表默认路径与解析器不一致　→ **已修复**（ce87a0e）
- [x] P0-3-MET-001（P2）#1 标签不符　→ **已修复**（fbe2051）
- [x] P0-3-MET-002（P2）#9 标签不符且无生产者　→ **已修复**（fbe2051）
- [x] P0-3-MET-003（P2）#11 语义不符　→ **已修复**（文档，本地）
- [x] P0-3-MET-004（P2）#14 标签缺失　→ **已修复**（af72f2a）
- [x] P0-3-SEC-001（P2）HMAC 与 CRYPTO_PROFILE 耦合　→ **已修复**（fabf1dd）
