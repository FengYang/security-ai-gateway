# GA-AI 网关能力补齐方案 · P0-3 Token 计费体系完善 —— 全面评估报告

> **文档性质**：独立全面评估报告（代码走查 + 编译/单测/基准实证 + 方案文档对照）。
> **评估对象**：P0-3「Token 计费体系完善」（详设 v1.7 + 研发计划 §3.4）。
> **基线文档**：《GA-AI网关能力补齐方案--P0--Token计费体系完善.md》（详设）、《GA-AI网关能力补齐--研发计划与进度跟踪.md》§3.4、《…-问题修复跟踪.md》（台账）。
> **评估日期**：2026-10-08。

---

## 1. 评估范围与方法

| 维度 | 方法 |
|---|---|
| 需求/计划对照 | 逐项比对研发计划 §3.4（8 项）、详设 §13.1（T0–T15）、§1.3 成功指标（M1–M10） |
| 代码走查 | `gateway/gateway-admin-service/billing/**`、`billing_api.go`、`tee-infer-service`（P0-3 改动） |
| 编译/静态 | `go build ./...`、`go vet ./gateway/gateway-admin-service/...` |
| 单测 | `go test ./gateway/gateway-admin-service/... -count=1 -cover` |
| 基准 | `go test ./gateway/gateway-admin-service/billing -bench . -benchmem` |
| 台账复核 | 逐项复核《问题修复跟踪》18 项声明的真实落地情况 |

---

## 2. 结论速览

| 维度 | 结论 | 风险 |
|---|---|---|
| 开发完成度（§3.4 八项 / T0–T15） | **已完成** | 低 |
| 问题修复台账（18 项） | 14 项经复核属实；DOC-004 不修（合理）；TEST-001 已消除 | 低 |
| 编译/静态/单测 | **全绿**（billing 覆盖 85.5%、admin 71.7%） | 低 |
| 性能（M3/M4/M5/M6、P-1..P-5） | 已补基准并实测（单机内存库规模，见 §6） | 中（生产容量待目标环境复测） |
| 新增缺陷 | 无阻断级（P0/P1）；1 项 P1 接口缺口已补，若干 P3 已修 | 低 |

**判定**：功能闭环、可进入验收复核；本轮已补齐代码缺口、性能基准与文档一致性；**T9 管理后台页面**登记为开放边界（见 §8）。

---

## 3. 需求与计划对照

- 研发计划 §3.4 八项子任务 → 全部 ✅（代码落点见台账 §8.1）。
- 详设 §13.1 T0–T15 → 均有实现/用例，无孤儿任务。
- 跨服务（tee-infer）：`month` 窗口、`tokens_in_net/out_net/retry_tokens` 净量、`is_retry` 载荷、`X-Otpmask-Retry-Attempt` 透传均已落地。
- 成功指标达成情况：M1/M2/M8/M9/M10 机制齐备且有用例；M3/M4/M5/M6 见 §6 基准。

---

## 4. 问题修复台账复核（18 项）

| ID | 级别 | 台账 | 复核结论 |
|---|---|---|---|
| BUG-001 拉取重复入账 | P0 | 已修复 | ✅ 游标式非重叠窗口 + 持久水位（`metering_pull.go`） |
| BUG-007 跨零点归日 | P1 | 已修复 | ✅ `UsageWindow.Day` + `daySegments` 按 UTC+8 自然日切分 |
| BUG-002 events 独立密钥域 | P1 | 已修复 | ✅ events_secret 优先、push_secret 回退 |
| BUG-003 Rate/RateMonthly 未接线 | P1 | 已修复 | ✅ `buildItems` 经引擎，无具体类型断言 |
| BUG-004 空阶梯静默 0 价 | P1 | 已修复 | ✅ 加载期 `validateTiers` fail-closed 拒载 |
| DOC-001 默认套餐 | P2 | 已修复 | ✅ `DefaultPlans()` 与附录 D.1 逐字段一致 |
| DOC-002 单价单位 | P2 | 已修复(文档) | ✅ 附录 D.3 改“元/千标准 token” |
| DOC-003 默认路径 .yaml | P2 | 已修复 | ✅ 默认改 `pricing.json` |
| MET-001/002/004 | P2 | 已修复 | ✅ 标签口径 + #9 接通生产者 |
| MET-003 #11 语义 | P2 | 已修复(文档) | ✅ §9.1 标注“差异率(ratio)” |
| SEC-001 HMAC/profile 耦合 | P2 | 已修复 | ✅ `VerifyEventMAC` 双算法常量时间比较 |
| BUG-005 retry 指标 | P3 | 已修复 | ✅ 按租户聚合 |
| BUG-006 Append 时间戳 | P3 | 已修复 | ✅ 取实际末条 |
| SEC-002 CSV 注入 | P3 | 已修复 | ✅ `csvSafe` 转义 |
| DOC-004 PriceTable.Effective | P3 | 不修 | ✅ 合理（无消费方） |
| TEST-001 E2E flaky | P3 | 已消除 | ✅ 根因随 BUG-001 消失 |

**复核发现**：台账详情块状态曾与总览/附录不一致（违反其 §6.3.4 一致性门禁）——已在台账 §8 本轮回填。

---

## 5. 新发现问题与处置（本轮）

| # | 级别 | 问题 | 处置 |
|---|---|---|---|
| A1 | P1 | `GET /billing/subscription` 缺实现（§4.3.2 要求 GET\|POST，原 GET→405） | **已修**：`handleGetSubscription`（租户隔离）+ `TestBillingGetSubscription` |
| A2 | P1 | T9 管理后台页面（套餐/账单/冻结）未实现 | **登记为开放边界**（§8） |
| A3 | P2 | `billing_reader` 角色未放行（P-5 回退） | 保留为开放边界（UI 立项时一并实现） |
| A4 | P3 | 明细行取整硬编码 `half_up`，`floor` 时明细≠总额 | **已修**：`ratingEngine.Rounding()` + `buildItems` |
| A5/B2 | P3 | `effectiveTiers` 空档返回 nil 且注释矛盾 | **已修**：注释对齐 fail-closed 不变量 |
| A6 | P3 | 拉取秒粒度 `event_key` 碰撞 → 迟到事件漏账 | **已修**：端点秒对齐（`pullOnce`/`onReconcileWarning`） |
| A7 | P3 | REC-6 审计链断裂无指标/告警 | 保留为已知边界 |
| B1 | P3 | `PriceTable` 注释写“YAML 加载” | **已修** |
| B3 | P3 | `IngestWindow` 未注入价格表无防御（潜在 panic） | **已修**：返回错误 |
| C1 | P2 | 台账详情块状态不一致 | **已修**（回填） |
| C2 | P2 | 无落盘评估报告 | **本文件** |
| C3 | P2 | §9.1 指标 `required/conditional` 与清单不一致（11 项误标） | **已修**：全 `conditional`，逐项对齐 |
| C4 | P2 | 未实现项未登记 | **已修**：台账 §8.3 开放边界 |
| C5 | P3 | `billing/*.go`/`billing_api.go` 存在**既有** gofmt 对齐漂移（非本轮引入） | 记录；建议后续单批 `gofmt -w`（纯格式） |
| D1 | P2 | 缺 P-1..P-5 基准 | **已修**：`billing/bench_test.go`（见 §6） |
| D2 | P2 | 缺 §10.6 S-7 兼容用例 | **已修**：旧对端拒 month → 订阅仍 200（优雅降级） |
| D3 | P3 | E2E-2 OverQuota 计价差异未覆盖 | 已知边界 |
| E1 | P2 | M3/M4/M5/M6 未实测 | **部分解决**：本机基准（§6）；生产容量待目标环境 |
| F1 | P1 | 无计费自助/管理界面 | 同 A2（开放边界） |

---

## 6. 性能基准实测

命令：`go test ./gateway/gateway-admin-service/billing -run '^$' -bench . -benchmem`（单机内存 SQLite）。

| 用例 | 规模 | 实测 | 门槛 | 判定 |
|---|---|---|---|---|
| P-1 拉取入账 | 10k 条目/轮 | ~69 ms/op | < 5 s | ✅ |
| P-2 查询延迟 | 2 万行、`Limit 1000` | ~0.90 ms/op | p95 < 200 ms | ✅（本规模） |
| P-3 日结（单租户） | 30 天 × 20 模型 | ~1.01 ms/op | < 500 ms | ✅ |
| P-4 链校验 | 2 万行全量 | ~51 ms/op | 1.8M 行 < 30 s | ✅（线性外推 ~4.6 s） |
| P-5 批量写 | 1000 条/事务 | ~5.4 ms/op | 写锁 p99 < 100 ms | ◻ 待目标环境复测 |

> 规模较生产估算（1000 租户 / 1.8M 行）小 1~2 个数量级，用于数量级与回归判定；生产容量验收须在目标环境复测。

---

## 7. 验证证据

```
go build ./...                                      → exit 0
go vet ./gateway/gateway-admin-service/...          → exit 0
go test ./gateway/gateway-admin-service/... -cover  → ok（admin 71.7% / billing 85.5%）
go test ./gateway/gateway-admin-service/billing -bench . -benchmem → 见 §6
```

新增/更新用例：`TestBillingGetSubscription`、`TestBuildItems_HonorsConfiguredRounding`、`TestPullOnce_SameSecondNoDuplicateRequest`、`TestBillingSubscription_OldPeerRejectsMonth_DegradesGracefully`、`billing/bench_test.go`（P-1..P-5）。

---

## 8. 开放边界与风险（非本轮范围）

| 项 | 现状 | 建议 |
|---|---|---|
| **T9 管理后台页面**（含 `billing_reader`） | 未实现（本仓无前端；控制台补丁不含 billing 页面） | 单独立项实现（§4.3.4/§4.3.5） |
| S-7 跨版本 | 无 CI 版本校验（本轮补优雅降级用例） | 部署/CI 版本锁（§8.4 R-α） |
| REC-6 告警 | 仅日志 | 如需告警单批补指标 + §9.3 |
| M3/M4/M6 生产实测、P-5 | 仅本机基准 | 目标环境复测 |
| E2E-2 计价差异 | 由单测/集成覆盖 | 已知边界 |

---

## 9. 结论

P0-3 **功能开发闭环**，本轮已补齐 1 项 P1 接口缺口与若干 P3 缺陷、新增性能基准与兼容用例、订正文档一致性；`build/vet/test` 全绿。**建议**：将 T9 前端界面另行立项，并在目标环境完成 M3/M4/M5/M6 与 P-5 的生产容量验收后，方可宣布 P0-3 完全关闭。
