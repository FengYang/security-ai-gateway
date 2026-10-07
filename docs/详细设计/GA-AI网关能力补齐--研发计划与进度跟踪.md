# GA-AI 网关能力补齐 · 研发计划与进度跟踪

> **文档性质**：执行层总控文档（研发主计划 + 进度看板）
> **所属域**：网关功能面（AI 网关能力补齐）
> **版本**：v1.15 · 2026-10-06
> **基准依据**：《GA-AI 网关能力补齐方案》v5.5
> **更新频率**：每周一更新（周报同步）
> **文档说明**：
> - 本文件是能力补齐项目的**唯一进度跟踪源**
> - 每项功能对应一份详细设计文档，放在 `详细设计/P{阶段}/` 子目录下
> - 详细设计文档统一命名：`GA-AI网关能力补齐方案--P{X}--{功能名}.md`
> - 状态变更必须同步更新本文档 + 对应详细设计文档

---

## 目录

1. [项目总览](#1-项目总览)
2. [功能全景清单（19 项）](#2-功能全景清单19-项)
3. [P0 详细进度（0-3 个月）](#3-p0-详细进度0-3-个月)
4. [P1 详细进度（3-6 个月）](#4-p1-详细进度3-6-个月)
5. [P2 概览（6-12 个月+）](#5-p2-概览6-12-个月)
6. [里程碑与关键路径](#6-里程碑与关键路径)
7. [团队与分工](#7-团队与分工)
8. [进度管理机制](#8-进度管理机制)
9. [风险与问题跟踪](#9-风险与问题跟踪)
10. [详细设计文档索引](#10-详细设计文档索引)

---

## 1. 项目总览

| 项 | 内容 |
|---|---|
| **项目名称** | GA-AI 网关能力补齐 |
| **目标** | 补齐商品化能力（路由/缓存/计费）+ 强化差异化壁垒（国密/合规/密态） |
| **总周期** | 约 9 个月（P0 3 月 + P1 3 月 + P2 3 月+） |
| **功能总数** | 19 项（P0 5 项 + P1 8 项 + P2 6 项） |
| **总工作量** | 约 45 人月（中值） |
| **当前阶段** | P0 W5：P0-1 路由模块全链路完成；P0-2 语义缓存 P0 规划内功能基本落地（E1–E4B 完成、G1 基准+报告、G3 灰度脚本、**HNSW 向量索引 `16d9fba`**），余 #15 saved_cost（待外部价格表）与待外部环境验收项，见 §3.3 与《语义缓存-研发交接说明》§7.5 |
| **当前迭代** | Iteration 2：路由失败率感知 + 缓存二期启动（W3-W4 路由侧已完成） |

**阶段定义**：

| 阶段 | 时间 | 目标 | 完成标志 |
|---|---|---|---|
| **P0** | 第 1-3 月 | 准入 + 商业能力补齐 | 路由可用 + 缓存降本 + 计费可收费 + 国密双 profile 可用 |
| **P1** | 第 4-6 月 | 企业级 + 合规资质 | 全链路 tracing + 自助门户 + 等保初测 + 国密 S3 |
| **P2** | 第 7-12 月+ | 护城河 + 规模化 | 密评通过 + MCP 网关 + HSM + 多集群 |

---

## 2. 功能全景清单（19 项）

> 状态定义：
> - 🔲 未启动
> - 📝 详细设计中
> - 🔨 开发中
> - 🧪 测试中
> - ✅ 已完成
> - ⏸️ 暂停/降优先级
> - ❌ 取消
> - ⚠️ 偏差裁定（已评审并按裁定处置，本体文档记录偏差）

### 2.1 P0 级（0-3 个月，5 项）

| # | 功能模块 | 工作量 | 优先级 | 状态 | 负责人 | 详细设计文档 | 备注 |
|---|---|---|---|---|---|---|---|
| P0-1 | 多模型智能路由 | **6.5-8.5 周（增量）** | P0 | ✅ W5 测试完成 + 部署运维文档交付（开发/测试/文档全链路完成，待整体上线验收） | 待分配 | [P0--多模型智能路由.md](./P0/GA-AI网关能力补齐方案--P0--多模型智能路由.md) | Wasm 自研（非 ai-proxy 扩展）；主备+权重+EWMA失败率+熔断+重试预算+三级降级+主动健康检查；2 FTE 并行；W3 收口与 3 项偏差见 §3.2「W3 收口说明」；W4 全部完成（灰度/API/凭证/可观测/计费接口）；W5 测试全通过 + 部署运维文档交付 |
| P0-2 | 语义缓存（分两期） | 5-7 周 | P0 | 🔶 主体实现完成（详设 **v1.11**；E1–E4B 功能 + G1 基准报告 + G3 灰度脚本 + **HNSW 向量索引 `16d9fba`** 均已落地；余 #15 saved_cost 与真机/真机 sidecar/真实 Redis 验收） | 待分配 | [P0--语义缓存.md](./P0/GA-AI网关能力补齐方案--P0--语义缓存.md) | 一期精确缓存 + 二期语义缓存；详设 v1.5 覆盖 §3.3 全部 11 项子任务、逐项 L3（含流式分段缓存/维度化 TTL/可缓存性判定/请求合并/灰度控制器）；**第 3 轮补"机制接线"**（§7.2 读时快审唯一实现 + 语义命中经 finishHit、§7.3 抖动全路径同分布采样）；**第 4 轮补"注入侧接线 + 指标契约"**（抖动三段闭合、`lookups_total{kind,result}` 契约重定义）；**第 5 轮（空白视角重审）修 3 P0**（**S-1/D-6** 形态 B 区分 B-共享/B-退化、**A-1/D-7** 负向命中回放接线、**A-2/D-3** single-flight 失败收敛 N+1→N）+ 补 §5.3.1 RedisBackend 接口/命令级伪代码（T4 由 L2+ 升 L3）+ 流式写入分片采集 + 指纹预筛限 strict 场景 + 附录 J 记 20 项订正/8 项拒绝；主方案 §4.2 已同步回写（v5.5）；**实现进展（2026-10-07，本体 v1.11）**：E1 写入限流 / E2 预热 / E3 灰度 / E4+E4-B 管理 API（10/10）完成、G1 基准+报告落盘、G3 灰度脚本、**HNSW 向量索引（默认后端 hnsw）`16d9fba`**；余项与外部依赖见 §3.3 与本目录《语义缓存-研发交接说明》§7.5 |
| P0-3 | Token 计费体系完善 | 6-8 周 | P0 | 📝 详细设计 v1.4（已过 4 轮评审、第 4 轮修复全部落地，达 L3，**待用户编码指令**） | 待分配 | [P0--Token计费体系完善.md](./P0/GA-AI网关能力补齐方案--P0--Token计费体系完善.md) | 套餐+账单+用量API；详设 v1.4 覆盖 §3.4 全部任务、逐项 L3（见 §3.4 任务分解）；**第 3 轮**分离对账门禁/冻结判据 + retry 双路归因；**第 4 轮**阶梯入/出分轴（保可加性）+ pull 净量口径 + 生产者表回填 + A-28 口径传播 |
| P0-4 | 国密 S2 核心路径下沉 | 7-9 周 | P0 | 🟡 编码收口（详设 v1.20 迭代；库层 + cryptop sidecar 13 端点 + 插件零密码（B1，`wasm-guard` 三门禁全绿）+ 服务侧信封/审计/全量接线（B2-B4）+ 双读兼容 + profile 切换工具（B5）+ 密钥分级/国密 TLS/基准/切换演练/集成回归（B6#9-10/12-14）全部完成；**唯一留场项 = E2E-05 真实部署环境端到端**，其余全绿；进展见 §3.5） | 待分配 | [P0--国密S2核心路径下沉.md](./P0/GA-AI网关能力补齐方案--P0--国密S2核心路径下沉.md) | Wasm密码运算下沉+双读兼容 |
| P0-5 | TEE 威胁模型初稿 | 1-2 周 | P0（轻量并行） | ✅ 三份交付物已成稿；**威胁模型 v0.7 + 安全白皮书大纲 v1.1 + 侧信道风险披露说明 v1.1 均已过第 1 轮多角色评审 + 第 2 轮元评审（A-）** | 待分配 | [P0--TEE威胁模型.md](./P0/GA-AI网关能力补齐方案--P0--TEE威胁模型.md)｜[白皮书大纲](./P0/GA-AI网关能力补齐方案--P0--安全白皮书大纲.md)｜[侧信道披露](./P0/GA-AI网关能力补齐方案--P0--侧信道风险披露说明.md) | 三份独立交付物（威胁模型本体 **v0.7** + 白皮书大纲 **v1.1** + 侧信道披露），均达发布级；完整白皮书 P1 M5；威胁模型含 **STRIDE 39 条 + 供应链 6 条 = 45 条** + LLM 特有 5 条（单列）/4 攻击树/12 GAP（**GAP-01/05 已闭环**）；见 §3.6 |

> **P0 总工作量**：约 24-33 人周 ≈ 6-8 人月（含并行）

### 2.2 P1 级（3-6 个月，8 项）

| # | 功能模块 | 工作量 | 优先级 | 状态 | 负责人 | 详细设计文档 | 备注 |
|---|---|---|---|---|---|---|---|
| P1-1 | MCP 协议网关 | 6-8 周 | P2 | 🔲 | 待分配 | [P1--MCP协议网关.md](./P1/GA-AI网关能力补齐方案--P1--MCP协议网关.md) | 已从 P1 降为 P2 |
| P1-2 | 全链路 tracing + 排障面板 | 9-11 周 | P1 | 🔲 | 待分配 | [P1--全链路tracing.md](./P1/GA-AI网关能力补齐方案--P1--全链路tracing.md) | 含自助排障面板 |
| P1-3 | 等保合规资质路径 | 8-12 周 | P1 | 🔲 | 待分配 | [P1--等保合规资质路径.md](./P1/GA-AI网关能力补齐方案--P1--等保合规资质路径.md) | 等保三级+渗透测试+白皮书 |
| P1-4 | 多租户自助门户 | 8-10 周 | P1 | 🔲 | 待分配 | [P1--多租户自助门户.md](./P1/GA-AI网关能力补齐方案--P1--多租户自助门户.md) | 注册/Key管理/用量/账单 |
| P1-5 | 国密 S3+S4（认证模块 + 密评） | 15-23 周 | P1 | 🔲 | 待分配 | [P1--国密S3-S4认证模块与密评.md](./P1/GA-AI网关能力补齐方案--P1--国密S3-S4认证模块与密评.md) | 含密评 S4（M7-M9） |
| P1-6 | TTFT 严格性能择优 | 4.5-6.5 周 | P1 | 🔲 | 待分配 | [P1--TTFT严格性能择优.md](./P1/GA-AI网关能力补齐方案--P1--TTFT严格性能择优.md) | 从 P0 降级，自研策略引擎 |
| P1-7 | 全流量审计改造 | 4-5 周 | P1 | 🔲 | 待分配 | [P1--全流量审计改造.md](./P1/GA-AI网关能力补齐方案--P1--全流量审计改造.md) | 从未命中留痕抽出独立 |
| P1-8 | **安全加固（威胁模型 GAP 闭环）** | 9-13 周 | P1 | 🔲 | 待指派 | [P0--TEE威胁模型.md](./P0/GA-AI网关能力补齐方案--P0--TEE威胁模型.md) | **承接威胁模型 §10.2 的 P1 安全加固类 GAP（02/03/04/06/09/10）**；GAP-07/08 并入 P1-3、GAP-11 并入 P0-4、GAP-12 归 P2；任务分解见 **§4.1** |

> **P1 总工作量**：约 54-88.5 人周 ≈ 13-22 人月（含并行，部分跨到 M7-M9；含 P1-8 安全加固 9-13 人周）

### 2.3 P2 级（6-12 个月+，6 项）

| # | 功能模块 | 工作量（估） | 优先级 | 状态 | 负责人 | 详细设计文档 | 备注 |
|---|---|---|---|---|---|---|---|
| P2-1 | MCP 协议网关化 | 8-12 周 | P2 | 🔲 | 待分配 | [P2--MCP协议网关化.md](./P2/GA-AI网关能力补齐方案--P2--MCP协议网关化.md) | 网关级MCP统一管控 |
| P2-2 | A2A 协议支持 | 4-6 周 | P2 | 🔲 | 待分配 | [P2--A2A协议支持.md](./P2/GA-AI网关能力补齐方案--P2--A2A协议支持.md) |  |
| P2-3 | HSM 集成（金融级） | 6-8 周 | P2 | 🔲 | 待分配 | [P2--HSM集成.md](./P2/GA-AI网关能力补齐方案--P2--HSM集成.md) | 金融客户标配 |
| P2-4 | 多集群管理 | 8-10 周 | P2 | 🔲 | 待分配 | [P2--多集群管理.md](./P2/GA-AI网关能力补齐方案--P2--多集群管理.md) |  |
| P2-5 | 插件市场/开发者生态 | 8-12 周 | P2 | 🔲 | 待分配 | [P2--插件市场与开发者生态.md](./P2/GA-AI网关能力补齐方案--P2--插件市场与开发者生态.md) |  |
| P2-6 | 行业解决方案模板 | 6-8 周 | P2 | 🔲 | 待分配 | [P2--行业解决方案模板.md](./P2/GA-AI网关能力补齐方案--P2--行业解决方案模板.md) | 金融/政务/能源 |

> **P2 总工作量**：约 40-56 人周 ≈ 10-14 人月（估算，待详细设计）

---

## 3. P0 详细进度（0-3 个月）

### 3.1 迭代计划

| 迭代 | 时间 | 主题 | 主要交付 |
|---|---|---|---|
| **Iteration 0** | W0（当前周） | 启动准备 + 详细设计 | P0 启动会 + 技术选型确认 + P0-1/P0-2 详细设计 |
| **Iteration 1** | W1-W2 | 路由 MVP + 缓存一期 | 路由主备+权重可用；精确缓存 PoC；国密 S2 PoC |
| **Iteration 2** | W3-W4 | 路由失败率感知 + 缓存二期启动 | 路由三策略完整；语义缓存设计 + embedding 集成；计费启动 |
| **Iteration 3** | W5-W6 | 计费核心 + 国密下沉主路径 | 套餐+配额+计量联调；Wasm密码运算下沉完成 |
| **Iteration 4** | W7-W8 | 缓存灰度（gate通过） + 双读兼容 + 自助用量 | 精确缓存达标 + 场景重复率评估通过 → 语义缓存灰度上线；国密双读兼容通过；用量API |
| **Iteration 5** | W9-W10 | 账单系统 + 国密收尾 + 集成测试 | 账单完整可用；国密 S2 全部验收；集成测试 |
| **Iteration 6** | W11-W12 | P0 验收 + 切换演练 + P1 准备 | P0 全量验收；国密切换演练报告；P1 详细设计启动 |

### 3.2 P0-1 多模型智能路由 · 任务分解

> **v1.2 同步 v0.6 设计**：技术路线从"ai-proxy 扩展"改为 **Wasm 数据面自研 + gateway-core 控制面 + ai-proxy 协议转换** 三层协作；流式重试 8 天（最大风险）；人力 2 FTE 并行。W0-W2 前置工作已完成。

| 子任务 | 工作量 | 状态 | 负责人 | 依赖 | 起止周 | 设计深度 |
|---|---|---|---|---|---|---|
| W0：详细设计 + 多角色评审 | 3 天 | ✅ 完成 | 待分配 | — | W0 | v0.8（A-） |
| W1：路由引擎框架（rxroute/RouteTable/routecache/routeengine） | 3 天 | ✅ 完成 | 待分配 | 设计通过 | W1 | L3 |
| W2：PoC 验证（SSE 解析 + 路由接线 + 计费对齐） | 5 天 | ✅ 完成 | 待分配 | 引擎框架 | W2 | — |
| **W3-1：Wasm 流式重试核心（最大风险）** | **8 天** | ⚠️ 偏差裁定（不实现） | 待分配 | PoC 通过 | W3 | L3 |
| W3-2：非流式快速重试 + 重试预算 | 3 天 | ✅ 完成（开关默认关闭） | 待分配 | 引擎框架 | W3 | L3 |
| W3-3：EWMA 失败率 + 动态权重 | 4 天 | ✅ 完成 | 待分配 | 权重完成 | W3 | L3 |
| W3-4：熔断器（三状态 + 单探测半开 + CAS） | 4 天 | ✅ 完成 | 待分配 | 失败率完成 | W3 | L3 |
| W3-5：主动健康检查（onTick + mixed 模式） | 3 天 | ✅ 完成（**改由 Envoy 承担**：`deploy/k8s/envoy-gateway.yaml` + `deploy/helm/otpmask` 均配置 `health_checks` + `/healthz/live`；插件侧 `routeengine/healthcheck.go` 保留纯逻辑库 + 单测，不接线调度——设计裁决 A 与部署配置一致） | 待分配 | 熔断器完成 | W3 | L3 |
| W3-6：熔断-重试耦合 + 三级降级 | 3 天 | ✅ 完成 | 待分配 | 熔断+重试完成 | W3 | L3 |
| W4-1：灰度切流 + 自动回滚 + 租户白名单 | 7 天 | ✅ 完成 | 待分配 | 权重完成 | W4 | L3 |
| W4-2：控制面配置管理 API（CRUD + dry-run + 回滚） | 4 天 | ✅ 完成（**9 个端点**：CRUD + dry-run + endpoint-status + rollback + history + push + audit；**独立 API 文档**：`gateway-core/internal/api/API.md`，含数据模型/错误码/部署配置） | 待分配 | 控制面框架 | W4 | L3 |
| W4-3：端点凭证安全（secret_ref + 热更新） | 2 天 | ✅ 完成（P0 简化版：km/env scheme） | 待分配 | 引擎框架 | W4 | L3 |
| W4-4：可观测性（指标 + 日志 + tracing） | 3 天 | ✅ 完成（P0 最小可行版） | 待分配 | 主功能完成 | W3-W4 | L3 |
| W4-5：计费联动（多模型单价 + 重试不计费） | 2 天 | ✅ 完成（接口预留，等 P0-3） | 待分配 | 计费模块 Mock 可用 | W4 | L3 |
| 单元测试（>80% 覆盖率） | 4 天 | ✅ 完成（routeengine 83.5% + routecache 90.6%；**含竞态测试** `make route-race**：4 场景 -race 用例全绿**） | 待分配 | 各模块完成 | W4 | — |
| 集成测试（L1 Engine 层） | 3 天 | ✅ 完成（9 个 E2E 场景 + 13 个灰度场景） | 待分配 | 单元测试完成 | W4-W5 | L2/L3 需测试环境 |
| E2E + 混沌测试 | 3 天 | ✅ 完成（**6 个 E2E 场景**：基础路由/热更新/多租户/版本单调/签名存在/控制面健康；**可复现脚本**：`make route-e2e` + `make route-e2e-build` 编译 Linux 二进制`；混沌测试入口 `make route-chaos` + K8s 故障注入说明） | 待分配 | 集成测试完成 | W5 | — |
| 性能测试 + 优化 | 2 天 | ✅ 完成（路由决策开销：QPS -1.5%，延迟 +0.18ms，可接受；**补充 100 端点大规模基准**：100 weighted ~ 2.5μs、100 failure-aware ~ 2.6μs，零内存分配；`make route-bench-scale`） | 待分配 | 功能测试通过 | W5 | — |
| 安全测试 | 2 天 | ✅ 完成（6 项全通过：fail-closed / 降级 L2 / 超长输入 / 空模型 / 鉴权拦截 / 注入防护） | 待分配 | 功能完成 | W5 | — |
| **P1-2 处方头防重放（JTI 一次性消费）** | 2.2 天 | ✅ 完成（`rxroute/ReplayGuard`：LRU+过期双淘汰，默认 10K 容量 × 30s 窗口；数据面验签后消费，重放降级 L2；17 个单测覆盖；默认关闭=与 P0 行为一致，`replay_guard_enabled=true` 开启） | 待分配 | P0-1 路由模块 | P1 | — |
| **P1-6 路由表内存上限（防 DoS）** | 1.5 天 | ✅ 完成（`routecache/EstimatedSize` 保守估算 + `Cache.Update` 超限拒绝 fail-closed + 旧表保留；默认 1MB，可配置；15 个单测覆盖；超限回调+日志+可观测） | 待分配 | P0-1 路由模块 | P1 | — |
| **P2-1 流式重试（Envoy 层 V3 方案）** | 2.5 天 | ✅ 完成（Envoy retry_policy + outlier_detection + retry_budget；插件侧开关 + 重试归因头注入；默认关闭=与 P0 行为一致；4 个单测覆盖；三套部署：裸 Envoy + Helm + Higress） | 待分配 | P0-1 路由模块 | P2 | — |
| 部署运维文档 + 上线验收 | 2 天 | ✅ 完成（路由模块运维手册写入 GA-部署指南.md §10；验收清单为 §10.6，整体上线时统一执行） | 待分配 | 测试通过 | W6 | — |

> **人力假设**：2 FTE 并行（1 人负责 Wasm/Go 数据面核心，1 人负责控制面 API/测试/可观测）。总工作量约 70 人日 ≈ 35 人工作日 ≈ 7 周。
> **关键路径**：路由引擎框架 → 主备 → 失败率感知 → 熔断器 → **流式重试（8天，最大风险）** → 降级 → 可观测 → 测试 → 验收

### 3.3 P0-2 语义缓存 · 任务分解

| 子任务 | 工作量 | 状态 | 负责人 | 依赖 | 起止周 | 对应设计章节 | 设计深度 |
|---|---|---|---|---|---|---|---|
| 详细设计文档输出 | 3 天 | ✅（**v1.11** 全文 L3 覆盖；第 5 轮评审已修复） | 待分配 | — | W0 | 全文 | **L3** |
| 一期：精确缓存核心逻辑 | 4 天 | ✅（主链原生接线 `1a94c90`） | 待分配 | 详细设计 | W1-W2 | §4.1/§4.3-4.5/§5.1-5.3/§5.6-5.7/§6.0-6.3/§6.8/§6.10-6.13 | L3 |
| 一期：缓存命中率监控 + 负向缓存 | 3 天 | ✅（负向拒答 `0fca210` / 写入 `11bc861`；#38） | 待分配 | 核心逻辑 | W2 | §6.4/§9.1-9.5 | L3 |
| 二期：embedding 集成方案选型 | 2 天 | ✅（选型 + sidecar 契约实现 `9370029`；**真机 sidecar 待外部依赖**） | 待分配 | 详细设计 | W1 | §3.4/附录 D | L3（**选型深度**） |
| 二期：Redis VSS 接入 + 向量检索 | 5 天 | ✅（形态 B/C 代码完成 `637475f`/`4de9427`/`eac659a`；**进程内 HNSW 索引落地 `16d9fba`（默认后端 hnsw）**；集成实测待真实 Redis） | 待分配 | 选型确定 + Redis 就绪 | W3-W4 | §3.3/**§5.3.1**/§5.3-5.4/§6.5/§6.9 | L3 |
| 二期：相似度阈值配置（场景化） + 误命中率监控 | 3 天 | ✅（#7/#33/#34 已发射） | 待分配 | 向量检索完成 | W4 | §4.2/§6.5/§6.6 | L3 |
| 缓存安全：写前审查 + 读时快审 + 侧信道抖动 | 4 天 | ✅（写前/快审/抖动 ✅；**§7.4.2 写入限流已落地 `0136ab0`/`e453fec`，规则 26 + #6**） | 待分配 | 核心逻辑 | W3-W4 | §7.1-7.5 | L3 |
| 缓存预热机制 | 2 天 | ✅（`warmer.go` 按 §6.7 重构 `46cf1da`/`b89d207`、`#18` 已发射、规则 11；**预热端点 #6/#7 已挂 `0d14783`**） | 待分配 | 精确缓存完成 | W3 | §6.7 | L3 |
| 密态路径 embedding 方案（TEE 内） | 3 天 | 🔶（设计已就绪；**真机验证受外部依赖阻塞**） | 待分配 | TEE 架构确认 | W4-W5 | §3.4.2/§7.6/附录 D | L3 |
| 单元测试 + 集成测试 | 4 天 | 🔶（单测覆盖率 **86.4%**；I-1..I-8 基本闭环；**E2E E-1..E-4 受外部阻塞**） | 待分配 | 全部功能完成 | W5 | §10.1-10.3 | L3 |
| 灰度发布 + 性能基准测试 | 3 天 | 🔶（#36 灰度已落地 `a678a04`、灰度脚本 `8552be1`、**BM-1..8 基准+报告已落盘 `1c9396b`（本地实测 5 项 + hnsw BM-2 达标，缺项待真机）**；**runtime 热更新装配归后续**） | 待分配 | 测试通过 | W6 | §8.3/§12 | L3 |

> 注：① Redis VSS 依赖 Redis 8.0+ 或 Redis Stack，需提前确认基础设施版本。② 本表新增"对应设计章节"与"设计深度"两列，对齐《...多模型智能路由》附录 F.3 任务-设计双向追溯要求；详细设计 **v1.5** 覆盖上表全部 11 项子任务，逐项达 L3（自检见详设附录 A；其中 T3 为"选型深度 L3"）。③ **v1.1** 相对 v1.0 新增 §5.7（TTL 维度）、§6.0（可缓存性判定）、§6.12（流式分段缓存）、§6.13（请求合并）、§6.8.3（多副本失效传播）、§9.5（tracing），依据《语义缓存-多角色评审报告-第1轮》§3.2 修复清单。④ **v1.2** 相对 v1.1 订正 `tenant_policy` 语义为两值域（`off`/`exact_only`）、判定时机移至场景分类之后、§12 灰度补全接口/伪代码/边界/测试四件套（§12.4-12.6）、§4.2 补内存水位与 `gray.write_only`、§9.1 补 12 指标，依据《语义缓存-多角色评审报告-第2轮》§3.2 修复清单。⑤ **v1.3** 相对 v1.2 以**调用图审计**补齐"机制接线"（**不新增功能点/范围**）：§6.5.1 语义命中改经 `finishHit`（读时快审 §7.2 + 抖动 §7.3），`readFastCheck()` 成为唯一实现；删除死代码 `engine.sampleJitter()`，抖动统一入口 `JitterInjector.Sample(ctx)` 且 **miss 路径同分布采样**（J-1）；`FastScanner.Scan` 补 `error` 落地 B-7.2-2 fail-closed；§7.1.2 访问器/字段名订正，依据《语义缓存-多角色评审报告-第3轮》§3.2 修复清单。⑥ **v1.4** 相对 v1.3 修复**抖动注入侧未接线**（**N4-P0-1**，采样→注入→观测三段链路闭合：`waitUntil` = 指标 #11 唯一生产点、`Replay` 携 `releaseAt`、miss 路径显式调用）+ **指标 #1 契约重定义**（**N4-P1-1**：`lookups_total{kind,result}` 最深到达层恰发一条、§6.5.1 五个 miss 返回点全发射使 M2 分母完备、M1/M2 公式改分母完备口径）+ `jitterInjector` 并发锁（**N4-P1-3**，补 `-race` 用例）+ **发射 API 唯一化**（**N4-P1-4**，`stats.observe/observeDuration` 为唯一通道、`metrics.*` 降为 typed 封装）+ 12 项 P2 一致性订正（附录 I）；仍**不新增功能点/范围**，详设 v1.4 覆盖全部 11 项子任务、逐项达 L3。依据《语义缓存-多角色评审报告-第4轮》§3.2 修复清单。⑦ **v1.5** 为**第 5 轮空白视角独立重审**修复（3 P0 + 6 P1 + 8 P2/P3，详见详设附录 J）：**S-1/D-6** 形态 B 澄清"共享"定义（区分 **B-共享**/密钥同源 vs **B-退化**/仅失效通道，默认按 B-退化 部署验收）；**A-1/D-7** 负向命中回放接线（`LookupResult.IsNegative()` + `Replay` 仅收正向 + §7.3.1 分流拒答）；**A-2/D-3** single-flight 失败收敛（leader 失败即刻广播、等待者上游调用 N+1→N）；新增 **§5.3.1 RedisBackend 接口与命令级实现**（使 T4 由 L2+ 升 L3）；**A-5/D-1** 流式写入分片采集 `segmentsFor`；**S-4** 指纹预筛限 strict 场景；加 **U-13**（场景分类准确率基线）；**T3** 澄清为"选型深度 L3"；另 **8 项拒绝**（T9/S-2/S-3/O-4/C-1/C-2/P-2/P-4，理由见详设附录 J 末段）。仍**不新增功能点/范围、不变更工时**。依据《语义缓存-多角色评审报告-第5轮》§三。⑧ **2026-10-07 状态列同步**：本节 P0-2 状态列此前与仓库事实不一致（§1/§2.1 称"详设待编码"，本表 T1–T6 标 ✅、T7–T10 标 🔲），现依**代码事实**（基线 `4ab5784`，`cacheengine` 覆盖率 86.1%，§9.1 指标 35/39）回填：T1–T6 ✅、T7–T10 🔶（部分完成，余项与收敛计划见《语义缓存-研发交接说明》§7.5）。**口径以仓库为准**。⑨ **2026-10-07 HNSW 批次二次同步**：基线 `16d9fba`（含 HNSW 向量索引），`cacheengine` 覆盖率 **86.4%**，§9.1 指标 **38/39**（余 #15）。本次更新：详细设计 **v1.11**、T4 增「进程内 HNSW（默认后端 hnsw）」、**§7.4.2 写入限流（#6）与 §6.7 预热（#18 + 端点）由 🔶 升 ✅**、单测覆盖 86.4%、灰度+基准由 🔶 更新为「#36/灰度脚本/基准报告均已落盘，**runtime 热更新装配归后续**」；余项（E2E 真机、真机 sidecar、真实 Redis、#15 价格表、runtime 热更）与外部依赖见《语义缓存-研发交接说明》§7.5。

### 3.4 P0-3 Token 计费体系完善 · 任务分解

| 子任务 | 工作量 | 状态 | 负责人 | 依赖 | 起止周 | 对应设计章节 | 设计深度 |
|---|---|---|---|---|---|---|---|
| 详细设计文档输出 | 3 天 | ✅（**v1.4**，2026-10-01 全文重写 ∪ 第 1/2/3/4 轮修复；**第 4 轮评审 A-26..A-31/O-8/D-12 已全部修复**） | 待分配 | — | W1 | 全文 | **L3** |
| 套餐系统：4 档套餐定义 + 超期/超额策略 | 5 天 | ✅（2026-10-02，T1+T2：`billing/plan.go`/`plan_store.go`/`quota.go`；4 档默认套餐幂等初始化、订阅排程/过期判定、配额编译含 month 窗口、HTTP 下发；`plan_test.go` 18 用例） | 待分配 | 详细设计 | W3-W4 | §4.1.2/§5.2/§6.4.2/§6.4.4/附录 D | L3 |
| 账单系统：日结/月结 + 账单明细 + 导出 | 5 天 | ✅（2026-10-02，T5：`billing/billing.go`/`bill.go`/`bill_store.go`/`export.go`/`reconcile.go`/`ledger_fold.go`；幂等日结/月结、L2 零容差门禁、超额单列、CSV 导出；`billing_test.go` 9 用例） | 待分配 | 套餐完成 | W4-W5 | §4.1.6/§5.3/§6.6-6.8 | L3 |
| 用量 API：租户级用量查询 + 余额告警 | 3 天 | ✅（2026-10-02，T6/T8：`billing_api.go` 账本/账单/套餐/冻结端点 + RBAC；`anomaly.go` 配额预警 ScanQuotaWarn；`billing_api.go`/`anomaly_test.go` 覆盖） | 待分配 | 套餐完成 | W4 | §4.3/§6.11 | L3 |
| 多模型计费：系数换算 + 阶梯定价 | 3 天 | ✅（2026-10-02，T3/T4：`billing/pricing.go`/`rating.go`/`metering*.go`；标准 token 唯一换算（A-9）、入/出分轴累进阶梯（A-26）、唯一取整（R-16）、超额套餐级基数+瀑布归属（A-44）；`rating_test.go` 12 用例） | 待分配 | 路由计费联动可用 | W4 | §4.1.4/§4.2/§5.4/§6.5/附录 D | L3 |
| 计费数据完整性：哈希链 + 签名 + 审计联动 | 3 天 | ✅（2026-10-02，T3a/T7：`billing/ledger.go`/`ledger_store.go`/`signature.go`；SHA-256 长度前缀链（std_in/std_out/price_ver 入链 A-40）、append-only 触发器、HMAC 签名+密钥轮换、VerifyBillingChain 关联校验；`ledger_test.go`/`signature_test.go` 14 用例） | 待分配 | 账单完成 | W5 | §7.1-7.6 | L3 |
| 账单异常检测 + 冻结机制 | 2 天 | ✅（2026-10-02，T8：`billing/anomaly.go`/`freeze.go`/`freeze_controller.go`/`scheduler.go`；spike 四级判据（A-25/A-36）、冻结状态机、S-1..S-10 调度器（单飞 guard）；`anomaly_test.go` 覆盖） | 待分配 | 账单完成 | W5-W6 | §4.1.7/§6.9-6.10 | L3 |
| 对账回归测试 + 零容差校验 | 3 天 | ✅（2026-10-02，T11-T13：`billing/integration_test.go` INT-1..7 + `reconcile_test.go` REC-1..7；零容差 diff=0、0.05% 不冻结 / 5% 冻结、阈值边界、retry 计入、链断裂检出；覆盖率 **81.8%** ≥80%） | 待分配 | 全部完成 | W6 | §10.4/§6.12 | L3 |

> 注：① 本表新增"对应设计章节"与"设计深度"两列，对齐《...多模型智能路由》附录 F.3 任务-设计双向追溯要求；详细设计 **v1.4**（2026-10-01 全文重写 + 第 1/2/3/4 轮评审修复）覆盖"研发计划 §3.4 本表 8 项 ∪ 骨架 §13 15 行 ∪ 主方案 v5.5 §4.3.3 任务"的**并集**，展开为 **T0-T15** 逐项达 L3（自检见详设**附录 A**；任务-设计双向追溯见详设 **§13.1**；关键反例回归锚见详设**附录 G**；第 1/2/3/4 轮评审问题与落点见详设**同目录《...-多角色评审报告-第{1,2,3,4}轮.md》§5**）。**v1.4** 相对 v1.3 为**第 4 轮评审（B-）修复**：**A-26（P0）**阶梯**入/出改各占独立月累计轴**（订正 A-21 串接，恢复 `Σ日=月` 可加性，附反例 **附录 G-4** + 回归 **T-6.5-9**）；**A-27** pull 侧 `tokens_in/out` **剔除 retry（净量）** + `retry_tokens` 单列（§4.4 声明"不改语义"**限于标识字段**）；**O-8** 回填生产者表 #10/#12/#17 真实发射点；**A-28** §6.12.4/§10.2/§10.4 统一 A-22 口径；**A-29/A-30/A-31/D-12** 为 P2 一致性回填（含新增 **S-10 关联校验** + **R-34**、§6.5.5 超额**入/出分价**）。校验规则扩 **R-1..R-34**、调度任务加 **S-10**、测试加 **T-6.5-9**；**不新增功能点/范围、不变更工时**。**v1.3** 相对 v1.2 为**第 3 轮评审（B）修复**：**A-22（P0）**分离对账**出账门禁 vs 冻结判据**两判据并接通 `onReconcileWarning`（消死代码+指标 #20 得生产者）；**A-23（P0）** retry 归因**两路落地**（push `is_retry` + `aggregateUsage` 按 `IsRetry` 分组），使默认 `sync_mode=pull` 下 M9 可证；**A-21**`rateModel` 入出**串行**；**A-24** ∞ 档 `overlap` 特判 + 空档单档全量；**A-25** spike 严重级专用阈值 **R-33**；**O-7** 新增 **§9.1.1 唯一生产者对照表**；**D-11** 5 处编译性订正。校验规则 **R-1..R-33**、指标 **21 项 + 生产者表**、测试新增 **T-6.3-8**；**不新增功能点/范围、不变更工时**。② 工作量口径：本表按研发粒度沿用 3-5 天/项；详设 §13.1 按**可施工粒度**拆为 **41 人日 ≈ 8.2 人周**（主方案 §4.3 计 6-8 周，一致）。③ 详设新增（相对 v0.1 骨架）：**§2.3 依赖 P-1..P-6**、**§4.2 配置校验规则 R-1..R-34**、**§5 数据模型（账本/套餐/账单/冻结）**、**§6 流程 16 节（边界 B-x + 测试 T-x）**、**§7 完整性（哈希链/签名/双向关联/不变量 INV-1..10）**、**§9.1 指标登记表（21 项，source=admin，登记进 `scripts/metrics-required.txt`）+ §9.1.1 唯一生产者对照表**、**§10 测试分层（单测/集成/E2E/对账回归零容差/性能/安全兼容）**、**§15 待确认 U-1..U-15**、**附录 A-G**（G=第 4 轮关键反例回归锚）；v1.1 另新增 **§4.1.8 存储接口 / §4.6 符号清单 / §6.4.5 下发通道总表 / §6.15.1 启动自检 / §6.16 调度器总表 / §11.4 备份恢复**。④ 关键裁决：**两级对账**（L1 既有 TEE 内零容差 + L2 新增账务域出账门禁）、**金额域作用域精确化**（金额仅入 `/billing` 域、`/usage` 响应逐字节不变，U-1）、**重试 token 归平台成本**（★ v1.1 改为：路由经请求头 `X-Otpmask-Retry-Attempt` 下行 retry 标记 → tee-infer 解析并落审计 `IsRetry`，token **唯一来源 = tee-infer**，`BillingNotifier` token 计数退役，详设 §6.3.3；**唯一数据面改动** = 该请求头透传 + `IsRetry` 落审计）、**新增 `/billing` 域而非改 `/usage`**（U-9）、**tee-infer 新增 month 窗口**（P-2/U-2）、**日/月阶梯统一月累计**（A-6）。⑤ 详设**不新增代码/开发**，本行仅登记"详细设计输出"完成；其余 7 行待开发阶段执行。
>
> 注（**2026-10-02 开发落地**）：P0-3 **8 行子任务已全部开发完成**（T0 详设 + T1-T13 后端实现），实现落于 `gateway/gateway-admin-service/billing/`（新包，21 个 Go 文件）与 `gateway/gateway-admin-service/billing_api.go`（HTTP 接线），最小化改动既有 `main.go`/`audit.go` 及 6 个测试文件的 `buildAdminMux` 调用点。**关键约束落实**：① 默认关闭 `BILLING_ENABLED=false` → `/billing/*` 不注册、`/metrics` 追加渲染 0 字节（R-1/M10 逐字节一致）；② 金额域隔离（账本无金额列 INV-3，金额仅 `/billing` 域）；③ 单写者 `sync_mode`（A-12/R-30）；④ 零容差出账门禁（L2 diff>0 不出账）+ 冻结仅 ratio>0.1%（A-22）；⑤ std 锁定入账（A-32/A-39）+ 入/出分轴可加（A-26）+ 唯一取整（R-16）+ 超额套餐级基数（A-44）。**验证**：`go build ./...`、`go vet` 均通过；`go test ./gateway/gateway-admin-service/...` 全绿（billing 包 **81.8%** 覆盖率 ≥ 80% 目标）；`scripts/metrics-required.txt` 登记 23 项 billing 指标（conditional，关闭时不判失败）。**遗留（如实声明）**：a) 价格表按 **JSON** 加载（原文 §5.4 写 `pricing.yaml`）——为不引入 yaml 依赖，格式改为等价 JSON，字段名一致；~~b) `MonthStdBefore` 为直读账本（A-37 内存缓存为 P1 性能项，未做）~~；~~c) 多租户跨租户强隔离依赖 token 内 `tenant` 声明，当前 `claims` 不含该字段 → 按"已认证可读 + admin 可写"实现（P-5 `billing_reader` 就绪后收紧）~~；~~d) tee-infer 侧 `month` 窗口与 `X-Otpmask-Retry-Attempt` 透传为跨服务改动，本次未触碰~~。
>
> 注（**2026-10-02 第二批：跨服务接线闭环，遗留 d 已消除**）：完成 tee-infer 与数据面插件的 P0-3 侧接线，**跨服务契约端到端打通**。**改动清单（最小化）**：① **tee-infer `month` 窗口**（`main.go`）：新增 `quotaWindowMonth="month"` + `quotaWindowKeyFor` 分支（UTC+8 自然月 `2006-01`）+ `validQuotaWindow` 白名单；复用既有通用窗口计数/重置机制，**无新增状态字段**。② **`/usage` 净量双字段**（`billing.go` + `modelUsage`）：`billingIncrement`/`modelUsage` 新增 `tokens_in_net`/`tokens_out_net`/`retry_tokens`，`aggregateUsage` 按 `IsRetry` 分流（重试归平台成本，净量剔除重试），守恒 `tokens_in+tokens_out == tokens_in_net+tokens_out_net+retry_tokens`；原 `tokens_in/out` 口径不变（向后兼容）。③ **重试归因**（`audit.go` + `main.go` + wasm `routedispatch.go`）：`AuditEvent` 新增 `IsRetry`（证据字段，**不进 hash**，旧 WORM 链兼容）；`handleInfer` 解析 `X-Otpmask-Retry-Attempt` 并贯通 4 处 `infer` 审计发射点（vectors / text 成功 / text engine_error / output_block content_filter）；数据面 `dispatchState.send` 仅在**重发**（`Attempt>1`）时下行该头（纯逻辑函数 `retryAttemptHeaderValue` 可单测）。④ **billing 侧消费净量**（`metering_pull.go`）：拉取映射改用 `_net` + `retry_tokens`，并对旧版对端（无 `_net` 字段）做**兼容回退**（视为无 retry 的净量）。**验证**：`go build ./...`、`go vet`（tee-infer/admin/billing/wasm）通过；新增单测（tee-infer `net_billing_test.go`：month 窗口键与跨月重置、头解析、净量/重试守恒；billing `metering_test.go`：净量消费与旧版回退；wasm `routedispatch_test.go`：重试头取值）全绿；既有 tee-infer/admin/billing/wasm 测试无回归。**残余（如实）**：`IsRetry` 仅覆盖非流式与流式**产出侧**infer 事件；上游流式重发（§6.6）在本 SDK 不可实现（既有偏差），故流式重试归因不适用。
>
> 注（**2026-10-02 第三批：月累计缓存 A-37，遗留 b 已消除**）：实现 §6.5.1 **★A-37 月累计缓存**（性能增强，**不改任何计算结果**）。**设计**（`billing/monthstd_cache.go`）：`CachedMonthStd` 包装账本实现 `MonthStdProvider`，键 = 租户+模型+月，值 = `{stdIn, stdOut, upTo}`（`upTo` = 已累计到的自然日，含）。**三种路径**：① 命中（`upTo == period-1`）→ O(1) 返回；② **增量推进**（`upTo < period-1`）→ 只查 `SumStdRange(dayAfter(upTo), period)` 增量段并累加（**A-37 核心收益**：日结第 30 天的成本由 O(全月条目×模型数) 降为 O(增量段)）；③ 未命中/回退查询（`upTo > period-1`）→ 全量回源且**不回写**（保持游标单调，防回退污染）。**失效策略（★A-51）**：仅 `InvalidateDayIfBackfill` 在**补账**（写入 ≤ 已推进游标的某日）时删除对应月缓存；**价格表热更新不触发失效**（std 入账已锁定 A-32/A-39，历史值不变）——已删去旧版与后半句互斥的失效条件。**接线**：新增 `NewRatingEngineWithCache(rounding, ledger)`（返回引擎 + 缓存句柄）；`billing_api.go` 与测试构造器改用之；`IngestWindow` 提交后对每条入账条目调用 `InvalidateDayIfBackfill`（正常前进不失效）。**配套**：账本新增 `SumStdRange`（区间求和），`MonthStdBefore` 重构为复用之（全量语义不变）。**验证**：新增 `monthstd_cache_test.go`（8 用例）——命中/增量调用模式（计数替身断言 full/rng 次数）、月结短路、**回退不改缓存**、补账失效、前进不失效、跨月隔离、与直读一致性、端到端（`IngestWindow` 补账 → 缓存失效重算）；billing 包覆盖率 **85.4%**（原 81.8%）；`go build ./...`/`go vet` 通过；`go test ./...` 全模块通过。
>
> 注（**2026-10-02 第四批：跨租户强隔离，遗留 c 已消除**）：按 §7.4 落地 `/billing/*` **跨租户强隔离**（口径经用户确认＝**token `tenant` 声明**，方案 A）。**实现**：① `claims`（`auth.go`）新增可选 `Tenant` 字段（`json:"tenant,omitempty"`）——旧令牌缺字段保持零值，**解析向后兼容**；② `billing_api.go` 新增 `tenantAllowed(r, tenant)`：**admin 可跨租户**（运营/财务口径）；**非 admin（auditor 等）仅限令牌 `tenant` 声明租户**，声明缺失或不符一律 **403（fail-closed）**；「tenant 为空的全量列举」仅 admin 可用（禁止越权全量读取）；③ 应用点＝三个读端点：`GET /billing/bills`（列表）、`GET /billing/bills/{id}[,/verify,/export]`（按账单 `TenantID` 判定）、`GET /billing/ledger`；写端点本就要求 `admin`（天然可跨租户）。**作用域**：**仅新 `/billing/*` 域**，既有 `/usage`（M2 A-2'）**未改动**（最小化修改）。**依赖（如实声明）**：非 admin 会话要读计费，需由令牌签发方（Java 控制台）在令牌中签入 `tenant` 声明；未签入前**仅 admin 可读**（能力受限而非错误，符合 fail-closed）。**验证**：新增 `billing_api_test.go`（跨租户隔离矩阵 8 断言：admin 全量/任意租户 200、auditor 自身租户 200、跨租户 403、全量列举 403、缺声明 403、账单详情跨租户 403/admin 200、账本查询隔离；另验证计费关闭时端点 404）；`go vet` 通过；admin-service 测试覆盖率 65.9% → **69.6%**；`go test ./...` 全模块通过。

> 注（**2026-10-02 第五批：A-37 预热落地**）：补齐 §6.5.1 ★A-37 明列的**预热**项（第三批登记为未做）。**实现**：`CachedMonthStd.Warm(tenant, modelKeys, upToDay)`（以 `dayAfter(upToDay)` 为查询起点复用既有三路径并回填，使缓存游标推进到 `upToDay`，**不引入新口径**；空模型列表/非法日期 = no-op）；账本新增 `ModelKeysInMonth`（去重枚举该租户该月模型键）供枚举；`BillingService.WarmMonthStd(tenant, upToDay)` 对外暴露（供启动/缺口扫描 S-8 接线）；**调用点**＝`CloseDaily` 出账成功后自动预热到当日（best-effort，失败仅记日志并退化为下次回源），使**次日日结的 `monthStdBefore` 直接命中**。**验证**：新增 4 用例（预热后次日命中且零回源、空模型/非法日期 no-op、预热值与直读一致、`CloseDaily` 后自动推进命中）；billing 包覆盖率保持 **85.4%**；`go vet` 通过；`go test ./...` 全模块通过。**边界（如实声明）**：① 启动期预热（S-8 缺口扫描触发）的**调用点仍未接线**——调度器（`scheduler.go`）尚未在 `main.go` 启动，故当前预热由「日结后自动」覆盖日常路径，运维可显式调用 `WarmMonthStd` 预热；② 建议后续单批完成「scheduler 接线 + S-8 缺口补账」。

> 注（**2026-10-02 第六批：调度器接线 + S-8 缺口补账**）：① **S-8 缺口扫描落地**（`billing/backfill.go`）：`BillingService.BackfillGaps(ctx, today, lookbackDays)` 扫「账本有用量日（`DaysWithUsage`：净 token 或 retry > 0）」（`ledger_fold.go` 新增 `Tenants`/`DaysWithUsage`）与「已出日账（`bills.kind=daily`）」的**差集**，逐日 `CloseDaily` 补出；**幂等**（`UNIQUE(tenant,kind,period)` 兜底，可重入、重启可重跑 B-6.6-4）；**跳过当日/未来日**（仍在累积，不提前出账）与**冻结租户**（`ErrFrozen` → `Skipped`，解冻后由下轮补出 B-6.10-3）；回看窗口 `lookbackDays`；返回 `BackfillReport{Tenants,Missing,Closed,Skipped,Failed}`。**补账后自动预热月累计缓存**（`CloseDaily` 内置 A-37 预热）→ 启动冷态一次扫描即完成**预热**，前述边界①解除。② **调度器接线**：`billing.BackfillTask(svc, lookbackDays)` 生产任务；`billingHandler.sched`（`schedule.enabled=true` 时构造，默认 true）+ `StartSchedulers(ctx)`/`Close()`；`main.go` 在计费域启用后 `bih.StartSchedulers(context.Background())`，并以 `defer` 顺序保证**先停调度、后关存储**。③ **配置**：`ScheduleConfig` 新增 `Enabled`（`BILLING_SCHEDULE_ENABLED`，默认 true）与 `BackfillLookbackDays`（`BILLING_SCHEDULE_BACKFILL_LOOKBACK_DAYS`，默认 7）。④ **S-2 覆盖关系（如实声明）**：S-2「日结」由 S-8 覆盖——缺口扫描每日执行等价于「确保截至昨日已出账」，故未新增 `daily_close_at` 定时触发机制（避免与 S-8 重复出账；`UNIQUE` 亦保证二者互不冲突）。**验证**：新增 `backfill_test.go`（8 用例：补出缺日、幂等重入、跳过当日/未来、回看窗口、冻结跳过、解冻补出、空账本 no-op、任务包层重入）+ `billing_api_test.go::TestBillingSchedulerWiring`（enabled 决定构造调度器、`Close()` 幂等）；billing 覆盖率保持 **85.4%**；`go build ./...`/`go vet` 通过；`go test ./...` 全模块通过。
>
> 注（**2026-10-02 第七批：S-6 链校验 + S-10 关联校验接线**）：按 §6.16 接线两项**纯读、事后审计性质**的完整性任务，并**修正一处既有锚定缺陷**（经用户裁定「修正锚定后接线」）。**① 锚定缺陷修正（随本批发现并修复）**：`CloseDaily`/`CloseMonthly` 原以**全局链尾** `Ledger().Head().EntryHash` 作 `bills.ledger_head`，而 §7.3 `VerifyBillingChain` 经 `ReproduceHead(tenant,period,want)` **按租户+周期重放**比对 → 多租户下二者天然不等（实测 `ReproduceHead(t1)=false`），使 §7.3「账单→账本链＝强（重放可复现）」不成立、且按原样接线 S-10 会把正常账单误标 `assoc_mismatch`。修正：新增 `periodTailHash(tenant,from,to)`（`billing/verify.go`，取账本 `Range` **本租户本周期末条** `EntryHash`）作锚定值；周期内无条目返回 `""`（空账单不锚定，关联校验自动跳过）。**② S-6 链校验**：`BillingService.VerifyLedgerChain()`（§7.1.2）全量 `Ledger().Verify()`，成功即 `SetChainBroken(brokenAt>=0)`（**指标 #4 唯一生产者**）；断裂置位后 `CloseDaily` 经新增门禁（`billing.go` 步骤 1b）返回 `ErrChainBroken`（**停出账，fail-closed**）；任务构造器 `VerifyChainTask(svc)`。**③ S-10 关联校验**：`verifyAssocAfterClose(bill)`（出账后即时，`CloseDaily`/`CloseMonthly` 内）与 `VerifyAssocRecent(fromPeriod)`（巡检，`VerifyAssocTask(svc, lookbackDays)`）；失败**不阻断**——`UpdateStatus(bill,"assoc_mismatch")` + `IncAssocVerify("fail")`（指标 #22）+ 日志留证；已出账**金额不变**（仅状态机迁移，`UpdateStatus` 契约）。**④ 接线**：`billing_api.go` `SchedulerTasks` 注入 `VerifyChain`/`VerifyAssoc`（`Backfill` 保留）；巡检 lookback 复用 `schedule.backfill_lookback_days`（有界巡检）。**验证**：新增 `billing/verify_test.go`（6 用例：链完好/断裂停出账/复位恢复/多租户锚定可复现/巡检通过/巡检标 `assoc_mismatch` 且金额不变）；修复 `metrics_test.go::TestMetricsProducers` 泄漏的进程级 `chain_broken` 标志（原无消费方故无害，现影响出账门禁）；`go build ./...`、`go vet` 通过；`go test ./...` 全模块通过。
>
> 注（**2026-10-02 第八批：S-5 异常扫描接线**）：按 §6.9/§6.16 落地并接线异常扫描。**① `AnomalyDetector.Scan(tenants, day)`（§6.9.1 四类规则）**：① spike（复用既有 `ScanSpike`，A-36 样本 <3 天不判 / A-25 同维度阈值分级）；② reconcile_diff（L2 差异率 > 0，经可选 `*Reconciler`，nil 跳过）；③ quota_warn（套餐月配额剩余比 < `quota_warn_ratio`，依 `plan.MonthlyTokens` + 当月 std 累计，并回填指标 **#12** `quota_remaining_ratio`——该指标此前**无生产者**；无套餐/不限量不告警 B-6.11-3）；④ pricing_missing（当日账本出现单价表未知 modelKey，`__retry__` 聚合行豁免）。**指标 #10 `anomaly_total` 唯一生产者＝`Scan` 返回点**（逐条发射，对齐 ★ O-8）；**#10 发射已由 `ScanSpike` 上移至统一出口**（此前 ScanSpike 内发射且无生产调用点，故无回归）。**② 依赖注入**：新增 `NewAnomalyDetectorForStore(store, prices, rec, cfg, now)`（供 main 构造；内含 `*sqliteLedgerStore` 断言与 `PlanStore` 获取）；`AnomalyConfig` 缺省补齐 `ReconcileAlertRatio`(0.001)/`QuotaWarnRatio`(0.2)。**③ 调度接线**：`ScanAnomaliesTask(det)`（枚举 `Tenants()` + 扫描 UTC+8 当日）；`billing_api.go` 注入 `ScanAnomalies`（与 S-6/S-8/S-10 并列），单价表提供器 `priceProvider` 由计价与检测共用。**验证**：新增 `billing/scan_test.go`（5 用例：④ 单价缺失 critical、③ 配额预警、② L2 差异、无异常、任务可运行）；`go build ./...`/`go vet` 通过；`go test ./...` 全模块通过。**现状偏差（如实声明）**：L2 对账器（`reconciler`）在生产未接线（`BillingService`/检测器均传 nil），故**规则② 当前为空操作**，规则①③④ 生效；规则② 待 L2 接线后自动生效（无需改代码）。
>
> 注（**2026-10-02 第九批：S-7 余额告警接线**）：按 §6.11/§6.16 落地余额告警通知与调度接线。**① 通知器与去重（`billing/notify.go`）**：`Notifier` 接口（`WarnQuotaLow(tenant, rem, periodKey)`，§4.1.x）；`QuotaAlertStore.MarkIfNew` + SQLite 表 `quota_alerts(tenant_id, period_key, alerted_at, PRIMARY KEY(tenant_id,period_key))`（**持久化去重**：重启不重复告警，B-6.11-1）；`QuotaNotifier`（先 `MarkIfNew`，首次才交付；`sink` 可选＝邮件/Webhook，未配置仅本地日志——外部告警由 Prometheus 规则 `BillingQuotaLow` 依指标 #12 触发，§9.3）。**② 配额逻辑复用**：新增 `AnomalyDetector.QuotaRemaining`（纯查询，供 S-5/S-7 共用）与 `QuotaWarnThreshold`；`scanQuota` 改为「`QuotaRemaining` + 回填 #12 + `quotaWarnAnomaly`」；`quotaWarnAnomaly` 落 **B-6.11-2**（已耗尽 rem=0 → `critical`，否则 `warning`），`ScanQuotaWarn` 委托之（既有行为不变 + 耗尽升级）。**③ 调度接线**：`CheckQuotaTask(det, notifier)`（枚举租户 → 低于阈值 → `WarnQuotaLow`，periodKey=当月）；`billing_api.go` 构造 `QuotaNotifier(store.QuotaAlerts(), nil, now)` 并注入 `CheckQuota`。**④ 存储**：`Store` 接口新增 `QuotaAlerts()` 子存储访问器 + `quota_alerts` 建表。**验证**：新增 `billing/notify_test.go`（5 用例：去重存储首次/重复/换周期、通知器幂等交付、S-7 任务命中通知、无套餐不通知、耗尽 critical）；`go build ./...`/`go vet` 通过；`go test ./...` 全模块通过。
>
> 注（**2026-10-02 第十批：S-9 到期扫描接线**）：按 §6.4.2/§6.16 落地到期扫描。**① `BillingService.ScanExpiries(now)`（`billing/expiry.go`）**：枚举「当前订阅」（`PlanStore.ListSubscriptions(now)` 取每租户 `effective_at ≤ now` 的**最新一条**——**不可用 `Resolve`**，因其过滤已过期项，无法用于到期检测），对带 `expires_at` 者：剩余 ≤30/≤7/≤0 天 → 指标 **#21** `plan_expiring_total{days=30|7|0}`；**宽限（到期后 7 天）结束仍逾期** → 指标 **#10** `anomaly_total{kind="plan_expired",severity="critical"}`；**不自动降级**（§6.4.2 原则：自动过期 ≠ 自动降级）。**② 去重抽象泛化（因出现第二处用途）**：S-7 的 `QuotaAlertStore`/`quota_alerts` 泛化为通用 `AlertStore`/`alert_dedup`（`MarkIfNew(tenant,key,at)`）——S-7 key=`"YYYY-MM"`（月周期）、S-9 key=`"expiry:<到期时间>:<阈值>"`；`Store` 访问器更名 `AlertDedup()`（原 `QuotaAlerts()`），避免新建重复去重表。**③ 存储**：`PlanStore` 新增 `ListSubscriptions(now int64)`。**④ 调度接线**：`ScanExpiriesTask(svc)` 注入 `ScanExpiries`（`billing_api.go`）。**验证**：新增 `billing/expiry_test.go`（5 用例：T-30 触发 + 幂等、到期三档齐发、宽限结束逾期 + 幂等、无到期跳过、任务可运行）；S-7 测试同步更名 `AlertDedup()`；`go build ./...`/`go vet` 通过；`go test ./...` 全模块通过。
>
> 注（**2026-10-02 第十一批：S-3 月结定时接线**）：按 §6.7/§6.16 落地月结定时触发。**① 触发机制**：调度器新增 `spawnMonthly`——每 10 分钟检查 UTC+8 的「日/时刻」，命中 `monthly_close_day` 且 ≥ `monthly_close_at` 即经 `guard` 单飞执行 `CloseMonthly`；**当日重复触发安全**（`UNIQUE(tenant,kind,period)` 幂等），故无需额外"当日一次"状态。时间工具新增 `clockOfNs`（UTC+8 `"HH:MM"`）与 `dayOfMonthOfNs`（UTC+8 日）。**② 任务**：`CloseMonthlyTask(svc)` 对全部租户（账本 `Tenants()`）结算**上月**（`prevMonth(dayOfNs(now))`）；冻结租户跳过（解冻后补出）；逐租户独立、失败仅记录。**③ 配置**：`ScheduleConfig` 新增 `MonthlyCloseDay`/`MonthlyCloseAt`（自 `period` 段同步，避免重复定义）。**④ 接线**：`billing_api.go` 注入 `CloseMonthly`。**验证**：新增 `billing/monthly_test.go`（4 用例：`prevMonth`、`clockOfNs`/`dayOfMonthOfNs`、月结任务结算上月 + 幂等、调度器按月注册不 panic）；`go build ./...`/`go vet` 通过；`go test ./...` 全模块通过。**精度说明（如实声明）**：触发粒度 = 10 分钟（非精确 03:10），落点为"当月 close_day 且 ≥ close_at"，与「错峰 + 不提前」意图一致。
>
> 注（**2026-10-02 第十二批：S-1 增量拉取接线**）：按 §6.1.1/§6.16 接线增量拉取（**P0-3 运行时调度任务至此全部落地**）。**① 拉取单元 `pullOnce(ctx)`（`billing/metering_pull.go`）**：滑动窗口 `[now-lookback, now)` → `PullSource.Pull` → `IngestWindow(win, sync_mode)`；**时钟回拨保护**（`now < lastPollNs` → 记指标 #17 `clock_skew` 并跳过本轮，B-6.1-3）；拉取/入账失败 → 记指标 #5 `error` 且不推进（重叠窗口 + `event_key` 幂等，B-6.1-1/8）；入账成功路径的 #5 `ok` 由既有 `IngestWindow` 发射（避免重复计数）。**② 源注入**：`BillingService.SetMeteringSource(src, lookback, syncMode)`；`billing_api.go` 复用计量令牌构造 `NewTEEPullSource(tee_url, token, 30s)`（与配额下发器同令牌）。**③ 调度接线**：`PullTask(svc)` 注入 `SchedulerTasks.Pull`，调度器按 `ScheduleConfig.PullInterval`（自 `source.pull_interval` 同步）周期触发；文档 `RunMeteringLoop` 的 ticker 由调度器统一提供（避免双重循环）。**④ 单写者门控**：`sync_mode=push` 时拉取入账为空操作（`CanWrite` 门控，A-12/R-30）；未注入源时 no-op。**验证**：新增 `billing/pull_test.go`（6 用例：正常入账、拉取失败不写账、非写者模式不写账、时钟回拨跳过、未注入源 no-op、任务可运行）；`go build ./...`/`go vet` 通过；`go test ./...` 全模块通过。
>
> 注（**2026-10-02 第十三批：异常→冻结自动联动**）：按 §6.10.1/§6.10.2 打通「S-5 critical 异常 → 冻结」。**① 联动实现**：`AnomalyDetector.SetFreezeLinker` + `ApplyFreezes(anomalies)`——对 **severity=critical 且 kind∈{spike,reconcile_diff,pricing_missing}** 的异常调用 `Freeze(tenant, reason=kind, severity=critical, by="system")`；**已冻结者跳过**（避免每 5 分钟重复冻结/审计刷屏，并保留首次 reason，B-6.10-1）；`plan_expired` **不冻结**（§6.4.2 不自动降级）；未注入 linker 时 no-op。`FreezeLinker` 接口（`Frozen`/`Freeze`）由既有 `*FreezeController` 满足。**② 任务接线**：`ScanAnomaliesTask` 在 `Scan` 后调用 `ApplyFreezes` 并记录冻结数。**③ 冻结审计**：新增 `freezeAuditSink`（`package main`）把冻结/解冻落管理面审计链（`bill_freeze`/`bill_unfreeze`，actor=by〔自动冻结为 `"system"`〕），注入 `NewFreezeController`（此前 audit 恒为 nil，`FreezeAuditSink` 接口无实现）。**④ 冻结副作用**：既有「停出账（`ErrFrozen`）+ 不阻断入账」由 `CloseDaily/CloseMonthly` 与 `IngestWindow` 承载；`auto_throttle`（下调配额）P0 默认关，未启用。**验证**：新增 `billing/freeze_link_test.go`（4 用例：kind/severity 白名单、已冻结不重复、无 linker no-op、端到端 critical spike → frozen）；`go build ./...`/`go vet` 通过；`go test ./...` 全模块通过。
>
> 注（**2026-10-02 第十四批：L2 对账器接线**）：按 §6.12/§6.16 S-4 接线账务域对账器（**此前 `reconciler` 恒为 nil，出账门禁与 S-5 规则② 均为空操作**）。**① 计量侧读取器**：`NewPullNetReader(PullSource)` 实现 `NetMeteringReader`——把 UTC+8 自然日闭区间 `[dayFrom,dayTo]` 经 `dayRangeNs` 换算为 UTC 纳秒左闭右开窗口，复用 tee-infer 拉取源 `Pull` 并取该租户净量三元组（缺租户 → 零值；接口无 ctx，内部 30s 超时）。**② 构造**：`NewReconcilerForStore(store, reader, alertRatio)`（包外无法引用账本具体类型）；`L2` 增 `ledger==nil` 降级守卫。**③ 接线**：`billing_api.go` 提前解析计量令牌（`hasToken`）→ 构造复用拉取源 + `Reconciler`（`alertRatio=cfg.Anomaly.ReconcileAlertRatio`）→ 注入 `NewBillingService` 与 `NewAnomalyDetectorForStore`。**激活后行为**：出账门禁（`L2 diff>0 → 不出账`，fail-closed，B-6.12-1）、S-4「每次出账前」对账、S-5 规则② `reconcile_diff` 生效（可经第十三批联动冻结）；**未配置计量令牌时保持 nil 降级**（与既有行为一致）。**验证**：新增 `billing/reconcile_link_test.go`（5 用例：读取器映射/缺租户零值、源错误传播、`dayRangeNs` 24h 与起点、ForStore 零差异通过、nil 账本降级）；`go build ./...`/`go vet` 通过；`go test ./...` 全模块通过。
>
> **如实声明（L2 口径与文档差异，本批未改）**：现 `Reconciler.L2` 的差异三元组取 **in/out/retry**（`diffRetry`，回归 **`TestREC4_RetryCountedInDiff`** 锁定，注释称「M9 平台成本同口径」），而详设 **§6.12.2 伪代码取 in/out/requests 且声明「retry 不入本对账（另列 RetryToks）」**——**二者冲突，本批不改语义**（改则破坏既有 T13 回归）。差异仅影响 `ratio` 分母与"retry 不一致"分支；`diff==0`（M1 同口径相等）门禁行为一致。**建议单列一批裁定并统一**（含 REC-4 与 §6.12.2 取舍）。
>
> 注（**2026-10-02 第十五批：L2 口径裁定（A：代码对齐文档）**）：经用户裁定，消除第十四批登记的 **L2 差异三元组文档-实现冲突**——**采纳 A「代码对齐文档 §6.12.2」**。**改动**：`Reconciler.L2` 第三轴由 `RetryToks` 改为 **`Requests`**（差异 = `|入差| + |出差| + |请求数差|`；分母 = 计量侧 `入+出+请求数`，≤0 取 1）；**retry 不参与 L2**（`RetryToks` 仍随 `NetTotals` 提供，由 M9 单独校验平台成本口径），与 §6.12.2「retry 不入本对账（另列 RetryToks）」一致。**契约随之更新**：`L2Result.Diff/Ratio` 注释。**回归同步**：`TestREC4_RetryCountedInDiff` → 重写为 **`TestREC4_RequestsCountedRetryExcluded`**（请求数差计入、retry 差被忽略）；`TestREC3_RatioBoundary` 调整为请求数口径下**恰好 0.1%** 边界；`TestCloseDaily_ReconcileBlocked/Pass` 与 `TestINT5_ReconcileGateBlocks` 的账本种子补 `Requests` 使两侧同口径（避免请求数轴引入非预期差异）。**验证**：`go build ./...`/`go vet` 通过；`go test ./...` 全模块通过。**本体（详设 §6.12.2）无需改动**（其伪代码本即取 `Requests`）。
>
> 注（**2026-10-02 第十六批：对账回补重拉 `onReconcileWarning` 接线**）：按 §6.12.3 落地 L2 软分支的**重叠窗口回补重拉**。**① 触发**：`gateL2`（`CloseDaily`/`CloseMonthly` 共用）在 `!Pass`（diff>0）且 **`!ShouldFrz`（即 `0<ratio≤alertRatio`，软分支）** 时调用 `onReconcileWarning(tenant, dayTo)`——**不改变**「diff>0 一律不出账」硬门禁（A-22）；硬分支（ratio>0.1%）交由 S-5 判冻结。**② 回补**：`onReconcileWarning` 非阻塞起协程，以 **2×pull_lookback** 加宽窗口经 `repullWindowed` 重拉并入账（复用 S-1 拉取源；入账幂等由 `event_key` 兜底 §6.3.4）；内部用脱离请求的 `context.Background()`+30s 超时（避免 HTTP 请求结束取消回补）。**③ 幂等**：`markRepulledOnce`（`(tenant,day)` 进程内**仅一次**，带互斥；同 warning 不反复触发）。**④ 指标**：`IncAutoRepull()` 为 **#20 `auto_repull_total` 的唯一生产者**（此前无生产者）。**验证**：新增 `billing/repull_test.go`（5 用例：幂等标记、加宽窗口重拉入账、软分支排回补、硬分支不排、无源 no-op）；`go build ./...`/`go vet` 通过；`go test ./...` 全模块通过。**偏差说明（如实声明）**：详设伪代码 `pullOnceWindowed(ctx, tenant, day, widen)` 为**按租户**回补；本实现的 `PullSource.Pull(ctx,from,to)` 为**全租户窗口**接口，故回补按加宽窗口**全租户**重拉（非目标租户的重复数据由 `event_key` 幂等丢弃），语义等价。
>
> 注（**2026-10-02 第十七批：自动解冻接线（B-6.10-2）**）：闭环 §6.10 状态机的**恢复边**。**① 枚举能力**：`FreezeStore` 新增 `List()`（sqlite 全量查，按租户升序）；`FreezeController.ListFrozen()` 返回**未到期**记录。**② 联动**：`AnomalyDetector.AutoUnfreeze(day)`——遍历生效冻结，**仅 `reason=reconcile_diff`** 者对当日重新 `L2`；`Pass`（对账恢复）→ `Unfreeze(tenant, "system")`（落 `bill_unfreeze` 审计）；`manual`/`pricing_missing` **不自动解冻**（B-6.10-2 须人工）；仍不一致则保持冻结。`FreezeLinker` 接口扩展 `Unfreeze`/`ListFrozen`。**③ 接线**：`ScanAnomaliesTask` 在 `Scan` 后**先 `AutoUnfreeze` 再 `ApplyFreezes`**（同一租户二者互斥：对账 Pass → 无 reconcile 异常、不冻结；对账失败 → 不解冻），日志增「解冻」计数。**验证**：新增 `billing/unfreeze_test.go`（5 用例：对账恢复解冻、仍不一致保持、manual 保持、pricing_missing 保持、无 reconciler no-op）；`go build ./...`/`go vet` 通过；`go test ./...` 全模块通过。
>
> 注（**2026-10-02 第十八批：告警外部交付 Webhook sink**）：落地 §6.11 的**外部交付**通道（此前 `QuotaNotifier.sink` 恒为 nil，仅本地日志 + Prometheus 规则）。**① 实现**：`NewWebhookAlertSink(url, timeout)`——返回 `func(tenant, rem, periodKey)` 交付闭包，JSON POST `{kind:"quota_low", tenant, remaining_ratio, period}` 至 Webhook；**url 空 → 返回 nil**（保持"仅日志"降级）；交付失败/非 2xx **仅记日志、不 panic、不向上返回错误**（fire-and-forget；可靠性由 Prometheus 规则侧兜底）。**② 配置**：`SecretsConfig.AlertWebhookURL`（env `BILLING_SECRETS_ALERT_WEBHOOK_URL`；空 = 关闭；建议以 env 注入，URL 可能含 token）。**③ 接线**：`billing_api.go` 将 sink 注入 `NewQuotaNotifier`（S-7 余额告警；`periodKey` 幂等去重已具备）。**验证**：新增 `billing/alert_sink_test.go`（3 用例：空 URL → nil、HTTP POST 载荷与头断言、非 2xx/不可达不 panic）；`go build ./...`/`go vet` 通过；`go test ./...` 全模块通过。**范围说明（如实声明）**：本 sink 当前仅服务**配额告警**（`Notifier.WarnQuotaLow`）；其他告警（S-9 `BillingPlanExpiring`、关联校验失败等）仍走日志 + Prometheus 规则（§9.3）；如需统一外部交付，后续可泛化 sink 载荷。
>
> 注（**2026-10-02 第十九批：S-9 租户通知接线**）：补齐 §6.4.2「到期提醒…**通知租户**」（此前仅指标 #21）。**① sink 泛化（第二处用途）**：`NewWebhookAlertSink` 由配额专用签名 `func(tenant,rem,periodKey)` 泛化为通用 `AlertSink func(AlertEvent)`（`AlertEvent{Kind,Tenant,Severity,RemainingRatio,Period,Days}`）；`QuotaNotifier` 改用 `AlertSink` 并构造 `kind="quota_low"` 事件（附带 B-6.11-2 severity：耗尽 → critical）。**② 到期通知**：`BillingService.SetAlertSink` + `alertSink` 字段；`ScanExpiries` 在**与指标 #21 同一幂等闸（`fresh`）**处投递 `kind="plan_expiring"`（`Days=30|7|0`，`Period=到期日 UTC+8`）→ **每订阅每阈值仅一次**（复用 `alert_dedup`）。**③ 接线**：`billing_api.go` 构造**单个** sink 实例，同时注入 `NewQuotaNotifier` 与 `svc.SetAlertSink`（S-7/S-9 共用；空 URL → nil 降级）。**验证**：`expiry_test.go` 增 `TestScanExpiries_Notifies`（阈值交付 + 幂等）；`alert_sink_test.go`/`notify_test.go` 随签名泛化同步；`go build ./...`/`go vet` 通过；`go test ./...` 全模块通过。
>
> 注（**2026-10-02 第二十批：§9.3 billing PrometheusRule 清单 + promtool 单测**）：落地 §9.3 告警规则（此前**全仓无 billing 版 PrometheusRule**）。**交付形态（经用户裁定＝A）**：以 `kind: PrometheusRule` CRD 为**单一事实源**（`deploy/monitoring/billing-prometheusrule.yaml`，供 kube-prometheus-stack/PrometheusOperator `kubectl apply`）；promtool 无法直读 CRD，故附**机械生成**纯规则文件的步骤（`spec:` 段去 2 空格；生成物 `.billing-promtool-rules.yaml` 为构建产物**不入库**），并附 promtool 单测 `deploy/monitoring/billing-prometheusrule-promtool-test.yaml`。**规则（10 条，组 `billing.rules`）**：`BillingLedgerChainBroken`(#4/critical)、`BillingReconcileDiff`(ratio>0.1%/critical)、`BillingReconcileWarning`(0<ratio≤0.1%/warning)、`BillingPricingMissing`(#18/critical)、`BillingCloseMissed`(M3 代理/warning)、`BillingAnomalySpike`(**warning/critical 同名双规则**，A-25/A-30)、`BillingQuotaLow`(#12/warning)、`BillingPullErrorSustained`(#5/warning)、`BillingAssocVerifyFailed`(#22/critical)；**`BillingFrozenSustained` 未落地**（见剩余项）。**工程口径**：① `reconcile_diff` 指标**值即差异率**，阈值直接用 0.001（对齐 §6.12.3，非"绝对差>0"）；② 计数器类一律 `increase(...[窗])` 而非 `> 0`（避免"历史发生过即永久 firing"）；③ `BillingCloseMissed` 为**代理判据**（§9.1 无"最近日结时间"指标）："26h 内有入账 且 无日结执行" ⇒ 疑似漏跑。**实测（本机 docker `prom/prometheus:v2.53.2`）**：`promtool test rules` → **SUCCESS**（9 场景：链断裂 pending→firing、配额低、关联校验失败、单价缺失、拉取连续失败、spike warning/critical、对账硬/软分支、日结漏跑、健康基线全静默）；`promtool check rules` → **SUCCESS: 10 rules found**。
>
> 注（**2026-10-02 第二十一批：`gateway_admin_billing_frozen` 指标补全 + `BillingFrozenSustained` 告警回填**）：闭合 §9.3 最后一条告警。**① 指标（§9.1 新增 #24）**：`gateway_admin_billing_frozen`（gauge, `tenant`；1=冻结 / 0=解冻）——§9.3 `BillingFrozenSustained`（冻结持续 >24h）此前**无可用信号**（`freeze_total` 仅计数，无状态/时长）。**② 生产者**：`FreezeController.Freeze` 置 1、`Unfreeze` 置 0（状态变更即置）；`AnomalyDetector.SyncFrozenGauge()` 在 S-5 每轮**以冻结存储回填**（`ListFrozen`，跳过已到期），**解决进程重启后 gauge 归零**（否则 `for: 24h` 永不累计）；S-5 任务在租户枚举前调用（无租户亦回填）。**③ 登记**：`scripts/metrics-required.txt` 增 `admin gateway_admin_billing_frozen conditional`；本体 §9.1 表增 **#24**、§9.1.1 生产者表增 #24 行（★ O-7 强制）。**④ 告警回填**：`deploy/monitoring/billing-prometheusrule.yaml` 增 `BillingFrozenSustained`（`gateway_admin_billing_frozen == 1`，`for: 24h`，warning）；promtool 单测增场景（23h pending / 26h firing）并纳入健康基线静默断言（规则 10→**11**）。**实测（docker `prom/prometheus:v2.53.2`）**：`promtool check rules` → **SUCCESS: 11 rules found**；`promtool test rules` → **SUCCESS**（10 场景）。**踩坑与修正（如实记录）**：`for: 24h` 场景初版用 **1h 采样间隔** → 超过 Prometheus 默认 **5m lookback**，样本陈旧使告警状态中断、`for` 永不累计（`got:[]`）；改为 **5m 采样**后通过——该约束已写入测试注释。**Go 验证**：新增 `billing/frozen_gauge_test.go`（3 用例：冻结/解冻置位、重启回填、已到期不置位）；`go build ./...`/`go vet` 通过；`go test ./...` 全模块通过。
>
> 注（**2026-10-02 第二十二批：P0-3 验收复核（§10 测试矩阵对照）**）：对 P0-3 全量交付做**离线可证**的验收复核，**并修正第二十一批「剩余项清零」的过度表述**（复核发现 §6.3.1 推送消费与 M6 观测**未实现**）。
>
> **✅ 通过项**：① `go build ./...`、`go vet` 通过；② `go test -count=1 ./...` 全绿（含 19 批新增用例）；③ **覆盖率 billing 85.2%**（≥80%，§10.1 目标达成）、main 69.3%；④ 指标门禁**静态核对**：`scripts/metrics-required.txt` 24 条 billing 条目 ↔ 代码生产者 **22 条命中**；⑤ §9.3 PrometheusRule 11 条由 **promtool 实测**（`check rules`/`test rules` SUCCESS）；⑥ §10.2 **INT-1..7 全部存在**；⑦ §10.6 **S-1/S-2/S-5/S-8** 有用例（S-6 部分：`TestRenderMetrics_EmptyWhenDisabled` + `TestBillingIsolationDisabledWhenFeatureOff`）。
>
> **⚠️/❌ 验收发现（未达标，如实登记）**：
> 1. **指标生产者缺失 2 条**（清单登记、**全仓无发射**）：`gateway_admin_billing_push_total`（#6）、`gateway_admin_billing_quota_apply_duration_seconds`（#13）。对应能力亦**未实现**：§6.3.1 **推送 webhook 消费**仅有 `PushEvent`/`PushToWindow`（后者无生产调用点），**无 webhook 端点、无 HMAC 验签**；§6.4.1 **M6 配额热生效时延**未观测。按本体 §9.1.1「**生产者缺失即视为该指标未实现**」＝未实现（门禁 #9 因二者 `conditional` 不 FAIL ⇒ **门禁盲区**）。
> 2. **§10.1「配置校验 R-1..R-34 逐条非法拒绝」未逐条**：`config_test.go` 仅 9 条 R-*（R2/R4/R5/R7/R9/R16/R27/R30/R33）；实现侧 `validateConfig` 覆盖 R-1..R-34（读码确认），缺逐条用例。
> 3. **§10.4 REC-5 缺失**（L1 已 blocked → L2 仍可从 `/usage` 拉取对账，B-6.12-2）。
> 4. **§10.4 REC-6 语义不符**：文档 REC-6＝「审计链断裂 → 全局冻结（B-6.12-4）」；现 `TestREC6_ChainBrokenDetected` 测的是**账本**链断裂检出（对应 S-1/INV-2）。
> 5. **§10.6 S-3（`/usage` 域金额字段扫描，CI 强制）未实现**（`scripts/` 无对应扫描脚本或测试）。
> 6. **§10.6 S-4（未验签 webhook → 401）无用例**（依赖发现 1 的未实现能力）。
> 7. **§10.3 E2E-1..4 无自动化**（依赖真机 tee-infer + compose/kind）；E2E-4 仅**部分**覆盖，无「全响应逐字节 diff」。
> 8. **环境限制（非缺陷）**：`make test`（`-race`）本机不可跑（`CGO_ENABLED=0` 且无 gcc）；门禁 #9 `check-metrics-green.ps1` 需运行中的 tee/admin/core/plugin，本机无栈（来源不可达 → SKIP，≠ FAIL）。
>
> 注（**2026-10-02 第二十三批：推送消费 webhook（§6.3.1）补齐 —— 处置复核发现 1**）：按用户指令先做 A。**① wire 契约对齐（本体 §4.1.5/§4.4）**：admin 侧 `PushEvent` 原为**窗口级**（`from_ns/to_ns/requests/by_model`）——与 tee-infer 实际 `billingEventPayload`（**事件级**）**并不对齐**（注释误称"已对齐"）→ 重写为事件级 `{event_id, tenant, request_id, engine_type, model, tokens_in/out, result, is_retry, ts}`；新增 `pushEventToWindow`（单租户单模型；`ts`→UTC+8 归日；`is_retry` → `retry_toks` 归因且 `tokens_*` 置零；负 token/非法 `ts`/字段缺失 → **不落账** B-6.3-4）；移除旧 `PushToWindow`。**② 端点**：`POST /v1/adminext/billing/events`（`handleBillingEvents`）——**HMAC 验签**（`X-Signature: sha256=<hex>`，密钥＝**`source.push_secret_ref`**〔经用户裁定 A〕；未配置 / 头缺失 / 常量时间不等 → **401 fail-closed** B-6.3-1）→ JSON 反序列化（非法 → 400）→ 委托 `ConsumePush`；**不经 `authMiddleware`**（推送方无管理面 JWT），鉴权由 HMAC 承担。**③ 单一写路径（INV-8/A-8）**：`BillingService.ConsumePush` 委托既有 `IngestWindow`（std 锁定 + 事务 + `UNIQUE(event_key)` 幂等），`event_key = push-{event_id}-{tenant}-{model}`（§6.3.4 事件级）；单写者门控（`sync_mode=push` 才写账，`=pull` 仅实时视图）；冻结租户**仍入账**（B-6.3-6）。**④ 指标 #6 生产者**：新增 `IncPush(result)`（ok/frozen/error/unknown_result）；并**修正 `IngestWindow` 的指标所有权**——原其代发 `pull_total`（会把推送计成拉取），现改由 `pullOnce`/`repullWindowed` 发射 #5、`ConsumePush` 发射 #6。**⑤ 接线缺陷修正**：`sync_mode`/`pull_lookback` 原**仅在"有计量令牌"时注入** → 无令牌时 `CanWrite` 恒 false（**推送永不入账**，由新测试暴露）；改为**无条件注入**（拉取源仍依赖令牌）。**⑥ 跨服务**：tee-infer `billingEventPayload` 补 **`is_retry`**（omitempty；值取审计证据字段 `IsRetry`，§4.1.5/§6.3.3）。**验证**：admin 新增 `billing/consume_push_test.go`（7 用例：push 入账+std 锁定、`event_id` 幂等、`is_retry` 归因、pull 模式不写账、冻结仍入账、负 token 不落账、未知 result 兜底）；`billing_api_test.go` 增 `TestBillingEventsWebhook`（200 入账 / 错签名 401 / 无签名 401 / 非法 JSON 400 / GET 405）与 `TestBillingEventsWebhook_NoSecretFailClosed`（S-4）；`metering_test.go` 的 `TestPushToWindow` → `TestPushEventToWindow`；tee-infer `billing_test.go` 增 `is_retry` 载荷断言；`go build ./...`/`go vet` 通过；`go test` 全绿（admin + tee-infer 包）。
>
> **复核发现 1 处置**：`gateway_admin_billing_push_total`（#6）**已具备唯一生产者**（`IncPush`）。**同发现剩余子项**：`gateway_admin_billing_quota_apply_duration_seconds`（#13，**M6**）仍无生产者（下一批 B 处理）。
>
> 注（**2026-10-02 第二十四批：M6 配额热生效时延（§6.4.1）补齐 —— 处置复核发现 1 剩余子项**）：按用户指令做批 B。**① 生产者（#13）**：`ObserveQuotaApply(seconds)`（`billing/metrics.go`）发射 `gateway_admin_billing_quota_apply_duration_seconds`（§9.1 #13，此前**无生产者**）。**② 回读确认（P-1/M6，§6.4.1 2c）**：`billing/quota.go` 新增 `QuotaReader` 接口 + `httpQuotaApplier.GetQuota`（`GET {base}/usage/quota?tenant=X`，管理头 `X-Admin-Token`）与 `ConfirmQuotaApplied(ctx, rd, tenant, want, within, poll)`——**轮询回读至「已生效限额 ⊇ 期望」**（顺序无关，`quotaLimitsCovered` 集合子集判定），≤`within` 返回 nil，超时返回违约（含 want/got 诊断）；读错重试不中断。**语义锚定**：`POST /usage/quota` 返回 2xx **≠** 已生效，**回读是 M6 判据的唯一构造点**（A-14）。**③ 计时接线**：`billing_api.go::handleSubscription` 以 **受理时刻**（`start := time.Now()`）为 M6 起点；配额下发成功后回读确认（预算 `m6ApplyWithin=60s`、轮询 `m6ApplyPoll=1s`；`quotaApplyBudget` 字段可注入以缩短测试），**确认失败仅告警不回滚**（TEE 已生效为准，§6.4.1）；无论确认成败均 `ObserveQuotaApply(time.Since(start))`——**违约也观测**，使 60s 超时可被暴露。**④ tee-infer 回读端点**：新增 `handleQuotaReadback`（`GET /usage/quota?tenant=X`，**只读**，鉴权 `checkMetering`；缺 `tenant` → 400，未配置租户 → 200 空 `limits`），`handleQuota` 按 `GET` 分派（POST 写路径不变）。**验证**：新增 `billing/quota_confirm_test.go`（8 用例：立即/延迟确认、读错恢复、超时、空期望、nil reader、集合覆盖、指标渲染）+ `billing_api_test.go`（`TestBillingSubscription_M6Confirmed`／`_M6UnconfirmedStill200`：确认成功/超时两条路径均 200 且 #13 被观测、订阅不回滚）+ `tee-infer-service/quota_test.go`（回读视图多维断言、缺 tenant/未配置租户边界）；`go build ./...`/`go vet` 通过；`go test`（admin + tee-infer 包）全绿。**偏差说明（如实声明）**：`ObserveHistogram` 用**全局默认桶**（上限 **10s**），而 M6 SLA = **60s** → 现值落 +Inf，无法区分 10s 以上；`metrics.Registry` 无自定义桶入口，本批**未扩展**（若需 `histogram_quantile` 可分位刻画 M6，建议单批为 registry 增自定义桶 API，注意勿扰动既有直方图）。**复核发现 1 至此两子项（#6/#13）均已具备生产者，关闭**。
>
> 注（**2026-10-02 第二十五批：批 C —— §10.1 R-1..R-34 逐条 / R-29 / REC-5 / REC-6 / §10.6 S-3**）：处置复核发现 2/3/4/5，并**订正第二十二批复核的一处失实表述**（该批复核称"实现侧 `validateConfig` 覆盖 R-1..R-34（读码确认）"——**经逐条读码与实际拒绝测试证伪**：**R-29 全仓未实现**；**REC-6 亦未实现**，原 `TestREC6_ChainBrokenDetected` 实为**账本**链篡改＝S-1/INV-2）。
>
> **C-1 §10.1 R-1..R-34 逐条非法拒绝（测试为主）**：新增 `TestConfig_AllRulesReject`（表驱动 **31 条**：env 驱动 × 断言「拒加载 + 错误信息含规则号」）+ `TestValidateConfig_DirectStruct`（**R-3 `sqlite` 空 dsn 与 R-4 空 `tee_url` 经 env 不可达**——`getEnv` 空值回退默认，故直接构造 `BillingConfig` 调 `validateConfig`）；R-14 复用既有 `TestLoadPriceTable_MissingVersion`；R-1 由 `TestBillingIsolationDisabledWhenFeatureOff`/`TestRenderMetrics_EmptyWhenDisabled` 覆盖；R-8≡R-9、R-23/R-31 为 bool（无非法面）。**逐条归属已在用例注释中登记**（避免"看似全绿实则漏条"）。
>
> **C-1 R-29（★ 新增实现，此前未实现）**：新增 `BillingService.ValidatePlanPricing`（`over_quota=charge` 须 ① `MonthlyTokens>0`（非免费档）② 当前单价表 `PriceTable.HasNonZeroPrice()`（非全 0 价））；`billing_api.go::handlePlans` POST 接线（400 拒）；`PriceTable.HasNonZeroPrice()`。**口径说明（P0 实情，如实声明）**：P0 单价表为**全局单表**（按 `model_key` 计价），`Plan.PriceID` **全仓无到单价表的映射**，故 R-29 的"`PriceID` 对应单价表"按**当前全局单价表**解释（若后续为 PriceID 引入独立价目，需同步收紧）。测试：`TestValidatePlanPricing_R29`（免费档拒/付费通过/非 charge 跳过/全 0 价拒）+ `TestBillingPlanUpsert_R29`（API 400/200）。
>
> **C-2 §10.4 REC-5**：`TestREC5_L2PollsUsageIndependentOfPush`——真实 `httptest` 提供 `/usage?from&to`，经 `TEEPullSource → PullNetReader → Reconciler.L2`，账本与 `/usage` 净量同口径 → `diff=0`；并断言确实发生拉取（命中计数），证明 **L2 数据源＝拉取，不依赖推送**（B-6.12-2，L1 停不影响 L2）。
>
> **C-3 §10.4 REC-6（★ 新增实现，此前未实现）**：① 校验器 `AuditChainVerifier` + `TEEAuditVerifier`（`GET {tee}/audit/verify` 解析 `{ok}`）；② `BillingService.VerifyAuditChain` → `SetAuditChainBroken(!ok)`（**独立的进程内标志**，与账本链 `chainBroken` 互不覆盖）；③ **全局出账门禁** `integrityGate`（账本链 or 审计链断裂 → 停出账；`CloseDaily` **与 `CloseMonthly` 共用**）+ `ErrAuditChainBroken`；④ S-6 `VerifyChainTask` 增校验审计链；⑤ `billing_api.go` 注入校验器（tee_url + 可选令牌）。测试 `billing/audit_chain_test.go`（断裂 → **全租户**日结/月结均 `ErrAuditChainBroken`、完好复位、nil 校验器 no-op、HTTP 契约）。原 `TestREC6_ChainBrokenDetected` → **更名 `TestS1_LedgerChainTamperDetected`**（账本链篡改检出＝S-1/INV-2，与 REC-6 是两条不同的链）。**顺带修正（如实声明）**：`CloseMonthly` 此前**无**账本链门禁（仅 `CloseDaily` 有），本批统一为共用 `integrityGate`（使"全局停出账"对日/月结一致，属 REC-6 语义补齐）。**偏差（如实声明）**：REC-6 暂无专用指标/告警（§9.1 未定义新指标），仅日志留证；如需告警可后续单批补指标 + §9.3 规则。
>
> **C-4 §10.6 S-3（CI 强制，金额域隔离）**：tee-infer 新增 `TestUsageDomainNoAmountFields`——`httptest` 打 `/usage`、`/usage?tenant=`、`/usage?from&to`（增量权威口径）三视图，**递归扫描响应 JSON 全部 key**，命中 `amount/total/price/cost/fee/currency/subtotal/unit_price/price_version` 即失败；随 `go test ./...` 在 CI 强制、离线可跑（M10/INV-4 直接证据）。
>
> **验证**：`go build ./...`、`go vet ./gateway/...` 通过；`go test ./...` **全模块全绿**（新增 ~50 断言）；本批新增/改动文件 gofmt 干净。**复核发现收敛**：发现 2（R-1..R-34 逐条）✅；发现 3（REC-5）✅；发现 4（REC-6）✅；发现 5（S-3）✅；发现 6（S-4 未验签 webhook→401）已于第二十三批 `TestBillingEventsWebhook_NoSecretFailClosed` 落地 ✅。**剩余**：发现 7（§10.3 E2E-1..4 无自动化，依赖真机 tee-infer + compose/kind）——属环境限制，待有栈时补。**另**：第二十四批声明的 histogram 默认桶上限 10s < M6 的 60s 仍为遗留项（建议单批扩展 registry 自定义桶）。
>
> 注（**2026-10-02 第二十六批：metrics registry 自定义直方图桶 —— 消除第二十四批 M6 遗留**）：**① 机制**：`Registry.RegisterHistogram(name, buckets)`（新增 `histBuckets` 覆盖表 + `histogramBuckets(name)` 取值；`ObserveHistogram` 改走覆盖优先）——支持为 SLA 跨度显著大于默认上限（10s）的直方图登记自定义桶；**约束**：须在**首次观测前**登记（样本按边界累计，事后改桶会使历史计数与新边界不一致，已在注释与文档标明）；空名/空切片 no-op；包级转发 `RegisterHistogramBuckets`。**② 应用（M6 #13）**：`gateway_admin_billing_quota_apply_duration_seconds` 登记桶 `{0.05,0.1,0.25,0.5,1,2.5,5,10,20,30,45,60,90,180}`（**含 60s SLA 边界**），于 `init()` 注册（先于任何请求）——修复"现值 >10s 全落 `+Inf`、无法分位刻画 M6"。**验证**：新增 `TestRegistry_CustomHistogramBuckets`（登记后按自定义边界累积 + 未登记仍用默认桶）+ `TestObserveQuotaApply_CustomBuckets`（渲染含 `le="60"`）；`go build ./...`/`go vet` 通过；`go test ./gateway/gateway-admin-service/...` 全绿。**未改动（如实声明）**：`close_duration_seconds`（#7，M3/M4 分钟级 SLA）同受默认桶 10s 之限，本批**未登记**（未被要求；如需可分位刻画，同机制单批登记即可，勿扰动既有直方图）。**第二十四批的 M6 histogram 残留至此关闭**。
>
> 注（**2026-10-02 第二十七批：M6 分位告警规则（§9.3 增补）**）：**形态经用户裁定＝仅 p95 分位**（未加低流量绝对兜底）。**① 规则**：`BillingQuotaApplySlowP95`——`histogram_quantile(0.95, sum(rate(gateway_admin_billing_quota_apply_duration_seconds_bucket[30m])) by (le)) > 60`，`for: 10m`，**warning**；窗口取 **30m**（套餐变更为低频事件，短窗样本不足）。**② 依赖**：#13 的**自定义直方图桶**（含 60s 边界，第二十六批）——否则 >10s 全落 `+Inf`，分位不可用。**③ 本体登记**：经用户裁定**同步登记 §9.3**（增一行，标注"批 C 增补（M6）"），保持唯一事实源。**④ promtool 实测（docker `prom/prometheus:v2.53.2`）**：`check rules` → **SUCCESS: 12 rules found**；`test rules` → **SUCCESS**（新增场景 `quota-apply-p95-slow`：5m pending / 40m firing；健康基线增 #13 快路径静默断言）。**⑤ 顺带修正（文档缺陷，如实声明）**：CRD 文件头生成命令原为 `Select-String -SimpleMatch '^spec:$'`——`-SimpleMatch` 按**字面**匹配，永不命中 `spec:` → 生成物损坏（实测 `mapping values are not allowed`）；已改为正则 `Select-String '^spec:$'`；另修正 promtool 测试文件头 docker 示例——镜像 entrypoint 为 `prometheus`，`docker run ... prom/prometheus promtool ...` 会报 `unexpected promtool`，须 `--entrypoint promtool`（已按实测更新两处文档命令）。**验证**：`go build/vet` 与 Go 测试不受影响（本批纯 YAML/文档）。
>
> 注（**2026-10-02 第二十八批：§10.3 E2E 自动化落地 —— 并修复 E2E 暴露的 S-1 拉取认证缺陷**）：**①★ 关键缺陷修复（E2E 直接暴露，非静态分析可得）**：`teeInferPullSource.Pull`（`billing/metering_pull.go`）原用 `Authorization: Bearer <token>` 作认证头，而 tee-infer 计量端点 `checkMetering`/`checkAdmin` **只认 `X-Admin-Token`** → **受保护 tee-infer（配置了 admin/meter token）下 S-1 拉取恒 401**，账本永空、日结/L2/M1 全线失效（此前本地环境 tee-infer 多为开发模式免令牌，掩盖了该缺陷；既有 `pull_test` 用替身源，未覆盖 HTTP 头）。修复＝改用 `X-Admin-Token`（与 `httpQuotaApplier`/`GetQuota` 一致）；新增回归 `TestTEEPullSource_AuthHeader`（httptest 断言头名，不符即 401）。**② 端点增补（E2E-3 触发点）**：`POST /v1/adminext/billing/verify-chain`（admin）——手动触发全量完整性校验（S-6 账本链 + REC-6 审计链，与调度器 `VerifyChainTask` 同逻辑），返回 `{ledger_broken_at, ledger_broken, audit_chain_ok}`；同步登记本体 **§4.3.2**。单测 `TestBillingVerifyChain`（405/403/200 + 空账本完好）。**③ E2E 自动化（§10.3）**：新增 `e2e/` 包（`//go:build e2e`，**进程级**编排——`go build` 两服务二进制 + 随机端口子进程 + 仅 HTTP 驱动；tee-infer 走 `-engine-url` 空＝本地模拟引擎 + **token 模式** vectors 推理以规避信封握手；admin 侧驱动自签 HS256 内部 JWT）。**覆盖**：E2E-1（推理→S-1 拉取→日结→`/bills`→`/verify`(valid)→导出）、E2E-2**基础**（4 档套餐绑定→配额下发并回读生效→超限 429）、E2E-3（篡改账本→`verify-chain` 断裂 + 指标 #4 置 1 + 停出账 409）、E2E-4（`enabled=false` vs `true` 的 `/v1/adminext/usage` **逐字节一致** + 关闭时 `/billing/*` 404）。**实测**：`go test -tags e2e ./e2e/ -v -timeout 15m` → **4/4 PASS（16.4s）**。**④ 形态差异（如实声明）**：编排用**进程级**而非 §10.3 原文的 `docker-compose/kind`（同为"真机两服务真实链路"，已同步 §10.3 说明）。**⑤ 范围（如实声明）**：E2E-2 为**基础版**——OverQuota 的**计价差异**（degrade/charge 超额账单形态）不在 E2E 重复，由 §10.1/§10.2 单测与集成覆盖。**验证**：`go build ./...`/`go vet ./gateway/...` 通过；`go test ./...`（默认，e2e 由 tag 排除）**全模块全绿**；E2E 4/4 绿。**复核发现 7（§10.3 E2E 无自动化）收敛**。
>
> 注（**2026-10-02 第二十九批：#7 出账耗时自定义桶 + M3/M4 分位告警（§9.3 增补）**）：**形态经用户裁定＝两条 p95（daily + monthly）**。**① 自定义桶（#7）**：`gateway_admin_billing_close_duration_seconds` 登记桶 `{0.1,0.5,1,5,10,30,60,120,300,600,1200,1800,3600,7200}`（`billing/metrics.go`，`init()` 与 M6 一并注册）——默认上限 10s 无法刻画分钟级出账。**★ 关键约束（分位可判定性）**：阈值须**严格落在桶区间内**，否则 `histogram_quantile` 上限只能取到最高有限桶上界（若阈值=3600 则该式 `> 3600` **永不成立**）；故在日/月预算之上各留一档（1200 日预算 → 桶给到 1800；3600 月预算 → 桶给到 7200）。**② 告警（2 条，warning）**：`BillingCloseDailySlowP95`＝`histogram_quantile(0.95, sum(rate(close_duration_seconds_bucket{kind="daily"}[24h])) by (le)) > 1200`；`BillingCloseMonthlySlowP95`＝同式 `kind="monthly"` 且 `> 3600`。**窗口取 24h**：出账按**租户逐条**观测（一轮日结/月结 = N 个样本），日结每日天然有样本；月结虽为月度低频，但其样本在同一时段形成**簇**，24h 窗足以覆盖（无月结时无数据 → 不触发）。**③ 本体登记**：§9.3 增两行（标注"增补（M3/M4）"）。**④ promtool 实测（docker `prom/prometheus:v2.53.2`）**：`check rules` → **SUCCESS: 14 rules found**；`test rules` → **SUCCESS**（新增 `close-daily-p95-slow`（5m pending / 60m firing）、`close-monthly-p95-slow`（同）；健康基线增两规则静默断言）。**验证**：新增 `TestObserveClose_CustomBuckets`（渲染含 `le="1200"`）；`go build ./...`/`go vet ./gateway/gateway-admin-service/...` 通过；`go test ./gateway/gateway-admin-service/...` 全绿。

> 注（**第 4 轮评审 → v1.4 修复**）：评审结论 **B-（有条件通过，不构成 L3 放行）**，详见同目录《...-多角色评审报告-第4轮.md》。本轮方法增量＝**修复连带面复算** + **判据指标必查生产者**（O-7 契约的执行化），核心发现为 **v1.3 修复"主修复点已改、连带子句未改"**。**1 项 P0：A-26** —— **A-21 的"入出串行横轴"破坏文档自身的可加性**（§6.7「无迟到数据 `Σ日=月` 恒等」/ T-6.5-7 / U-11「可加性已证」三处成假；反例：两日各 in6/out6 时 Σ日 906 ≠ 月 1230）。**3 项 P1**：**A-27**（A-23 pull retry 归因与 §4.4「不改既有字段语义」冲突，pull 侧 `tokens_in/out` 含 retry 与否**未定义** → M9 或契约必破其一）；**O-8**（§9.1.1 生产者表 **#10/#12/#17 经调用图审计证伪**：#10 符号 `AnomalyDetector.Emit` **不存在**、#12 §6.4.1 无发射、#17 引用错误）；**A-28**（A-22「门禁≠冻结」**未传播**：§6.12.4/§10.2/§10.4 仍写"`diff>0`→冻结"）。**4 项 P2**：A-29（§6.5.4 数据来源仍仅 push）/A-30（§9.3 spike"不冻结"与 A-25 冲突）/A-31（`VerifyBillingChain` 无调用点）/D-12（`extraAmount` 超额 in/out 双价口径未定）。**T4/T5/T3/T7 曾降 L2+、T8/T2 为 L3-**。
>
> **修复状态（v1.4 已全部落地，0 拒绝）**：**A-26** 采用推荐方案 **(a) 拆分 in/out 独立月累计轴**（`monthStdBefore` 返回分轴二元组、`rateModel(stdIn,stdOut,inBefore,outBefore,mp)`），连带复算 §6.5.1/§6.5.2/§6.7/§6.5.5/§6.6.1，反例固化为**附录 G-4** + 新增回归 **T-6.5-9**；**A-27** pull 侧 `tokens_in/out` 剔除 retry（净量）+ `retry_tokens` 单列、§4.4 声明"不改语义"限于标识字段；**O-8** 回填 #10/#12/#17 真实发射点（含 §6.1.1 新增时钟回拨保护 `incClockSkew`）；**A-28** 全文统一 A-22 口径；**A-29/A-30/A-31/D-12** 为 P2 一致性回填（新增 **S-10 关联校验** + **R-34**、`extraAmount` 超额**入/出分价** + **入优先占额**）。校验规则 **R-1..R-34**、调度任务 **S-10**、测试 **T-6.5-9**、附录 **A-G**。第 4 轮报告 §5 已回填"✅ 已接受 + v1.4 落点"。**建议进入第 5 轮**：聚焦 A-26 分轴连带面**闭包复算** + 各"已修复"行**原始子句逐条**回填。

### 3.5 P0-4 国密 S2 核心路径下沉 · 任务分解

| 子任务 | 工作量 | 状态 | 负责人 | 依赖 | 起止周 |
|---|---|---|---|---|---|
| 详细设计文档输出 | 3 天 | ✅ 完成（**v1.20**：v1.6 L3 放行 → 编码期 14 次版本迭代：v1.7 信封 KDF 裁决 / v1.8 流式 CPS / v1.9 掩码下沉 R4·A / v1.10 服务侧 B2 / v1.11 审计双验 B3 / v1.12 B4 全量接线 + rxroute 拆包 / v1.13 计费双读 / v1.14 profile 切换工具 / v1.15 密封双读 / v1.16 密钥分级 / v1.17 国密 TLS / v1.18 性能基准 / v1.19 切换演练 / v1.20 集成回归） | 待分配 | — | W0-W1 |
| 密码下沉 PoC：otpmask → cryptop 后端 | 5 天 | ✅ 完成（**B1**：库层 + 插件侧全线接入——jwt/keystore CPS 化、路由/限流 HMAC 经 `/v1/hmac`+常量时间比较、routeengine 随机源经 `/v1/rand`、crypto.go 掩码经 `/v1/mask/stream`；B4-e `rxroute` 拆包后 `make wasm-guard` 断言①a/①b/② **三门禁全绿**） | 待分配 | 详细设计 | W1-W2 |
| 信封加密国密化接线 + 联调 | 4 天 | ✅ 完成（**B2** 服务侧：tee-infer `session.go` 出口 `SealEnvelopeWithSuite(cryptoSuite())`、入口 wire suite 双读、进程级 Provider 装配 `-crypto-profile`/`-mask-prg` + R-2/R-14/R-21 启动校验；**B4** 插件侧 seal/open/签名 全量 CPS 接线 + 流式批量解密；**全仓 go test 绿**） | 待分配 | PoC 通过 | W2-W3 |
| 审计日志国密签名接线 + 验证 | 2 天 | ✅ 完成（**B3**：三条链 `hash_alg` 版本化（证据字段，不进 hash）+ 与 profile 解耦的分派；tee-infer 写入端打标；`audit-verify` 双验（SHA-256+SM3）；TST 锚对齐 `sm3`。**intl 逐字节零行为变更**；T-5.2-1..6 绿） | 待分配 | PoC 通过 | W3 |
| 业务调用点全量接线（所有密码使用点） | 6 天 | ✅ 完成（**B4-a~e 逐项提交**：B4-a 掩码 PRG 选择 / B4-b admin / B4-c gateway-core / B4-d auth/mcpsec/teecore/计费 Webhook / **B4-e rxroute 拆包 + 插件请求头阶段 CPS** ⇒ `wasm-guard` 三门禁全绿；B4 后全仓 `go build`/`vet`/`test` 绿） | 待分配 | 信封+审计完成 | W3-W4 |
| 密码后端服务：本地 sidecar + 可执行入口 | 5 天 | ✅ 完成（**13 端点服务** `gateway/cryptopsvc` + 独立可执行入口 `cmd/cryptopsvc`；12 项单测绿；metrics 9 项；静态密钥 env 注入；启动期 6 项校验 fail-closed；CallTimeout 中间件 50ms；批处理 64 ops 隔离） | 待分配 | PoC 通过 | W2-W3 |
| 双读兼容：intl ↔ sm-software 互读逻辑 | 4 天 | ✅ 完成（**B5-a/b/c 三件**：B5-a 存储密封双读（suite 前缀 + AEAD 认证判别 + 历史密钥环）/ **B5-b** 计费链算法标识 + 双读 / **B5-c** profile 切换端点 + 两脚本 + 两 make；intl↔sm 双向可读；未知算法 fail-closed） | 待分配 | 调用点接线 50% | W4 |
| profile 切换工具 + 回滚验证 | 3 天 | ✅ 完成（**B5-c**：`POST /v1/adminext/cryptop/profile` 管理端点 + `cryptop-switch-profile.sh` + `cryptop-verify-consistency.sh` + 2 个 Makefile 目标；编排受理模式；sidecar 一致性校验；审计 + #12 指标；脚本退出码 0/2/3/4/5/6；12 项单测 + 4 项脚本测试全绿） | 待分配 | 双读完成 | W4-W5 |
| 密钥管理分级体系：三级密钥 + 轮换 + 销毁 | 4 天 | ✅ 完成（**B6 #9**：teecore 三级密钥体系 + 派生链 + 轮换接口 + 内存零化 + 审计事件；`keymgmt_test.go` 全绿） | 待分配 | 密码后端完成 | W3-W4 |
| 国密 TLS 前置方案集成验证 | 2 天 | ✅ 完成（**B6 #10**：`deploy/tlcp/certgen` SM2 双证书生成工具 + nginx-tlcp 配置样例 + `verify.sh` 三断言验证脚本；certgen 3 用例 + 脚本 2 用例全绿；Tongsuo 为唯一外部依赖） | 待分配 | 前置网关就绪 | W5 |
| 静态扫描验证 Wasm 内无密码运算代码 | 1 天 | ✅ 完成（**`make wasm-guard` 三门禁全绿**：**①a** 插件源码 direct import 零密码 ✅ / **①b** 闭包内本仓包零密码 ✅ / **②** `protocol/go` framing 零密码 ✅；`wasm-objdump` 符号检查（门禁 2）随 wasm 产物接线完成后执行） | 待分配 | 下沉完成 | W5 |
| 基准测试：intl vs sm-software 性能对比 | 2 天 | ✅ 完成（**B6 #12**：`cryptop/bench_test.go` + `cryptopsvc/bench_test.go` + `Makefile bench-s2`；自适应组计时修正 Windows 单调钟粒度；T-8.1 矩阵 {intl,sm}×{Seal/Open/Hash/HMAC/Sign/Verify/KDF}×{1KB,64KB}；T-8.2 sidecar P99≤10ms 断言；T-8.3 batch vs sequential 4.5–5.1× 断言；交付 PERF-S2-1 报告） | 待分配 | 双读完成 | W5 |
| 国密切换演练：测试环境完整演练 + 报告 | 3 天 | ✅ 完成（**B6 #13**：`scripts/cryptop-drill.sh` 八步编排 + 报告模板（6 段 JSON）；前置检查 + 基线快照 + 三段式切换（服务端→插件→收桥）+ 功能/双读/性能钩子 + 回滚 + 报告产出；失败 block 语义；4 项脚本测试全绿（有状态 mock 全链路）；默认产物 `deploy/drill-runs/`（.gitignore）） | 待分配 | 全部功能完成 | W6 |
| 集成测试 + 回归测试 | 5 天 | ✅ 完成（**B6 #14**：真实进程级矩阵——INT-1 密码服务链（双档）/ INT-2 sidecar 插件全原语 / INT-3 tee→admin 跨服务三链双验 / INT-4 两阶段切换五步（含 restart 409+滚动+一致性+回滚）/ INT-5 密封双读+计费双读（双向）/ E2E-06 sidecar 停机 fail-closed；全量 e2e 8 顶层测试 130.7s 全绿；**E2E-05 真实部署环境端到端留部署环境执行**） | 待分配 | 全部完成 | W5-W6 |

> **实施批次与进展（2026-10-06）**——编码期改用**批次实施**（依据《GA-AI网关能力补齐方案--P0--国密S2核心路径下沉-开发实现情况评审报告.md》§六 B1–B6），**本表用于对齐"子任务 ↔ 批次"**；§3.5 下文原"①–⑥ 顺序"叙述保留作历史参考，其口径以本批次表为准。
>
> | 批次 | 范围 | 对应子任务 | 状态 |
> |---|---|---|---|
> | **B1** | 插件零密码收口（含**掩码下沉 R4·方案 A**：`/v1/mask/stream` 入参 `key_ref`→`seed`） | 密码下沉 PoC、静态扫描 | ✅ **完成**（`make wasm-guard` 断言 **①a/①b/② 全绿**——①b 原唯一命中项 `gateway/rxroute` 已由 B4-e 拆包消除；插件 7 包单测绿） |
> | **B2** | 服务侧接线·组①信封/会话 · 组③信封 AEAD · 组⑥TST · 组⑦证明验签 ＋ **组⑨存储密封**（tee-infer） | 信封加密国密化接线、业务调用点（组①③⑥⑦⑨） | ✅ **完成**（`go build`/`go vet` + 全仓 `go test` 绿；订正本体 §5.4.4 `cryptop.Sign` 误映射） |
> | **B3** | 服务侧·组② 审计 + **双验（SHA-256+SM3）** | 审计日志国密签名接线 + 验证 | ✅ **完成**（`hash_alg` 版本化三条链 + `audit-verify` 双验；T-5.2-1..6 绿；全仓 `go test` 绿） |
> | **B4** | 服务侧·组③④⑧⑪⑫⑬ 掩码 PRG 选择 + 其余业务调用点（admin/auth/mcpsec/teecore/**`rxroute`**）+ `rxroute` 拆包 | 业务调用点全量接线 | ✅ **完成（拆为 B4-a~e，逐项提交）**：B4-a 掩码 PRG 选择；B4-b admin；B4-c gateway-core；B4-d auth/mcpsec/teecore/计费 Webhook；**B4-e `rxroute` 拆包 + 插件请求头阶段 CPS ⇒ `wasm-guard` 三门禁全绿** |
> | **B5** | 双读（**存储密封 suite 前缀 + 跨 profile 双读**）+ profile 切换工具/回滚 | 双读兼容、profile 切换工具 | ✅ **完成（拆三件，逐项提交）**：**B5-b** 组⑬ 计费链算法标识 + 双读 ✅（v1.13）；**B5-c** §4.3.10 端点 + §12.6 两脚本 + 两 make ✅（v1.14）；**B5-a** 组⑨ 存储密封双读（suite 前缀 + AEAD 认证判别 + 历史密钥环）✅（v1.15） |
> | **B6** | 密钥分级 + 国密 TLS + 基准 + 演练 + 集成回归 | 密钥管理分级、国密 TLS、基准、演练、集成测试 | ✅ **完成**：**#9 密钥管理分级体系** ✅（v1.16，636ecf6）；**#10 国密 TLS** ✅（v1.17，9b5e3d3）；**#12 基准** ✅（v1.18，d3257fd）；**#13 切换演练** ✅（v1.19，a4a5190）；**#14 集成回归** ✅（v1.20，89b4e6d；E2E-05 留部署环境） |
>
> **当前进度小结**：库层（`cryptop`/`cryptoops`/`cryptopsvc`/`clients`）已就绪；**插件侧（B1）＋服务侧组①③⑥⑦⑨（B2）＋审计链与双验（B3）＋其余业务调用点（B4-a~e）＋双读与切换工具（B5-a/b/c）＋ B6 五项（#9 密钥分级 ＋ #10 国密 TLS ＋ #12 性能基准 ＋ #13 切换演练 ＋ #14 集成回归）已全部接线并全绿**；**`make wasm-guard` 三门禁全部转绿**。**P0-4 编码实施收口（E2E-05 真实部署环境端到端为唯一留场项）；可选离线重建旧密封 blob**。

> **§3.5 编码进展（按提交滚动更新，对齐详设 v1.6 附录 C 测试锚）**
>
> | 日期 | 落点 | 代码/单测 | 说明 |
> |---|---|---|---|
> | 2026-10-05 | 详设前置③ `tsa.go:59` `TSAPublicKey` 泄密钥 | `gateway/tee-infer-service/tsa.go`（独立安全修复） | 原 `sha256.New().Sum(key)` 泄密钥前 16B，改正确摘要口径 |
> | 2026-10-05 | §5.3.2 `Keystream` 原语（Provider 19→20） | `gateway/cryptop/{provider,intl,sm}.go` + `keystream_test.go`（8 项，`-race` 绿） | intl=HMAC-SHA256 PRG（逐字节等价现役掩码）/sm=SM4-CTR；确定性/域分离/密钥敏感/块连续/长度边界/密钥长度校验/跨档不互操作 |
> | 2026-10-05 | §5.3.2 `cipher/mask` PRG 可插拔 | `cipher/mask/*`（`hmacPRG`＋`NewStreamWithProvider` 接缝，`mask_prg` 三值） | 迁移期保 intl 灰度兼容（T-5.3-8 逐字节断言）|
> | 2026-10-05 | §5.1.2 信封国密化（suite 感知 + SM4 suite） | `protocol/go/cryptoops/`（新增）| `DeriveSubkey(kEnc,dir,suite)`＋`suiteKeySize`（AES→32/SM4→16/未知→0 fail-closed）；`SuiteSM4GCM=2`＋`sm4GCMSuite{p cryptop.Provider}`＋构造期 profile 绑定断言（G-7）；`SealEnvelopeWithSuite`；`OpenEnvelope` 先读 wire suite 再派生。单测 `cryptoops/envelope_test.go` T-5.1-1..7 绿 |
> | 2026-10-05 | §5.4.5 拆包：`protocol/go` 拆分 framing 与 cryptoops | `protocol/go/envelope.go`（framing-only 重写，删 AEAD/套件/HKDF/签名）＋ `protocol/go/cryptoops/{envelope,sm,sign}.go`（新增） | framing（`Envelope`/`Encode`/`Decode`/`CounterWindow`/`CheckStreamSequence`/常量/`EnvelopeNonce`/`EnvelopeAAD`）留 `protocol/go`（零 `crypto/*` 依赖，**门禁 1 断言 `go list -deps protocol/go | grep crypto/*` 零命中已验**）；AEAD/HKDF/套件注册/HMAC 签名下沉 `cryptoops`（仅 Go 服务/sidecar 链接）。导出 `PutBytes/PutString/PutUint64/BoolWord` 供 cryptoops 复用；调用点（tee-infer main/session/e2e、cross_helper、插件零密码迁移中间态）改指 `cryptoops`。`go build ./...`＋`go vet ./...`＋全部相关包 `go test` 绿；wasip1 插件镜像构建 OK |
> | 2026-10-05 | §4.3 **cryptop sidecar 服务 13 端点** | `gateway/cryptopsvc/{server,metrics}.go`（新增）＋ `gateway/cryptop/p256.go`（组⑦ 例外原语） | 端点：`/v1/{capabilities,rand,hash,hmac,seal,open,sign,verify,kdf,mask/stream,session/begin,session/end,batch}`＋`/metrics`；会话 KDF 逐字节对齐 tee-infer `session.go`（`otpmask/session/v1`→`kdf/{sig,enc}/v1`）；§4.4 错误码映射（`verify_failed`=200 `{ok:false}`、`unknown_key_ref`=404、`key_size_mismatch`/`decrypt`=400、`limit_exceeded`=413、`not_implemented`=501）；R-3 50ms 超时中间件（无 goroutine 竞态、fail-closed）；R-6 批处理每 op 错误隔离；R-8 上限（n≤4096/count≤65536/ops≤64）；R-14/R-21 `mask_prg`×profile 校验＋bridge WARN＋#15 gauge；R-20 监听地址 loopback 校验；`cryptop.VerifyP256`（TDX quote 恒 P-256，不随 profile）；指标 #1/#2/#3/#4/#6/#7/#8/#9/#11/#15（手写 Prometheus，`_sum`/`_count` 与 `_bucket` 同标签集）。单测 `cryptopsvc/server_test.go` 12 项绿（`-count=1`），`go vet`/`go build` 绿 |
> | 2026-10-05 | §4.7 **插件侧 CryptoClient + Breaker** | `gateway/wasm/otpmask-plugin/cryptoclient/{breaker,client}.go`（新增，传输无关核心）＋ `cryptoclient/client_test.go`（13 项，`-race` 绿）＋ `gateway/wasm/otpmask-plugin/cryptoclient.go`（package main 适配层） | **分层**：核心**不 import proxy-wasm hostcall** ⇒ 原生单测（§4.7 "或经接口抽象以便单测 mock"）；package main 提供 `wrapperTransport`（出站经 `wrapper.ClusterClient`）＋ `pluginCryptoMetrics`（#13/#14/#5）＋ `newPluginCryptoClient` 工厂。**CPS 偏差**：proxy-wasm `DispatchHttpCall` 本质异步，客户端签名由 §4.7 同步记号落为**回调式**（`cb(status,hdr,body)`），属 §4.7 自留缝。语义：C-4 fail-closed（不可达/超时/错误**绝不**回退插件内运算）、R-3 超时、R-4 `Breaker`（5 次/30s，`OnStateChange`=#5 唯一生产者）、R-10 不重试、§4.4 错误码（`verify_failed`=200 `{ok:false}` 非错误）、R-6 批处理每 op 隔离。指标 #13=`Call` 入口、#14=`FailClosed` 错误分支。`go vet` green；wasip1 插件镜像构建 OK。**调用点全量接线（§5.4.5 checklist）为下一子任务** |
>
> | 2026-10-05 | §4.3.6/§4.7 **信封方向子密钥 KDF 通路（R8-P1-1 落点）** | `protocol/go/envelope.go`（新增 `EnvelopeSubkeyInfo(dir)`＋`subkeyInfoC2S/S2C` 常量）＋ `protocol/go/cryptoops/envelope.go`（`subkeyInfo` 收敛为委派 `protocol.EnvelopeSubkeyInfo`，**单一事实源**）＋ `gateway/wasm/otpmask-plugin/cryptoclient/client.go`（新增 `KDF` 方法，映射 `/v1/kdf`）＋ `cryptoclient/client_test.go`（＋2 项：`TestKDFReturnsChildKeyRef`/`TestKDFEmptyChildIsFailClosed`） | **用户裁决**（2026-10-05）：信封方向子密钥**经 `/v1/kdf` 派生**。插件在 `SessionBegin` 后以 `salt=nil`、`info=protocol.EnvelopeSubkeyInfo(dir)`、`out_len=32` 派生 c2s/s2c 两个**子密钥 KeyRef**，再以之调 `/v1/seal`/`/v1/open`（AEAD key＝`DeriveSubkey(kEnc,dir,suite)`，**非** K_enc）。`/v1/kdf` info 字面量收敛至 `protocol/go`（framing，插件可链）**根除**"插件派生 info ≠ cryptoops info"漂移（v1.7 R8-P1-1）。C-5：KDF 仅返回子 KeyRef，不返密钥字节。测试 `protocol/go`/`cryptoops`/`cryptoclient -race` 全绿；wasip1 构建＋`go vet` OK |
> | 2026-10-05 | 详设 **v1.8**：流式响应解密 CPS 机制（R8-P2-2） | `docs/…--国密S2核心路径下沉.md`（新增 §5.4.6；§4.5-② 口径订正；§16 v1.8 变更行；§5.4.5 测试行/附录 A/C 同步） | **用户裁决**（2026-10-05）：流式响应解密 = **批量 CPS**。v1.7 及之前对"插件 seal/open 现为同步返回、sidecar 模型下须改 CPS（尤其流式如何异步解密）"**零描述**。§5.4.6 补机制（先例＝仓库内 `qwen3guard-plugin`）：`ctx.NeedPauseStreamingResponse()` 接管响应体 → 逐上游 chunk 聚合完整 `data:` 帧为**一次 `/v1/batch` open**（key_ref=s2c 方向子密钥）→ 回调 `proxywasm.InjectEncodedDataToFilterChain(data,endStream)` 注流 → 流末 `ResumeHttpResponse()`；单飞互斥；fail-closed 不回退本地。§4.5-② 口径订正：流式路径**按上游 chunk 计**。新增 **T-5.4-7** |
> | 2026-10-05 | §4.3.4/§4.7 **`Client.Seal` 显式 nonce 透传**（步① 前置） | `cryptoclient/client.go`（`Seal(ref,aad,nonce,pt,cb)`；`len(nonce)==0`→sidecar 生成、`>0`→用给定 nonce）＋ `cryptoclient/client_test.go`（`TestSealDecodesMockResponse` 改 nil nonce＋断言体不含 nonce；新增 `TestSealSendsExplicitNonce`） | 信封路径必须传**确定性** `protocol.EnvelopeNonce(counter)`（与 tee-infer `OpenEnvelope` 的 nonce 派生一致，否则信封不可互通）。v1.7 客户端 `Seal` 无 nonce 入参 ⇒ 信封路径无确定性 nonce 可用。`cryptoclient` 单测绿＋wasip1 构建 OK |
> | 2026-10-06 | §5.4.5 插件接线（**B1·非 mask 部分**） | `gateway/wasm/otpmask-plugin/{jwt.go,keystore.go,routecache/*,ratelimitcache/*,routeengine/engine.go,cryptoclient.go}` ＋ `Makefile`（新增 `wasm-guard`） | 插件零密码收口：`jwt.go`/`keystore.go` 改 **CPS**（HMAC 经 `/v1/hmac`＋常量时间比较；seed/nonce 经 `/v1/rand`）；`routecache`/`ratelimitcache` 引 `Verifier` 接缝、`routeengine` 注入 `RandSource`；新增适配层 `symmetricVerifyMAC`/`sidecarTableVerifier`/`routeRandSource`。**实测发现**：sidecar `/v1/verify` 的 `key_ref` 分支为**签名验签**（Ed25519/SM2），**不能验 HMAC** ⇒ 按仓库既有先例改用 `/v1/hmac`＋常量时间比较（用户裁决 D1）。`go build`/`go vet`/插件 7 包 `go test` 绿 |
> | 2026-10-06 | §4.3.7 **掩码下沉（B1·mask，R4·方案 A）** | `gateway/cryptopsvc/server.go` ＋ `gateway/wasm/otpmask-plugin/{cryptoclient/client.go,crypto.go,main.go}` ＋ 单测；本体 **v1.9** | **用户裁决**：`/v1/mask/stream` 入参 `key_ref` → **`seed`（base64）**。**实测依据**：插件持有的掩码 seed 来自 TEE `/key/issue`（TEE 侧 `/v1/infer` 以 `km.Lookup(nonce)` 取**同值**），**非** sidecar 内 `K_enc` 的 KDF 输出 ⇒ 原"sidecar 由 `key_ref` 派生 seed"**实现层不可达**（`recompute.go` 的 `K_enc` 派生 seed 仅用于 TEE **内部**层掩码）。落地：sidecar 去 `lookupKey`/内部 KDF、保留 PRG 选择与 seed 长度校验（hmac≥32 / sm4=16）；插件 `crypto.go` **删 `cipher/mask` 依赖**改经 sidecar（模算术留插件）；`main.go` 6 处调用点 CPS 化 ＋ 200 响应统一暂停接管。本体 §4.3.7/§5.3.2/F-P2-7 注同步订正 |
> | 2026-10-06 | §9.1 **门禁 1 判据订正** ＋ `make wasm-guard` 重定义 | `Makefile`（wasm-guard 改三断言）＋ 本体 §9.1/§16（v1.9） | **评审发现**：原 `go list -deps … \| grep '^crypto/'` **恒非零输出**——插件经 higress `wrapper` 必链 `net/http` → `crypto/tls` → `crypto/*` 全树。按 R-11「**直接** import」口径拆为 **①a**（插件源码 direct import）＋ **①b**（闭包内**本仓**包 direct import ＋闭包无 `gmsm`）＋ **②**（`protocol/go` framing）。**①b 实测命中 `security-ai-gateway/gateway/rxroute`（`crypto/hmac`+`sha256`）＝真实剩余缺口**（`route.go:126` `rxroute.VerifyWith` 处方验签），已登记 §5.4.5 待接线行 |
> | 2026-10-06 | **B2：服务侧接线·组①③⑥⑦ ＋ 组⑨存储密封** | `gateway/tee-infer-service/{crypto_runtime.go(新增),main.go,session.go,tsa.go,enclave.go,enclave_tdx.go,recompute.go}` ＋ 测试；本体 **v1.10** | **进程级 Provider 装配**（`crypto_runtime.go`：包级默认 intl ＋ `initCryptoRuntime(profile,maskPRG)`；`main.go` 增 `-crypto-profile`/`-mask-prg`＝§12.3；R-2 profile 非法/`sm-module` **启动拒**、R-21① `intl+bridge` **启动拒**、R-21② `sm+bridge` WARN、sm 档注册 SM4-GCM 套件）。**组①**：X25519→`GenerateECDHKeyPair`/`ECDH`、HKDF→`KDF`、rand→`Rand`、证明验签→`cryptop.VerifyP256`（删本地 `parseP256Pub`/`verifyP256Sig`）；`sealPayload`→`SealEnvelopeWithSuite(cryptoSuite())`（入口按 wire suite 双读）。**组⑥**：TST HMAC/Hash→Provider，`TST.Algorithm` 版本化 ＋ 验签双读。**组⑨**：飞地密封 `AES-GCM`→`Provider.SealWithNonce/Open`（**格式 AAD‖nonce‖ct 保持逐字节同构**）、`contextHash`/measure→`Hash`、`loadSealKey` 长度随 `SymmetricKeySize()`。**例外保留**（§5.4.2）：证明自签 `signProofBinding` 恒 **ECDSA-P256/SHA-256**（用户裁决 Q1；`cryptop` 仅 `VerifyP256`、无 SignP256）；`reportDataBinding` 本批暂缓（Q2，留 B4 与插件 `attest.go` 同批）。**intl 逐字节零行为变更**；`go build`/`go vet` ＋ 全仓 `go test` 绿 |
> | 2026-10-06 | **B3：审计链国密签名（组⑤）+ `audit-verify` 双验 + TST 锚（组⑥）** | `gateway/tee-infer-service/{audit.go,crypto_runtime.go,tsa.go,main.go}` ＋ `gateway/gateway-admin-service/audit.go` ＋ `gateway/gateway-core/internal/policyaudit/policyaudit.go` ＋ `gateway/audit-verify/{schema.go,verifier.go,report.go}` ＋ 新增测试 `audit-verify/hashalg_test.go`、`tee-infer-service/audit_hashalg_test.go`；本体 **v1.11** | **`hash_alg` 版本化（§5.2.2）**：三条链各增 `HashAlg`（json `hash_alg`，**证据字段不进 hash**，B-5.2-1）；`hash()`→`hash()/hashWithErr()`，字段序与长度前缀**逐字节不变**（intl 旧链哈希恒定，T-5.2-1 固定向量保持）。**分派与进程 profile 解耦（关键）**：`""` 恒 SHA-256（R-13）/`"sm3"` 恒 SM3（R-12）；各包持**固定双 provider**（SHA-256=intl / SM3=sm），不用随 profile 漂移的 `cryptoProvider`。**写入端**：tee-infer 请求路径事件打 `hashAlgTag()` 且 `PayloadSHA` 经 `payloadHashHex`（随 profile，F-P2-4 裁决）；外部固定摘要事件（策略 manifest 自摘要）保持缺省 SHA-256（同档，混合链 T-5.2-3）；admin/core 本批只落字段+分派机制（打标随 B4）。**`audit-verify`**：按 `hash_alg` 重算（R-12 未知 → 验证失败带原因；R-13 缺省 → SHA-256）、`checkTST` 按 `TST.algorithm` 分派、`ChainBreakError.Reason`。**TST 锚**：`tsa.go` sm 档 `TST.Algorithm` 由 `"hmac-sm3"` **订正为 `"sm3"`**。**intl 逐字节零行为变更**；新增 T-5.2-2..6 绿，`go build`/`go vet` ＋ 全仓 `go test` 绿 |
> | 2026-10-06 | **B4-a~e：其余业务调用点接线（组⑧⑪⑫⑬）＋ `rxroute` 拆包与插件请求头阶段 CPS** | `gateway/{tee-infer-service/recompute.go, gateway-admin-service/{crypto_runtime.go,auth.go,billing_api.go,broker_secret.go,audit.go,main.go}, gateway-core/internal/{route/routetable.go,ratelimit/signer.go,policyaudit/policyaudit.go}, auth-service/{crypto_runtime.go,jwt.go}, mcpsec/{crypto_runtime.go,model.go}, teecore/{crypto_runtime.go,keymgmt.go}, tee-infer-service/billing.go, rxroute/prescription.go, rxroute/rxsign/*(新), wasm/otpmask-plugin/{route.go,route_decide_test.go}, gateway-core/internal/route/{prescription.go,rxroute_bridge_test.go}}`；本体 **v1.12** | **a** `recompute.go` 层掩码 PRG 按 `mask_prg` 选（`newLayerStream`；seed 长度随 PRG）。**b** admin：进程 provider（`CRYPTO_PROFILE`）+ JWT/Webhook HMAC + `keyFingerprint` 恒 SHA-256 + 链写入端打标。**c** gateway-core：表签/验签 + `policyaudit` 打标。**d** auth/mcpsec/teecore（`deriveLocked` 保留 HMAC 语义，**有意偏离 §5.4.4 的 `KDF` 映射**——HKDF 会改变跨进程请求 seed）+ 计费 Webhook。**e** `rxroute` **拆包**（framing 零密码 / 新子包 `rxsign` 承载密码）+ 插件处方验签改经 **sidecar `/v1/hmac`**，并在**请求头阶段** `ActionPause`→回调内决策→`ResumeHttpRequest`（fail-closed 时**不** Resume）；`decideRoute` 退化为纯逻辑。**验收：`make wasm-guard` ①a/①b/② 全绿**；intl 逐字节零行为变更；全仓 `go build`/`vet`/`test` 绿。**缓做**：`admin/billing/{signature,ledger}.go` 持久化计费链（需算法标识+双读）→ **B5** |
> | 2026-10-06 | **B5-b：组⑬ 计费链算法标识 + 双读** | `gateway/gateway-admin-service/billing/{crypto_runtime.go(新),signature.go,ledger.go,ledger_store.go,store.go,hashalg_test.go(新),ledger_test.go}`；本体 **v1.13** | **账单签名**：`signWith` 前缀自述 `hmac-sha256:`/`hmac-sm3:`；`Verify` 改按**候选签名自身前缀**分派复算（旧账单跨档可验；无/未知前缀按 SHA-256 fail-safe = B-5.4-1）；保留双密钥轮换。**账本**：`LedgerEntry` 增 `hash_alg`（证据字段，**不进自身哈希**）；`ComputeEntryHash` 改 `(string,error)` 并按自述分派（SHA-256/SM3 两 provider **固定**、与进程 profile 解耦 ⇒ 旧条目可复算；未知值 fail-closed）。**持久化**：DDL 增列 + **幂等 `ALTER TABLE` 迁移**（捕获 `duplicate column name`）+ INSERT/SELECT/Scan 同步。**测试**：`T-5.4-⑬-1/2/3`（前缀分派双读 / sm3 标记条目落库后可验 / 未知算法 fail-closed）。intl 逐字节零行为变更；全仓 `go build`/`vet`/`test` 绿。**裁决记录**：B5-c 先行；B5-a 用「AEAD 认证决定 + 历史密钥环」 |
> | 2026-10-06 | **B5-c：profile 切换工具（§4.3.10 管理端点 + §12.6 两脚本 + 两 make）** | `gateway/gateway-admin-service/{audit.go,metrics.go,cryptop_profile.go(新),main.go,cryptop_profile_test.go(新),cryptop_profile_script_test.go(新)}` ＋ `scripts/{cryptop-switch-profile.sh,cryptop-verify-consistency.sh}(新)` ＋ `Makefile`；本体 **v1.14** | **用户裁决**：生效语义＝**编排受理**（端点校验＋sidecar 一致性＋审计＋#12 指标后受理目标态；restart 模式由外部滚动重启生效，hot 跨 provider 返 `restart_required` 409）；sidecar 缺省 `http://127.0.0.1:8082`（`CRYPTOPSVC_URL` 覆盖）。**端点** `POST /v1/adminext/cryptop/profile`（admin 角色、confirm=true、100ms 侧车超时）：from==current 否则 409 `stale_from`；GET sidecar `/v1/capabilities` 核 profile 一致（409 `inconsistent`）/不可达 503；R-14 矩阵校验（intl 仅 hmac-sha256；sm-* 为 sm4/bridge）；身份切换须带合法 PRG（400）；真 no-op 拒（400）；sm-module 501。**审计**：action `cryptop.profile.switch` + profile_from/to/switch_mode/mask_prg 四字段，**条件编码**（空值不进 hash，旧链逐字节不变）。**#12**：`gateway_cryptop_profile_switch_total{from,to}`（仅 PRG 切换 from==to 同样计数，T-12.6-5）。**脚本退出码**：0 成功（联动 verify）/2 端点拒绝/3 restart_required/4 sidecar 不可达/5 profile 不符/6 全域目标探活失败。测试：handler 面（鉴权/7 校验用例/501/409/503/成功断言审计四字段+#12/hot 跨 provider/仅 PRG/无 PRG 身份切换）＋脚本面 T-12.6-1..4（真实 git bash + mock admin/sidecar 端到端）全绿；全仓 `go build`/`vet`/`test`（39 包）绿 |
> | 2026-10-06 | **B5-a：组⑨ 存储密封双读（suite 前缀 + AEAD 认证判别 + 历史密钥环）** | `gateway/tee-infer-service/{enclave.go,enclave_tdx.go,enclave_test.go}`；本体 **v1.15** | **用户裁决**：历史密钥环经 env 注入（`OTPMASK_MOCK_SEAL_KEY_HISTORY`/`OTPMASK_TDX_SEAL_KEY_HISTORY`，冒号分隔多枚 hex，32/16 可混）；跨档启动**不自动重写**密封文件。**wire**：新写恒定 `suite(1)‖AAD‖nonce‖ct`（suite 复用 `protocol.SuiteAESGCM/SM4GCM`）。**读取**：首字节已知 suite → 固定双 provider（与进程 profile 解耦）按新格式解析，**任一失败回退无前缀旧格式**（恒 AES fail-safe）；候选密钥当前优先、环按序、仅长度匹配者。**测试**：T-7.1（intl 写→sm 环读/缺环 fail-closed）、T-7.2（sm 写→intl 回滚环读）、T-7.4（旧格式 ×intl/sm、首字节撞 0x01/0x02 真实碰撞回退、环序、篡改/上下文拒绝、新写带前缀）+ 环加载解析。`main.go` 零改动；全仓 `go build`/`vet`/`test` 绿 |
> | 2026-10-06 | **B6#13：国密切换演练编排器（T-13.1 脚本化 + T-13.2 报告模板，§13）** | `scripts/cryptop-drill.sh`（新）＋ `gateway/gateway-admin-service/cryptop_drill_script_test.go`（新）＋ `Makefile` ＋ `.gitignore`；本体 **v1.19** | **演练编排**（§13.2 八步）：① 前置检查（capabilities 可达 + 起点 profile 校验，默认 intl，`START_PROFILE` 覆盖）；② 基线快照留档 evidence；③ **三段式切换**——3.1 经既有 `cryptop-switch-profile.sh` 服务端先行（→sm-software + `PRG=bridge`），切后再取 capabilities 断言 profile/prg；3.2 插件侧结果验证（`PLUGIN_PROBE_URL` 带 `X-OTPMask-MaskVersion: sm4` 探活，**配置下发属外部系统，脚本只验结果**，未给 SKIP）；3.3 `from==to` 仅 PRG→sm4 **收桥**（T-12.6-5），记录 3.1→3.3 整段 `switch_phase_seconds`；④⑤⑥ 功能/双读/性能经 `DRILL_FUNCTION_CMD`/`DRILL_DUALREAD_CMD`/`DRILL_PERF_CMD` 钩子 `bash -c` 执行，**缺省 SKIP**（不假装环境特定步骤）；⑦ 回滚显式 `PRG=hmac-sha256`（已核对端点：无 PRG 时当前 sm4 对 intl 非法会被 R-14 拒；步7 文档简写，脚本按真实规则执行），仅当前确为 sm 时执行；⑧ 报告产出。**失败语义**：依赖步 `blocked`，失败也尽力产出报告；incidents 逐条记录。**报告 §13.4 六段**：environment / profile_switch_records / steps / incidents / compliance_note / summary+conclusion；退出码 **0（SKIP 不失败）/1 失败/2 参数错**；默认产物目录 `deploy/drill-runs/`（.gitignore）。**测试 4 用例**：bash -n；**有状态 mock 全链路**（共享 profile/prg 态随三次切换变迁，sidecar/admin/plugin 三 mock，断言切换三元组序列、九步全 pass、六段齐全、终态 intl/hmac-sha256 无残留、插件头记录 sm4）；全钩子缺省 SKIP 仍 exit0；rejectAll 时 3.1 fail + 后续 blocked + 回滚 skip + incident 非空 + exit1。**耗时说明**：端到端用例本机 17–37s——探针实证系 Git for Windows fork/exec 开销（每个子进程 125–250ms，`true` 亦 250ms；排除代理与脚本问题），脚本约百次子进程；Linux CI 毫秒级。全仓 build/vet/41 含测试包绿（commit a4a5190，4 files +661）。真实 DRILL 报告在部署环境经钩子跑出，口径同 #10 |
> | 2026-10-06 | **B6#12：国密 S2 性能基准（T-8.1/8.2/8.3，§8）** | `gateway/cryptop/bench_test.go`（新）＋ `gateway/cryptopsvc/{bench_test.go(新),server_test.go}` ＋ `Makefile`；本体 **v1.18** | **方法**：Go testing.B；发现并解决测量口径——**本机 Windows 单调钟在紧循环下读数粒度达数 ms**（逐次计时 83% 被读 0；探针实证），微基准采用**自适应组计时**（128 起 8 倍倍增探针估单次耗时，每组 ≥5ms，组耗时均摊），sidecar 采用 **64 次/组**（~8ms）；分位最近秩。**T-8.1 矩阵** {intl,sm-software}×{Seal/Open,Hash,HMAC,Sign/Verify,KDF}×{1KB,64KB}：实测比值（软件无硬比值，F-P1-6，如实报告）——SM4-GCM **33–55%**（大块 707–751 MB/s，优于主方案 20–33% 预估）、SM3/HMAC-SM3 **19–31%**（SHA-NI 拉开差距）、SM2 签名/验签 **51–83%**（1.2–1.94×，低频路径）；KDF 固定 32B 输出、secret 随尺寸（HKDF 上限 8160B，64KB 出长直接报错——首轮误测 65ns 已订正）。**T-8.2**：`TestSidecarSealLatencyP99` 两档各 4096 次强制断言（随 go test 生效）——P50 122–126µs、**P99 0.35–0.40ms ≤ 10ms**（余量 >25 倍）。**T-8.3**：64×seal(1KB) batch 1.6–1.8ms vs sequential 8.2–8.4ms，**4.5–5.1×**；`TestBatchVsSequential` 断言 batch 严格占优。夹具 newTestServer 放宽 testing.TB 复用于 Benchmark；Makefile 新增 `bench-s2`（现有 bench 不动）；全仓 build/vet/41 含测试包绿（commit d3257fd，4 files +407）；交付 **PERF-S2-1 报告**（docs/详细设计/P0，gitignore），备注 S3 选型须求 SM3/SM4 双加速指标 |
> | 2026-10-06 | **B6#10：国密 TLS 前置仓库内交付（§12.4，SM2 TLCP 双证书）** | `deploy/tlcp/certgen/{main.go,certgen_test.go}`（新）＋ `deploy/tlcp/{verify.sh,verify_script_test.go,nginx-tlcp.conf.example}`（新）＋ `Makefile`；本体 **v1.17** | **certgen**（Go，仅复用 emmansun/gmsm sm2/smx509，无自研密码）：SM2 自签根（ca.crt，keyCertSign/cRLSign）＋ 签名证书（KeyUsage **digitalSignature** critical、EKU serverAuth）＋ 加密证书（**keyEncipherment｜dataEncipherment｜keyAgreement** critical，兼容静态/ECDHE 套件）；全 SM2-SM3 签名，证书 PEM、私钥 PKCS8（PRIVATE KEY）；flag `-out/-cn/-dns/-ips/-days/-org`（产物 *.crt/*.key 已 gitignore）。**verify.sh**：T-12.4-1 `s_client -ntls` 断言协议 TLCP + 协商 ECC-SM2-WITH-SM4；T-12.4-2 `tongsuo verify` 双证书均链至 SM2 根 + SM2 OID（1.2.156.10197.1.301）+ 两公钥独立；T-12.4-3 内层信封 suite 首字节=02（ENVELOPE_FILE 可选，缺省 SKIP）；恒出证据 JSON；退出码 **0 全过 / 1 断言失败 / 7 Tongsuo 不可用全 SKIP / 8 参数错**。**nginx-tlcp.conf.example**：Tongsuo enable-ntls + TLCPv1.1 双证书 server 块，内层标准 TLS1.3 到 Envoy，并显式 XFF/X-Forwarded-Proto 透传（B-12.4-1，不透传则限流按网关 IP，R-13）。**唯一外依** = Tongsuo/Nginx 卸载二进制（运维交付件 U-12）。测试：certgen 3 用例（5 PEM/证书 profile+双链 verify+SAN/私钥证书匹配）、脚本 2 用例（Git bash `bash -n` + 无 tongsuo exit7-JSON，WSL bash 按惯例排除）；本机无 make/tongsuo，make 目标在 CI/部署机生效；全仓 41 含测试包 build/vet/test 绿（commit 9b5e3d3，6 files +720） |
> | 2026-10-06 | **B6#14：集成 + 回归测试（§11.4/11.5 真实进程级矩阵）** | `gateway/cryptopsvc/cmd/cryptopsvc/main.go`（新）＋ `e2e/{s2_harness,s2_services,s2_sidecar,s2_dualread}_e2e_test.go`（新）＋ `gateway/cryptopsvc/server_test.go` ＋ `Makefile`；本体 **v1.20** | **sidecar 可执行入口**（用户裁决落点 `cmd/cryptopsvc`）：`-listen`（缺省 127.0.0.1:8082）/`-profile`/`-mask-prg`/`-call-timeout-ms`，静态密钥经 env **`CRYPTO_STATIC_KEYS`**（JSON KeyRef→hex），启动期 R-2/R-14/R-16/R-20/R-21 校验失败 exit1。**真实进程矩阵**：**INT-1** 密码服务链（intl/sm 两档）；**INT-2** sidecar 插件全原语——HMAC 确定性断言（D1：不走 /v1/verify）、外部 P-256 验签（SEC1 裸点 + 裸 r‖s 64B + 原始消息；合法/篡改）、Seal/Open、MaskStream、Session 净值归零；**INT-3** tee→admin 跨服务三链（推理+quota）经 audit-verify 双验；**INT-4** 两阶段切换五步（hot 跨 provider 409→restart 受理→全域滚动→一致性；PRG hot 同 provider；回滚）——订正顺序：**PRG hot 须先受理（sidecar 仍 from 态）后滚动**，先滚会被判「无维度变更」；**INT-5** 密封双读 + 计费双读（intl↔sm 双向，同 DB 跨进程）；**E2E-06** sidecar 停机 fail-closed。**跨 profile 认证**：JWT 双算法（sm 进程验 **HMAC-SM3**/intl HMAC-SHA256），令牌按阶段/profile 经 `adminTokenFor`/`authHdrFor` 发放；env 同名覆盖经 `appendEnv`（Windows 重复键取首个）。**稳定性修复**：全仓并行时 Windows 调度抖动致 R-3=50ms 偶发误判 → 测试夹具 CallTimeout 放宽 1s（产品缺省不动，P99≤10ms 断言独立锁定），补 **TestR3CallTimeoutFailClosed**（中间件 + 确定 sleep 假 handler；1ns 超时断言因单调钟可读 0 被否）。**检查**：全量 e2e 8 顶层测试（含既有 TestE2E_Billing）130.7s 全绿；全仓 `build`/`vet`/`test -count=1` 绿（commit 89b4e6d，7 files +1558）。**E2E-05 真实部署环境端到端经用户裁决留场**（#13 mock 编排 + INT-4 真实切换覆盖本机可验证部分） |
>
> **接线前置发现（2026-10-05）**：详设 §5.4.5 要求 `attest.go:101,111`（`Session.sealPayload`/`openPayload`＝`cryptoops.SealEnvelope`/`OpenEnvelope`）改走 `/v1/seal`、`/v1/open`，但**信封方向子密钥在 sidecar 模型下无指定机制**，三处互斥：
> - `SealEnvelope(kEnc,…)`（`cryptoops/envelope.go:149`）的 AES key = **方向子密钥** `DeriveSubkey(kEnc,dir,suite)`（info＝`otpmask/kdf/enc/{c2s,s2c}/v1`），**非** K_enc；tee-infer `session.go:113/123` 同源。故 sidecar 必须派生**同一**子密钥才 wire 兼容。
> - §4.3.4 `/v1/seal{key_ref,aad,plaintext,nonce?}` 映射 `Provider.Seal(key,nonce,pt,aad)`＝**裸 AEAD**（用 key_ref 的**原始** key）；§4.3.8 `session/begin` 注册的 `key_ref_enc` ⇒ **原始 K_enc**（`cryptopsvc/server.go:562,567`）。⇒ 直接 `Seal(key_ref=K_enc_ref)` 会用 K_enc 当 AES key，与 tee-infer `OpenEnvelope`（派生子密钥）**不可互通**。
> - 插件**无任何指定途径**取得方向子密钥的 KeyRef：§4.3.6 `/v1/kdf` 存在且其示例入参 `alias` 恰为 `otpmask/kdf/enc/v1`（即子密钥族）→ 强烈暗示经 `/v1/kdf` 派生；但**同节** R6-P1-1 注又写「**`CryptoClient` 不设 `KDF` 方法（无插件调用点）**」，与信封需求**自相矛盾**。
>
> **影响**：阻塞子任务 #2（"插件经 sidecar 的 seal/open 打通"）与 §5.4.5 会话行（`SessionBegin`/`SessionEnd`、`attestSession` KeyRef 化）——因会话密钥材料与 seal/open/mask/sign 耦合，**无法部分迁移**（改 `Session` 持 KeyRef 即令 seal/open 无原始密钥可用）。
>
> **建议解法（待设计确认，须先修 §4.3.6 注）**：插件在 `SessionBegin` 后经 **`/v1/kdf`**（info＝`otpmask/kdf/enc/c2s/v1`·`…/s2c/v1`，`alias` 同名）派生两个**子密钥 KeyRef** 存入会话，再以之调 `/v1/seal`（显式 nonce＋aad）；`CryptoClient` 相应补 `KDF`/`DeriveSubkey` 方法，`SessionEnd` 销毁 4 个 ref（sig/enc/c2s/s2c）保 T-5.4-6 净值归零。仅用已实现端点、插件零密码、与 tee-infer 逐字节兼容。**§4.3.6 注须删「无插件调用点」。**
>
> **次要待确认**：插件静态 MAC 密钥（route verify key、JWT secret）须以 KeyRef 引用，但 13 端点无「注册/命名静态 KeyRef」者；§6.2 仅言"同一份配置可用于两 profile"，未言 sidecar 启动登记。jwt/routecache/ratelimitcache 接线前须确认 sidecar 是否按约定名（如 `otpmask/jwt/v1`）预注册。
>
> **裁决与解除（2026-10-05）**：上述阻塞已由**用户裁决"经 `/v1/kdf` 派生"**解除；详设升 **v1.7**（§4.3.6 订正注、§4.7 补 `CryptoClient.KDF`、§5.4.5 信封行＋SessionEnd 行、§16 v1.7 变更行），代码补 `protocol.EnvelopeSubkeyInfo` 单一事实源＋`CryptoClient.KDF`（上表末行）。
>
> **下一步**：执行插件**业务调用点全量接线**（§5.4.5 checklist，闭 R-11）——**顺序**：① `attestSession` KeyRef 化（`K_sig`/`K_enc`/`K_c2s`/`K_s2c` 4 ref）＋ `sealPayload`/`openPayload` 改经 `/v1/seal`/`/v1/open`（含 framing 组装）＋ 响应流式解密路径（`SSEStreamDecoder`/`processOutputBody`）的 **CPS/暂停-恢复**改造；② attest 握手（ECDH/验签/`reportDataBinding`）改经 `SessionBegin`+`/v1/verify`+`/v1/hash`；③ `SignRequest`/`VerifyResponse`→`/v1/hmac`/`/v1/verify`；④ mask→`/v1/mask/stream`；⑤ rand→`/v1/rand`；⑥ jwt/routecache/ratelimitcache→`/v1/verify`。**次要待确认**（上段）须随 ③⑥ 落定。→ 审计链国密签名（§5.2，子任务 4）。
>
> **编码期耦合发现（2026-10-05）**：上述 ①/②/③ **不可再分**（原编号为"可分步"表述，实际强耦合）——`attestSession` 一旦改持 **KeyRef**（去掉 `K_sig`/`K_enc` 原始字节），则：① 会话密钥的**生产者**只能是对 sidecar 的 `SessionBegin`（握手，②）；② `requestK_sig()`（`main.go:246`）返回的 `KeyRef` 使 `cryptoops.SignRequest`/`VerifyResponse`（`main.go:643,727,932`）无原始 key 可用 ⇒ 必须同批改 `/v1/hmac`/`/v1/verify`（③）。故 ①+②+③ 须作为**一个迁移单元**（quote 路径）落地，否则中间态不可编译。**插件 `x25519`/`ecdsa`/`sha256`/`subtle`/`cryptoops` 会随该单元一并迁出（R-11 在此单元后才可静态判定为闭）**。④⑤⑥ 相对独立，可各自成单元。**建议下一步按"①+②+③ 单元"实施**（含 §5.4.6 流式批量 CPS ＋ `envelope_test.go`/`attest_test.go`/`contentlabel_test.go` 改 mock-sidecar seam）。
>
> **执行路径调整（2026-10-06）**：上文"①–⑥ 顺序"与"①+②+③ 单元"叙述**已被批次实施（B1–B6）取代**（见本节"实施批次与进展"表）。实际路径：**B1** 先闭插件侧（非 mask 部分 ＋ 掩码下沉 R4）→ **B2** 落服务侧组①③⑥⑦⑨ → **B3** 审计双验 → **B4** 掩码 PRG 选择 ＋ 其余业务调用点（含 `rxroute`）＋ **插件 `seal/open` 单元（原①+②+③）** → B5 双读/切换 → B6 分级/TLS/基准/演练/回归。**原"①+②+③ 不可再分"结论仍成立**，只是落在 B4 而非紧接 v1.7 之后。

### 3.6 P0-5 TEE 威胁模型初稿 · 任务分解

> **v1.6 同步**：三个子任务交付物已按"**三份独立文档**"重写为发布级（原三合一《P0--TEE威胁模型初稿.md》已删除，由下列三份取代）；威胁事实全部锚定 2026-10-05 仓库代码实测（逐条含 `文件:行号`），并参考 NIST SP 800-154/800-57、IETF RFC 9334(RATS)、CCC 机密计算威胁模型、Intel TDX Threat Model、OWASP LLM Top 10、等保 GB/T 22239 / 密评 GB/T 39786 / GB/T 45654 等业界经验。
>
> **v1.7 同步（评审闭环）**：威胁模型先经**第 1 轮多角色评审**（`…-多角色评审报告-第1轮.md`，总评 B）修订，再经**第 2 轮元评审**（`…-多角色评审报告-第2轮.md`，总评 **A-，通过**）：17 项处置全部闭环且证据可核、未处置项无虚标；元评审新发现 5 项已处置；**其后 D-1 锚点统一 → A-1 立项（P1-8）→ v0.6 P2/P3 余项全量收尾。GAP-01/05 已随本轮交付闭环。**
> **v1.9 同步（白皮书大纲评审闭环）**：**《安全白皮书大纲》**经第 1 轮多角色评审（总评 B：1 P0 + 6 P1 + 16 P2 + 8 P3）修订为 **v1.1**，再经第 2 轮元评审（总评 **A-，通过**，31 项处置全部闭环）；大纲目录补 LLM 威胁/LINDDUN、锚点统一 `文件:符号`、门禁增"证据可核性 + GAP 一致性"。
> **v1.11 同步（侧信道披露评审闭环）**：**《侧信道风险披露说明》**经第 1 轮多角色评审（总评 B：1 P0 + 5 P1 + 12 P2 + 8 P3）修订为 **v1.1**，再经第 2 轮元评审（总评 **A-，通过**，26 项处置全部闭环；元评审即时订正 2 项路径问题）。**至此 P0-5 三份交付物全部两轮评审通过（A-）**，待安全/法务/产品三方会签后对外。
> **v1.12 同步（系统性评审修复）**：威胁模型升 **v0.7**，修复 6 项问题（口径统一/DFD 增强/SLSA 路线/GAP 回填机制/资产分级判据/测试映射扩充），详见《TEE 威胁模型》变更记录 v0.7 条目。

| 子任务 | 工作量 | 状态 | 负责人 | 依赖 | 起止周 | 对应交付物 | 验收判据 | 设计深度 |
|---|---|---|---|---|---|---|---|---|
| 威胁模型文档（v0.1 → **v0.7**） | 3 天 | ✅ v0.7（两轮多角色评审 A-；系统性评审修复 6 项：口径统一/DFD 增强/SLSA 路线/GAP 回填机制/资产分级判据/测试映射扩充） | 待分配 | — | W1 | [P0--TEE威胁模型.md](./P0/GA-AI网关能力补齐方案--P0--TEE威胁模型.md) | 覆盖主方案 §4.5.2 全部威胁范围；含方法论/信任边界/资产/攻击者模型/DFD 要素编号/威胁清单（STRIDE 39 + 供应链 6 = 45 条 + LLM 特有 5 条）/4 棵攻击树/缓解-验证矩阵/12 项 GAP；每条现状可回溯代码锚点（符号优先）；含 LINDDUN 隐私维度 | **L3** |
| 安全白皮书大纲 + 目录 | 1 天 | ✅ **v1.1**（第 1 轮多角色评审 + 第 2 轮元评审**均通过，A-**） | 待分配 | 威胁模型初稿 | W2 | [P0--安全白皮书大纲.md](./P0/GA-AI网关能力补齐方案--P0--安全白皮书大纲.md) | 锁定 11 章三级目录；逐章含"要点/素材来源/角色/字数/依赖/DoD"；含措辞红线（以披露说明 §7 为准）与证据优先级（`文件:符号`）；含 G0-G4 门禁 + 三项必做检查；目录含 LLM 威胁与 LINDDUN | L2 |
| 侧信道风险披露说明 | 1 天 | ✅ **v1.1**（第 1 轮多角色评审 + 第 2 轮元评审**均通过，A-**；26 项处置完毕） | 待分配 | 威胁模型初稿 | W2 | [P0--侧信道风险披露说明.md](./P0/GA-AI网关能力补齐方案--P0--侧信道风险披露说明.md) | 覆盖 7 类侧信道/相关威胁边界（含 **§3.7 输出侧明文 TG-I-12**）；**10 项**已实施缓解（含代码符号级佐证）；**9 项**不承诺范围；4 套标准话术（中/英/极简/技术）+ **§6.5 能力分级对照**；**7+5+4** 禁止/应避免/强制限定词；10 条客户 Q&A；含法规依据、**§10.4 版本绑定**与三方会签控制；附录 C 能力-证据索引 | L2 |

> **验收与后续**：① 三份文档待**安全工程师 + 架构师 + 法务**评审会签后对外；② 威胁模型 §10.2 的 **GAP-01/GAP-05**（生产禁用 mock / 生产强制管理令牌）**已随本轮交付闭环**（`startup_guard.go` + `-dev-mode`，2026-10-05）；③ 其余 GAP 随 P1 白皮书（M4-M5）与 P1-3 等保 / P1-5 密评协同推进（**P1 安全加固类 GAP 需在研发计划立项并指派 owner**）；④ 侧信道披露为**对外口径唯一源**，白皮书第 10 章须逐字引用。

---

## 4. P1 详细进度（3-6 个月）

> P1 详细任务分解将在 P0 开发过半（约 W6-W8）时补充。以下为里程碑级规划（**P1-8 安全加固已先行分解，见 §4.1**）。

| 功能 | M4（第 4 月） | M5（第 5 月） | M6（第 6 月） | 状态 |
|---|---|---|---|---|
| P1-2 全链路 tracing | 启动 + 70% 覆盖率 | v1 + 90% 覆盖率 + 排障面板 | 优化 + 稳定 | 🔲 |
| P1-3 等保合规 | 差距分析 + 技术整改启动 | 技术整改 + 渗透测试 + 白皮书 | 进入测评 | 🔲 |
| P1-4 多租户自助门户 | 后端 API + 注册/Key 管理 | 用量 + 账单 + 策略配置 | 审计查询 + 优化 | 🔲 |
| P1-5 国密 S3+S4 | S3 选型 + S3 接入联调 | S3 生产接入 + S4 差距分析 | S4 整改启动 + 等保同步 | 🔲 |
| P1-6 TTFT 严格择优 | 策略引擎设计 + PoC | 策略引擎 + gateway-core 集成 | 上线 + 优化 | 🔲 |
| P1-7 全流量审计改造 | 方案确定 + 开发启动 | 上线 + 调优 | 稳定 + 等保验证 | 🔲 |
| P1-8 安全加固（GAP 闭环） | T1/T2/T3/T4/T6 完成（证明链/度量/飞地鉴权/密封密钥/overlay） | T5（审计 fail-closed）+ 集成回归 | 稳定 + GAP 状态回填 | 🔲 |

### 4.1 P1-8 安全加固（威胁模型 GAP 闭环）· 任务分解

> **立项依据**：《TEE 威胁模型》v0.4 §10.2 的 **P1 安全加固类 GAP（GAP-02/03/04/06/09/10）**。
> **负责人：待指派**（人名留空；**评审须与主责分离**）。指派后回填本表与 §7.2。

| 子任务 | 对应 GAP | 工作量 | 状态 | 负责人 | 依赖 | 阶段 | 验收判据 |
|---|---|---|---|---|---|---|---|
| T1 真实远程证明接线（`attest-verify` 接入客户端信任路径 + Intel PCS/DCAP 证明链） | GAP-02 | 2-3 周 | 🔲 | 待指派 | 真机 TDX 可用 | M4 | 真机 Quote 验证通过；伪造 Quote 被拒 |
| T2 飞地度量校验（解析 MRTD/RTMR 并与白名单比对） | GAP-03 | 1-2 周 | 🔲 | 待指派 | T1 | M4 | 度量不匹配即拒绝会话 |
| T3 飞地端鉴权（JWT 验签 + 租户声明强校验；`X-Tenant-ID` 降为提示） | GAP-04 | 1.5-2 周 | 🔲 | 待指派 | — | M4 | 无有效令牌 → 401/403；跨租户矩阵通过 |
| T4 密封密钥 TDX 派生（或 KMS 注入 + 内存零化） | GAP-06 | 1-2 周 | 🔲 | 待指派 | 真机 TDX | M4 | 无派生密钥时密封文件不可解 |
| T5 审计链写失败 fail-closed（可配置）+ 真 WORM 后端 | GAP-09 | 1-2 周 | 🔲 | 待指派 | 存储后端选型 | M5 | 写失败即拒服务；外部公证可验 |
| T6 overlay 修正（sgx 与实现不一致）+ 外部 RFC3161 TSA 接入 | GAP-10 | 1 周 | 🔲 | 待指派 | TSA 证书 | M4 | overlay 启动不 Fatal；TST 可被独立验签 |
| T7 集成与回归 | — | 1 周 | 🔲 | 待指派 | T1-T6 | M5 | 威胁模型 §9.7 测试锚点全绿；GAP 状态回填威胁模型 |

> 合计约 **9-13 人周**（与 §2.2 P1-8 估一致）。**GAP-07/08 → P1-3；GAP-11 → P0-4；GAP-12 → P2**，不在本表。

---

## 5. P2 概览（6-12 个月+）

> P2 待 P1 启动后再做详细分解。当前为里程碑级规划。

| 功能 | 目标时间 | 前置依赖 | 状态 |
|---|---|---|---|
| P2-1 MCP 协议网关化 | M7-M9 | MCP bridge 已存在 + 网关策略框架成熟 | 🔲 |
| P2-2 A2A 协议支持 | M9-M10 | MCP 网关化基础 | 🔲 |
| P2-3 HSM 集成（金融级） | M7-M9 | 国密 S3 接入完成 + 金融客户需求 | 🔲 |
| P2-4 多集群管理 | M9-M12 | 单集群稳定 + 客户规模上来 | 🔲 |
| P2-5 插件市场/开发者生态 | M10-M12 | 插件体系稳定 + 外部开发者需求 | 🔲 |
| P2-6 行业解决方案模板 | M8-M12 | 等保+密评通过 + 标杆案例 | 🔲 |

---

## 6. 里程碑与关键路径

### 6.1 里程碑总览

| 里程碑 | 时间 | 关键交付 | 关键验收标准 |
|---|---|---|---|
| **M0** | W0 | P0 启动 | 启动会通过 + 技术选型确认 + 详细设计模板就位 |
| **M1** | 第 1 月末 | 路由主备+权重 + 国密下沉 PoC + TEE 威胁模型初稿 | 主备切换 100% 成功；密码下沉 PoC 通过 |
| **M2** | 第 2 月末 | 路由三策略完整 + 国密 S2 核心下沉 + 精确缓存 | 失败率感知可用；双读兼容通过；精确缓存可测 |
| **M3** | 第 3 月末 | 缓存二期 gate 评审 + 语义缓存灰度（条件达成） + 计费体系完善 + 国密 S2 收尾 + 切换演练 | P0 全量验收通过；精确缓存达标 + 场景重复率评估通过 → gate 通过启动灰度；演练报告产出 |
| **M4** | 第 4 月末 | 套餐账单系统 + tracing 启动 + 等保差距分析 + S3 选型 | SaaS 可收费；tracing 覆盖率 > 70% |
| **M5** | 第 5 月末 | tracing v1 + 白皮书 + 等保整改 + S3 接入 + 全流量审计上线 | tracing > 90%；渗透测试首轮完成 |
| **M6** | 第 6 月末 | 等保进入测评 + 门户 v1 + 密评启动 + TTFT 择优上线 | P1 验收通过；等保初测完成 |
| **M7-M9** | 第 7-9 月 | 密评通过（力争） + 三证拿齐 + 战略窗口收尾 | 密评报告获取；P2 启动 |

### 6.2 关键路径（Critical Path）

```
P0 启动 → 国密 S2 PoC → 信封加密国密化 → 业务调用点全量接线 → 双读兼容 → 国密切换演练 → P0 验收
          ↘ 路由 → 计费 → 套餐账单 → 收费闭环 ↗
```

**最长路径**：国密 S2 下沉（约 7-9 周），是 P0 关键路径上耗时最长的单项。

---

## 7. 团队与分工

### 7.1 团队配置（满配）

| 角色 | 人数 | P0 投入 | 主要负责模块 |
|---|---|---|---|
| 后端工程师（Go） | 3-4 人 | 100% | 路由、缓存、计费、国密、tracing |
| 前端工程师 | 1-1.5 人 | 60-80% | 缓存看板、自助门户、排障面板 |
| 安全工程师 | 0.5-1 人 | 100% | 国密架构、威胁模型、渗透测试、等保密评 |
| 测试工程师 | 1.5-2 人 | 100% | 全模块测试、混沌测试、性能测试 |
| 运维/DevOps | 0.5-1 人 | 70% | CI/CD、Redis、监控、部署 |
| 产品经理 | 1 人 | 100% | 需求、优先级、验收、对外协调 |

> 待补充具体人员名单与分工。

### 7.2 模块责任人矩阵

| 模块 | 主负责人 | 备份负责人 | 设计评审人 |
|---|---|---|---|
| P0-1 路由 | 待分配 | 待分配 | 待分配 |
| P0-2 缓存 | 待分配 | 待分配 | 待分配 |
| P0-3 计费 | 待分配 | 待分配 | 待分配 |
| P0-4 国密 S2 | 待分配 | 待分配 | 待分配 |
| P0-5 TEE 威胁模型 | 待分配 | 待分配 | 待分配 |
| P1-8 安全加固（GAP 闭环） | 待指派 | 待指派 | 待指派 |

> **P1-8 负责人待指派**（人名留空）：指派后须回填本表与 §4.1，并同步《P0--TEE威胁模型》§10.2「研发计划登记」列（A-1 追溯闭环）。

---

## 8. 进度管理机制

### 8.1 会议节奏

| 会议 | 频率 | 参与人 | 产出 |
|---|---|---|---|
| **站会** | 每日 10 分钟 | 全体研发 | 当日进度 + 阻塞问题 |
| **周进度会** | 每周一 1 小时 | 全体 + 产品 | 上周总结 + 本周计划 + 风险同步 |
| **迭代评审会** | 每 2 周 2 小时 | 全体 + 业务方 | 迭代交付演示 + 反馈收集 |
| **架构评审会** | 按需（重要设计前） | 架构师 + 模块负责人 | 技术方案评审结论 |
| **里程碑评审** | 每月末 | 全体 + 管理层 | 里程碑验收 + 下月计划 |

### 8.2 文档更新机制

- **本进度总表**：每周一更新（周进度会后）
- **详细设计文档**：设计完成后冻结，变更走评审流程
- **方案本体文档（v5.x）**：重大变更时同步更新，作为口径锚点
- **状态流转**：详细设计完成 → 开发中 → 测试中 → 已完成，每次状态变更必须更新本文档

### 8.3 完成定义（DoD）

每项功能"完成"意味着：

- [ ] 详细设计文档评审通过
- [ ] 代码开发完成 + Code Review 通过
- [ ] 单元测试覆盖率 > 80%
- [ ] 集成测试通过
- [ ] E2E 测试通过
- [ ] 性能基准测试达标（如适用）
- [ ] 安全评审通过（安全相关功能）
- [ ] 文档齐全（API 文档 + 运维文档 + 变更记录）
- [ ] 生产灰度验证通过（如适用）
- [ ] 本进度表状态更新为 ✅

---

## 9. 风险与问题跟踪

### 9.1 当前开放风险

| ID | 风险描述 | 影响 | 概率 | 应对措施 | 状态 | 责任人 |
|---|---|---|---|---|---|---|
| R-001 | Redis VSS 版本不匹配（现网是 7.x） | 高 | 中 | P0 启动前确认 Redis 版本；若不可升级，评估 Milvus 替代方案 | 🔲 待确认 | 待分配 |
| R-002 | 国密下沉后延迟增加超预期 | 中 | 中 | PoC 阶段重点测性能；本地 sidecar + 连接池优化 | 🔲 PoC 验证 | 待分配 |
| R-003 | ai-proxy 扩展能力不足，需走 gateway-core 路径 | 中 | 中 | W1 完成 PoC 验证；预留 gateway-core 方案 2-3 人周 | 🔲 PoC 验证 | 待分配 |
| R-004 | P0 四件套人力吃紧，四项都延期 | 高 | 中 | 两波次交付（准入波+商业波）；优先级动态调整 | 🔲 跟踪 | 待分配 |
| R-005 | 密评周期不可控（通常 3-6 个月） | 高 | 高 | M4 启动差距分析，预留充足整改时间 | 🔲 远期 | 待分配 |

### 9.2 问题日志

| ID | 问题描述 | 发现日期 | 状态 | 解决方案 | 责任人 | 关闭日期 |
|---|---|---|---|---|---|---|
| （暂无） | — | — | — | — | — | — |

---

## 10. 详细设计文档索引

### P0 阶段（7 份）

- [P0--多模型智能路由](./P0/GA-AI网关能力补齐方案--P0--多模型智能路由.md)
- [P0--语义缓存](./P0/GA-AI网关能力补齐方案--P0--语义缓存.md)
- [P0--Token计费体系完善](./P0/GA-AI网关能力补齐方案--P0--Token计费体系完善.md)
- [P0--国密S2核心路径下沉](./P0/GA-AI网关能力补齐方案--P0--国密S2核心路径下沉.md)
- [P0--TEE威胁模型](./P0/GA-AI网关能力补齐方案--P0--TEE威胁模型.md)（P0-5 本体）
- [P0--安全白皮书大纲](./P0/GA-AI网关能力补齐方案--P0--安全白皮书大纲.md)（P0-5 交付物）
- [P0--侧信道风险披露说明](./P0/GA-AI网关能力补齐方案--P0--侧信道风险披露说明.md)（P0-5 交付物）

### P1 阶段（7 份）

- [P1--MCP协议网关](./P1/GA-AI网关能力补齐方案--P1--MCP协议网关.md)
- [P1--全链路tracing](./P1/GA-AI网关能力补齐方案--P1--全链路tracing.md)
- [P1--等保合规资质路径](./P1/GA-AI网关能力补齐方案--P1--等保合规资质路径.md)
- [P1--多租户自助门户](./P1/GA-AI网关能力补齐方案--P1--多租户自助门户.md)
- [P1--国密S3-S4认证模块与密评](./P1/GA-AI网关能力补齐方案--P1--国密S3-S4认证模块与密评.md)
- [P1--TTFT严格性能择优](./P1/GA-AI网关能力补齐方案--P1--TTFT严格性能择优.md)
- [P1--全流量审计改造](./P1/GA-AI网关能力补齐方案--P1--全流量审计改造.md)

### P2 阶段（6 份）

- [P2--MCP协议网关化](./P2/GA-AI网关能力补齐方案--P2--MCP协议网关化.md)
- [P2--A2A协议支持](./P2/GA-AI网关能力补齐方案--P2--A2A协议支持.md)
- [P2--HSM集成](./P2/GA-AI网关能力补齐方案--P2--HSM集成.md)
- [P2--多集群管理](./P2/GA-AI网关能力补齐方案--P2--多集群管理.md)
- [P2--插件市场与开发者生态](./P2/GA-AI网关能力补齐方案--P2--插件市场与开发者生态.md)
- [P2--行业解决方案模板](./P2/GA-AI网关能力补齐方案--P2--行业解决方案模板.md)

---

> 文档结束。本文档为能力补齐项目的研发主计划，所有进度跟踪以本文为准。每周一更新。
