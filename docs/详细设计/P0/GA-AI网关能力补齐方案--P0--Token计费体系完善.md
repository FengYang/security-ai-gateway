# GA-AI 网关能力补齐方案 -- P0 -- Token 计费体系完善

> **文档性质**：开发级详细设计文档
> **所属阶段**：P0（0-3 个月）
> **模块编号**：P0-3
> **版本**：v1.7 · 2026-10-02
> **基准依据**：《GA-AI 网关能力补齐方案》v5.5 第 4.3 节；《GA-AI网关能力补齐--研发计划与进度跟踪》§3.4（P0-3 任务分解）；《GA-计费接口设计》（接口冻结）；《GA-控制面限流与计量设计》（执行点矩阵 / 容差 0 / 预算周期 UTC+8）
> **质量门禁**：《多模型智能路由》附录 F（L1/L2/L3 三级标准 + F.2 评审必查项 + F.3 任务-设计双向追溯）
> **行业对标**：LiteLLM（预算/Key 级限额）、Portkey（→ PANW Prisma AIRS，用量分析）、1Panel AI 网关（组→用户→Key 三级配额继承 + 六维用量统计）、OpenRouter（credits 计量）
> **当前状态**：✅ 详细设计 v1.7（全文重写为开发级详细设计；覆盖研发计划 §3.4 8 项 + 骨架 §13 15 行 + 主方案 §4.3.3 任务的并集，逐项达 L3；**已应用第 1 轮评审修复** A-1..A-11、**第 2 轮评审修复** A-12..A-20、**第 3 轮评审修复** A-21..A-25 + O-7 + D-11、**第 4 轮评审修复** A-26..A-31 + O-8 + D-12、**第 5 轮评审修复** A-32..A-38 + D-13、**第 6 轮评审修复** A-39..A-43 + D-14..D-17、**第 7 轮评审修复** A-44..A-52，自检见附录 A、§16 变更记录）
> **负责人**：待分配
> **预估工作量**：41 人日 ≈ 8.2 人周（§13.1 逐行合计口径；主方案 §4.3.3 计 7-8 人周，本表按可施工粒度拆分）
> **计划起止**：W1 - W8
> **上一版本**：v1.6（2026-10-02，应用第 6 轮评审 A-39..A-43 + D-14..D-17）；v1.5（2026-10-02，应用第 5 轮评审 A-32..A-38 + D-13）；v1.4（2026-10-01，应用第 4 轮评审 A-26..A-31 + O-8 + D-12）；v1.3（2026-10-01，应用第 3 轮评审 A-21..A-25 + O-7 + D-11）；v1.2（2026-10-01，应用第 2 轮评审 A-12..A-20 + D-9/D-10）；v1.1（2026-10-01，应用第 1 轮评审 A-1..A-11）；v1.0（2026-10-01 全文重写达 L3）；v0.1（2026-09-29 骨架版，14 处"待补充"）

---

## 阅读指引

### 设计深度标记

本文档每个功能点顶部标注设计深度（附录 F.1 三级标准）：

| 等级 | 含义 | 本文档覆盖 |
|---|---|---|
| **L3** | 完整伪代码 + 接口定义 + 边界条件 + 运行环境适配 + 测试用例清单 | ✅ 全部 16 项任务（含**选型类子项**：其 L3 落点＝"选型深度 L3"，候选/结论/风险/退路齐全，见 §5.6） |
| L2 | 状态机/流程图 + 伪代码 + 数据结构 + 边界条件 | — |
| L1 | 概念级（不能开发） | — |

> **口径适配说明**：附录 F.1 的 L3 定义含"Wasm 适配说明"一项。本模块**不在 Wasm 内运行**——账单/套餐/定价/查询是**控制面账务域**（落 `gateway/gateway-admin-service`，主方案 §4.3.2 归属），数据面路由仅承担"重试标记下行"这一处边缘接线（§6.3.3，**不提供 token**）。故以"**运行环境适配（admin-service 进程约束 + 与 TEE 数据面的松耦合）**"（§6.15）替代"Wasm 适配说明"，覆盖同一审查意图（内存、并发模型、无阻塞调用、调用边界）。

### 术语与口径

| 术语 | 定义 | 出处 |
|---|---|---|
| **计量（metering）** | 在 TEE 明文域内按请求累加 `tokens_in/tokens_out/requests` 并落审计链 | `gateway/tee-infer-service/main.go:265`、`audit.go` |
| **账本（ledger）** | 控制面账务域内、由计量数据重建的**追加式**计费账户（哈希链） | 本文 §5.1 |
| **计价（rating）** | 把用量（标准 token）按**单价表 + 系数 + 阶梯**折算为金额 | 本文 §6.5 |
| **出账（billing/结算）** | 日结/月结生成账单、签名、交付、冻结 | 本文 §6.6-6.8/§6.10 |
| **标准 token** | 以系数折算后的统一计费单位：`tokens_in×in_coef + tokens_out×out_coef` | 本文 §6.5 |
| **平台成本 token** | 重试（retry）产生、**不计入用户**的 token（计平台成本） | 主方案 §4.3.2；本文 §6.3.3/§6.5.4 |
| **计量唯一真源** | `tee-infer` 审计链——Higress 只见密文无法计量 | `billing.go:4` |
| **零容差** | 账本 ↔ 审计链逐日逐租户三元组（requests/tokens_in/tokens_out）差异 **= 0** | `reconcile.go:5`；主方案 §4.3.5 |
| **出账门禁** | 账单生成/交付前的硬阻断：对账不通过 → 冻结该租户账单 | 本文 §6.12 |
| **TEE 明文域** | `tee-infer-service` 进程内可信执行环境；本项目唯一允许出现请求/响应明文的位置 | 项目机密边界铁律 |

---

## 目录

1. [背景与目标](#1-背景与目标)
2. [功能范围](#2-功能范围)
3. [架构设计](#3-架构设计)
4. [接口设计](#4-接口设计)
5. [数据模型](#5-数据模型)
6. [详细流程](#6-详细流程)
7. [数据完整性与防篡改](#7-数据完整性与防篡改)
8. [性能与容量规划](#8-性能与容量规划)
9. [可观测性](#9-可观测性)
10. [测试方案](#10-测试方案)
11. [部署与配置](#11-部署与配置)
12. [灰度发布](#12-灰度发布)
13. [任务拆解与进度](#13-任务拆解与进度)
14. [风险与依赖](#14-风险与依赖)
15. [待确认事项](#15-待确认事项)
16. [变更记录](#16-变更记录)
- [附录 A：L3 覆盖度自检表](#附录-al3-覆盖度自检表)
- [附录 B：边界条件总表](#附录-b边界条件总表)
- [附录 C：测试用例总表](#附录-c测试用例总表)
- [附录 D：套餐与定价模型（含阶梯/系数）](#附录-d套餐与定价模型含阶梯系数)
- [附录 E：与旧版 v0.1 的差异订正](#附录-e与旧版-v01-的差异订正)
- [附录 F：既有计费链路现状复核（代码实证）](#附录-f既有计费链路现状复核代码实证)

---

## 1. 背景与目标

### 1.1 背景

计费是商业模式的基础。本项目**底层已上生产**（计量 + 审计链 + 对账），但**上层（套餐/账单/自助）尚未实现**，无法支撑商业化收费：

- **已就绪**（代码实证，见附录 F）：`tee-infer` 内 token 级计量（`usageRecord`，`main.go:217`）、审计哈希链（`audit.go`，唯一真源）、`GET /usage`（累计）+ `from/to` 增量聚合（`billing.go:53`）、零容差对账（`reconcile.go`，容差 0，5 差异分类）、Webhook 推送端（HMAC + 重试 + 幂等，`billing.go:96-254`）、配额引擎 `teequota`（预占式原子计数 + `POST /usage/quota`，多维窗口 minute/day）。
- **缺口**（本文档要补）：① 无套餐模型；② 无单价表/金额（现状**刻意无单价**，`usage.go:24` 硬约束；单价由外部计费系统维护，`GA-计费接口设计.md:23`）；③ 无日结/月结账单与导出；④ 无租户自助账单查询；⑤ 数据面重试计费**未接线**（`engine.go:633` 传 `-1` token）；⑥ 无异常检测/冻结。

主方案 §4.3 将 Token 计费体系列为 P0-3，目标"解锁 SaaS 商业模式，支持企业分级套餐与租户自助管理"。

### 1.2 目标

| 维度 | 目标 |
|---|---|
| **套餐与配额** | 4 档套餐（免费/基础/专业/企业）定义、租户绑定与升降级；按套餐编译 token 配额与并发/速率限制；**热下发不重启**（复用 `teequota` 推拉架构） |
| **计量接线** | 重试标记由数据面路由经**请求头**（`X-Otpmask-Retry-Attempt`）传播至 `tee-infer`，`tee-infer` 给审计事件打 `IsRetry` 并随 push 携带**真实 token**（§6.3.3）；重试 token 归**平台成本**，不计用户 |
| **多模型计费** | 单价表（控制面配置，非硬编码）+ 输入/输出系数换算 + 阶梯定价（累进） |
| **账单** | 日结/月结自动生成、账单明细、CSV/PDF 导出、签名 |
| **自助查询** | 租户级用量/配额/账单查询 API + 余额告警 |
| **完整性** | 账本哈希链 + 日账单签名（用户可验证）+ 计费↔审计**双向关联** |
| **异常与冻结** | 用量突增/对账差异/配额预警/单价缺失 四类检测 + 账单冻结机制 |
| **向后兼容** | 默认 `billing.enabled=false` 时，**与现网逐字节行为一致**（无账单、无金额、`/usage` 响应不变，附录 F.2.4） |
| **机密边界** | 账务域**不接触明文**；单价表为公开配置；金额计算不需要内容明文 |

### 1.3 成功指标（可测量口径）

> 所有指标给出**公式 + 数据来源**，避免"指标存在但无法判定达标"（附录 F.2.5）。

| # | 指标 | 公式 | 目标 | 数据来源 | 关联任务 |
|---|---|---|---|---|---|
| M1 | 计量↔账本完整性 | `Σ(账本三元组) − Σ(审计链三元组)`（逐日逐租户） | **= 0**（硬门禁） | `gateway_admin_billing_reconcile_diff`（§9.1 #11）+ `/audit` | T3/T13 |
| M2 | 计费准确率 | 对账回归用例通过数 / 总用例数 | **100%** | §10.4 回归报告 | T13 |
| M3 | 日结及时率 | 日结完成时刻 ≤ 次日 `daily_close_at + 20min` | ≥ 99.9% | `gateway_admin_billing_close_duration_seconds`（§9.1 #7） | T5 |
| M4 | 月结及时率 | 次月 1 日 `monthly_close_at + 60min` 前完成 | 100% | 同上（`kind=monthly`） | T5 |
| M5 | 用量查询 API 延迟 | p95（进程内查询 + DB 读） | < 200ms | `gateway_admin_billing_api_duration_seconds`（§9.1 #9） | T6 |
| M6 | 配额热生效时延 | 套餐变更受理 → **回读确认**信号（**回读确认**：`GET /usage/quota` 返回"已生效限额 == 目标"；未确认则重试/告警）≤ 60s | ≤ 60s | `gateway_admin_billing_quota_apply_duration_seconds`（§9.1 #13） | T2 |
| M7 | 异常检测覆盖率 | 4 类规则（突增/对账差异/配额预警/单价缺失）有指标 + 告警的比例 | 100% | §9.1 #10-12、#14 + 告警规则清单（§9.3） | T8 |
| M8 | 账单可验证率 | 签名验证通过账单数 / 已出账单数 | 100% | `/billing/{id}/verify` 全绿 | T7 |
| M9 | 重试 token 归平台 | 用户账单中 `retry_tokens` 合计 | **= 0**（不变量） | 账本 `retry_toks` 列 + 账单明细（§6.5.4） | T3/T4 |
| M10 | 金额域隔离 | `/usage` 域响应含金额字段的用例数 | **= 0**（不变量，CI 校验） | §10.4 字段扫描用例 `S-3` | T6/T7 |

> **M1 与"0.1%"的关系（口径澄清，第 1 轮自查）**：主方案 §4.3.2 异常检测写"对账差异 > 0.1%"，§4.3.5 验收写"零差异"。二者**层次不同**——**出账门禁**恒为 **0 差异**（硬，M1）；**异常检测告警**用 **0.1%** 作**告警分级阈值**（软）：`0 < ratio ≤ 0.1%` → `warning`（**不冻结**、自动触发**未入账尾段**回补重拉；★ BUG-001 订正：原“重叠窗口回补”已改为游标非重叠 + 按 UTC+8 自然日切分，回补只重拉未入账尾段）；`ratio > 0.1%` → `critical`（**冻结**该租户账单 + 人工介入）。即"冻结恒在 > 0"，0.1% 只影响**告警级别与是否需人工**。该口径精确化登记 **U-6**。

### 1.4 行业对标速览

> 对标事实取自本项目已核验的竞品总报告（2026-09 核验，`docs/GA-竞品对比分析-1Panel与主流AI网关-2026-09-16.md`）。未核验项标注「待核验」并不作设计依据。

| 能力 | LiteLLM | 1Panel AI 网关 | Portkey(→PANW) | 本方案 |
|---|---|---|---|---|
| 配额层级 | Key/Team/User 预算 | **组→用户→Key 三级继承** | Workspace/Key | 套餐→租户（+ 附加维度），**继承模型列 U-7** |
| 用量统计维度 | 多维度 | **六维** | 多维度 | tenant × model × 日/月（三维，§5.5） |
| 账单/结算 | 外部对接为主 | 用量日志推 ES | 分析面板 | **内建日结/月结 + 签名**（超集） |
| 阶梯定价 | 支持 | 支持 | 支持 | **累进阶梯**（§6.5） |
| 重试不计费 | — | — | — | **平台成本口径**（§6.5.4） |
| 金额可验证 | — | — | — | **账单签名 + 审计链关联**（§7） |

**结论：本方案在"账单完整性/可验证性"与"TEE 计费口径"上无同构竞品**（竞品多以外部计费系统 + ES 日志为主）。

---

## 2. 功能范围

### 2.1 In Scope（研发计划 §3.4 ∪ 骨架 §13 ∪ 主方案 §4.3.3 的并集）

| # | 子任务 | 来源 | 本文档设计章节 | 目标深度 |
|---|---|---|---|---|
| T0 | 详细设计文档输出（本任务） | 研发计划 §3.4 | 全文 | L3 |
| T1 | 套餐系统：4 档定义 + 配额模板 + 升降级 + 超期/超额策略 | 研发计划 §3.4②；主方案 §4.3.3 | §4.1.2 / §5.2 / §6.4 | L3 |
| T2 | 配额与速率限制：套餐→配额编译 + 多维 enforce + 热下发 | 骨架 §13；主方案 §4.3.3 | §4.1.3 / §4.4 / §6.4 | L3 |
| T3 | 计量服务：retry 标记经请求头传播 + 平台成本口径（A-1 重定位） | 骨架 §13 | §4.1.5 / §6.3 | L3 |
| T4 | 多模型计费：单价表 + 系数换算 + 阶梯定价 | 研发计划 §3.4⑤；主方案 §4.3.3 | §4.2 / §5.4 / §6.5 / 附录 D | L3 |
| T5 | 账单系统：日结/月结 + 明细 + 导出 | 研发计划 §3.4③；主方案 §4.3.3 | §4.1.6 / §5.3 / §6.6-6.8 | L3 |
| T6 | 用量查询 API：租户自助 + 余额告警 | 研发计划 §3.4④；主方案 §4.3.3 | §4.3 / §6.11 | L3 |
| T7 | 计费数据完整性：账本哈希链 + 账单签名 + 审计联动 | 研发计划 §3.4⑥；主方案 §4.3.3 | §7.1-7.3 | L3 |
| T8 | 账单异常检测 + 冻结机制 | 研发计划 §3.4⑦；主方案 §4.3.3 | §4.1.7 / §6.9-6.10 | L3 |
| T9 | 管理后台：套餐/账单页面 | 主方案 §4.3.3 | §4.3.4 | L3 |
| T10 | 可观测性 + 仪表盘 | 骨架 §13 | §9.1-9.5 | L3 |
| T11 | 单元测试 | 骨架 §13 | §10.1 | L3 |
| T12 | 集成测试 | 骨架 §13 | §10.2 | L3 |
| T13 | 对账回归测试（零容差）+ 零容差校验 | 研发计划 §3.4⑧ | §10.4 | L3 |
| T14 | E2E 测试 | 骨架 §13 | §10.3 | L3 |
| T15 | 文档 + 上线验收 | 骨架 §13 | §11.3 / §12 | L3 |

> 覆盖度自检见 **附录 A**（逐子任务对照附录 F.2 五项检查）。
>
> **补充纳入项**（主方案 §4.3.1/§4.3.2 明确、子任务未单列，并入 T1/T2/T5）：
> - **预付费/后付费两模式**：主方案 §4.3.1 列为 P1 → 本文 **Out of Scope**（§2.2），仅预留 `Plan.PayMode` 字段（§5.2）不实现。
> - **套餐与配额热更新**（主方案 §4.3.1 P0）→ 并入 T2。
> - **`/usage` 接口扩展（账单/套餐信息）**（主方案 §4.3.2）→ 并入 T6（新增 `/billing` 域，**不改** `/usage` 既有响应，§4.3.1）。

### 2.2 Out of Scope（明确排除，防范围蔓延）

| 排除项 | 理由 | 归属 |
|---|---|---|
| 在线支付集成 | 需支付渠道与合规评审 | P1（自助门户阶段） |
| 发票系统 | 需税务对接 | P1 |
| 代理商/分销/多级分润 | 依赖合同体系 | P1 |
| 多币种结算 | 单币种（人民币）先行；`PriceTable.Currency` 字段预留 | P1 |
| **预付费/后付费双模式** | 主方案 §4.3.1 已标 P1；P0 只做**后付费**（按用量出账） | P1 |
| **缓存命中折扣计费** | 与语义缓存同口径：商用前**命中也全额计量**（`GA-计费接口设计-多角色评审报告` P1-R1-3 裁决） | §15 U-1（语义缓存） |
| **输出侧拦截 token 的计费口径细化** | 与《输出侧内容审查》§4.9 `filtered_tokens` 口径耦合，需跨模块会签；P0 按"输入全计、输出按实际产生计"暂行（§15 U-8） | 跨模块（U-8） |
| 外部计费系统对接 | P0 内建账务域；**既有 webhook 推送端保留**，可继续推给外部系统（双轨，§3.6） | 保留能力 |

### 2.3 依赖与前提（开工前置）

| # | 前提 | 影响 | 未满足时的处置 |
|---|---|---|---|
| P-1 | 账务存储选型冻结（SQLite / PostgreSQL / 文件账本，§5.6） | 决定 §4.1.1 存储接口实现与事务能力 | 退**文件账本**（append-only JSONL + 启动重建索引），无 SQL 查询，导出改流式扫描 |
| P-2 | `tee-infer` 新增 **month 窗口**（套餐月配额，§6.4.3） | 决定"月 Token 配额"能否精确生效 | 退"月配额 = 日预算 = 月配额/当月天数"（口径降级，登记 U-2） |
| P-3 | 单价表来源与维护责任冻结（控制面配置 vs 外部下发，§5.4） | 决定 §6.5 计价输入 | 单价表缺失 → **不出账**（冻结该租户），仅出"用量账单"（金额列空，§6.10.3） |
| P-4 | 金额域边界会签（§3.1.3） | 决定"金额列不出现"约束的精确化是否放行 | 未放行 → 账单**不含金额**，只出用量明细（降级为"用量账单"） |
| P-5 | RBAC 角色扩展（新增 `billing_reader` 只读账单角色，§4.3.5） | 决定自助查询的授权粒度 | 退用现有 `auditor/admin` 角色 |
| P-6 | `gateway-core` 配额下发通道可达（`TeeQuotaApplier`，已有，`tee_client.go:16`） | 决定套餐热下发 | 退"离线批量下发"（人工触发，非热） |

---

## 3. 架构设计

### 3.1 部署位置与信任边界（★ 本设计的第一性问题）

#### 3.1.1 计量（metering）必须在 TEE 内，不可外移

| 判断 | 依据 |
|---|---|
| 只有 `tee-infer` 能看见真实 response 并计 token | 输出 token 数由推理引擎产生，明文仅在 `tee-infer` 内（`main.go:265` `recordUsage`） |
| Higress/Wasm 只见密文，无法计量 | `billing.go:4` 明确"Higress 只见密文无法计量" |
| 结论 | **计量与审计链保持现状落在 `tee-infer`**（不迁移）；本模块**不修改**计量口径，仅在数据面补一处"重试标记"经请求头下行（§6.3.3），token 数仍**只**由 `tee-infer` 产生 |

#### 3.1.2 账务（rating/billing/套餐/查询）落在控制面账务域，输入必须锚定审计链

| 判断 | 依据 |
|---|---|
| 账务不接触明文 | 账务输入仅为**结构化计数**（tenant/model/tokens_in/tokens_out/ts），不含内容明文；金额计算不需要内容 |
| 单价/金额**不是机密** | 单价表是**公开商业定价**（§5.4），与租户密钥/明文无关 |
| 落点遵循主方案 | 主方案 §4.3.2 明确"套餐管理：在 `gateway-admin-service` 层实现；账单系统：日级聚合 + 月结账单，**存储于 admin service**" |
| 结论 | **账务域落 `gateway/gateway-admin-service`**（`billing` 子系统，复用其鉴权/RBAC/审计链/度量/HTTP 框架）；**唯一输入通道** = 拉取 `tee-infer GET /usage?from&to`（主）+ webhook `POST /billing/events`（辅，§6.3） |

> **为何不新建独立进程**：主方案 §4.3.2 已把套餐/账单归属 `admin-service`；独立进程会引入第二套鉴权/审计/部署面，收益不抵成本。账务域以**包级子系统**并入，通过**账本哈希链 + 审计链锚定**获得独立可信性（§7.3）。

#### 3.1.3 "金额列不出现"约束的**作用域精确化**（★ 需会签，登记 U-1）

现状硬约束原文（`usage.go:24`）："金额列不出现（**现仅计量无单价**，项目硬约束）"；`GA-计费接口设计.md:23`："本项目无单价，由外部计费系统维护"。

| 项 | 原文 | 前提 | 本方案裁决 |
|---|---|---|---|
| 作用域 | `usage.go` **用量代理端点**（`/v1/adminext/usage`） | "现仅计量无单价" | 约束**前提已变**（引入单价表）→ **精确化而非推翻** |
| 精确化后 | — | — | ① **`/usage` 域继续不出现金额**（响应字段级 CI 校验，M10）；② **金额仅在 `/billing` 域出现**，受 RBAC（`billing_reader`/`admin`）保护；③ 单价表**不在**网关硬编码，由控制面配置（§5.4） |

> **裁决理由**：主方案 §4.3.5 验收要求"月结账单生成正确""多模型计费按系数换算正确""用量突增/对账差异告警"——**均以金额/单价概念存在为前提**，否则无法验收。原约束是"外部计费系统对接假设"下的**阶段性约束**（其自述前提即"现仅计量无单价"），P0-3 引入内建定价后须演进。**放行需产品/财务会签**（U-1）；未放行按 P-4 降级为"用量账单"。

### 3.2 已有资产盘点（代码实证）

> 原则：**能复用不重写**。下表为 §6 流程与 §4 接口的直接锚点。

| 资产 | 位置 | 现状 | 本方案用法 |
|---|---|---|---|
| 租户用量计量 | `main.go:217` `usageRecord` / `:265` `recordUsage` / `:581` `recordModelUsage` | ✅ 生产 | **只读复用**（计量口径不改） |
| 模型维度计量 | `main.go:232` `modelUsage` | ✅ 生产 | 只读复用 |
| 审计哈希链 | `audit.go:25` `AuditEvent` / `:82` `hash()` / `:fe` `append` | ✅ 生产（含 WORM） | 账务**锚定源**（§7.3）；`Infer/Engine/Model` 字段为账务维度 |
| 增量聚合 | `billing.go:53` `aggregateUsage(from,to)` | ✅ 生产 | **账务拉取直接调用**（口径单一） |
| Webhook 推送 | `billing.go:96-254` `billingWebhook`（HMAC+重试+幂等+block） | ✅ 生产 | 辅通道；`block` 语义由 L1 对账驱动（§6.12.1） |
| 零容差对账（L1） | `reconcile.go`（容差 0，5 分类，`reconcileInterval=5min`） | ✅ 生产 | **L1 对账**（TEE 内，已满足）；本模块新增 **L2 对账**（§6.12.2） |
| 配额引擎 | `main.go:290` `quotaLimit`/`:436` `reserveQuota`；`ratelimit/teequota.go` | ✅ 生产（minute/day/累计） | T2 复用；**新增 month 窗口**（§6.4.3） |
| 配额下发通道 | `gateway-core/internal/api/tee_client.go:16` `TeeQuotaApplier` → `POST /usage/quota` | ✅ 生产 | T2 热下发唯一通道；**★ A-41 同通道携带模型系数表**（`ApplyCoefficients`，§4.1.3/§6.4.5） |
| 套餐→配额编译基座 | `ratelimit/teequota.go:77` `CompileTEEQuota` | ✅ 生产（策略表 → QuotaUpdate） | T2 **扩展**（套餐 → QuotaUpdate，复用校验/合并逻辑） |
| 管理面代理骨架 | `admin-service/usage.go`（只读代理 + 审计留痕 + 503 语义） | ✅ 生产 | T6 扩展 `billing` 代理与端点 |
| 管理面审计链 | `admin-service/audit.go:42` `auditActionQuotaSet` | ✅ 生产 | T1/T8 **新增动作**（`plan_bind`/`bill_freeze`…，§4.3.5） |
| 数据面重试标记 | `wasm/.../routeengine/engine.go:164` `BillingNotifier`（**预留、`:633` 传 `-1`**）；`route.go:35` `proxy-wasm-go-sdk`（证实 Wasm 只见密文） | ⚠️ 预留 | **不再用于计 token**（A-1）；改为路由追加 `X-Otpmask-Retry-Attempt` 头（§6.3.3）——本模块唯一数据面改动 |
| 指标基座 | `tee-infer/metrics.go`（`writeCounter` 手写模式）；`scripts/metrics-required.txt` | ✅ 生产 | T10 沿用模式；账单指标 source=`admin` |

### 3.3 分层架构

```
┌──────────────────────────────────────────────────────────────────┐
│  控制面 · gateway-admin-service（非 TEE，不接触明文）              │
│                                                                  │
│   [API 层]  /v1/adminext/billing/*   （复用 admin 鉴权 + RBAC）    │
│              ├─ /usage(代理)  ├─ /plans  ├─ /subscription          │
│              └─ /bills  /bills/export  /freeze                     │
│   [账务域 billing 子系统]                                          │
│     PlanStore ─┐                                                   │
│     QuotaCompiler ──► gateway-core TeeQuotaApplier ──► tee-infer  │
│     RatingEngine ◄─ PriceTable（控制面配置）                        │
│     BillingGenerator ──► LedgerStore（哈希链账本）                 │
│     AnomalyDetector ──► FreezeController ──► PlanStore/Quota       │
│     MeteringSource（拉取为主 / webhook 为辅）                      │
│   [调度器] 日结 / 月结 / 拉取 / 对账 / 告警 定时任务               │
└───────────────▲──────────────────────────┬───────────────────────┘
     拉取 /usage?from&to（主）              │ 热下发 POST /usage/quota
     webhook /billing/events（辅）          │ （经 gateway-core）
┌───────────────┴──────────────────────────▼───────────────────────┐
│  数据面 · tee-infer（TEE 明文域）                                 │
│   计量：reserveQuota/recordUsage/recordModelUsage                 │
│   审计链（唯一真源）+ L1 对账（容差 0）+ webhook 推送 + billing.block│
└──────────────────────────────────────────────────────────────────┘
        ▲
        │ 重试标记（T3 接线，唯一数据面改动）
┌───────┴──────────┐
│ Wasm otpmask 插件 │  routeengine.BillingNotifier（预留 → 退役，A-1）；重试改经请求头
└──────────────────┘
```

### 3.4 技术选型

| 选型项 | 结论 | 理由 | 备选 |
|---|---|---|---|
| 账务落点 | `gateway-admin-service`（包级子系统） | 主方案 §4.3.2 归属；复用鉴权/审计/度量 | 独立进程（否决，收益不抵成本） |
| 账务存储 | **SQLite（纯 Go 驱动，禁 CGO）** | 账务需事务 + 关系查询 + 单文件契合单机 admin | PostgreSQL（企业版/多副本，U-3）；文件账本（P-1 兜底） |
| 金额计算语言 | Go（`math/big.Rat` 或 `int64` 分） | 避免浮点误差；金额以**分**存 `int64` | 浮点（否决，违反零容差） |
| 单价表下发 | 控制面配置（挂载/热加载） | 非硬编码（§3.1.3）；与策略下发同构 | 外部下发（U-4） |
| 账单签名 | HMAC-SHA256（可选 Ed25519，U-5） | 与既有 webhook `X-Signature` 同构；验签无需私钥分发 | Ed25519（对外可验证性更强） |
| 拉取 vs 推送 | **拉取为主、推送为辅**（既有契约，`billing.go:6`） | 拉取幂等、可重放、免疫重启；推送可丢可补 | 仅推送（否决，丢事件即丢账） |
| 调度 | 进程内 ticker + 持久化游标 | 单实例 admin；任务幂等（`PeriodKey` 去重） | 外部 cron（备选，部署可换） |

### 3.5 模块划分

| 模块 | 职责 | 任务 | 章节 |
|---|---|---|---|
| 套餐管理 | 套餐定义/租户绑定/升降级/超额策略 | T1 | §4.1.2 / §5.2 |
| 配额编译与下发 | 套餐 → `QuotaUpdate` 编译 + 经 `gateway-core` 热下发 | T2 | §4.1.3 / §6.4 |
| 计量接入 | 拉取/推送消费 + 重试点接线 + 幂等归并 | T3 | §4.1.5 / §6.3 |
| 计价引擎 | 单价表 + 系数换算 + 阶梯定价 | T4 | §4.2 / §6.5 |
| 账本 | 追加式哈希链账本（唯一写入） | T3/T7 | §5.1 / §7.1 |
| 账单 | 日结/月结 + 明细 + 导出 + 签名 | T5/T7 | §4.1.6 / §6.6-6.8 |
| 自助查询 API | 用量/配额/账单查询 + 余额告警 | T6 | §4.3 / §6.11 |
| 异常检测与冻结 | 4 类检测 + 冻结状态机 | T8 | §4.1.7 / §6.9-6.10 |
| 对账（L2） | 账本 ↔ 审计链逐日对账（出账门禁） | T7/T13 | §6.12.2 |
| 管理后台 | 套餐/账单页面 | T9 | §4.3.4 |
| 可观测性 | 指标/日志/告警/大盘/tracing | T10 | §9 |

### 3.6 与相邻模块的接口边界

| 相邻模块 | 边界 | 契约 |
|---|---|---|
| **语义缓存（P0-2）** | 缓存命中**全额计量**（不折扣）；`saved_cost_estimate` 是**观测口径非计费依据**（语义缓存 §9.1 #15） | 只读；账务**不消费**缓存节省指标（§4.5） |
| **输出侧审查** | 拦截/遮蔽 token 的计费口径（`filtered_tokens`，输出审查 §4.9） | 跨模块会签 **U-8**；P0 按"输入全计、输出按实际产生计" |
| **智能路由（P0-1）** | 重试 token 归平台成本；路由重试时追加 `X-Otpmask-Retry-Attempt` 头 | T3 接线（§6.3.3）；路由**不感知**金额、**不提供** token（A-1） |
| **控制面限流（已有）** | 套餐 → 策略表 → `CompileTEEQuota` → `POST /usage/quota` | T2 复用；套餐是策略表的**上游生成器** |
| **外部计费系统** | 既有 webhook 推送端保留（可双轨） | 不破坏 `billingEventPayload` wire 格式（§4.4） |

---

## 4. 接口设计

### 4.1 账务域核心接口（T1-T3/T5/T8，L3）

> **设计深度：L3**。全部为**进程内 Go 接口**（`gateway/gateway-admin-service/billing` 包，§3.1.2）。
> 命名空间：`gateway/gateway-admin-service/billing`。金额一律 `int64`（单位：**分**），杜绝浮点。

#### 4.1.1 账本接口（T3/T7）

```go
// LedgerEntry 账本条目（追加式；金额列不得 UPDATE/DELETE，§7.5）。
// ★ A-32：新增 StdIn/StdOut（入账时按当日价格表版本算好的标准 token）与 PriceVer（系数版本追溯）。
//   月累计标准 token = SUM(StdIn) / SUM(StdOut)，热更新下恒成立（可加性充要条件）。
type LedgerEntry struct {
    Seq       uint64 `json:"seq"`         // 单调递增序号（链序）
    TenantID  string `json:"tenant"`
    ModelKey  string `json:"model_key"`   // "engine_type/model"（空侧省略斜杠，复用 modelDimensionKey）
    Day       string `json:"day"`         // UTC+8 自然日 "2006-01-02"
    TokensIn  int64  `json:"tokens_in"`   // ★ A-42：输入 token **净量**（剔除 retry；与审计链净量三元组一致 = M1 零容差基准；retry 另列 RetryToks）
    TokensOut int64  `json:"tokens_out"`  // ★ A-42：输出 token 净量（同上）
    Requests  int64  `json:"requests"`
    RetryToks int64  `json:"retry_toks"`  // 重试 token（平台成本，不计用户；M9）
    StdIn     int64  `json:"std_in"`      // ★ A-32：标准输入 token（入账时锁定价格表版本算好）
    StdOut    int64  `json:"std_out"`     // ★ A-32：标准输出 token
    Source    string `json:"source"`      // pull | push | manual
    PriceVer  string `json:"price_ver"`   // ★ A-32：入账时价格表版本（系数追溯依据）
    EventKey  string `json:"event_key"`   // 幂等键（去重）：见 §6.3.4
    PrevHash  string `json:"prev_hash"`   // 前序 EntryHash
    EntryHash string `json:"entry_hash"`  // 本条哈希（不进自身，§7.1.2）
    CreatedAt int64  `json:"created_at"`  // UTC 纳秒
}

// LedgerHead 链尾摘要（供锚定/对账/L2）。
type LedgerHead struct {
    Seq       uint64 `json:"seq"`
    EntryHash string `json:"entry_hash"`
    UpdatedAt int64  `json:"updated_at"`
}

// LedgerQuery 只读查询条件。
type LedgerQuery struct {
    TenantID string // "" = 全部
    DayFrom  string // 闭区间起点 ""=最早
    DayTo    string // 闭区间终点 ""=最新
    Limit    int    // 0 = 不限
}

// LedgerStore 账本存储（唯一写入入口；实现必须并发安全 + 事务）。
type LedgerStore interface {
    // Append 追加一批条目（EventKey 去重；返回实际新增数与新链尾）。
    // 幂等：重复 EventKey 静默跳过（不报错），保证"拉取重叠窗口"可安全重放。
    Append(tx Tx, entries []LedgerEntry) (added int, head LedgerHead, err error)
    // Range 只读查询（按日/租户；金额计算在读取侧，账本只存用量）。
    Range(q LedgerQuery) ([]LedgerEntry, error)
    // Verify 校验哈希链完整性；返回首个断链 Seq（-1 = 完好）。
    Verify() (brokenAt int, err error)
    // Head 链尾摘要。
    Head() (LedgerHead, error)
    // ReproduceHead 重放 period 内条目，判定链尾 == want（账单锚定校验，§7.3）。
    // ★ D-11：作为 **LedgerStore 接口方法**声明（不可在接口类型上另开接收者方法）。
    ReproduceHead(tenant, period, want string) bool
}
```

#### 4.1.2 套餐接口（T1）

```go
// Plan 套餐定义（§5.2 / 附录 D）。
type Plan struct {
    ID            string   `json:"id"`             // free | basic | pro | enterprise（可自定义扩展）
    Name          string   `json:"name"`
    MonthlyTokens int64    `json:"monthly_tokens"` // 标准 token 月配额（<=0 = 不限/定制）
    Concurrency   int      `json:"concurrency"`    // 并发上限（下发至数据面限流，§6.4.3）
    CacheTier     string   `json:"cache_tier"`     // none | exact | semantic
    ModelScopes   []string `json:"model_scopes"`   // 允许模型白名单（空 = 全部）
    OverQuota     string   `json:"over_quota"`     // reject | degrade | charge（超额策略，§6.4.4）
    PriceID       string   `json:"price_id"`       // 关联单价表条目（§5.4）
    ExtraLimits   []QuotaLimit `json:"extra_limits,omitempty"` // 附加维度（如 tpm）
    PayMode       string   `json:"pay_mode"`       // postpaid（P0 仅此值；prepaid 字段预留，§2.2）
    Version       int64    `json:"version"`        // 套餐定义版本（热更新用）
}

// Subscription 租户套餐绑定（含生效时刻，支持升降级排程）。
type Subscription struct {
    TenantID  string `json:"tenant"`
    PlanID    string `json:"plan_id"`
    EffectiveAt int64 `json:"effective_at"` // UTC 纳秒；到点生效（§6.4.2）
    ExpiresAt int64  `json:"expires_at"`    // ★ P-4：到期时刻（0=不过期）；驱动到期告警/宽限
    BoundBy   string `json:"bound_by"`      // 操作人（审计）
    BoundAt   int64  `json:"bound_at"`
}

// PlanStore 套餐与订阅存储。
type PlanStore interface {
    GetPlan(planID string) (*Plan, error)
    PutPlan(p *Plan) error                 // 版本+1，落 admin 审计链
    ListPlans() ([]Plan, error)
    Bind(s Subscription) error             // 绑定/升降级（落审计 plan_bind）
    Resolve(tenant string, now int64) (*Plan, error) // 取"当前生效"套餐（取 EffectiveAt ≤ now 的最近一条）
}
```

#### 4.1.3 配额编译与下发接口（T2）

```go
// QuotaCompiler 套餐 → 控制面配额更新（复用 ratelimit.QuotaUpdate）。
type QuotaCompiler interface {
    // Compile 生成限额更新；p == nil（无套餐）→ 返回 nil（不改变现状）。
    Compile(tenant string, p *Plan) []ratelimit.QuotaUpdate
    // ConcurrencyLimit 生成并发/速率维度（下发数据面限流，非 TEE）。
    ConcurrencyLimit(p *Plan) int
    // ModelCoefs ★ A-41：从价表抽取**模型系数表**（tee-infer 换算标准 token 用；不含单价/阶梯）。
    ModelCoefs(tbl PriceTable) []ModelCoef
}

// QuotaApplier 热下发（经 gateway-core；生产用 HTTP 适配，测试可注入 stub）。
type QuotaApplier interface {
    Apply(ctx context.Context, updates []ratelimit.QuotaUpdate) error
    // ApplyCoefficients ★ A-41：下发**模型系数表** → tee-infer（与配额同 TEE 通道、同消费者）。
    //   tee-infer 据此在 `reserveQuota` 把原始 token 换算为**标准 token**，使月配额 enforce 与账务计费**同口径**
    //   （A-33 目标）。key = ModelKey；仅含 InCoef/OutCoef——**不含单价/阶梯**（单价属账务域、不进 TEE，INV-3/INV-7）。
    //   版本随 `PriceTable.Version`（系数即价表的一部分）；tee-infer 记录 `coef_version` 供 B-6.4-3 版本校验。
    ApplyCoefficients(ctx context.Context, coefs []ModelCoef) error   // 逐条下发（同 B-6.4-2）
}

// ModelCoef 下发 tee-infer 的模型系数最小集（★ A-41）。
type ModelCoef struct {
    ModelKey string  `json:"model_key"`
    InCoef   float64 `json:"in_coef"`
    OutCoef  float64 `json:"out_coef"`
}

// PolicyApplier 数据面策略下发（并发 / 缓存档 / 超额降级），经 gateway-core **策略表**
//（非 TEE 配额通道）；与 QuotaApplier 并列，解决"套餐副作用无下发通道"（review A-5）。
type PolicyApplier interface {
    ApplyConcurrency(ctx context.Context, tenant string, limit int) error   // Plan.Concurrency
    ApplyCacheTier(ctx context.Context, tenant, tier string) error          // Plan.CacheTier → 语义缓存(P0-2)
    ApplyOverQuota(ctx context.Context, tenant, policy string) error        // Plan.OverQuota=degrade 落点
}
```

**编译规则（`Compile`）**：

| 套餐字段 | 编译结果 | 说明 |
|---|---|---|
| `MonthlyTokens > 0` | `{window:"month", max_tokens: MonthlyTokens}` | **需 tee-infer 新增 month 窗口**（§6.4.3 / P-2） |
| `ExtraLimits[]` | 逐条 `QuotaLimit` | 复用既有 minute/day/累计 |
| `MonthlyTokens <= 0` | 不下发限额（不限） | 企业版定制 |
| `Concurrency > 0` | 数据面限流（非 TEE） | 经 `gateway-core` 策略表 |

#### 4.1.4 计价接口（T4）

```go
// PriceTable 单价表（控制面配置；非硬编码，§3.1.3）。
type PriceTable struct {
    Version   string                `json:"version"`
    Effective string                `json:"effective"` // 生效日 "2006-01-02"
    Currency  string                `json:"currency"`  // 仅 "CNY"（P0，§2.2）
    Models    map[string]ModelPrice `json:"models"`    // key = ModelKey
}

type ModelPrice struct {
    InCoef   float64 `json:"in_coef"`   // 输入系数（标准 token 换算；如 GPT-3.5=1.0, GPT-4=10.0）
    OutCoef  float64 `json:"out_coef"`  // 输出系数
    Tiers    []Tier  `json:"tiers"`     // 阶梯（按**标准 token 月累计**，累进）
}

type Tier struct {
    UpToTokens int64   `json:"up_to_tokens"` // 本档上界（标准 token）；0 = 无穷（最高档）
    InPer1K    float64 `json:"in_per_1k"`    // 每 1000 输入标准 token 单价（**单位：元**；★ DOC-002 订正）
    OutPer1K   float64 `json:"out_per_1k"`   // 每 1000 输出标准 token 单价（**单位：元**；★ DOC-002 订正）
}

// Amount 金额（分，int64）。
type Amount int64

// RatingEngine 计价引擎（纯函数，无副作用，便于单测）。
type RatingEngine interface {
    // Rate 计算某租户某周期的金额（先累加后取整，§6.5.3）。
    // 分档依据恒为"月累计标准 token"（§6.5.2），由 u.TenantID + u.Period 定位区间。
    Rate(u UsageAgg, tbl PriceTable) (Amount, error)
    // RateMonthly 月结权威计价：对整月聚合（Epoch="monthly"）按"整月累计"分档重算（§6.7）。
    // 语义 = Rate 传入月聚合；显式命名以固定"月结权威入口"，避免误用日账口径（A-3）。
    RateMonthly(u UsageAgg, tbl PriceTable) (Amount, error)
    // RateMu 计算周期的**亚分**金额（千分之一分，**未取整**）。
    // ★ A-44：把取整**外提**为唯一入口点——`Rate`/`RateMonthly` ≡ `roundAmount(RateMu(...), mode)`；
    //   月结（§6.7）直接消费本函数得月账权威额（月账**唯一取整点**，R-16）。
    RateMu(u UsageAgg, tbl PriceTable) (int64, error)
    // ExtraAmount 套餐级超额费（**亚分**，未取整；`OverQuota=charge`，§6.5.5）。
    // ★ A-43：唯一调用点 = `CloseMonthly`（§6.7 步骤 2b）——此前已定义却**全文无调用点**（死代码），现接线。
    // ★ A-44 订正（两条 P0）：
    //   ① **单位**：返回**亚分**（与 `RateMu` 同量纲）。由 `CloseMonthly` 生成**超额账单**时**单独一次
    //      `roundAmount`**（★ A-45：超额**不并入月账**，月账与超额账单**各自取整一次**，R-16；旧版返回
    //      亚分却 `+= Amount`（分）→ ±1000× 且不可编译）；
    //   ② **基数**：以**套餐级合计**（Σ_模型 当月 std）对 `Plan.MonthlyTokens` 判超额（旧版逐模型
    //      各拿全额上限比 → 多模型系统性漏收）。签名随之由 `(modelKey,u,p,mp)` 改为 `(u,p,tbl)`。
    ExtraAmount(u UsageAgg, p *Plan, tbl PriceTable) (int64, error)
    // StandardTokens 系数换算（标准 token，配额与阶梯共用）。
    // ★ 唯一换算实现（A-9）：所有「原始 token → 标准 token」的换算路径均须调用此方法，禁止各自内联系数乘。
    //   分列为 stdIn/stdOut（阶梯 InPer1K/OutPer1K 分别计价；配额合计用 stdIn+stdOut）。
    // ★ D-13 适用范围界定（★ A-39 订正：Rate/ExtraAmount 改为读账本锁定 std，不再换算）：
    //   ✅ 需要调用（原始 token → 标准 token）——**仅入账路径**：
    //     - 入账写入 std_in/std_out（§6.2 aggToEntries；§4.6 entryFromPush 推送入账同理）——按**入账时**价格表版本算好存账本
    //     - push 路径的 retry 归因（若 push 载荷给的是原始 token）
    //   ❌ 不需要调用（输入已是标准 token / 或直接读账本锁定 std）：
    //     - Rate 计价（§6.5.1）：★ A-39 改为直接消费 `UsageAgg.StdIn/StdOut`（账本锁定值），**不重算**
    //     - ExtraAmount 超额计费（§6.5.5）：★ A-39 同上（取 `u.ByModel[].StdIn/StdOut`）
    //     - 配额编译（§6.4.1 ApplyPlan → QuotaUpdate）：Plan.MonthlyTokens / ExtraLimits 中的 token 限额
    //       套餐定义直接给的就是**标准 token**（与计价口径统一，见附录 D），故编译时直接下发，无需换算。
    //     - monthStdBefore（§6.5.1）：直接读账本 std_in/std_out 字段（A-32，入账时已算好）。
    //     - spike 检测的 avgStd / dayStd：读账本 std 字段。
    //   测试断言（T-6.5-6 A-9 审计）：grep `StandardTokens(` 的调用点应只出现在上述 ✅ 路径中。
    StandardTokens(in, out int64, mp ModelPrice) (stdIn, stdOut int64)
}
```

#### 4.1.5 计量接入接口（T3）

```go
// UsageAgg 用量聚合（单租户，含模型维度）。
// 周期口径（★ A-2）：Period 为计价/配额共用周期键——Epoch="daily" 时 "2006-01-02"，
// Epoch="monthly" 时 "2006-01"；均为 UTC+8 自然日/月（R-10）。TenantID 显式携带，
// 使 RatingEngine.Rate（§6.5.1）与 monthStdBefore 无需外部上下文即可定位分档区间。
type UsageAgg struct {
    TenantID  string                     `json:"tenant"`
    Epoch     string                     `json:"epoch"`      // daily | monthly（周期粒度）
    Period    string                     `json:"period"`     // "2006-01-02" | "2006-01"
    TokensIn  int64                      `json:"tokens_in"`  // ★ A-42：**净量**（剔除 retry；与账本 tokens_in 同口径）
    TokensOut int64                      `json:"tokens_out"` // ★ A-42：净量
    Requests  int64                      `json:"requests"`
    RetryToks int64                      `json:"retry_toks"` // 平台承担（不进用户金额，M9）
    StdIn     int64                      `json:"std_in"`     // ★ A-39：锁定的标准输入 token 合计（账本 std_in 求和，不重算）
    StdOut    int64                      `json:"std_out"`    // ★ A-39：锁定的标准输出 token 合计
    ByModel   map[string]*ModelUsageAgg  `json:"by_model"`
}
type ModelUsageAgg struct {
    TokensIn  int64 `json:"tokens_in"`  // 净量（剔除 retry）
    TokensOut int64 `json:"tokens_out"` // 净量
    Requests  int64 `json:"requests"`
    RetryToks int64 `json:"retry_toks"`
    StdIn     int64 `json:"std_in"`     // ★ A-39：该模型**账本锁定**标准输入 token（foldByModel 累加，非现场换算）
    StdOut    int64 `json:"std_out"`    // ★ A-39
}
```

> **★ A-42（口径唯一化）**：`UsageAgg.TokensIn/Out` **一律为净量**（剔除 retry，retry 单列 `RetryToks`）。两条产线同口径：① `foldByModel`（账本折叠，账本 `tokens_in` 已不含 retry）→ 直接得净量；② `MeteringSource.Pull`（拉 `/usage`）**显式映射 `tokens_in_net → TokensIn`、`tokens_out_net → TokensOut`**（**不用**含 retry 的老字段 `tokens_in/out`）。§6.12.2 L2 对账因此两侧同为净量 → `diff=0` 可判（M1），且 retry 不入对账（M9）。
>
> **★ A-39（std 唯一来源 = 账本锁定值）**：`UsageAgg.StdIn/StdOut` **只由 `foldByModel` 从账本 `std_in/std_out` 字段累加**得到（入账时已按当时价格表算好并锁定，§5.1/§6.2）；**禁止**在计价时用当前价格表重算 std（否则与 `monthStdBefore` 异源，月中调价破坏日/月可加性，见附录 G-5）。

```go

// SyncMode 账本单写者模式（★ A-12）：二者互斥，防跨通道重复入账（§6.3.2/R-30）。
const (
    SyncModePull = "pull" // 拉取写账本（默认/权威）；推送仅实时视图
    SyncModePush = "push" // 推送写账本；拉取仅供 L2 对账
)

// MeteringSource 计量数据源（拉取为主 + 推送为辅；★ A-12：账本单写者，由 sync_mode 选定）。
// 注：Pull/ConsumePush 的**账本写入副作用**受 sync_mode 门控——非当前写入者的一方不改账本（§6.1.1/§6.3.1）。
type MeteringSource interface {
    // Pull 增量拉取 [from, to)（复用 tee-infer aggregateUsage 口径）。
    // ★ A-42（口径唯一化）：消费 `GET /usage` 的 **`tokens_in_net/tokens_out_net`** 字段映射到
    //   `UsageAgg.TokensIn/TokensOut`（= **净量**，剔除 retry）；`retry_tokens → UsageAgg.RetryToks`。
    //   即 `tokens_in_net → TokensIn`、`retry_tokens → RetryToks`，二者不重叠（M9 保）。
    //   映射依据恒等 `tokens_in = tokens_in_net + retry_tokens`（§4.4）；**不得**整型映射含 retry 的
    //   老字段 `tokens_in` 到 `UsageAgg.TokensIn`（否则用户被计 retry 费 → M9/INV-5 破）。
    Pull(ctx context.Context, from, to int64) (map[string]*UsageAgg, error)
    // ConsumePush 消费单条推送事件（HMAC 校验 + 幂等，§6.3.3）。
    ConsumePush(ev PushEvent) error
}

// PushEvent 推送事件（与 tee-infer billingEventPayload 对齐，§4.4）。
type PushEvent struct {
    EventID    string `json:"event_id"`
    TenantID   string `json:"tenant"`
    RequestID  string `json:"request_id"`
    EngineType string `json:"engine_type"`
    Model      string `json:"model"`
    TokensIn   int    `json:"tokens_in"`
    TokensOut  int    `json:"tokens_out"`
    Result     string `json:"result"`     // ok | engine_error
    IsRetry    bool   `json:"is_retry"`   // ★ T3 新增字段（§4.4，向后兼容 omitempty）
    TS         string `json:"ts"`
}
```

> **`IsRetry` 接线说明（T3，§4.4，A-1 订正）**：既有 `billingEventPayload`（`billing.go:125-135`）**无** `is_retry` 字段。T3 新增 `IsRetry bool json:"is_retry,omitempty"`（**加字段不改语义**，旧消费方忽略即向后兼容）；其值**由 `tee-infer` 产生**——来自审计事件证据字段 `IsRetry`（§6.3.3 ②），该字段源头是数据面路由下行的 `X-Otpmask-Retry-Attempt` 头。**数据面不提供 token**（`tokens_in/out` 恒由 `tee-infer recordUsage` 产生）。

#### 4.1.6 账单接口（T5）

```go
// Bill 账单（日结/月结）。
type Bill struct {
    ID         string     `json:"id"`
    TenantID   string     `json:"tenant"`
    Kind       string     `json:"kind"`       // daily | monthly | overage（★ A-45：`charge` 套餐超标单列的"超额账单"，§6.7 步骤 4b）
    Period     string     `json:"period"`     // "2026-10-01" | "2026-10"
    Items      []BillItem `json:"items"`
    Total      Amount     `json:"total"`      // 分
    Currency   string     `json:"currency"`
    PriceVersion string   `json:"price_version"` // ★ 生成时锁定的单价表版本（§7.2.2/S-4；热更新不变，B-6.6-6）
    Status     string     `json:"status"`     // draft | frozen | issued | void | assoc_mismatch（★ D-16：S-10 关联校验不符标记，不阻断已出账，§7.3）
    Sig        string     `json:"sig,omitempty"`         // 签名（§7.2）
    LedgerHead string     `json:"ledger_head"`           // 生成时的账本链尾（锚定）
    AuditHead  string     `json:"audit_head"`            // 生成时的审计链尾（锚定，§7.3）
    GeneratedAt int64     `json:"generated_at"`
}
type BillItem struct {
    ModelKey        string  `json:"model_key"`
    StandardTokens  int64   `json:"standard_tokens"` // 折算后
    TokensIn        int64   `json:"tokens_in"`
    TokensOut       int64   `json:"tokens_out"`
    RetryToks       int64   `json:"retry_toks"`      // 展示为"平台承担"（不计入 Total）
    Amount          Amount  `json:"amount"`          // 分
    TierBreakdown   []TierLine `json:"tier_breakdown,omitempty"` // 阶梯分解（可解释性）
}
type TierLine struct {
    UpToTokens int64  `json:"up_to_tokens"`
    Tokens     int64  `json:"tokens"`
    Amount     Amount `json:"amount"`
}

// BillingGenerator 账单生成（幂等：同一 Period 重复调用返回既有账单）。
type BillingGenerator interface {
    CloseDaily(ctx context.Context, tenantID, day string) (*Bill, error)
    CloseMonthly(ctx context.Context, tenantID, month string) (*Bill, error)
    Get(billID string) (*Bill, error)
    List(q BillQuery) ([]*Bill, error)
    Export(billID, format string) ([]byte, string, error) // (内容, contentType)
    Verify(billID string) (bool, error)                    // 签名验证
}
```

#### 4.1.7 异常检测与冻结接口（T8）

```go
// Anomaly 异常记录。
type Anomaly struct {
    TenantID string `json:"tenant"`
    Kind     string `json:"kind"`   // spike | reconcile_diff | quota_warn | pricing_missing | plan_expired
    Severity string `json:"severity"` // warning | critical
    Ratio    float64 `json:"ratio"` // 差异率/倍数（可复核）
    Detail   string `json:"detail"`
    At       int64  `json:"at"`
}

// AnomalyDetector 四类异常检测（§6.9）。
type AnomalyDetector interface {
    Scan(tenants []string, day string) []Anomaly
}

// FreezeController 冻结状态机（§6.10）。
type FreezeController interface {
    Freeze(tenant, reason string, until int64, by string) error // 落审计 bill_freeze
    Unfreeze(tenant, by, reason string) error                    // 落审计 bill_unfreeze
    State(tenant string) (frozen bool, reason string, until int64)
}

// PlatformCostView 平台成本视图（★ C-1：内部核算，**非对外账单**；retry 归平台）。
type PlatformCostView interface {
    // Retry 某租户某周期的平台承担 retry token（按模型）；period "2006-01"。
    Retry(tenant, period string) map[string]int64
    // Total 全平台某周期 retry token 合计（供成本核算）。
    Total(period string) int64
}
```

#### 4.1.8 存储与事务接口（T3/T5/T7，★ A-4）

> §6 流程中出现的 `s.store.Begin()` / `s.store.Ledger()` / `s.store.Bills()` / `s.store.Plans()` 在
> 此显式定义（此前为隐含约定 → 不可编译，A-4）。实现落 SQLite（`sqlTx` 包一层 `database/sql.Tx`）。

```go
// Tx 事务句柄（单写事务 BEGIN IMMEDIATE；§7.1.1 并发安全前提）。
type Tx interface {
    Commit() error
    Rollback() error
}

// Store 账务域存储聚合根：提供事务与各子存储的 accessor。
// 实现必须并发安全；Ledger().Append 在单写事务内串行化（§7.1.1）。
type Store interface {
    Begin() (Tx, error)          // 开事务（写路径统一入口，§6.1.1/§6.6.1）
    Ledger() LedgerStore         // §4.1.1
    Bills() BillStore            // 账单子存储
    Plans() PlanStore            // §4.1.2
    Freezes() FreezeStore        // 冻结子存储
    Close() error                // 优雅关闭（§6.15）
}

// BillStore 账单持久化（幂等由 UNIQUE(tenant_id,kind,period) 保证）。
type BillStore interface {
    Put(b *Bill) error                    // 插入；冲突返回 ErrUnique（调用方转 Get，§6.6.1）
    Get(billID string) (*Bill, error)
    List(q BillQuery) ([]*Bill, error)
    UpdateStatus(billID, status string) error // 仅状态机迁移（draft→frozen/issued/void，及已出账→assoc_mismatch），不改金额
    // ★ A-50（订正 D-16 半落地）：迁移集合**必须含 `assoc_mismatch`**——S-10 `VerifyBillingChain`
    //   失败时对**已出账**账单标 `status=assoc_mismatch`（§7.3/§6.16），故状态机须允许 `issued → assoc_mismatch`。
}

// BillQuery 账单查询条件。
type BillQuery struct {
    TenantID string // "" = 全部
    Kind     string // "" = 全部；daily|monthly|overage
    From     string // 闭区间起点（period 字符串比较）
    To       string
    Limit    int
}

// FreezeRecord 冻结行（对齐 §5.7 freezes 表）。
type FreezeRecord struct {
    TenantID string
    Reason   string // spike|reconcile_diff|pricing_missing|manual
    Severity string // warning|critical
    FrozenAt int64
    Until    int64 // 0 = 无限（人工解除）
    By       string
}

// FreezeStore 冻结状态持久化（§5.7）。
type FreezeStore interface {
    Put(f FreezeRecord) error
    Get(tenant string) (*FreezeRecord, error)
    Delete(tenant string) error // 仅解冻
}

// ErrUnique 唯一约束冲突哨兵（供 isUnique(err) 判定，§6.6.1）。
var ErrUnique = errors.New("billing: unique constraint violated")
```

> **`isUnique(err)`（A-4 收敛）**：`func isUnique(err error) bool { return errors.Is(err, ErrUnique) }`——
> 取代此前的"约定实现"，成为 §6.6.1 可编译的直接依赖。

### 4.2 配置 Schema 与编号校验规则（L3）

> **设计深度：L3**。配置随 `gateway-admin-service` 加载（`config.go` 同级），支持**热更新**（§6.14）。规则编号 `R-n` 供 CI 校验（非法配置**拒绝加载**，不静默降级）。

```yaml
billing:
  enabled: false                 # 默认关闭（与现网逐字节一致，附录 F.2.4）      R-1
  store:
    driver: sqlite               # sqlite | postgres（P0 仅二值；file 已移除，A-18） R-2
    dsn: "/var/lib/gateway/billing.db"                                          R-3
    wal: true
  source:
    tee_url: "http://127.0.0.1:19090"        # tee-infer 基址                    R-4
    admin_token_ref: "env:BILLING_TEE_TOKEN" # 引用，不落明文                    R-5
    sync_mode: "pull"            # ★ 账本单写者：pull(默认/权威) | push（A-12）   R-30
    pull_interval: 60s                                                        R-6
    pull_lookback: 24h           # 首次部署回溯窗口（★ BUG-001：游标非重叠后不再用于重叠重放）  R-7
    push_enabled: true                                                        R-8
    push_secret_ref: "env:BILLING_HOOK_SECRET" # webhook HMAC 校验密钥           R-9
  period:
    timezone: "UTC+8"            # 预算周期 = UTC+8 自然日/月（唯一口径）        R-10
    daily_close_at: "02:10"                                                   R-11
    monthly_close_day: 1                                                      R-12
    monthly_close_at: "03:10"                                                 R-13
  rating:
    price_table: "/etc/gateway/pricing.yaml"  # 控制面配置，非硬编码             R-14
    rounding: "half_up"          # 金额取整：half_up | floor                    R-15
    accumulate_then_round: true  # 先累加后取整（防逐笔舍入，§6.5.3）             R-16
    tier_mode: "progressive"     # 累进（P0 仅此值；R-17 收窄）                   R-17
    retry_attribution: "platform" # 重试 token 归平台成本                        R-18
  anomaly:
    daily_spike_ratio: 3.0       # 单日 > 过去 7 日均值 × 该值                   R-19
    reconcile_alert_ratio: 0.001 # ★ 0.1% 软阈值：ratio>0.1% 冻结；0<ratio≤0.1% 回补不冻结（A-22） R-20
    quota_warn_ratio: 0.2        # 剩余 < 20% 余额告警                          R-21
    auto_throttle: false         # ★ 冻结期自动降配（U-13；P0 默认关）           R-31
    spike_critical_ratio: 10.0   # ★ spike 判 critical 的倍数门槛（today/avg7 > 此值，A-25） R-33
  display:
    amount_display: false        # 金额展示（Stage 0 关；§12.2）                 R-23
  schedule:                      # 后台调度器周期（§6.16 总表）                  R-24..R-26, R-32
    anomaly_scan_interval: 5m    # 异常扫描（S-5）                              R-24
    verify_interval: 1h          # 链增量校验；全量每日低峰（S-6 → 指标#4）      R-25
    quota_scan_interval: 5m      # 余额告警检查（S-7）                          R-26
    expiry_scan_interval: 6h     # ★ 到期扫描（S-9 → 指标 #21，A-16）            R-32
    verify_assoc_interval: 24h   # ★ 关联校验（S-10 → VerifyBillingChain，A-31） R-34
  secrets:
    events_secret_ref: "env:BILLING_EVENTS_SECRET" # 独立于推送端 webhook 密钥   R-27
  api:
    listener: "admin"            # 复用 admin listener（不新开端口）             R-22
    price_public_url: ""         # 单价表对外公开渠道（验签复算用；空=不公开）    R-28
```

**编号校验规则（R-1 … R-34）**：

| 规则 | 内容 |
|---|---|
| R-1 | `enabled=false` 时**必须**不注册任何 `/billing` 端点、不启任何定时任务、`/usage` 响应逐字节不变 |
| R-2 | `driver` ∈ `{sqlite, postgres}`（**P0 仅二值**；`file` 无 schema/实现，**移除**，A-18）；非法即拒 |
| R-3 | `sqlite` 时 `dsn` 非空且父目录可写；`postgres` 时须另一 `dsn` 且 TLS 强制（U-3） |
| R-4 | `tee_url` 非空且合法 URL（仅 `http(s)`）；空 = `enabled` 必须为 false |
| R-5 | `admin_token_ref` 必须为引用形式 `env:NAME`/`file:PATH`，**禁止内联明文**（加载时正则校验） |
| R-6 | `pull_interval ∈ [10s, 1h]` |
| R-7 | `pull_lookback ∈ [pull_interval, 7d]`（★ BUG-001 订正：语义为**首次部署一次性回溯**窗口；游标非重叠后不再承担“覆盖重叠”） |
| R-8 | `push_enabled=true` 时 R-9 必须提供密钥，否则拒（防未验签 webhook） |
| R-9 | `push_secret_ref` 同 R-5 引用形式 |
| R-10 | `timezone` 必须为受支持时区；P0 **只允许 `UTC+8`**（保证与 tee-infer `quotaWindowKeyFor` day 窗口一致，`main.go:357`） |
| R-11/R-13 | 时刻格式 `HH:MM`；`daily_close_at` 必须 ≥ `00:05`（避开日界抖动） |
| R-12 | `monthly_close_day ∈ [1,3]`（月初容错窗口） |
| R-14 | 价格表路径存在且可解析；**版本号 `Version` 非空** |
| R-15 | `rounding ∈ {half_up, floor}` |
| R-16 | `accumulate_then_round` 必须为 `true`（**P0 强制**；置 false 拒加载——防逐笔舍入累积误差，§6.5.3） |
| R-17 | `tier_mode` 必须为 `progressive`（**P0 强制**；`flat` 会造成阈值附近金额跳变且无实现，**收窄**，A-18；其他值拒） |
| R-18 | `retry_attribution` 必须为 `platform`（P0 强制；其他值拒——M9 不变量） |
| R-19 | `daily_spike_ratio ∈ [1.5, 100]` |
| R-20 | `reconcile_alert_ratio ∈ [0, 1]`；`0` = 关闭软告警分级（仅 critical） |
| R-21 | `quota_warn_ratio ∈ [0.05, 0.9]` |
| R-22 | `listener` P0 只允许 `admin`（不新开端口） |
| R-23 | `amount_display ∈ {true,false}`；Stage 0（默认）恒 `false`（§12.2） |
| R-24 | `anomaly_scan_interval ∈ [1m, 1h]` |
| R-25 | `verify_interval ∈ [10m, 24h]`；**全量**链校验周期 ≤ 24h（低峰执行，§8.3/O-6） |
| R-26 | `quota_scan_interval ∈ [1m, 1h]` |
| R-27 | `events_secret_ref` 同 R-5 引用形式，且**取值必须不同于 `push_secret_ref`（R-9）**——独立鉴权域，防密钥同源面扩大（**S-2**）；相同即拒加载 |
| R-28 | `price_public_url` 空 = 单价表不对外公开；非空须为 `https` URL（验签复算端引用，§7.2.2/**S-4**） |
| R-29 | **交叉约束（C-2）**：`Plan.OverQuota=charge` 时，其 `PriceID` 对应单价表**不得全 0 价**且套餐**非免费档**（`MonthlyTokens>0`）；违反即拒——防"免费版产出金额账单" |
| R-30 | **账本单写者（★ A-12，P0）**：`sync_mode ∈ {pull, push}`；`sync_mode=pull` 时**拉取为唯一账本写入者**（`push_enabled` 仅作实时视图，**不写账**）；`sync_mode=push` 时**推送为唯一写入者**（拉取仅供 L2 对账）。**两通道不得同时写账**（配置即拒）——消除跨通道重复入账 |
| R-31 | `auto_throttle ∈ {true,false}`；**P0 默认 `false`**（冻结期不下调配额，U-13）；置 `true` 时冻结经 `QuotaApplier` 置 0（§6.10.2） |
| R-32 | `expiry_scan_interval ∈ [1m, 24h]`；到期扫描（S-9）周期。**P0 默认 `6h`**——过密（<1m）扫描无收益且放大 DB 压力，过疏（>24h）令到期运营闭环（§6.4.2）最长延迟一个周期仍未收敛（**A-16**） |
| R-33 | `spike_critical_ratio ≥ daily_spike_ratio`（`∈ [1.5, 1000]`）；spike 严重级 = `sev(today/avg7, spike_critical_ratio)`——**超此值判 `critical`（触发冻结）、否则 `warning`（不冻结）**。**★ A-25**：**不得**复用 `reconcile_alert_ratio`（对账专用阈值）为 spike 分级，否则任意 spike 恒 `critical`（与 §9.3「spike=warning 不冻结」/§6.10.1 冲突） |
| R-34 | `verify_assoc_interval ∈ [10m, 24h]`；**关联校验**（S-10 → `VerifyBillingChain`，§7.3/§6.16）周期。**P0 默认 `24h`**（出账后即时校验 + 每日全量巡检）（**★ A-31**：为原本无调用点的 `VerifyBillingChain` 补触发点） |

### 4.3 对外 API

#### 4.3.1 `/usage` 域（**不改响应**，向后兼容）

> **硬约束**：`/usage` 响应**不得**新增/修改字段（M10 / R-1）。套餐/账单信息一律走 **`/billing` 域**（与主方案 §4.3.2"扩展现有 /usage"**收敛**为"新增 /billing 域"——避免破坏既有消费方；差异登记 **U-9**）。

#### 4.3.2 `/billing` 域（新增，T6）

| 方法 | 路径 | 角色 | 说明 |
|---|---|---|---|
| GET | `/v1/adminext/billing/usage` | `billing_reader`/`auditor`/`admin` | 当前周期用量（标准 token + 金额**可选**，R-1 关闭时不返回金额） |
| GET | `/v1/adminext/billing/plans` | `billing_reader`/`admin` | 套餐列表 |
| GET | `/v1/adminext/billing/subscription` | `billing_reader`/`admin` | 当前租户套餐（自助时按 token 内租户） |
| GET | `/v1/adminext/billing/bills` | `billing_reader`/`auditor`/`admin` | 账单列表（`?kind&from&to`） |
| GET | `/v1/adminext/billing/bills/{id}` | 同上 | 账单详情 |
| GET | `/v1/adminext/billing/bills/{id}/export` | 同上 | 导出（`?format=csv\|pdf`） |
| GET | `/v1/adminext/billing/bills/{id}/verify` | 同上 | 签名验证（返回 `{valid, sig_alg, price_version, ledger_head, audit_head, recomputed_total?}`；`recomputed_total` 仅在 `price_public_url` 非空时返回，§7.2.2/S-4） |
| POST | `/v1/adminext/billing/plans` | `admin` | 套餐 CRUD（落审计 `plan_upsert`） |
| POST | `/v1/adminext/billing/subscription` | `admin` | 绑定/升降级（落审计 `plan_bind`） |
| POST | `/v1/adminext/billing/freeze` | `admin` | 冻结/解冻（落审计 `bill_freeze`/`bill_unfreeze`） |
| POST | `/v1/adminext/billing/verify-chain` | `admin` | **手动**触发全量完整性校验（S-6 账本链 + REC-6 审计链，与调度器同逻辑）；返回 `{ledger_broken_at, ledger_broken, audit_chain_ok}`（★ 增补：为 §10.3 E2E-3 / 运维即时核对提供触发点） |

#### 4.3.3 错误码（统一）

| HTTP | code | 场景 |
|---|---|---|
| 400 | `invalid_argument` | 参数缺失/非法（如 `format` 非 csv/pdf） |
| 403 | `forbidden` | 角色不足（`requireRole`）或跨租户访问 |
| 404 | `not_found` | 账单/套餐不存在 |
| 409 | `frozen` | 目标租户已冻结，账单不可交付（§6.10.3） |
| 422 | `pricing_missing` | 单价表缺该 model（拒出账，§6.10.3） |
| 503 | `datasource_unavailable` | tee-infer 不可达（沿用 `usage.go:18-22` 503 语义，**不静默返回 0/空**） |

#### 4.3.4 管理后台页面（T9，★ A-11：补页面级 RBAC / 边界 / 测试 / 薄伪代码）

| 页面 | 前端路由 | 数据源 API（§4.3.2） | 允许角色 | 金额列 | 写动作 → 审计 |
|---|---|---|---|---|---|
| 套餐管理 | `/billing/plans` | `GET|POST /plans` | 读 `billing_reader`；写 `admin` | 否（仅配额） | `plan_upsert` |
| 租户订阅 | `/billing/subscription` | `GET|POST /subscription` | 读 `billing_reader`；写 `admin` | 否 | `plan_bind` |
| 账单中心 | `/billing/bills` | `GET /bills`、`/bills/{id}`、`/export`、`/verify` | `billing_reader`/`auditor` | **是** | `bill_export`（导出时） |
| 用量与配额 | `/billing/usage` | `GET /usage`（代理，**不改**） | `billing_reader` | 否（R-1/M10） | — |
| 冻结管理 | `/billing/freeze` | `POST /freeze` | 读 `billing_reader`；写 `admin` | 否 | `bill_freeze`/`bill_unfreeze` |

> **页面契约**：前端只调 `/billing` 域；**金额列仅在"账单中心"页面出现**（§3.1.3）；页面为**薄展示层**（无本地计算），所有金额/配额由后端下发。

**薄伪代码（写动作统一形态，以后端为准）**：

```go
// POST /plans（套餐 upsert）——读写分离 + RBAC + 审计 + 校验，后端是唯一权威。
func (h *billingHandler) handlePlansUpsert(w http.ResponseWriter, r *http.Request) {
    if !h.rbac.Require(r.Context(), roleAdmin) { writeError(w,403,"forbidden"); return } // 页面级 RBAC
    var p Plan
    if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&p); err != nil {
        writeError(w,400,"bad_json"); return
    }
    if err := validatePlan(p); err != nil { writeError(w,422,err.Error()); return } // 含 R-29 交叉约束
    if err := h.plans.PutPlan(&p); err != nil { writeError(w,500,"store_error"); return }
    h.audit.Append(adminAuditEvent{Actor: actor(r), Action: actionPlanUpsert, Target: p.ID, Result: "ok"})
    writeJSON(w, 200, p)
}
// 前端仅：fetch → 渲染；无金额/配额本地计算（防"两套口径"）。
```

**边界（B-4.3-1..5）**：

| 编号 | 边界 | 处理 |
|---|---|---|
| B-4.3-1 | 低角色访问写页面 | 403（`requireRole`）；前端隐藏按钮但**以后端为准**（不信任前端） |
| B-4.3-2 | 跨租户访问账单页 | 403（token 内 `tenant` 强制，§7.4） |
| B-4.3-3 | 套餐页编辑并发（双管理员） | 乐观锁 `Plan.Version`；冲突 409 |
| B-4.3-4 | `enabled=false` | **页面不注册**（R-1，端点已注销 → 404） |
| B-4.3-5 | 账单页对冻结租户 | 只读可看（含 `frozen` 水印）；导出允许（B-6.8-2） |

**测试（T-4.3-1..4）**：T-4.3-1 页面级 RBAC（各角色可见/可写矩阵）；T-4.3-2 `enabled=false` 页面 404；T-4.3-3 写动作落审计链（`plan_upsert`/`plan_bind`/`bill_freeze`）；T-4.3-4 金额列仅现于账单页（前端快照断言，M10 扩展）。

#### 4.3.5 RBAC 角色与审计动作

| 项 | 结论 |
|---|---|
| 新角色 `billing_reader` | 只读账单/套餐/用量（P-5；未放行退用 `auditor`） |
| 新审计动作 | `plan_upsert` / `plan_bind` / `bill_freeze` / `bill_unfreeze` / `bill_issue` / **`bill_export`**（★ S-3：导出含金额，须可追溯"谁导了哪个租户账单"）/ `bill_verify`（可选）（落 `admin-service` 审计链，白名单 `auditEventActions` 扩展） |
| 复用动作 | `quota_set`（既有，`audit.go:42`）——套餐下发经配额通道时仍落 `quota_set` |

### 4.4 与 `tee-infer` / 控制面的接口约定（T3，L3）

| 方向 | 接口 | 契约 | 改动 |
|---|---|---|---|
| 账务 → tee-infer | `GET /usage?tenant&from&to` | 复用 `handleUsage`+`billingIncrement`（`main.go:2791`/`billing.go:43`）；★ A-23：聚合增 `retry_tokens` 维度（`aggregateUsage` 按 `IsRetry` 分组）供 pull 侧 retry 归因；**★ A-27+A-35：双字段过渡——既有 `tokens_in/out` 保留原口径（含 retry），新增 `tokens_in_net/tokens_out_net`（omitempty）为剔除 retry 的净量**，账务域 pull 消费 `_net` 字段（见下方 wire 兼容注） | **加 `retry_tokens` + `tokens_in_net/tokens_out_net`（均 omitempty）；老字段 `tokens_in/out` 口径不变** |
| 账务 → tee-infer | `GET /audit`（L2 对账） | 复用 `handleAudit` | **无** |
| 账务 → tee-infer | **`GET /usage/quota`**（★ P-1：**回读确认**，M6 判据） | **新增只读端点**：返回当前**已生效**限额（window → max_tokens）；T2 交付 | 新增（只读） |
| tee-infer → 账务 | `POST {billing}/events`（webhook） | `billingEventPayload`（`billing.go:125`） | **加 `is_retry` 字段（omitempty）** |
| 账务 → gateway-core | 套餐下发（经策略表 → `CompileTEEQuota`） | `ratelimit.QuotaUpdate`（`teequota.go:45`） | 复用；并发/缓存档/降级经 `PolicyApplier`（§4.1.3/§6.4.5） |
| **账务 → tee-infer（系数）★ A-41** | `QuotaApplier.ApplyCoefficients` → gateway-core → **`POST /usage/quota`（同通道携带系数表）** | `{model_key, in_coef, out_coef}[]`（**不含单价/阶梯**，INV-3/INV-7）；tee-infer 记 `coef_version` 供版本校验 | **T2 新增**：tee-infer 据此把原始 token 换算为**标准 token** 做月配额 enforce（§6.4.3 A-33 / §6.4.5 第 2 行） |
| **数据面路由 → tee-infer** | 请求头 `X-Otpmask-Retry-Attempt: <n>` | routeengine 重试点追加（P0-1） | T3 落地（§6.3.3，**唯一数据面改动**） |
| tee-infer 内部 | 审计事件证据字段 `IsRetry`（**不进 hash**） | `audit.go` `AuditEvent` 扩字段 | T3 落地（§6.3.3 ②） |

> **wire 兼容**：新增字段一律 `omitempty`；**不改既有字段名/语义**（`billingEventPayload` 的 `event_id/tenant/.../ts` 不动）。`X-Signature: sha256=` 头格式不变。
>
> **★ A-27 订正（`GET /usage` 口径）+ ★ A-35 双字段过渡（推荐方案 b）**：
> - **既有 `tokens_in` / `tokens_out` 保持原口径（含 retry）**——向后兼容，下游消费方（外部计费系统、容量规划脚本、监控面板）数值不跳变。
> - **新增 `tokens_in_net` / `tokens_out_net`**（omitempty）——剔除 retry 的净量，供账务域 pull 消费（M9）。
> - 既有 `retry_tokens` 单列；`tokens_in_net + retry_tokens = tokens_in`（恒成立，可对账）。
>
> **A-35 迁移策略**：v1.4 曾直接把 `tokens_in/out` 改为净量（A-27 方案 a），但第 5 轮评审指出：既有消费方若已按"含 retry"口径消费 → 改为净量后数值跳变 → 容量规划误判、外部计费系统双重剔除 → 少计费。双字段过渡（方案 b）**零破坏**——老字段原口径、新字段净量、账务域消费新字段、M9 通过新字段保证。等所有消费方迁移后再考虑 deprecate 老字段。
>
> **理由与自洽性**：
> - **必须订正**：若账务侧用含 retry 的口径入账 `tokens_in` → **用户被计 retry 费** → **M9 / INV-5 破**（T-6.3-3 明写"`tokens_*` 不含"）。
> - **不破向后兼容**：老字段 `tokens_in/out` 保留原口径（含 retry）→ 既有消费方逐字节兼容；新字段 `_net` 供账务域专用。
> - **L2 对账自洽**：L2 两侧（tee-infer `/usage` 净量 vs 账本）**同口径**——账务侧 pull 消费 `_net` 字段入账，`diff` 仍为 0（M1 不破）。
> - **恒等校验**：`tokens_in = tokens_in_net + retry_tokens`（输出同理）→ 任一消费方可自行验证两字段一致性。

### 4.5 与语义缓存/输出审查的计费口径接口（L3）

| 口径 | 结论 | 依据 |
|---|---|---|
| 缓存命中 | **全额计量**（不折扣） | 语义缓存 §2.2 / P1-R1-3 |
| `saved_cost_estimate` | **观测口径，非计费依据**；账务**不消费** | 语义缓存 §9.1 #15 |
| 重试 token | 归**平台成本**，不计用户（M9） | 主方案 §4.3.2；`engine.go:162` |
| 输出拦截 token（`filtered_tokens`） | P0 暂按"输入全计、输出按实际产生计"；精确口径待跨模块会签 | U-8（输出审查 §4.9） |
| `deny` 请求 | **不计费**（`aggregateUsage` 只统计 `action=infer`，`billing.go:56`） | `billing.go:51` |

### 4.6 辅助函数与内部符号清单（L3，★ A-10）

> **问题（review A-10）**：§6/§7 伪代码引用了若干**未定义符号**（`foldByModel`/`buildBill`/`dayUTC8`…）。本节给出**全部**辅助函数的签名与语义，使伪代码**自足可编译**。

```go
// ---- 时间/周期（UTC+8，R-10）----
func dayUTC8(ts int64) string            // "2006-01-02"（UTC+8）
func dayStart(day string) int64          // 该日 00:00:00 (UTC+8) 的 UnixNano
func dayEnd(day string) int64            // 该日 23:59:59.999… 的 UnixNano（闭区间端点）
func windowKey(ts int64) string          // 拉取窗口起点标识（同窗口重放 → 同键，§6.1.1）
func eventKey(tenant, modelKey, day, source, win string) string // §6.3.4 规则

// ---- 账本/聚合 ----
// foldByModel 条目 → UsageAgg（累加 tokens/std/retry/requests，ByModel 分桶）。
// ★ A-13：TenantID/Epoch/Period **必须显式传入**（不可从 entries 隐式推断）——它们被
// RatingEngine.Rate（§6.5.1 → monthStdBefore）消费以定位阶梯区间；签名不含则日结路径分档落空。
// ★ A-39：**std 直接累加账本锁定字段 e.StdIn/e.StdOut**（不做系数换算）——保证 Rate 与 monthStdBefore 同源。
func foldByModel(tenant, epoch, period string, entries []LedgerEntry) UsageAgg
    // 返回 UsageAgg{TenantID: tenant, Epoch: epoch, Period: period,
    //   TokensIn: Σe.TokensIn, TokensOut: Σe.TokensOut, RetryToks: Σe.RetryToks,
    //   StdIn: Σe.StdIn, StdOut: Σe.StdOut, ByModel: <按 modelKey 分桶，各含 StdIn/StdOut>}
// ★ A-39：推送入账同样按入账时价格表算好 std 并写入（与 §6.2 aggToEntries 等价），否则该 source 的 std 缺失。
func entryFromPush(ev PushEvent) []LedgerEntry     // 推送事件 →账本条目（含 is_retry 归因 + std 锁定，§6.3.4）
func sum(entries []LedgerEntry) (in, out, req int64) // 账本三元组求和（§6.12.2；★ A-42：token 净量，retry 另列）
func (s *BillingService) monthAgg(tenant, month string) UsageAgg
    // 整月聚合；★ A-13：返回 TenantID=tenant, Epoch="monthly", Period=month（供 RateMonthly 分档）
    // ★ A-39：等价 foldByModel(tenant,"monthly",month, 整月条目) → StdIn/StdOut = 整月**账本锁定 std 之和**（月结权威口径，
    //   不得用当前价格表重算；这就是 §6.7「月结按整月累计重算」的正确含义 = 重算**合计**而非重算**换算**）
func (s *BillingService) sumDaily(tenant, month string) Amount    // Σ 已出日账额（§6.7）
// ★ A-26：返回**两根独立轴**的"当月初至 period 起点"月累计标准 token（阶梯区间起点，§6.5.1/§6.5.2）。
// ★ A-32：实现 = 账本表 SUM(std_in)/SUM(std_out)（WHERE tenant=? AND model_key=? AND day>=monthStart AND day<period）。
//   各日 std 为入账时按当日价格表版本算好的定值（§5.1），热更新仅影响新条目，故月累计 = 各日 std 之和恒成立。
// ★ A-47：`monthStart` 显式定义为「period 所属月的月初日」= `period[:7] + "-01"`；当 period 为**月度串**
//   （如 "2026-10"，月结）时，`monthStart` = `period+"-01"`、且约定 `day < monthStart` **恒空**（月初无前置累计）
//   → 月结区间起点恒 0（不再依赖 "2026-10-05" < "2026-10" 的字典序巧合）。
func (e *ratingEngine) monthStdBefore(tenant, modelKey, period string) (stdInBefore, stdOutBefore int64)

// ---- 计价内部 ----
// ★ D-11/A-26：去除未使用的形参 modelKey；入/出**分轴**（inBefore/outBefore 各一根）。
func rateModel(stdIn, stdOut, inBefore, outBefore int64, mp ModelPrice) int64 // §6.5.2
// ★ A-24：契约规定 **up<=0 视作 +∞**（顶档 Tiers[last].UpToTokens=0），上界取 before+n。
func overlap(n, before, lo, up int64) int64      // [before,before+n) 与 [lo,up) 的交集长度（累进分段；up<=0 ⇒ +∞）
func prevUpTo(tier Tier, tiers []Tier) int64     // 本档下界（= 前一档 UpToTokens；首档 0）
// ★ A-44：`RateMu` 返回周期金额的**亚分**（未取整）；`Rate`/`RateMonthly` = `roundAmount(RateMu(...))`。
func (e *ratingEngine) RateMu(u UsageAgg, tbl PriceTable) (int64, error)   // §6.5.1（唯一取整点上移）
// ★ D-12/A-26：超额入/出**分价**（最高档 InPer1K/OutPer1K），单入参无法承载双价。
// ★ A-44：`ExtraAmount(u,p,tbl)` 返回**亚分**（★ 单位）+ **套餐级合计**基数（★ 基数），见 §6.5.5。
func rateAtTopTier(stdIn, stdOut int64, mp ModelPrice) int64 // 超额按最高档计价（亚分；§6.5.5）
func roundAmount(mu int64, mode string) Amount   // 千分之一分 →分（half_up/floor；负数见 §6.5.3/C-3）

// ---- 账单 ----
func buildBill(tenant, kind, period string, agg UsageAgg, amt Amount,
               tbl PriceTable, ledger LedgerStore, auditHead string) *Bill
    // 组账单 + 明细 + PriceVersion=tbl.Version + 链锚（§6.6.1）
func (s *BillingService) auditHead() string            // 当前 admin 审计链尾（§7.3）
func (s *BillingService) freezeAndAlert(tenant, reason string, diff float64) // 冻结 + 告警（§6.10；内部落 incFreeze 指标 #14）
// ★ D-11：signer 为 **BillingService 字段**（类型提供 Sign(*Bill) string / Verify(*Bill) bool，§7.2），非方法。
//   字段声明：s.signer billSigner

// ---- 完整性关联（★ A-14：§7.3 引用、v1.1 遗漏）----
// ★ D-11：ReproduceHead 已上移为 **LedgerStore 接口方法**（§4.1.1），经 s.store.Ledger().ReproduceHead(...) 调用
//   （**非** s.ledger 字段——统一走 Store accessor）。
func (s *BillingService) auditAnchorExists(head string) bool
    // 账单 AuditHead 是否出现在 tee-infer 审计链上（GET /audit 前缀匹配，§7.3）
func (s *BillingService) crossRefEvents(b *Bill) error
    // 账本条目 ↔ 审计事件双向对齐（push 按 event_id；pull 按 windowStart，§7.3）

// ---- 回补重拉（★ A-14：§6.12.3 引用、v1.1 遗漏）----
func (s *BillingService) repullInflight(tenant, day string) bool
    // 同 (tenant,day) 回补是否进行中（进程内幂等去重，§6.12.3）
func (s *BillingService) pullOnceWindowed(ctx context.Context, tenant, day string, widen time.Duration)
    // 加宽窗口的单窗口回补拉取（幂等：同 event_key 去重，§6.12.3/§6.3.4）

// ---- 错误哨兵（★ A-14：供各返回点复用）----
var (
    ErrUnique               = errors.New("billing: unique constraint violated") // §4.1.8/isUnique
    ErrFrozen               = errors.New("billing: tenant frozen")              // §6.6.1 冻结不出账
    ErrReconcile            = errors.New("billing: reconcile mismatch")         // §6.6.1/§6.7 出账门禁
    ErrLedgerAnchorMismatch = errors.New("billing: ledger anchor mismatch")     // §7.3 链锚对不上
    ErrAuditAnchorMissing   = errors.New("billing: audit anchor missing")       // §7.3 审计锚缺失
)
type ErrPricingMissing struct{ ModelKey string }  // §6.5.1
func (e ErrPricingMissing) Error() string { return "billing: pricing missing for " + e.ModelKey } // ★ D-11：补 Error() 以满足 error 接口

// ---- 通知 ----
type Notifier interface {
    WarnQuotaLow(tenant string, rem float64, periodKey string) error // §6.11（periodKey 幂等）
}

// ---- 价格表 ----
type PriceStore interface {
    Current() PriceTable            // 当前版本（内存快照）
    Reload(path string) error       // 热加载（版本化，§6.14）
    Has(modelKey string) bool       // 是否含该模型单价（§6.9 ④）
}

// ---- 配额回读确认（P-1/M6）----
func (s *BillingService) confirmQuotaApplied(ctx context.Context, tenant string,
    want []ratelimit.QuotaUpdate, within time.Duration) error
    // 轮询 tee-infer `GET /usage/quota`，断言"已生效限额 == want"，≤ within 返回 nil；
    // 超时返回错误（记 M6 失败 + 告警）。POST 2xx ≠ 生效，此项为 M6 判据的唯一构造点。

// ---- 异常检测内部 ----
func (d *detector) dayStd(tenant, day string) int64        // 当日标准 token
func (d *detector) avgStd(tenant, day string, n int) (avg float64, daysWithData int) // ★ A-36：返回有数据天数（不足 n 天的实际天数），供 spike 检测门槛判断
func (d *detector) reconcileRatio(tenant, day string) (float64, bool)
func (d *detector) quotaRemaining(tenant string) (float64, bool)
func (d *detector) modelsUsed(tenant, day string) map[string]struct{}
func sev(actual, threshold float64) string                 // 分级（warning/critical）

// ---- 数值工具 ----
func abs64(x int64) int64
func max64(a, b int64) int64
func min64(a, b int64) int64   // ★ A-44：ExtraAmount 瀑布归因「入先占额」用（§6.5.5）
func isUnique(err error) bool            // = errors.Is(err, ErrUnique)（§4.1.8）
func (h *billingHandler) verifyEventsHMAC(sig string, body []byte) bool // 独立密钥（R-27）
```

---

## 5. 数据模型

### 5.1 账本表 `billing_ledger`（T3/T7，L3）

> 追加式（仅 INSERT）。**金额不存账本**（账本只存用量 + 标准 token；金额在账单生成时按单价表计算，§6.5）。
>
> **★ A-32 订正（月累计基准定义）**：账本除原始 token 外，同时存 **入账时价格表版本对应的标准 token**（`std_in / std_out`）。这是「月累计标准 token」可加性成立的充要条件——价格表热更新（§6.14）只影响新入账条目的 std 系数，历史条目不变，故月累计 = 各日 std 之和恒成立，无热更新导致的跳变。

```sql
CREATE TABLE billing_ledger (
  seq         INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id   TEXT    NOT NULL,
  model_key   TEXT    NOT NULL,
  day         TEXT    NOT NULL,             -- UTC+8 "2006-01-02"
  tokens_in   INTEGER NOT NULL DEFAULT 0,   -- ★ A-42：输入 token **净量**（剔除 retry；与审计链净量三元组一致 = M1 零容差基准）
  tokens_out  INTEGER NOT NULL DEFAULT 0,   -- ★ A-42：输出 token 净量；retry 另列 retry_toks
  requests    INTEGER NOT NULL DEFAULT 0,
  retry_toks  INTEGER NOT NULL DEFAULT 0,   -- 平台成本（不计用户）
  std_in      INTEGER NOT NULL DEFAULT 0,   -- ★ A-32：标准输入 token（入账时按当日价格表版本算好）
  std_out     INTEGER NOT NULL DEFAULT 0,   -- ★ A-32：标准输出 token
  source      TEXT    NOT NULL,             -- pull|push|manual
  price_ver   TEXT    NOT NULL DEFAULT '',  -- ★ A-32：入账时锁定的价格表版本（可追溯系数依据）
  event_key   TEXT    NOT NULL,             -- 幂等键（§6.3.4）
  prev_hash   TEXT    NOT NULL,
  entry_hash  TEXT    NOT NULL,
  created_at  INTEGER NOT NULL,
  UNIQUE(event_key)                          -- 幂等去重的物理保障（★ A-12：**同通道内**去重；跨通道由单写者 `sync_mode` 保证不并存，§6.3.2/R-30）
);
CREATE INDEX idx_ledger_tenant_day ON billing_ledger(tenant_id, day);
```

**不可变保障（§7.5）**：① 应用层只 `INSERT`；② DB 触发器 `BEFORE UPDATE/DELETE ON billing_ledger` → `RAISE(ABORT,...)`（防绕过应用层）；③ 账本文件/DB 由 `admin-service` 的 WORM 生命周期管理（对齐审计链）。

**std_in/std_out 的语义约束（★ A-32）**：
- **写入时机**：仅入账时（`Append` 路径）由 `StandardTokens(tokens_in, tokens_out, priceAtThatTime)` 一次性算好写入，之后**永不修改**（与不可变保障一致）。
- **热更新不变量**：价格表版本升级后，新条目用新系数算 std，历史条目 std 不变 → 月累计 = `SUM(std_in)` / `SUM(std_out)` 单调稳定 → 分轴可加性（§6.5.2）恒成立。
- **可验证性**：用户拿到账单（含 `price_version`）后，可用 `std_in/tokens_in = in_coef`、`std_out/tokens_out = out_coef` 复算每条目的系数，验证金额计算链。
- **`retry_toks` 的 std**：retry token 归平台成本（不计用户），**不单独存 std**（无计价需求）。平台成本统计仍用原始 token。

### 5.2 套餐表 `plans` / 订阅表 `subscriptions`（T1，L3）

```sql
CREATE TABLE plans (
  id             TEXT PRIMARY KEY,
  name           TEXT NOT NULL,
  monthly_tokens INTEGER NOT NULL DEFAULT 0,   -- 标准 token（0=不限）
  concurrency    INTEGER NOT NULL DEFAULT 0,
  cache_tier     TEXT NOT NULL DEFAULT 'none', -- none|exact|semantic
  model_scopes   TEXT NOT NULL DEFAULT '',     -- JSON 数组串
  over_quota     TEXT NOT NULL DEFAULT 'reject',-- reject|degrade|charge
  price_id       TEXT NOT NULL DEFAULT '',
  extra_limits   TEXT NOT NULL DEFAULT '[]',   -- JSON
  pay_mode       TEXT NOT NULL DEFAULT 'postpaid',
  version        INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE subscriptions (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id    TEXT NOT NULL,
  plan_id      TEXT NOT NULL,
  effective_at INTEGER NOT NULL,   -- UTC 纳秒；支持排程升降级
  expires_at   INTEGER NOT NULL DEFAULT 0, -- ★ P-4：到期时刻（0=不过期）
  bound_by     TEXT NOT NULL,
  bound_at     INTEGER NOT NULL
);
CREATE INDEX idx_sub_tenant_eff ON subscriptions(tenant_id, effective_at DESC);
CREATE INDEX idx_sub_expires    ON subscriptions(expires_at) WHERE expires_at > 0; -- 到期扫描（S-9）
```

### 5.3 账单表 `bills` / 明细 `bill_items`（T5，L3）

```sql
CREATE TABLE bills (
  id           TEXT PRIMARY KEY,
  tenant_id    TEXT NOT NULL,
  kind         TEXT NOT NULL,      -- daily|monthly|overage（★ A-45：charge 套餐超标单列，§6.7 步骤 4b）
  period       TEXT NOT NULL,      -- "2026-10-01" | "2026-10"
  total        INTEGER NOT NULL,   -- 分
  currency     TEXT NOT NULL DEFAULT 'CNY',
  price_version TEXT NOT NULL DEFAULT '', -- 生成时锁定的单价表版本（B-6.6-6/S-4）
  status       TEXT NOT NULL,      -- draft|frozen|issued|void|assoc_mismatch（★ D-16：S-10 关联校验不符时标记，§7.3/§6.16）
  sig          TEXT NOT NULL DEFAULT '',
  ledger_head  TEXT NOT NULL,
  audit_head   TEXT NOT NULL,
  generated_at INTEGER NOT NULL,
  UNIQUE(tenant_id, kind, period)  -- 幂等：同周期唯一
);
CREATE TABLE bill_items (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  bill_id         TEXT NOT NULL,
  model_key       TEXT NOT NULL,
  standard_tokens INTEGER NOT NULL,
  tokens_in       INTEGER NOT NULL,
  tokens_out      INTEGER NOT NULL,
  retry_toks      INTEGER NOT NULL,          -- 展示"平台承担"
  amount          INTEGER NOT NULL,          -- 分
  tier_breakdown  TEXT NOT NULL DEFAULT '[]' -- JSON（可解释性）
);
```

### 5.4 单价表（`pricing.yaml`，控制面配置，T4，L3）

> 见 §4.1.4 的 `PriceTable` 结构；**不进 DB**（配置挂载 + 热加载，§6.14），版本随 `Version` 字段。附录 D 给系数/阶梯示例。

### 5.5 用量汇总视图（T6，L3）

> **派生视图，不落库**（可重算）：`usage_daily` = `SELECT tenant_id, day, SUM(...) FROM billing_ledger GROUP BY tenant_id, day`；`usage_monthly` 同理按 `substr(day,1,7)`。查询走索引 `idx_ledger_tenant_day`。

> **为何不建物化表**：账本已是唯一真源，物化汇总会引入"第二套账"与不一致风险（对齐 `reconcile.go:6` "不引入第二套账"）。

### 5.6 存储选型（L3 · **选型深度**，P-1）

| 候选 | 优势 | 劣势 | 结论 |
|---|---|---|---|
| **SQLite（纯 Go 驱动）** | 事务、关系查询、单文件、契合单机 admin | 高并发写弱（单写者） | **P0 推荐**（`modernc.org/sqlite`，禁 CGO） |
| PostgreSQL | 强并发、多副本 | 引入外部依赖与运维 | **企业版/多副本**（U-3） |
| 文件账本（JSONL + 索引重建） | 零依赖、与审计链同构 | 无事务/查询弱、月结并发难 | **P-1 兜底**（受限环境） |
| 风险 | SQLite 单写者下"拉取 + 日结 + 查询"并发需串行化（WAL + 单写锁） | — | §8.3 基准验证 |
| 退路 | 若并发不达标 → 拉取写"待处理队列"，日结批量提交（§6.6.2） | — | — |

### 5.7 冻结状态（T8，L3）

```sql
CREATE TABLE freezes (
  tenant_id  TEXT PRIMARY KEY,
  reason     TEXT NOT NULL,     -- spike|reconcile_diff|pricing_missing|manual
  severity   TEXT NOT NULL,     -- warning|critical
  frozen_at  INTEGER NOT NULL,
  until      INTEGER NOT NULL,  -- 0 = 无限（人工解除）
  by         TEXT NOT NULL
);
```

---

## 6. 详细流程

> 每节含**伪代码**（L3）+ **边界条件清单**（`B-<节>-<序>`）+ **测试用例清单**（`T-<节>-<序>`）。边界与测试只列**非显然**项（逐条可在 §10/附录 B/C 回指）。

### 6.1 计量采集总控流程（T3，L3）

#### 6.1.1 总控伪代码

```go
// RunMeteringLoop 采集循环：定时拉取（主）+ 消费推送（辅）→ 归并入账本。
func (s *BillingService) RunMeteringLoop(ctx context.Context) {
    t := time.NewTicker(s.cfg.Source.PullInterval)
    defer t.Stop()
    for {
        select {
        case <-ctx.Done():
            return
        case <-t.C:
            s.pullOnce(ctx)
        }
    }
}

// pullOnce 单次拉取 [cursor, now)（★ BUG-001 订正：**游标式非重叠窗口**，按 UTC+8 自然日切分；
//   游标三级回退 内存 lastPollNs → 持久化水位 billing_ledger_head.poll_end_ns → 首次部署 now-lookback）。
func (s *BillingService) pullOnce(ctx context.Context) {
    now := time.Now().UnixNano()
    // ★ B-6.1-3/O-8：时钟回拨保护——`now < 上次轮询时刻`（时间倒流）→ 记 `clock_skew` 并跳过本轮，
    //   防"负区间"（from > now）。指标 #17 `billing_clock_skew_total` 的**唯一生产者**。
    if now < s.lastPollNs { s.metrics.incClockSkew(); s.lastPollNs = now; return }
    s.lastPollNs = now
    from := now - int64(s.cfg.Source.PullLookback)
    aggs, err := s.source.Pull(ctx, from, now)   // 复用 tee-infer aggregateUsage
    if err != nil {
        s.metrics.incPullError()                  // rate limit / 不可达
        return                                    // 不推进游标（下轮重拉，幂等）
    }
    // ★ A-12：仅 sync_mode=pull 时拉取写账本（单写者）；sync_mode=push 时拉取仅供 L2 对账（不写账）
    if s.cfg.Source.SyncMode != SyncModePull {
        s.metrics.observeRealtimeView(aggs)       // 实时视图（不写账本）
        return
    }
    entries := s.aggToEntries(aggs, "pull", now)
    tx, err := s.store.Begin()                    // ★ A-15：Begin 返回 (Tx, error)
    if err != nil { s.metrics.incLedgerError(); return }
    added, head, err := s.store.Ledger().Append(tx, entries)
    if err != nil { tx.Rollback(); s.metrics.incLedgerError(); return }
    tx.Commit()
    s.metrics.observeLedgerHead(head)
    s.metrics.addLedgerEntries(added)
}
```

#### 6.1.2 边界条件清单

| 编号 | 边界 | 处理 |
|---|---|---|
| B-6.1-1 | tee-infer 不可达 | 不推进游标；记 `pull_error`；下轮重拉（幂等） |
| B-6.1-2 | 拉取区间横跨重启（tee-infer 内存态） | 拉取以**审计链**为准（免疫重启，`billing.go:3`），账本不缺 |
| B-6.1-3 | 时钟回拨（账务服务） | 检出 → 记 `clock_skew`，本轮跳过（防"负区间"） |
| B-6.1-4 | `pull_lookback` < `pull_interval` | **配置拒绝**（R-7） |
| B-6.1-5 | 账本写入事务失败 | 整体回滚；不发部分账（原子性） |
| B-6.1-6 | 拉取响应超大（多租户/多模型） | 分页拉取（按 tenant 分批，`?tenant=`）；单批上限保护 |
| B-6.1-7 | 空响应（无推理） | 正常返回；不写账（避免空条目） |
| B-6.1-8 | 重复拉取同一窗口 | `event_key` 去重（§6.3.4），`added=0` |

#### 6.1.3 测试用例清单

| 编号 | 用例 | 预期 |
|---|---|---|
| T-6.1-1 | tee-infer 宕机后恢复 | 无丢账（拉取补全） |
| T-6.1-2 | 同一窗口拉取两次 | 第二次 `added=0` |
| T-6.1-3 | tee-infer 重启（内存计数归零） | 账本不受影响（以审计链为准） |
| T-6.1-4 | 时钟回拨 | 检出并跳过 |
| T-6.1-5 | 事务中断（注入失败） | 账本无部分写入 |

### 6.2 增量拉取的幂等归并（T3，L3）

```go
// aggToEntries 把聚合结果展开为账本条目（租户 × 模型 → 条目）。
// ★ A-32：入账时按当日价格表版本算好 std_in/std_out 并写入；price_ver 锁定系数版本。
func (s *BillingService) aggToEntries(aggs map[string]*UsageAgg, source string, ts int64) []LedgerEntry {
    var out []LedgerEntry
    pt := s.price.Current()   // 入账时刻锁定的价格表版本（★ 统一价表访问器 = `s.price`，非 `s.rating`）
    for tenant, a := range aggs {
        for modelKey, mu := range a.ByModel {
            mp := pt.Models[modelKey]    // 无对应模型 → mp 为零值（系数=1，StandardTokens 内部兜底）
            stdIn, stdOut := s.rating.StandardTokens(mu.TokensIn, mu.TokensOut, mp)
            out = append(out, LedgerEntry{
                TenantID: tenant, ModelKey: modelKey, Day: dayUTC8(ts),
                TokensIn: mu.TokensIn, TokensOut: mu.TokensOut, Requests: mu.Requests,
                RetryToks: mu.RetryToks,
                StdIn: stdIn, StdOut: stdOut, PriceVer: pt.Version,
                Source: source,
                EventKey: eventKey(tenant, modelKey, dayUTC8(ts), source, windowKey(ts)),
                CreatedAt: ts,
            })
        }
    }
    return out
}
```

> **去向**：`eventKey` 规则见 §6.3.4。`windowKey(ts)` = 拉取窗口起点（同窗口重放 → 同键 → 去重）。

### 6.3 推送消费与数据面接线（T3，L3）

#### 6.3.1 Webhook 消费伪代码

```go
// handleBillingEvents POST /billing/events（HMAC 校验 + 委托 MeteringSource.ConsumePush）。
func (h *billingHandler) handleBillingEvents(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(io.LimitReader(r.Body, maxEventBytes))
    // 独立密钥域（R-27/S-2）：events_secret ≠ 推送端 push_secret
    if !h.verifyEventsHMAC(r.Header.Get("X-Signature"), body) {
        writeError(w, 401, "signature_invalid"); return
    }
    var ev PushEvent
    if err := json.Unmarshal(body, &ev); err != nil { writeError(w, 400, "bad_json"); return }
    // ★ A-8：经接口消费（幂等入账 + 冻结计数均在 ConsumePush 内）——消除"接口 vs 直写"双实现
    if err := h.source.ConsumePush(ev); err != nil {
        h.metrics.incPushError(); writeError(w, 500, "ledger_error"); return
    }
    writeJSON(w, 200, map[string]string{"status": "accepted"})
}
```

> **`ConsumePush` 唯一实现（A-8）**：`MeteringSource.ConsumePush(ev)` 内部完成——**先判 `sync_mode`（A-12）**：`sync_mode=push` 时幂等入账（`event_key = push:{event_id}`，§6.3.4）、`is_retry=true → retry_toks` 归因、冻结租户计数（`push_total{result="frozen"}`）、单写事务 `Append`；`sync_mode=pull`（默认）时**不写账本**，仅更新实时视图（`observeRealtimeView`）。handler 只做**验签 + 反序列化 + 委托**，**账本无第二写入路径**（INV-8）。测试 T-6.3-5 断言：绕过 handler 直调 `ConsumePush` 与经 handler 结果一致；T-6.3-7 断言 `sync_mode=pull` 时推送不产生账本行。

#### 6.3.2 拉取与推送的**双通道一致性（★ A-12 单写者订正）**

> **★ 设计订正（A-12，P0）**：v1.1 曾断言"推送 + 拉取**同 `event_key`** 去重"，但两通道键结构**不同**（`push:{event_id}` 事件级 vs `pull:{tenant}:{modelKey}:{day}:{windowStart}` 窗口级），**同一笔用量经两通道会写两行 → 重复入账**，破坏 M1 零容差并使出账门禁（L2 `diff>0`）常态自锁。根因：**push 是事件级、pull 是窗口级，二者不可用同一键去重**。订正为**单写者模型**：同一租户/周期**账本仅一个写入者**，由 `source.sync_mode` 选定（§4.2 / R-30）。

| `sync_mode` | 账本写入者 | 推送的作用 | 拉取的作用 | 丢失兜底 |
|---|---|---|---|---|
| **`pull`（默认，推荐）** | **拉取** | **不写账本**，仅更新实时视图（`observeRealtimeView`） | 幂等入账（**游标非重叠窗口**，★ BUG-001 订正） | 拉取即权威 → **不丢账**；推送丢失只影响实时性 |
| `push` | **推送** | 幂等入账（`push:{event_id}`）；事件级延迟最低 | **不写账本**，仅供 **L2 对账** 与缺口检测 | 推送丢失由 L2 对账检出（`diff>0`）→ 冻结 + 人工；不自动回补 |

- **同一通道内的幂等**：pull → **游标非重叠窗口**（★ BUG-001 订正：原“重叠窗口同键去重”因键含窗口两端而实际失效），窗口级 `event_key` 去重；push 重投 → 同 `event_id` 键去重。**跨通道不再要求同键**（因为不再并存写账）。
- **推送的 `is_retry=true` 事件**：`sync_mode=push` 时由 push 载荷记入 `retry_toks`（不进 `tokens_*` 用户口径，§6.3.4）；`sync_mode=pull` 时由**拉取侧按审计链 `IsRetry` 分组**归因（`aggregateUsage` 增 `IsRetry` 维度，§6.3.3/§6.3.4）。**★ A-23 订正**：两通道**同口径、均可归因**（此前"pull 侧归因"与 §6.3.4"pull 不含 retry 明细"自相矛盾）；单写者（`sync_mode`）保证同一周期仅一方写账，故不会重复计入。**默认 `sync_mode=pull` 下 retry 归因经拉取侧生效** → M9 可证。
- **配置互斥**：`R-30` 强制 `sync_mode` 与 `push_enabled` 语义一致（见 §4.2），**禁止两通道同时写账**。

> **为何不沿用"双写 + 同键去重"**：push 的事件级键与 pull 的窗口级键**天然不同粒度**，无法在不改变 push 粒度（改为窗口聚合）的前提下统一；而把 push 改为窗口聚合，会牺牲"事件级实时性"，得不偿失。单写者是**最小且不可误用**的解。

#### 6.3.3 重试标记接线：请求头传播（T3，★ 唯一数据面改动，A-1 重定位）

> **★ 设计冲突订正（A-1，P0）**：早期设计（v1.0）要求**数据面 Wasm** 的 `BillingNotifier.RecordUsage(...,inputTokens,outputTokens,isRetry,...)` **补齐 token 数**——这与 §3.1.1/§3.1.2 的机密边界**自相矛盾**：`route.go:35` 导入 `proxy-wasm-go-sdk`（该插件即 Higress 内 Wasm，`billing.go:4` 明示"Higress 只见密文无法计量"），`engine.go:633` 现有调用实参为 `-1,-1,false`（注释自认"token 用量未知"），且其引用的 `NotifyUsage` 全仓库**无定义**。故 Wasm 侧 token 恒 `-1` → 按 `B-6.3-4` 忽略 → `retry_toks` **恒为 0**，与 `T-6.3-3`/`M9` 直接冲突。
>
> **订正**：**token 数仍只由 `tee-infer` 产生**（§3.1.1）；数据面仅传播**一个重试标记**，`tee-infer` 据此给自己的审计事件打 `IsRetry`。`BillingNotifier` 的"token 计数"职责**退役**，其剩余的 `RecordUsage` 不再进计费链（保留为插件内部诊断计数，可选）。

**机制（重定位后）**：

```go
// ① 数据面 routeengine（Higress Wasm）：重试时在**发往 tee-infer 的上游请求**追加请求头。
//    仅 1 个 int32 标记，不含任何明文/token（不触碰机密边界）。
if retryAttempt > 0 {
    req.SetHeader("X-Otpmask-Retry-Attempt", strconv.Itoa(retryAttempt)) // P0-1 路由重试点
}

// ② tee-infer：在 /infer 处理入口解析该头，归属到本次推理的审计事件（证据字段，不入哈希链）。
retryAttempt := atoi(header("X-Otpmask-Retry-Attempt")) // 缺省 0
ev.IsRetry = retryAttempt > 0                            // AuditEvent 证据字段（不进 hash()）
//   —— 复用既有审计链（audit.go）：token 由 recordUsage 照旧产生，IsRetry 仅追加标签

// ③ tee-infer webhook 推送：billingEventPayload 携带真实 tokens + is_retry（§4.1.5 omitempty）。
//    → 账务侧收到 is_retry=true 的**真实 token 事件**，记入 retry_toks（不计用户，M9）。
```

**接线原则**：
1. **token 数唯一来源 = `tee-infer`**（`recordUsage`，`main.go:265`）——数据面**不**提供 token，信任边界不移（§3.1.1）；
2. **数据面唯一改动 = 追加 `X-Otpmask-Retry-Attempt` 头**（1 个 int32；`routeengine` 重试点）——比"Wasm 传 token"更小且**可实施**；
3. **`tee-infer` 新增 3 处**：① audit 事件 `IsRetry` 证据字段（**不进 `hash()`**，与既有 `OGCategory` 同构）；② push payload 的 `is_retry`（`omitempty`，向后兼容）；③ **`aggregateUsage` 按 `IsRetry` 分组**（`/usage` 增 `retry_tokens` 维度，供 pull 侧归因；★ A-23，默认 `sync_mode=pull` 下 M9 由此可证）；
4. **不阻塞请求路径**：头解析为 O(1)；推送沿用既有异步/退避链路（`billing.go:179`）。

> **为何不是"tee-infer 自判重试"**：`tee-infer` 只处理**单次**推理请求，看不到"同一逻辑请求的第 N 次尝试"；重试语义只有**路由**知道（P0-1）。故标记必须由路由产生、经请求头下行——这是"谁有信息、谁打标"的最小耦合解。

#### 6.3.4 `event_key` 幂等键规则（L3）

| source | event_key | 说明 |
|---|---|---|
| `pull` | `pull:{tenant}:{modelKey}:{day}:{windowStart}` | 同窗口重放 → 同键（**窗口级**） |
| `push` | `push:{event_id}` | 与审计 `event_id` 对齐（**事件级**） |
| `manual` | `manual:{txn_id}` | 人工补录（须审计） |

> **★ A-12：跨通道不同键，故账本设单写者**。上表键分属不同粒度（pull 窗口级 / push 事件级），**不可跨通道去重**；同一租户/周期账本**仅一个写入者**（`sync_mode`，§6.3.2/R-30）。`event_key` 仅在**同一通道内**保证幂等（同窗口重放 / 同事件重投）。

**`retry_toks` 归因（★ A-23：两通道同口径可归因）**：
- **push**（`sync_mode=push`）：payload `is_retry=true` → `retry_toks += tokens`（**路 ①**）。
- **pull**（`sync_mode=pull`，默认）：`tee-infer` `aggregateUsage`（`billing.go:53`）**按 `IsRetry` 分组**（`AuditEvent.IsRetry` 证据字段，§6.3.3 ②）→ `GET /usage` 返回的**计量口径**中 **`tokens_in/out` 剔除 retry（净量）**、`retry_tokens` 单列 → 拉取侧分别写入 `tokens_in/out` 与 `retry_toks`（**路 ②**；★ A-27：两字段**互斥不重叠**，故 M9 与 M1 同保）。
- 两路**均实现**；单写者（`sync_mode`）保证同一周期仅一方写账 → 不重复计入。

> **U-10 说明（★ A-23 订正：两路都落地）**：v1.2 曾取「路 ① 为唯一（靠 push 携带），且 pull 归零（偏保守）」——但因 **默认 `sync_mode=pull` 时 push 不写账**（A-12 单写者），导致默认配置下 `retry_toks ≡ 0`、M9 空转。**现改为两路都实现**：① 扩展 `AuditEvent` 增 `IsRetry`（证据字段、不进 hash，push 携带）；② 扩展 `aggregateUsage` 按 `IsRetry` 分组（pull 归因）。使**默认 pull 模式下 M9（用户账单 retry=0）可证**。两改动同为 **tee-infer 内部**（不改数据面 wire）。

#### 6.3.5 边界与测试

| 编号 | 边界 | 处理 |
|---|---|---|
| B-6.3-1 | webhook 未验签 | 401 拒绝，不入账 |
| B-6.3-2 | `event_id` 重复 | 去重，200 幂等 |
| B-6.3-3 | 未知 `result` 值 | 记 `ok` 兜底 + 指标 `unknown_result` |
| B-6.3-4 | 负 token（`-1`） | 忽略（不落账，不计负） |
| B-6.3-5 | 推送与拉取同窗口重叠 | **单写者模型**（A-12）：仅 `sync_mode` 指定的通道写账；另一通道不产生账本行 → **无重复** |
| B-6.3-6 | 冻结租户收到 push | 仍入账（供人工核账）+ 指标 |
| B-6.3-7 | events 密钥与推送端同源 | **配置拒绝**（R-27/S-2，须独立子密钥） |
| T-6.3-1 | 重放同 `event_id` × 10 | 仅 1 条入账 |
| T-6.3-2 | 篡改 body（签名不符） | 401 |
| T-6.3-3 | `is_retry=true` 事件 | `retry_toks>0`，`tokens_*` 不含 |
| T-6.3-4 | `sync_mode=push` 下重投同 `event_id` | 无重复（通道内键去重） |
| T-6.3-5 | 直调 `ConsumePush` vs 经 handler | 结果一致（唯一实现，A-8） |
| T-6.3-6 | 路由头 `X-Otpmask-Retry-Attempt=1` → tee-infer 审计 → push | `is_retry=true`（端到端，A-1） |
| T-6.3-7 | `sync_mode=pull` 时 push/pull 同窗口并存 | 账本**仅拉取写入**，推送**不产生行**（A-12 单写者） |
| T-6.3-8 | `sync_mode=pull`（默认）下含 retry 的上游聚合 | `retry_toks > 0`（A-23 路②：`aggregateUsage` 按 `IsRetry` 分组 → pull 归因；证明默认配置下 M9 非空转） |

### 6.4 套餐编译与热下发（T1/T2，L3）

#### 6.4.1 流程伪代码

```go
// ApplyPlan 绑定套餐并热下发配额（幂等：同子任务重复执行结果一致）。
func (s *BillingService) ApplyPlan(ctx context.Context, tenant, planID, by string) error {
    start := time.Now()                          // ★ A-14：M6 计时起点（此前未定义）
    p, err := s.plans.GetPlan(planID)
    if err != nil { return err }
    // 1. 解析套餐（版本化）→ 编译为控制面配额更新
    updates := s.compiler.Compile(tenant, p)
    // 2a. 经 gateway-core 下发 TEE 配额（teeQuota.ApplyQuota → POST /usage/quota）
    if err := s.quota.Apply(ctx, updates); err != nil {
        return fmt.Errorf("配额下发失败（TEE 保留现有配额）: %w", err)  // 不发送"清除"
    }
    // 2a'. ★ A-41：下发**模型系数表** → tee-infer（否则 tee-infer 无法把原始 token 换算为标准 token，
    //      A-33「配额 enforce 与计费同口径」不可实现）。系数来自当前价表，逐条下发（同 B-6.4-2）。
    if err := s.quota.ApplyCoefficients(ctx, s.compiler.ModelCoefs(s.price.Current())); err != nil {
        return fmt.Errorf("系数下发失败（TEE 保留旧系数）: %w", err)   // 与配额同失败语义：不回滚已生效项
    }
    // 2b. 下发数据面策略（并发/缓存档/超额降级；★ A-5：套餐副作用必须有通道）
    if err := s.policy.ApplyConcurrency(ctx, tenant, s.compiler.ConcurrencyLimit(p)); err != nil {
        return fmt.Errorf("并发下发失败: %w", err)
    }
    if err := s.policy.ApplyCacheTier(ctx, tenant, p.CacheTier); err != nil {
        return fmt.Errorf("缓存档下发失败: %w", err)   // → 语义缓存 P0-2
    }
    if err := s.policy.ApplyOverQuota(ctx, tenant, p.OverQuota); err != nil {
        return fmt.Errorf("超额策略下发失败: %w", err)  // degrade 落点
    }
    // 2c. ★ 回读确认（P-1）：POST 2xx 不等于生效；回读 tee-infer `GET /usage/quota`，
    //     断言"已生效限额 == 目标"，≤ 60s 内轮询确认（M6 判据由此可构造）。
    if err := s.confirmQuotaApplied(ctx, tenant, updates, 60*time.Second); err != nil {
        return fmt.Errorf("配额生效未确认: %w", err)   // 记 M6 失败 + 告警，不回滚（TEE 已生效为准）
    }
    // 3. 绑定订阅（含生效时刻）
    if err := s.plans.Bind(Subscription{TenantID: tenant, PlanID: planID,
        EffectiveAt: time.Now().UnixNano(), BoundBy: by, BoundAt: time.Now().UnixNano()}); err != nil {
        return err
    }
    // 4. 落审计（plan_bind / quota_set）
    s.audit.Append(adminAuditEvent{Actor: by, Action: actionPlanBind, Tenant: tenant, Target: planID, Result: "ok"})
    s.metrics.observeQuotaApply(time.Since(start))
    return nil
}
```

#### 6.4.2 升降级排程（L3）

- 绑定写入 `subscriptions.effective_at`；`Resolve(tenant, now)` 取 `effective_at ≤ now` 的**最近一条**。
- **升配即时生效**（`effective_at=now`）；**降配**默认次日 00:00 生效（`effective_at=次日`，避免同周期配额倒挂）——**策略可配**，登记 U-7（继承/降配语义）。
- 到期未续（免费版）：`Subscription` 保留，`Resolve` 仍返回该套餐（**不自动降级**）；**但须有运营闭环（★ P-4）**：

| 阶段 | 动作 | 载体 |
|---|---|---|
| T-30d / T-7d / T-0 | 到期提醒（`BillingPlanExpiring{tenant,days}`，warning） | 指标 **#21**（**S-9 `scanExpiries` 驱动**）；通知租户 |
| T0 ~ T0+7d | **宽限期**（仍享套餐，不降级） | `ExpiresAt` 驱动（S-9 扫描，§6.16） |
| 宽限结束仍逾期 | 告警升 `critical` + 生成运营待办 | `anomaly_total{kind="plan_expired"}`（S-9 兼发）；**仍不自动降级**（防误伤） |
| 运营确认降级/停用 | 经 `ApplyPlan`（人工，落审计 `plan_bind`） | §6.4.1 |

> **原则**：**自动过期 ≠ 自动降级**——降级不可逆地改变客户能力，一律**人工确认**（避免误伤付费客户）；系统只负责"到期可见 + 强提醒"。

#### 6.4.3 月窗口编译（T2，P-2）

```go
// Compile：MonthlyTokens > 0 → {window:"month", max_tokens: MonthlyTokens}
```

**★ A-33（口径统一）**：`MonthlyTokens` 单位为 **标准 token 合计**（与计费超额口径一致，§6.5.5）。
- tee-infer 月窗口**接收的就是标准 token**（控制面编译时**不**做系数换算，因为套餐定义直接给的就是标准 token）。
- **换算责任唯一（★ A-41 订正，消除 v1.5 的"责任悬空"）**：**tee-infer 是"原始 token → 标准 token"的唯一换算点**（数据面即时、请求前），换算所需**模型系数表经 `QuotaApplier.ApplyCoefficients` 下发**（§6.4.5 第 2 行 / §6.4.1 步骤 2a'），tee-infer 记录 `coef_version` 与价表同版（B-6.4-3）。**不再**依赖 `usageRecord` 中的 std 字段（该载荷无 std 字段、且属请求后产物，`reserveQuota` 时序上不可用）。
- `reject`/`degrade`/`charge` 三策略下的配额 enforce 均按标准 token 计数，保证与超额计费同一口径，避免「配额说还有余额但计费说超额」的用户困惑。
- **与账务侧 std 的关系**：tee-infer 换算的 std 用于**配额 enforce**；账务侧入账 `std_in/std_out`（§6.2 `aggToEntries`）由账务域按**同一系数表版本**独立算好写入账本（§4.1.4 `StandardTokens` 唯一实现）。**二者同系数源、同口径**；账本锁定 std 为计费权威值（§6.5.1），tee-infer 侧值仅用于配额判定（不影响账本，INV-3）。

**tee-infer 侧扩展（T2 交付）**：`quotaWindowKeyFor`（`main.go:352`）新增 `month`：

```go
case quotaWindowMonth: // "month"
    return now.In(time.FixedZone("UTC+8", 8*3600)).Format("2006-01")
```

`validQuotaWindow`（`main.go:364`）白名单加入 `quotaWindowMonth`。**不改**既有 minute/day/累计语义。

#### 6.4.4 超额策略（T1，L3）

| `OverQuota` | 行为 | 数据面落点 |
|---|---|---|
| `reject` | 超限即拒（429） | tee-infer 配额 enforce（既有） |
| `degrade` | 超限降级（如关闭语义缓存/降并发） | `PolicyApplier.ApplyOverQuota`（§6.4.5）→ 语义缓存/并发 |
| `charge` | 超限继续用，按**阶梯单价**计费 | 配额只告警不拒（`MaxTokens` 设为**软上限**，账务侧单独出"超额账单"） |

> **`charge` 的实现要点**：tee-infer 配额不支持"软上限"（enforce 即拒）。`charge` 策略下**不下发** month 限额，改为**账务侧**按 `MonthlyTokens` 计"超额部分"（§6.5.5）→ 月结时生成**独立"超额账单"**（`kind=overage`，§6.7 步骤 4b，**不并入月账**，★ A-45）。
>
> **交叉约束（★ C-2 → R-29）**：`charge` 套餐**不得**配置全 0 单价、**不得**落在免费档——否则"超额继续用"不产生任何金额，`charge` 语义被架空。此约束在**配置校验期**即拦截（§4.2 R-29）；套餐落库（§4.3.4 `handlePlansUpsert`）前先过 R-29。

#### 6.4.5 下发通道总表（★ A-5：三条副作用各自的消费者）

> **问题（review A-5）**：`Plan.Concurrency` / `Plan.CacheTier` / `Plan.OverQuota=degrade` 三条"套餐副作用"在 v1.0 中**定义了却无下发通道**（调用图审计：`QuotaCompiler.ConcurrencyLimit` 全文无调用点）。本节显式给出**五类下发的通道、消费者与失败语义**。
>
> **★ A-41（补第 5 类）**：v1.5 缺"**模型系数表 → tee-infer**"通道 → A-33「tee-infer 月窗口按**标准 token**计数」无实现路径（tee-infer 拿不到系数）。本节补入，使 T1/T2 的"配额与计费同口径"可落地。

| 副作用 | 通道 | 消费者（数据面落点） | 失败语义 |
|---|---|---|---|
| TEE 配额（token 限额，含 month） | `QuotaApplier.Apply` → `POST /usage/quota` | `tee-infer` `reserveQuota`（既有） | **报错回滚**（TEE 保留旧配额，B-6.4-2） |
| **模型系数表（`in_coef/out_coef`）★ A-41** | `QuotaApplier.ApplyCoefficients` → `POST /usage/quota`（同通道携带） | `tee-infer` `reserveQuota`（**原始 token → 标准 token** 换算） | **报错**（TEE 保留旧系数；月配额按旧系数继续，**不**静默按 1:1 计——否则口径错） |
| 并发/速率 | `PolicyApplier.ApplyConcurrency` → gateway-core **策略表** | `gateway-core` 限流（非 TEE 通道） | 报错（不影响 TEE 配额） |
| 缓存档（`none/exact/semantic`） | `PolicyApplier.ApplyCacheTier` → gateway-core 策略表 | **语义缓存 P0-2**（按租户读档） | 报错（缓存降级为 `none` 兜底） |
| 超额降级（`degrade`） | `PolicyApplier.ApplyOverQuota` → 策略表 | 语义缓存/并发（关闭语义缓存、降并发） | 报错；`reject`/`charge` 无此下发 |

> **调用点**：全部在 `ApplyPlan`（§6.4.1 步骤 2a/2a'/2b）**唯一入口**；热更新路径（§6.14 `Reload`）重放同一入口。**测试**：T-6.4-5 断言各类副作用各自到达其 stub 消费者（INT-3 扩展）；**T-6.4-7** 断言系数下发后 `reserveQuota` 按标准 token 计数（§6.4.6）。

#### 6.4.6 边界与测试

| 编号 | 边界 | 处理 |
|---|---|---|
| B-6.4-1 | 套餐不存在 | 400，不下发 |
| B-6.4-2 | 下发部分成功 | **逐条下发**（`tee_client.go:44`），失败即报错；TEE 保留现有配额（**不发清除**） |
| B-6.4-3 | 旧版 tee-infer（不识别 limits/month） | 版本耦合（`teequota.go:26-30`）——**部署须同版本**，否则该次下发被旧端视为"清除"；**CI 校验版本** |
| B-6.4-4 | 同租户重复绑定 | 幂等（同 plan → 无变化；不同 plan → 新增订阅记录） |
| B-6.4-5 | 企业版 `MonthlyTokens=0` | 不下发限额（不限），仅下发并发/速率 |
| B-6.4-6 | 降配与当月已用冲突 | 次日生效（§6.4.2） |
| B-6.4-7 | **系数下发与价表版本不一致**（★ A-41） | tee-infer 记录 `coef_version`；与配额下发**同版本**（同 `PriceTable.Version`）。版本不符 → 拒（同 B-6.4-3 版本耦合）；**不得**回退 1:1（防口径错，§6.4.5 第 2 行失败语义） |
| T-6.4-1 | 4 档套餐编译 | 配额值正确 |
| T-6.4-2 | 下发失败 | 报错且 TEE 保留配额 |
| T-6.4-3 | month 窗口跨月翻转 | 计数归零 |
| T-6.4-4 | 降配排程 | 次日生效 |
| T-6.4-5 | 副作用下发（§6.4.5） | 并发/缓存档/降级各自到达 stub 消费者 |
| T-6.4-6 | 回读确认（P-1/M6） | POST 2xx 但回读不符 → 判失败；回读符 → M6 计时停止 |
| T-6.4-7 | **系数下发 → 标准 token 计数（★ A-41）** | 下发 `{gpt-4: in=10}` 后，`reserveQuota` 对 100 原始输入 token 判为 **1000 标准 token**（月配额按标准 token 消耗）；系数版本与配额同版；版本不符 → 拒（B-6.4-7） |

### 6.5 计价引擎（T4，L3）

#### 6.5.1 计价伪代码

**★ A-37 月累计缓存（性能优化）**：
- `monthStdBefore` 是计价热路径（每次 `Rate` 调用、每模型调用一次）。若每次都从账本 `SUM(std_in/std_out)` 扫全月条目，第 30 天日结时复杂度为 O(月内条目数 × 模型数)。
- **缓存方案**：日结完成后写入 `month_accum` 内存缓存（key = `tenant+model+month`，value = `{stdIn, stdOut, requests, lastDay}`）。`monthStdBefore` 优先读缓存；缓存未命中时回源 DB 并回填。
- **失效策略**：仅在「**补账**（迟到数据写入某日，改变某月 `std` 累计）」时失效对应月份缓存——std 在入账时已按当日价表算好并**锁定**（A-32/A-39），**价格表热更新不影响历史 std 值**（只影响新条目），故热更新**不**触发缓存失效（只有补账会）。★ A-51：删去旧版"或价格表热更新且 affect 已入账日"这一与后半句**互斥**的触发条件。
- **预热**：日结启动时（启动时缺口扫描 + 每日日结）逐租户逐模型回填当月缓存。
- 此优化为**性能增强**，不影响正确性；P0 可先不做（DB 扫表 30 天量级可接受），P1 性能优化阶段引入。登记在 §8.4 P-3 项下。

```go
// Rate 计算周期金额（先累加后取整，§6.5.3）。
// ★ A-39（订正 v1.5 的 A-32 未闭环）：std 来源 = **账本锁定值** `mu.StdIn/mu.StdOut`
//   （由 foldByModel 从账本 `std_in/std_out` 字段累加；入账时各日按**当日价格表版本**算好的定值，§5.1/§6.2）。
//   **不再用当前价格表重算 std** —— 与 monthStdBefore（同样读账本锁定 std）**同源**，
//   故价格表热更新下 `Σ daily.Rate == RateMonthly` 恒成立（§6.7）。
//   （v1.5 曾在此用 `StandardTokens(mu.TokensIn, mu.TokensOut, mp)` 重算 → 与 monthStdBefore 异源，
//    月中调价即破坏可加性：见附录 G-5 反例。）
// RateMu 计算周期的**亚分**金额（千分之一分，未取整）。
// ★ A-44：把取整**外提**为唯一入口点——`Rate`/`RateMonthly` 均 = `roundAmount(RateMu(...))`；
//   月结（§6.7）消费本函数得**月账权威额**并在此**唯一一次取整**（R-16）；超额费由 `ExtraAmount`
//   单列**独立超额账单**、**各自取整一次**（★ A-45，不并入月账）。
func (e *ratingEngine) RateMu(u UsageAgg, tbl PriceTable) (int64, error) {
    var totalMu int64 // 千分之一分累计（亚分精度，最后统一取整）
    for modelKey, mu := range u.ByModel {
        mp, ok := tbl.Models[modelKey]        // tbl 仅提供**阶梯单价**（InPer1K/OutPer1K），不参与 std 换算
        if !ok { return 0, ErrPricingMissing{modelKey} }   // §6.10.3（★ A-46：指标 #18 的**唯一发射点**）
        // 阶梯：progressive（累进）——按"月累计标准 token"分档（§6.5.2）；
        // ★ A-26（订正 A-21）：**入/出各用一根独立的月累计轴**——输入按"输入月累计"、输出按"输出月累计"
        //   各自落在同一组阶梯上。区间起点 = 该租户该模型"当月初至周期起点"的**分轴**累计
        //   （A-2：u.TenantID/u.Period 显式携带）。此即 §6.7「累进可加」得以成立的充要条件。
        inBefore, outBefore := e.monthStdBefore(u.TenantID, modelKey, u.Period)  // ★ 账本锁定 std（区间起点）
        totalMu += rateModel(mu.StdIn, mu.StdOut, inBefore, outBefore, mp)       // ★ A-39：段长亦取自账本锁定 std
    }
    return totalMu, nil
}

// Rate 周期金额 = roundAmount(RateMu)（★ A-44：**唯一取整点**在此，R-16）。
func (e *ratingEngine) Rate(u UsageAgg, tbl PriceTable) (Amount, error) {
    mu, err := e.RateMu(u, tbl)
    if err != nil { return 0, err }
    return roundAmount(mu, e.cfg.Rounding), nil // ← 唯一取整点
}

// RateMonthly 月结权威入口（A-3）：语义 = Rate 传入月聚合（Epoch="monthly"），月累计起点 = 月初。
func (e *ratingEngine) RateMonthly(u UsageAgg, tbl PriceTable) (Amount, error) {
    return e.Rate(u, tbl)
}
```

#### 6.5.2 阶梯定价口径（T4，L3）

| 项 | 口径 | 理由 |
|---|---|---|
| 分档依据 | **各轴独立的月累计标准 token**（★ A-26 订正：输入按其"输入月累计"、输出按其"输出月累计"，各自 `Σ day ≤ 当日`） | "量越大单价越低"以月为观测周期；**分轴**是"累进对累计位置可加"的充要条件（§6.7） |
| 分档方式 | **累进（progressive）**：跨档时低档部分按低档单价、超出部分按高档单价 | 边界连续、可解释；`flat`（整档）会造成阈值附近金额跳变 |
| 阶梯应用维度 | **按模型**独立分档 | 不同模型单价不同，混合分档不可解释 |
| 输入/输出 | 分别计（`InPer1K`/`OutPer1K`）**且各占一根独立轴** | 输入输出成本结构不同；分轴后日/月累进**可加**（A-26） |

```go
// rateModel 返回"千分之一分"单位的亚分金额（累进阶梯）。
// ★ A-26（订正 A-21）：输入/输出各占一根**独立**的"月累计标准 token"轴——
//   输入落在 [inBefore, inBefore+stdIn)，输出落在 [outBefore, outBefore+stdOut)，
//   **两轴互不串接**。此即"累进对累计位置可加"的充要条件：
//   日结的各日区间精确划分月轴（[Σ_{k<d}std_k, Σ_{k≤d}std_k) 首尾相接），故
//   Σ_day rate(该日区段) == rate(整月区段 ∪) 恒成立（无迟到数据），§6.7 无需阶梯修正。
//   （A-21 曾令 out 起点 = inBefore+stdIn 而**串接**两轴，导致日/月不可加——已订正。）
// ★ A-24：overlap 契约规定 up<=0 视作 +∞（顶档 UpToTokens=0），故最高档正确计价。
func rateModel(stdIn, stdOut, inBefore, outBefore int64, mp ModelPrice) int64 {
    var mu int64
    for _, tier := range mp.Tiers {
        lo := prevUpTo(tier, mp.Tiers)
        inSeg  := overlap(stdIn,  inBefore,  lo, tier.UpToTokens)   // ★ A-26：输入轴独立
        outSeg := overlap(stdOut, outBefore, lo, tier.UpToTokens)   // ★ A-26：输出轴独立
        mu += int64(float64(inSeg)  / 1000.0 * tier.InPer1K  * 1000) // 分×1000
        mu += int64(float64(outSeg) / 1000.0 * tier.OutPer1K * 1000)
    }
    return mu
}
```

#### 6.5.3 取整与精度（L3，★ 零容差要点）

| 规则 | 内容 |
|---|---|
| 内部精度 | 全部以 **float64 系数输入**，但**金额累加用整数**（"千分之一分"= 0.001 分）；一次浮点乘后**立即截断为整数亚分单位** |
| 取整点 | **每个账单一次**（`accumulate_then_round=true`，R-16）——**禁止逐笔取整**（否则 N 笔累积误差 ≤ N×0.5 分，破坏零容差） |
| 取整方式 | `half_up`（默认）或 `floor`（R-15） |
| 负值（★ C-3） | **计费用量**恒 ≥ 0（token ≥ 0）；出负即 panic（不变量）。**但调整项/冲正**可为负（B-6.7-2/§7.5）——负数取整按 **`away_from_zero` 对称**（`half_up` 下 `-0.5 → -1`，即 `roundAmount(-x) == -roundAmount(x)`），保证"日账之和 + 调整项 = 月账"在取整后可加、对账不漂移 |

#### 6.5.4 重试 token 归因（T3/T4，L3，M9）

| 项 | 口径 |
|---|---|
| 归因 | `retry_toks` **不计入** `TokensIn/TokensOut`（不进用户金额）；单独列示为"平台承担" |
| 数据来源（★ A-23/A-29：**两路**） | **路①** push 事件 `is_retry=true`（`sync_mode=push`，§6.3.4）；**路②** pull 聚合 `retry_tokens`（`sync_mode=pull`，默认，§6.3.4）——**二者单写者互斥**，默认 pull 下由路②生效 |
| pull 侧净量口径（★ A-27+A-35） | `GET /usage` **双字段**：既有 `tokens_in/out` 保留原口径（含 retry，向后兼容）、新增 `tokens_in_net/tokens_out_net` 为剔除 retry 的净量 + `retry_tokens` 单列 → 拉取侧**消费 `_net` 字段入账**，`tokens` 与 `retry` 不重叠（M9 与 M1 同保）；恒等校验 `tokens_in = tokens_in_net + retry_tokens` |
| 用户账单约束 | `BillItem.RetryToks` 仅**展示**，**不计入 `Amount`**（M9 不变量） |
| 平台成本视图（★ C-1） | `PlatformCostView.Retry/Total`（§4.1.7）聚合 `retry_toks` 供**内部成本核算**（不进对外账单金额）；指标 **#19**（§9.1） |

```go
// 平台成本查询（内部端点 /v1/adminext/billing/platform-cost?period=2026-10，role=admin）
cost := s.platformCost.Retry(tenant, period)  // map[model_key]retryTokens
s.metrics.setPlatformRetryTokens(tenant, sum(cost)) // 指标 #19
```

#### 6.5.5 超额计费（`OverQuota=charge`，L3）

```go
// ★ D-11：补全入参与类型（此前片段引用未定义符号 monthStdTotal/plan/mp）。
// ★ D-12/A-26：超额金额**入/出分价**（`rateAtTopTier(stdIn, stdOut, mp)`）——单入参无法承载最高档双价。
// ★ A-33（口径统一）：
//   配额口径：Plan.MonthlyTokens 为**标准 token 合计**软上限（单位与计价维度一致）。
//   tee-infer 月窗口（§6.4.3）**同样按标准 token 计数**（与计费口径统一，避免两套换算）。
//   超额判定：不是"每轴独立超额"，而是**套餐级合计超额后按入优先占额分配到各轴**——
//   输入先占 [0, inUsed)、输出后占 [inUsed, inUsed+outUsed)；
//   超出 MonthlyTokens 的段即超额段，按其落在输入段/输出段的长度分别以最高档 InPer1K/OutPer1K 计价。
//   （与 A-26 分轴不矛盾：阶梯计费的"档位"按各轴独立累计；超额的"阈值"是合计软上限。）
// ★ A-44（P0 订正，两条）：
//   ① **单位**：返回**亚分**（千分之一分，与 `RateMu` 同量纲、**未取整**）——由 `CloseMonthly` 在
//      生成**超额账单**时**单独一次 `roundAmount`**（★ A-45：超额**不并入月账**，故月账与超额账单
//      各为独立账单、各取整一次，R-16）。旧版返回亚分却被并入月账 `+= Amount`（分）
//      → 金额 ±1000× 且 `Amount += int64` 不可编译。
//   ② **基数**：超额判定必须用**套餐级合计**（Σ_模型 当月 std）对 `Plan.MonthlyTokens`，
//      而非**逐模型**各拿全额上限比——后者在 n≥2 模型时恒 Σ_i max(0,m_i−L) ≤ max(0, Σ_i m_i−L)
//      → **系统性漏收**（反例：L=1000、双模型各 800 合计 1600，真实超额 600，旧法计得 0）。
//      归属规则：按各模型「当次+月前」合计 std **降序**（并列按 `modelKey` 升序）做**瀑布削额**——
//      套餐额度被前序模型吃尽后，超出部分归该模型；再在该模型内按「入先占、输出后占」拆到 in/out 轴。
func (e *ratingEngine) ExtraAmount(u UsageAgg, p *Plan, tbl PriceTable) (int64, error) {
    // 1. 套餐级合计：逐模型取「月前（账本锁定）+ 当次（账本锁定）」std。
    type mUsed struct{ mk string; inUsed, outUsed int64 }
    var ms []mUsed
    var totIn, totOut int64
    for mk, mu := range u.ByModel {
        inBefore, outBefore := e.monthStdBefore(u.TenantID, mk, u.Period)  // 标准 token（账本锁定，A-32/A-39）
        inUsed, outUsed := inBefore+mu.StdIn, outBefore+mu.StdOut           // 当次 std 亦取账本锁定值（A-39）
        if _, ok := tbl.Models[mk]; !ok { return 0, ErrPricingMissing{mk} }  // 缺价 → 拒出账（★ A-46）
        ms = append(ms, mUsed{mk, inUsed, outUsed})
        totIn += inUsed; totOut += outUsed
    }
    // 2. 套餐级合计超额（★ A-44②：基数 = 合计，非逐模型）
    overTotal := max64(0, totIn+totOut-p.MonthlyTokens)
    if overTotal == 0 { return 0, nil }
    // 3. 瀑布归属：合计用量降序（并列 modelKey 升序）——额度耗尽后余量即该模型超额段。
    sort.Slice(ms, func(i, j int) bool {
        si, sj := ms[i].inUsed+ms[i].outUsed, ms[j].inUsed+ms[j].outUsed
        if si != sj { return si > sj }
        return ms[i].mk < ms[j].mk
    })
    remaining := p.MonthlyTokens
    var totalMu int64   // 亚分
    for _, m := range ms {
        used := m.inUsed + m.outUsed
        if remaining >= used { remaining -= used; continue }   // 本模型整段在额度内
        consumed := remaining; remaining = 0                   // 本模型部分超额
        consumedIn := min64(consumed, m.inUsed)                // 入先占额
        overIn  := m.inUsed  - consumedIn                      // 入轴超额段
        overOut := m.outUsed - (consumed - consumedIn)         // 出轴超额段
        totalMu += rateAtTopTier(overIn, overOut, tbl.Models[m.mk])  // 该模型最高档 In/Out 双价（亚分）
    }
    return totalMu, nil
}
```

#### 6.5.6 边界与测试

| 编号 | 边界 | 处理 |
|---|---|---|
| B-6.5-1 | 单价表缺该 model | `ErrPricingMissing` → **拒出账**（冻结，§6.10.3） |
| B-6.5-2 | 系数为 0/负 | 缺省 1；负值拒加载（R-14 校验） |
| B-6.5-3 | 阶梯为空 | 视为**单档全量**：合成 `Tier{UpToTokens:0(∞), InPer1K, OutPer1K}`（单价取该模型系数档，**非** 0）——`overlap` 对 `up<=0` 视作 +∞（★ A-24），故计正常金额，**非** 0 金额 |
| B-6.5-4 | 阶梯不连续（上界未覆盖） | 配置校验拒绝（附录 D） |
| B-6.5-5 | 跨档边界（恰好 = 上界） | 归入**低档**（`[lo, up) → [lo, up]` 统一为左闭右开，最低档含 0） |
| B-6.5-6 | `half_up` 与银行家舍入 | **不用**银行家舍入（记账惯例用 half_up） |
| B-6.5-7 | 金额溢出 int64 | 上限校验（> 1e15 分拒绝，防异常数据） |
| T-6.5-1 | 单模型单日计价 | 与手算一致 |
| T-6.5-2 | 跨档累进 | 分段金额正确 |
| T-6.5-3 | 逐笔 vs 一次取整 | 差异用例（证明 R-16 必要性） |
| T-6.5-4 | retry token | 用户金额不含 |
| T-6.5-5 | 缺单价 | 出账被拒 |
| T-6.5-6 | 换算唯一实现（A-9） | `Rate` 与配额编译调用同一 `StandardTokens`，无内联乘（grep 断言） |
| T-6.5-7 | 日/月分档一致（A-6） | `Σ daily.Rate == RateMonthly(月聚合)`（无迟到数据） |
| T-6.5-8 | `UsageAgg` 生产端填充（A-13） | 日结 `foldByModel(tenant,"daily",day,…)` 返回的 `TenantID/Epoch/Period` 均非空；`Rate` 分档区间非退化 |
| T-6.5-9 | **入/出分轴可加性回归（★ A-26/A-32）** | 双日各 `in/out` 均非 0、跨档价跳变用例：`Σ daily.Rate == RateMonthly`（分轴成立）；**反向断言**：若两轴**串接**（旧 A-21）则该式**不成立**（附录 G-4 反例 → 防止 A-21 回归）；**★ A-32 追加**：「月中调价后仍可加」用例——D1 用价格表 v1（in_coef=1.0）入账 `in=1000` → 出日账；D2 热更新为 v2（in_coef=2.0）入账 `in=1000` → 出日账；断言 `Σ daily.Rate == RateMonthly(月聚合, v2)` 且 `monthStdBefore` 在 D2 返回 D1 的 std_in=1000（非重算为 2000） |
| T-6.5-10 | **超额段入优先占额（★ A-33）** | `MonthlyTokens=1000`，`inUsed=800`、`outUsed=400`（合计 1200，超额 200）→ 超额全部落在输出轴（overIn=0, overOut=200）；`inUsed=1100`、`outUsed=200`（合计 1300，超额 300）→ 入先超（overIn=100, overOut=200）；验证 overIn+overOut == overTotal 且金额 = overIn×InPer1K + overOut×OutPer1K |
| T-6.5-11 | **超额单位与单次取整（★ A-44①）** | `ExtraAmount` 返回**亚分**（未取整）；`CloseMonthly` 断言：月账 `amtAuthoritative == roundAmount(RateMu(月聚合))`、超额账单 `== roundAmount(ExtraAmount(...))`——**两账单各自独立一次取整**（R-16），**均不得把亚分当分直接相加**（防 ±1000× 金额回归）；`Amount += int64` 处编译必须通过（类型回归） |
| T-6.5-12 | **超额套餐级合计基数（★ A-44②）** | `MonthlyTokens=1000`，双模型 M1/M2 各 `inUsed+outUsed=800`（合计 1600）→ 真实超额 600，`ExtraAmount` **必须 > 0**（旧逐模型法得 0 = 漏收，防 A-44② 回归）；三模型各 600（合计 1800）→ 超额 800；并验证瀑布归属总量 `Σ over_i == overTotal` 且与模型下标顺序无关（仅与用量降序有关） |

### 6.6 日结账单生成（T5，L3）

#### 6.6.1 流程伪代码

```go
// CloseDaily 生成某租户某日账单（幂等：同 (tenant,daily,period) 唯一）。
func (s *BillingService) CloseDaily(ctx context.Context, tenant, day string) (*Bill, error) {
    if frozen, _ := s.freeze.State(tenant); frozen { return nil, ErrFrozen }  // 冻结不出账
    // 1. L2 对账（出账门禁，§6.12.2）
    ok, ratio := s.reconcileL2(ctx, tenant, day, day)
    s.metrics.setReconcileDiff(tenant, ratio)   // ★ O-7：指标 #11 生产者（M1 判据）
    if !ok {
        // ★ A-22：门禁与冻结**分离**——`diff>0` 一律**不出账**；**冻结**仅当超软阈值。
        if ratio > s.cfg.Anomaly.ReconcileAlertRatio {
            s.freezeAndAlert(tenant, "reconcile_diff", ratio)   // 硬：ratio>0.1% → 冻结 + 告警
        } else {
            s.onReconcileWarning(ctx, tenant, day)              // 软：0<ratio≤0.1% → 回补、不冻结（§6.12.3）
        }
        return nil, ErrReconcile
    }
    closeStart := time.Now()                    // ★ O-7：#7 日结耗时生产者
    // 2. 读数 → 计价
    entries, err := s.store.Ledger().Range(LedgerQuery{TenantID: tenant, DayFrom: day, DayTo: day})
    if err != nil { return nil, err }
    agg := foldByModel(tenant, "daily", day, entries)   // ★ A-13：显式携带 tenant/epoch/period；★ A-39：agg.StdIn/StdOut 累加自账本锁定值
    amt, err := s.rating.Rate(agg, s.price.Current())   // ★ A-39：std 取自 agg（账本锁定），s.price.Current() 仅提供阶梯单价
    if err != nil { s.freezeAndAlert(tenant, "pricing_missing", 0); return nil, err }
    // 3. 构造账单 + 明细（含阶梯分解）
    b := buildBill(tenant, "daily", day, agg, amt, s.price.Current(), s.store.Ledger(), s.auditHead())
    // 4. 签名 + 落库（唯一约束保证幂等）
    b.Sig = s.signer.Sign(b)
    if err := s.store.Bills().Put(b); err != nil {
        if isUnique(err) { return s.store.Bills().Get(b.ID) }  // 已存在 → 返回既有
        return nil, err
    }
    s.metrics.incBillIssued("daily")
    s.metrics.observeClose("daily", time.Since(closeStart))   // ★ O-7：指标 #7 生产者（M3/M4）
    return b, nil
}
```

#### 6.6.2 调度与并发（L3）

| 项 | 结论 |
|---|---|
| 触发 | 定时任务在 `daily_close_at`（默认 02:10）对**所有活跃租户**逐一出账 |
| 逐租户串行 | 单写者（SQLite WAL）；跨租户可并行（每租户一事务） |
| 幂等 | `UNIQUE(tenant_id,kind,period)`；重复触发返回既有账单 |
| 补账 | 漏跑的日子由"缺口扫描"补出（启动时扫 `bills` 与账本日期的差集） |

#### 6.6.3 边界与测试

| 编号 | 边界 | 处理 |
|---|---|---|
| B-6.6-1 | 当日无用量 | **不生成**空账单（避免噪音）或生成 0 元账单（**可配**，U-12） |
| B-6.6-2 | 对账不通过 | 冻结 + 不出账 |
| B-6.6-3 | 账单已存在 | 返回既有（幂等） |
| B-6.6-4 | 处理中途重启 | 未提交事务回滚；重启后缺口扫描补账 |
| B-6.6-5 | 跨日边界的请求（23:59:59 起，次日完成） | 以**审计事件时间戳**归日（与计量口径一致，`billing.go:52`） |
| B-6.6-6 | 单价表在生成中途热更新 | 账单**锁定生成时的版本**（`b.PriceVersion`，§4.1.6/§5.3），不因热更新而变 |
| T-6.6-1 | 正常日结 | 金额=流水折算 |
| T-6.6-2 | 重复日结 | 幂等 |
| T-6.6-3 | 重启补账 | 缺口补出 |
| T-6.6-4 | 冻结租户 | 不出账 + 409 |

### 6.7 月结账单生成（T5，L3）

- 触发：次月 `monthly_close_day`（默认 1）`monthly_close_at`（默认 03:10）。
- **统一口径（★ A-6 订正）**：**日结与月结的分档依据恒为"月累计标准 token"**（§6.5.2），**不存在**"日结按当日累计"的第二种口径。日结生成某日账单时，该日 token 落在"**当月初至昨日的累计**"之后的档位（**分轴** `monthStdBefore`，★ A-26/§6.5.1）；月结对整月聚合按"整月累计"重算——**★ A-39：「重算」= 对账本锁定 `std_in/std_out` **求和**得整月累计（`monthAgg` / `foldByModel` 累加），**不是**按当前价格表重算 std 换算**（后者即下条批判的"方案 a"）。
- **可加性（为何日账之和 ≈ 月账）**：**累进阶梯对累计位置可加**——`Σ_day rate(该日在累计中的区段) == rate(整月区段 ∪)`。**★ A-26 充要条件**：可加性要求**入/出各占一根独立轴**（§6.5.2）——日结时第 d 日在输入轴的区间 `[Σ_{k<d}stdIn_k, Σ_{k≤d}stdIn_k)`、在输出轴的区间 `[Σ_{k<d}stdOut_k, Σ_{k≤d}stdOut_k)` **首尾精确相接**，其并集即整月区间，故按轴可加。若两轴**串接**（A-21 旧口径 `outStart=inBefore+stdIn`），则日结各日的轴区间与月结**不一致 → 不可加**（反例见附录 G-4）。**订正后**：无迟到数据时 `Σ daily.amount == monthly.amount` 恒等，月结**不需**做阶梯修正。
  - **★ A-32 扩展（热更新下仍可加）**：`stdIn/stdOut` 在**入账时**按当日价格表版本算好并存入账本（§5.1 `std_in/std_out`），之后永不修改。价格表热更新（§6.14）只影响**更新后**新入账条目的 std 系数，历史条目不变 → 月累计 = 各日 std 之和恒稳定 → 日/月可加性在热更新下仍成立。若采用「月结对所有日按当前价格表重算 std」（方案 a），则热更新会导致已出日账的累计位置与月结对不上 → 调整项系统性非 0（非迟到数据导致），不可加。
- **调整项（安全线，非常规项）**：仅当发生**补账 / 迟到入账**（某日账单已出账后，又有 token 归入该日 → 见 B-6.6-4/B-6.6-5）时，已出日账之和会**低于**权威月额，其差记为**调整项**（`adjust = 权威月额 − Σ daily.amount`，可为负，B-6.7-2），实现"**月账权威**"。
- **U-11 登记（口径统一后）**：P0 已**统一**日/月分档为月累计，并证明可加性（★ A-26：可加性**充要条件 = 入/出分轴**，§6.5.2）；U-11 余项仅为"超额独立价 vs 最高档单价"（§6.5.5，★ A-26/D-12 已定**入出分价 + 入优先占额**约定）与"迟到数据的调整项呈现话术"（P-3），不再涉及日/月分档冲突。

```go
// CloseMonthly 月结：以月累计（账本锁定 std）重算阶梯（权威），生成调整项 + 超额账单。
// ★ A-44/A-45 订正：月账 = **阶梯基本费**（权威）；**超额费单列"超额账单"**（kind="overage"，§6.4.4），
//   二者**不混**——故 §6.7「无迟到数据调整项 = 0」成立（旧版把亚分超额 `+=` 进月账 → ① 单位 ±1000×、
//   ② 调整项恒非 0，见 A-44/A-45）。
func (s *BillingService) CloseMonthly(ctx context.Context, tenant, month string) (*Bill, error) {
    // 1. 月对账（出账门禁；★ A-22：与日结同口径——diff>0 不出账，冻结仅 ratio>0.1%）
    ok, ratio := s.reconcileL2(ctx, tenant, month+"-01", month+"-31")
    s.metrics.setReconcileDiff(tenant, ratio)   // ★ O-7：指标 #11 生产者
    if !ok {
        if ratio > s.cfg.Anomaly.ReconcileAlertRatio {
            s.freezeAndAlert(tenant, "reconcile_diff", ratio)
        } else {
            s.onReconcileWarning(ctx, tenant, month+"-01")
        }
        return nil, ErrReconcile
    }
    // 2. 月累计用量 → 按**整月累计**重算阶梯（权威口径）
    //    ★ A-39：aggMonth.StdIn/StdOut = 账本锁定 std 之和（monthAgg 累加，不按当前价格表重算）；
    //    s.price.Current() 仅提供**阶梯单价**（账单另行锁定 b.PriceVersion）。
    aggMonth := s.monthAgg(tenant, month)
    baseMu, err := s.rating.RateMu(aggMonth, s.price.Current())   // ★ A-44①：**亚分**（不在此时取整）
    if err != nil { s.freezeAndAlert(tenant, "pricing_missing", 0); return nil, err }
    // 3. 调整项 = 权威月额 − Σ 已出日账额（★ A-44①：月账**唯一取整点**在此，R-16）
    amtAuthoritative := roundAmount(baseMu, s.cfg.Rounding)
    dailySum := s.sumDaily(tenant, month)
    adjust := amtAuthoritative - dailySum
    // 4. 生成月账（含日账引用 + 调整项；**不含超额**——超额单列）
    monthlyBill := buildBill(tenant, "monthly", month, aggMonth, amtAuthoritative, s.price.Current(), s.store.Ledger(), s.auditHead())
    // 4b. 超额账单（★ A-43 接线 / ★ A-45 单列）：`OverQuota=charge` 套餐，**独立账单** kind="overage"，
    //     与月账同日生成、**不并入月账**（故月账"调整项 = 0"语义纯净；§6.4.4「账务侧单独出超额账单」）。
    var overageBill *Bill
    if p, _ := s.plans.Resolve(tenant, time.Now().UnixNano()); p != nil && p.OverQuota == "charge" {
        overMu, err := s.rating.ExtraAmount(aggMonth, p, s.price.Current())  // ★ A-44②：**套餐级合计**基数；返回亚分
        if err != nil { s.freezeAndAlert(tenant, "pricing_missing", 0); return nil, err }
        if overMu > 0 {   // 未超额则不生成空账单（B-6.6-1 同口径）
            overageBill = buildBill(tenant, "overage", month, aggMonth,
                roundAmount(overMu, s.cfg.Rounding), s.price.Current(), s.store.Ledger(), s.auditHead())
        }
    }
    // 5. 签名 + 落库（月账 + 可能的超额账各锁各自 PriceVersion/链锚）
    ...
    return monthlyBill, nil
}
```

**边界**：B-6.7-1 月内有不完整的日账 → 先补日账再月结；B-6.7-2 调整项为负（迟到数据使日账之和偏低，权威月额更高时为**正**；反向冲减时为**负**）→ 允许，账单明示；B-6.7-3 月结重复 → 幂等；B-6.7-4 调整项取整对称（C-3）；**B-6.7-5（★ A-44/A-45）** `charge` 套餐未超额（`ExtraAmount==0`）→ **不生成**超额账单（避免空账单）；超额账单与月账 **kind 不同**（`overage`/`monthly`），`UNIQUE(tenant_id,kind,period)` 保证各自幂等、互不覆盖。

**★ 交付口径声明（C-4/P-3）**：
- **权威性**：**月账为对外结算凭证（权威）**，日账为**预估值**（便于日常对账）。二者不一致时**以月账为准**，差额以**调整项行**显式列示（含 `period` 引用日账区间）。
- **对外话术**（写入账单 PDF/CSV 表头 & 租户自助页）：
  > "本月**应结金额以月账单为准**；日账单为按日预估，供日常核对。若因数据迟到/补录产生差异，月账单以『**调整项**』一行列示，调整项前后金额均可追溯。"
- **数字一致性**：无迟到数据时 `Σ 日账 = 月账`（§6.7 可加性），调整项为 0；有迟到数据时**仅**调整项不为 0（不重列全月明细），故对外**始终只呈现一个权威总额**（月账）。

**测试（T-6.7-*）**：

| 编号 | 用例 | 期望 |
|---|---|---|
| T-6.7-1 | 正常月结（无迟到） | `Σ 日账 = 月账`，调整项 = 0 |
| T-6.7-2 | 迟到数据 → 月结 | 调整项 = 权威月额 − Σ 日账（可为负，B-6.7-2），账单明示 |
| T-6.7-3 | **`OverQuota=charge` 套餐月结（★ A-43/A-45）** | 走 §6.7 步骤 4b：对**超 `MonthlyTokens` 的套餐级合计标准 token 段**生成**独立"超额账单"**（`kind="overage"`，金额 = 最高档 In/Out 分价，§6.5.5），**不并入月账**；断言**月账 `adjust == 0`**（无迟到数据，★ A-45：旧版并入月账 → 调整项恒非 0）；对照实验：`OverQuota=reject/degrade` 套餐**不生成**超额账单——证 `ExtraAmount` 此前为**死代码**（全文无调用点）已消除 |
| T-6.7-4 | **超额账单单位与取整（★ A-44）** | ① `ExtraAmount` 返回亚分；超额账单金额 `== roundAmount(overMu)`（**一次取整**，R-16）；② 计数器/金额断言：`monthlyBill.Amount` 与 `overageBill.Amount` **各自独立**、无一被放大 1000×；③ 多模型：`MonthlyTokens=1000`、M1/M2 各 800（合计 1600）→ `overageBill.Amount > 0`（旧逐模型法得 0 = 漏收）|

### 6.8 导出（T5，L3）

| 格式 | 内容 | 注意 |
|---|---|---|
| CSV | 明细行（模型/token/标准 token/阶梯/金额） | UTF-8 BOM（Excel 兼容） |
| PDF | 账单头 + 明细 + 签名 + 链锚 | **金额仅在此域出现**（§3.1.3）；含 §6.7 交付话术 |

> **水印（C-4/P-3）**：导出的**日账**标注"**预估**"，**月账**标注"**权威（结算凭证）**"；两者并存时以月账为准（§6.7）。

**边界**：B-6.8-1 超大账单（>10万行）→ 流式生成 + 分片；B-6.8-2 导出时账单被冻结 → 允许导出（带 `frozen` 水印）；B-6.8-3 `format` 非法 → 400；B-6.8-4 导出**必落 `bill_export` 审计**（actor/tenant/bill_id/format，★ S-3）。

### 6.9 异常检测（T8，L3）

#### 6.9.1 四类规则

```go
func (d *detector) Scan(tenants []string, day string) []Anomaly {
    var out []Anomaly
    for _, t := range tenants {
        // ① 用量突增：当日 > 过去 7 日均值 × spike_ratio
        today := d.dayStd(t, day)
        avg7, daysWithData := d.avgStd(t, day, 7)
        // ★ A-36：数据不足 3 天时不做 spike 检测（样本太少无统计意义，防新租户/月首误报）
        if daysWithData >= 3 && avg7 > 0 && float64(today) > avg7*d.cfg.SpikeRatio {
            // ★ A-25：spike 严重级用**自身维度**阈值 spike_critical_ratio（**非** ReconcileAlertRatio）——
            //   today/avg7 > spike_critical_ratio → critical（冻结）；否则 warning（不冻结，与 §9.3 一致）
            out = append(out, Anomaly{TenantID: t, Kind: "spike", Severity: sev(float64(today)/avg7, d.cfg.SpikeCriticalRatio), Ratio: float64(today)/avg7})
        }
        // ② 对账差异（L2）：0<ratio≤0.1% → warning；>0.1% → critical（§6.12.2）
        if ratio, ok := d.reconcileRatio(t, day); ok && ratio > 0 {
            // ★ A-19：不 shadow `sev` 函数名，复用统一分级 helper
            out = append(out, Anomaly{TenantID: t, Kind: "reconcile_diff", Severity: sev(ratio, d.cfg.ReconcileAlertRatio), Ratio: ratio})
        }
        // ③ 配额预警：剩余 < quota_warn_ratio
        if rem, ok := d.quotaRemaining(t); ok {
            // ★ O-8：指标 #12 `quota_remaining_ratio` 的**唯一生产者**——每次扫描回填当前剩余比
            //   （gauge；不限于低于阈值，使 Top-N 面板恒有值）
            d.metrics.setQuotaRemainingRatio(t, rem)
            if rem < d.cfg.QuotaWarnRatio {
                out = append(out, Anomaly{TenantID: t, Kind: "quota_warn", Severity: "warning", Ratio: rem})
            }
        }
        // ④ 单价缺失：账本出现单价表未知的 modelKey
        for mk := range d.modelsUsed(t, day) {
            if !d.price.Has(mk) {
                out = append(out, Anomaly{TenantID: t, Kind: "pricing_missing", Severity: "critical", Detail: mk})
            }
        }
    }
    // ★ O-8：指标 #10 `anomaly_total{kind,severity}` 的**唯一生产者**——统一出口逐条发射
    //   （此前 §9.1.1 误记为不存在的符号 `AnomalyDetector.Emit`；实为 `detector.Scan` 返回点）
    for _, a := range out {
        d.metrics.incAnomaly(a.Kind, a.Severity)
    }
    return out
}
```

#### 6.9.2 边界与测试

| 编号 | 边界 | 处理 |
|---|---|---|
| B-6.9-1 | 新租户（无 7 日均值） | 不判突增（无基线） |
| B-6.9-2 | 7 日全 0 | 不判突增（除零保护） |
| B-6.9-3 | 告警风暴（多租户同刻） | 聚合告警（按 kind 汇总） |
| B-6.9-4 | 误报（正常业务峰） | warning 不冻结，人工确认 |
| B-6.9-5 | 历史数据不足 3 天（新租户 / 月首）★ A-36 | 不判突增（样本太少无统计意义）；`avgStd` 返回 `daysWithData`，入口处 `daysWithData < 3` 直接跳过 |
| T-6.9-1 | 突增触发 | 告警 |
| T-6.9-2 | 新租户 | 不误报 |
| T-6.9-3 | 单价缺失 | critical |
| T-6.9-4 | 配额 19% | 告警 |

### 6.10 冻结/解冻状态机（T8，L3）

#### 6.10.1 状态机

```
         ┌────────────── critical 异常 ──────────────┐
 active ─┤  reconcile_diff>0.1% | spike>critical阈值 | pricing_missing ├─► frozen
    ▲    └───────────────────────────────────────┘             │
    │                                                          │
    └────────── 人工解冻（by != 系统）/ 自动恢复（对账转一致）◄─┘
```

#### 6.10.2 冻结副作用（L3）

| 副作用 | 说明 |
|---|---|
| 停止**账单交付** | `CloseDaily/CloseMonthly` 返回 `ErrFrozen`（不出新账；既有账保留） |
| 不阻断**入账** | 冻结期间仍入账本（供人工核账，`B-6.3-6`） |
| 可选：下调配额 | `auto_throttle=true`（U-13）时经 `QuotaApplier` 将配额置 0（**P0 默认关**） |
| 落审计 | `bill_freeze`（含 reason/severity/until/by） |

#### 6.10.3 关键：单价缺失 = 冻结（而非降级）

> 单价表缺该 model → **拒出账并冻结**（fail-closed）：宁可不计价，不可错计价（零容差）。这与"用量账单降级"（P-4 无单价场景）**不同**——后者是**全局无单价表**（整域降级为用量账单，无金额），前者是**部分 model 缺价**（异常，须人工）。

#### 6.10.4 边界与测试

| 编号 | 边界 | 处理 |
|---|---|---|
| B-6.10-1 | 冻结中又触发新异常 | 保留首次 reason + 升级 severity |
| B-6.10-2 | 自动解冻（对账恢复） | 仅解冻由 `reconcile_diff` 触发的；`manual`/`pricing_missing` **须人工** |
| B-6.10-3 | 解冻后补账 | 缺口扫描补出冻结期账单 |
| B-6.10-4 | 冻结期间的数据修改 | 禁止（账本不可变 + 冻结标志） |
| T-6.10-1 | 对账差异 → 冻结 | 出账被拒 |
| T-6.10-2 | 冻结 → 解冻 → 补账 | 账单补齐 |
| T-6.10-3 | pricing_missing 不解自动冻 | 须人工 |

### 6.11 余额告警（T6，L3）

```go
// 配额剩余 < quota_warn_ratio → 告警（邮件/Webhook），去重（每周期一次）。
if rem < warnRatio { s.notifier.WarnQuotaLow(tenant, rem, periodKey) }  // periodKey 幂等
```

**边界**：B-6.11-1 每周期只告警一次（`periodKey`）；B-6.11-2 已耗尽（rem=0）→ `critical`；B-6.11-3 无配额套餐（不限）→ 不告警。

### 6.12 两级对账（T7/T13，L3）

#### 6.12.1 L1 对账（tee-infer 内，已有）

- 口径：内存用量计数器 ↔ 审计链，窗口 `[启动, now)`，**容差 0**；不一致 → `billing.block`（**阻断 webhook 推送**，`billing.go:140`）。
- 本模块**不改** L1；账务侧**消费** `GET /reconcile`（`admin-service` 已有代理，`usage.go:206`）读 L1 状态。

#### 6.12.2 L2 对账（账务域，新增）

```go
// reconcileL2 账本 ↔ 审计链（逐日逐租户）对账 = 出账门禁。
// ★ A-14/A-15：显式接收 ctx（此前为未定义引用）；Range 双返回正确接收；类型正确取值。
// ★ A-42（口径唯一化，消除二义）：两侧**均取净量**（剔除 retry），retry 不入本对账（另列 RetryToks）——
//   · 账本侧 `sum(led)` 返回 `TokensIn/Out` = 净量（§4.6 `sum` 注释；账本条目不存 retry 于 tokens_* 内）；
//   · 审计链侧 `a.TokensIn` = `MeteringSource.Pull` 由 `tokens_in_net` 映射而来（§4.1.5），亦为净量。
//   故 M1 判据「Σ账本 − Σ审计链 = 0」在**同口径（净量）**下成立；retry 由 M9（`retry_toks` 不进用户金额）单独校验。
func (s *BillingService) reconcileL2(ctx context.Context, tenant, dayFrom, dayTo string) (bool, float64) {
    // 1. 账本侧三元组（净量；retry 另列）
    led, err := s.store.Ledger().Range(LedgerQuery{TenantID: tenant, DayFrom: dayFrom, DayTo: dayTo})
    if err != nil { return false, 0 }   // 账本不可读 → 不出账（fail-closed）
    lIn, lOut, lReq := sum(led)         // ★ A-42：净量
    // 2. 审计链侧三元组（从 tee-infer /usage?from&to 拉取；Pull 已把 tokens_in_net → TokensIn，净量）
    aggs, err := s.source.Pull(ctx, dayStart(dayFrom), dayEnd(dayTo))
    if err != nil { return false, 0 }   // 数据源不可达 → 不出账（fail-closed）
    a := aggs[tenant]                    // *UsageAgg（可能为 nil = 该租户零用量）
    var aIn, aOut, aReq int64
    if a != nil { aIn, aOut, aReq = a.TokensIn, a.TokensOut, a.Requests }  // ★ A-42：净量（同账本侧口径）
    // 3. 差异（净量对净量；retry 不参与，M9 另证）
    if lIn==aIn && lOut==aOut && lReq==aReq { return true, 0 }
    diff := abs64(lIn-aIn)+abs64(lOut-aOut)+abs64(lReq-aReq)
    ratio := float64(diff) / float64(max64(1, aIn+aOut+aReq))
    return false, ratio
}
```

#### 6.12.3 L2 判据口径（★ 零容差 vs 0.1%）

> **★ A-22 订正（消除 v1.2 三处自相矛盾）**：v1.2 中 `CloseDaily`（任意 `diff>0` 即冻结）、软告警行（`0<ratio≤0.1%` 不冻结）、注（冻结恒在 `diff>0`）**三者两两冲突**。现**明确分离「门禁」与「冻结」两个独立判据**，全文以此为准：

| 判据 | 条件 | 动作 |
|---|---|---|
| **出账门禁（恒）** | `diff = 0`（三元组全等） | 通过 → 出账；**`diff > 0` → 一律不出账**（`ErrReconcile`）——与冻结**解耦** |
| **冻结判据（硬）** | `ratio > 0.1%`（`ReconcileAlertRatio`） | `critical`：**冻结** + 人工（`reconcile_diff`） |
| **回补判据（软）** | `0 < ratio ≤ 0.1%` | `warning`：**不冻结**；触发**重叠窗口回补重拉**（`onReconcileWarning`，§6.12.3 下）；**下一轮重试出账** |
| 注 | 「**不出账**」恒在 `diff>0`（**门禁**）；「**冻结**」仅 `ratio>0.1%`（**判据**）——二者**分离** | 对齐 §1.3 / U-6；调用点 = §6.6.1 `CloseDaily` / §6.7 `CloseMonthly` 软分支 |

**★ 回补重拉的触发点与幂等（O-4）**：

```go
// 触发点：L2 对账发现 0<ratio≤0.1%（warning）时，非阻塞地排一次"未入账尾段回补"。
// ★ BUG-001 订正：原为“加宽窗口 [now-2×lookback, now)”，会覆盖**已入账区间**→重复入账；
//   现改为从**游标**起重拉未入账尾段 [cursor, now)（游标由 pullRange 逐段推进，天然非重叠）。
// ★ A-14/A-20：显式接收 ctx；day 统一为 string（与 §6.9/§6.16 幂等键一致）。
func (s *BillingService) onReconcileWarning(ctx context.Context, tenant, day string) {
    if s.repullInflight(tenant, day) { return }        // 幂等：同 (tenant,day) 回补进行中则跳过
    go func() {
        from := s.lastPollNs                           // ★ BUG-001：从游标起重拉未入账尾段
        if from <= 0 { from = s.store.Ledger().PollWatermark() }
        if from <= 0 || from >= s.now() { return }     // 无可回补区间 → no-op
        s.pullRange(ctx, from, s.now())               // 逐自然日段入账（非重叠 → 不重复）
        s.metrics.incAutoRepull()                      // 指标：自动回补次数
    }()
}
```

> **★ 调用点（A-22 接线）**：`onReconcileWarning` 现由 **`CloseDaily`（§6.6.1）/`CloseMonthly`（§6.7）的「软分支」**调用（`0<ratio≤0.1%` 时）——消除 v1.2「定义了机制却无调用点」的死代码（调用图审计①）。指标 #20 `auto_repull_total` 由此具备唯一生产者。
> **幂等键**：`(tenant, 回补日)` 进程内去重 + 账本 `event_key` 兜底（回补与常规拉取同键 → 不重复入账）。**仅一次**（同 warning 不反复触发）；回补后仍偏差 → 下一轮 `ratio` 若升 `critical`（>0.1%）则**冻结**。**告警行**见 §9.3 `BillingReconcileWarning`。

#### 6.12.4 边界与测试

| 编号 | 边界 | 处理 |
|---|---|---|
| B-6.12-1 | tee-infer 不可达 | 不出账（fail-closed） |
| B-6.12-2 | L1 已 blocked（推送停） | L2 仍可从 `/usage` 拉取对账（拉取不依赖推送） |
| B-6.12-3 | 账本多算了（重复入账漏去重） | **diff>0 → 不出账（门禁，`ErrReconcile`）**；**仅 `ratio>0.1%` 才冻结** + 人工（★ A-22/A-28 口径统一；**不应发生**，唯一约束兜底） |
| B-6.12-4 | 审计链断裂（`/audit/verify` 失败） | 视为 L2 不可信 → 冻结全部租户出账（**全局**） |
| T-6.12-1 | 账本 vs 审计一致 | 通过 |
| T-6.12-2 | 差 1 token（`0<ratio≤0.1%`） | **不出账 + 软回补（不冻结）**；仅 `ratio>0.1%` 才冻结（★ A-22/A-28：修正原"冻结（warning 级）"与判据表冲突） |
| T-6.12-3 | 差 5%（>0.1%） | 冻结（critical） |
| T-6.12-4 | 审计链断 | 全局冻结 |
| T-6.12-5 | **含 retry 的窗口对账（★ A-42）** | 账本净量 ↔ 审计链 `tokens_in_net` **同口径** → `diff=0`（不因 retry 破 M1）；同一窗口 `retry_tokens>0` 时 `RetryToks` 单列、不进三元组；反例断言：若误映射含 retry 的老字段 `tokens_in` 入 `UsageAgg.TokensIn` → `diff=retry>0`（证口径必须取 `_net`） |

### 6.13 故障降级（T3/T5，L3）

| 故障 | 降级 |
|---|---|
| tee-infer 不可达 | 停止拉取/对账；**不出新账**（fail-closed）；已出账不受影响；告警 |
| SQLite 不可写 | 账务域进入**只读**（查询可用、入账停）；告警 |
| 单价表加载失败 | 保留上一版本（内存）；无版本则不出账（P-3 降级为用量账单） |
| 审计链不可读 | L2 无法对账 → 不出账（fail-closed） |

**边界**：B-6.13-1 降级期间重启 → 恢复后缺口补账；B-6.13-2 只读态查询 → 200（不阻断自助）。

### 6.14 配置热更新（T1/T4/T8，L3）

```go
// Reload 热更新配置（幂等；非法配置回滚保留旧值）。
func (s *BillingService) Reload(newCfg Config) error {
    if err := validate(newCfg); err != nil { return err }   // R-1..R-34
    // 原子替换；进行中的账单**锁定旧版本**（B-6.6-6）
    s.cfg.Store(newCfg)
    s.price.Reload(newCfg.Rating.PriceTable) // 版本化
    // ★ A-41：系数随价表变更 → **必须重下发 tee-infer**（否则配额按旧系数、计费按新系数 → 口径分叉，A-33 失效）。
    //   失败**不回滚价表**（新价表仅影响后续入账 std，历史已锁定 §4.1.5）；记告警，下次 ApplyPlan/对账补齐（B-6.14-4）。
    if err := s.quota.ApplyCoefficients(context.Background(), s.compiler.ModelCoefs(s.price.Current())); err != nil {
        s.log.Warn("系数重下发失败（tee-infer 暂用旧系数，配额口径滞后）", "err", err, "ver", s.price.Current().Version)
    }
    return nil
}
```

**边界**：B-6.14-1 非法配置 → 拒绝并保留旧值（R-n）；B-6.14-2 热更新价格表 → 新账单用新版本，历史账单不变；B-6.14-3 热更新 `enabled` → 关闭时注销端点/停任务（R-1）；**B-6.14-4**（★ A-41）价表热更新须同步重下发 tee-infer 系数，失败即告警并在下次 `ApplyPlan` 补齐，期间配额口径以 tee-infer 旧系数为准（账务计费仍以账本锁定 std 为权威，§6.5.1）。

### 6.15 运行环境适配（admin-service 进程约束）（L3）

| 约束 | 说明 |
|---|---|
| 内存 | 账务域常驻内存 = 配置 + 单元价表 + 游标 + 缓存；明细走 DB（不全量载入） |
| 并发模型 | admin-service 单进程多 goroutine；账本写入**单写者**（WAL）；查询并发 |
| 无阻塞调用 | 拉取/推送/计价**不在** HTTP 请求热路径（推理链路零感知）；仅查询 API 在请求路径 |
| 与 TEE 松耦合 | 账务域**不导入** tee-infer 包；仅 HTTP 契约（§4.4）；TEE 不可达时账务降级而非崩溃 |
| 优雅关闭 | 停止调度器 → 等待进行中事务提交 → 关闭 DB |

**边界与测试**：B-6.15-1 panic recover（账务域 panic 不拖垮 admin 主服务）；B-6.15-2 优雅关闭不丢进行中账单；T-6.15-1 panic 隔离；T-6.15-2 关闭时事务完整。

#### 6.15.1 启动自检清单（★ O-5）

> 服务启动（`billing.enabled=true`）时**逐项**自检；任一失败 → **降级为只读**（查询可用、入账/出账停）并告警，**不静默启动**。

| # | 自检项 | 判据 | 失败动作 |
|---|---|---|---|
| SC-1 | DB 可写 | `PRAGMA quick_check` OK 且可开写事务 | 拒绝启动（fail-closed） |
| SC-2 | 单价表可读 | `pricing.yaml` 解析成功 + `Version` 非空 | 只读（P-3 降级用量账单） |
| SC-3 | 账本链完好 | `LedgerStore.Verify() == -1` | 只读 + `chain_broken=1` 告警 |
| SC-4 | 游标一致性 | 链尾 `head` 与 `billing_ledger` MAX(seq) 一致 | 重建 head（B-7.1-5） |
| SC-5 | 审计链可达 | `GET /audit` 2xx | 只读（L2 无法对账） |
| SC-6 | 缺口扫描 | `bills` 与账本日期差集已排程补账 | 记录待补清单 |

### 6.16 后台调度器总表（T3/T5/T7/T8，★ A-7/O-1）

> **问题（review A-7/O-1）**：v1.0 仅定义了 `RunMeteringLoop`（拉取，§6.1.1），**日结/月结定时、L2 对账周期、异常扫描、链校验、余额告警检查均无触发定义**（调用图审计：`AnomalyDetector.Scan` / `LedgerStore.Verify` 无调用点 → 指标 #4 `chain_broken` 无生产者）。本节给出**全部后台任务的周期、幂等键、单实例锁与调用点**（运维据此部署）。

| # | 任务 | 触发周期 | 幂等键 | 单实例锁 | 调用点 | 失败语义 |
|---|---|---|---|---|---|---|
| S-1 | 增量拉取 `pullOnce` | `source.pull_interval`（60s） | **游标（非重叠）**；按 UTC+8 自然日切分（★ BUG-001/007 订正） | 无需（可重入；`pollMu` 串行化） | §6.1.1 | **不推进游标**（失败段下轮覆盖），无丢账无重复 |
| S-2 | 日结 `CloseDaily`（活跃租户） | `daily_close_at`（02:10） | `(tenant,daily,period)` | **single-flight**（进程级 `Once`/`sync.Mutex`） | §6.6.1/§6.6.2 | 逐租户独立；失败留待缺口扫描 |
| S-3 | 月结 `CloseMonthly` | `monthly_close_day=1 @ 03:10` | `(tenant,monthly,period)` | single-flight | §6.7 | 同上 |
| S-4 | L2 对账 `reconcileL2` | 每次拉取后 + 每次出账前 | `(tenant,from,to)` | 无需（纯读） | §6.12.2 | 作为出账门禁 |
| S-5 | 异常扫描 `AnomalyDetector.Scan` | `schedule.anomaly_scan_interval`（5m） | `(kind,tenant,day)` | single-flight | §6.9 | 记 `anomaly_total` |
| S-6 | **链校验 `LedgerStore.Verify`** | `schedule.verify_interval`（增量 1h；全量每日低峰 04:00） | — | single-flight | §7.1.2 → **指标 #4** | 断裂 → `chain_broken=1` + 停出账 |
| S-7 | 余额告警检查 | `schedule.quota_scan_interval`（5m） | `(tenant,periodKey)` | 无需 | §6.11 | 记告警 |
| S-8 | 缺口扫描（补账） | 启动时 + 每日一次 | `(tenant,kind,period)` | single-flight | §6.6.2 | 重试 |
| S-9 | **到期扫描 `scanExpiries`** | `schedule.expiry_scan_interval`（6h） | `(tenant,periodKey)` | single-flight | §6.4.2 → **指标 #21** | 记 `plan_expiring_total`（不阻塞） |
| S-10 | **关联校验 `VerifyBillingChain`** | 出账后即时 + 每日低峰 04:30 全量 | `(bill_id)` ★ A-34 | single-flight | §7.3 → 出账/月度巡检 → **指标 #22** ★ A-34 | 锚定不符 → 标记账单 `assoc_mismatch` + 记 `billing_assoc_verify_total{result="fail"}` + 告警 `BillingAssocVerifyFailed`（**不阻断已出账**，事后审计性质）★ A-34 |

> **★ S-9 接线（A-16）**：到期扫描是 **`gateway_admin_billing_plan_expiring_total`（指标 #21，§9.1）的唯一生产者**——调用图审计下，v1.1 定义了指标 #21 与 §6.4.2 到期运营闭环，但**无任何调度器驱动**（与 A-7 同类缺陷）。S-9 补齐触发点：对每个活跃租户，读 `Plan.ExpiresAt`，按 `(days=30,7,0)` 三档判定，命中即 `metrics.incPlanExpiring(days)`；`days=0`（当日到期）兼发一条 `anomaly_total{kind="plan_expired"}`（A-17 kind 枚举）。幂等键 `(tenant,periodKey)` 保证同一周期每档只记一次，避免 6h 周期内重复计数。

> **调用点定义（伪代码）**——统一在 `StartSchedulers`：
> ```go
> func (s *BillingService) StartSchedulers(ctx context.Context) {
>     go s.RunMeteringLoop(ctx)                                  // S-1（§6.1.1）
>     s.cron.At(cfg.DailyCloseAt,   s.guard(s.closeDailyAll))    // S-2
>     s.cron.At(cfg.MonthlyCloseAt, s.guard(s.closeMonthlyAll))  // S-3
>     s.cron.Every(cfg.AnomalyScan,    s.guard(s.scanAnomalies)) // S-5
>     s.cron.Every(cfg.VerifyInterval, s.guard(s.verifyChain))   // S-6 → metrics.setChainBroken()
>     s.cron.Every(cfg.QuotaScan,      s.guard(s.checkQuotaLow)) // S-7
>     s.cron.RunNow(s.backfillGaps)                              // S-8（启动 + 每日）
>     s.cron.Every(cfg.ExpiryScan,     s.guard(s.scanExpiries))  // S-9 → metrics.incPlanExpiring(days)（A-16）
>     s.cron.Every(cfg.VerifyAssoc,    s.guard(s.verifyBillingAssoc)) // S-10 → VerifyBillingChain（★ A-31：补调用点）
> }
> // verifyChain：broken, err := s.store.Ledger().Verify(); if err == nil { s.metrics.setChainBroken(broken >= 0) }
> //             —— 这是指标 #4（§9.1）的唯一生产者（A-7 接线）
> // verifyBillingAssoc：对近 N 日出账逐张 VerifyBillingChain(b)（S-10）；不符记账单 `status=assoc_mismatch` 并 `metrics.incAssocVerify("fail")`（不阻断）
> ```
>
> **单实例锁**：admin-service 为**单实例**（§3.4）；`guard` = 进程内互斥 + 幂等键去重，防同进程重入；多副本（企业版 U-3）时由 DB 行锁 / 分布式租约替代。

---

## 7. 数据完整性与防篡改（T7，L3）

> **设计深度：L3**。本节给出**账本哈希链**（§7.1）、**账单签名**（§7.2）、**计费↔审计双向关联**（§7.3）三种机制的完整构造/校验伪代码、边界与测试，并在 §7.6 汇总**不可违反的安全不变量**（供 CI 与评审逐条核验）。

### 7.1 账本哈希链（T7，L3）

> **★ 前提声明（S-1）**：本链为**无密钥 SHA-256** 链接——`Verify()` 能检出**意外损坏与"就地"篡改**（改单条 → 该条哈希不符；删/插/重排 → 链接断），但**不能**阻止"取得库文件写权限后从断点重算整链"。因此 **"链可验证" ≠ "防篡改"**：防篡改**实质依赖 §7.5 的 WORM**（存储层不可改）。二者**必须共存**：链给"可检测性"，WORM 给"不可改性"。SQLite 单机场景若 WORM 未落地（`billing.db` 可写），则仅能防**非root/非直接文件访问**的篡改——该边界登记 **U-14**。
>
> **可选强化（HMAC-keyed 链）**：将 `computeHash` 的 `sha256.New()` 换为 `hmac.New(sha256.New, chainKey)`（`chainKey` 同 §7.4 引用式加载）。则无密钥者**无法**重算后续 `entry_hash`，抵近"无 WORM 也不可重算"。代价：验链需持有 `chainKey`（密钥管理面 +1）。P0 **默认无密钥**（依赖 WORM）；企业版/U-14 裁决后可切。

#### 7.1.1 链构造伪代码

```go
// computeHash 计算条目哈希（稳定序列化；EntryHash 自身不参与，防自指）。
// 稳定序列化约定：字段按固定顺序以 '|' 连接；整数用十进制；字符串原样（不含 '|'）。
// ★ A-40：**计价基（std_in/std_out/price_ver）必须进哈希**——否则「改 std / 改价格版本 / 改单价依据」
//   落在链外、可被就地篡改而 Verify() 检不出，直接违反 INV-2（"账本=不可否认计价依据"）。
//   序列化顺序**冻结**（v1.6 起，后续不得插队/改名，只能追加到末尾）：
//     seq|tenant|model|day|in|out|req|retry|std_in|std_out|source|price_ver|event_key|prev
//   ⚠️ **破坏性变更 / 版本边界**：v1.6 相对 v1.5 的 `entry_hash` 序列化**不兼容**（新增 3 字段），
//     存量 v1.5 链**不可用 v1.6 口径互验**。★ A-49② 迁移策略：**唯一采纳 ①「主键/台账重建」**
//     （P0 首选；账本为 TEE 内派生数据、可由审计链重放，重建后全链 v1.6 口径、`Verify()` 单口径）。
//     原列 **②「`chain_epoch` 分界 + `Verify()` 按 epoch 选口径」明确不采纳**——因 `bills`/账本
//     **无 `chain_epoch` 列**（§5.1）、`Verify()`（§7.1.2）**无 epoch 分支**，该选项无落地支撑（A-49②）。
//     **未重建前不得混用**（否则 Verify 全红）。
func (e *LedgerEntry) computeHash() string {
    h := sha256.New()
    fmt.Fprintf(h, "%d|%s|%s|%s|%d|%d|%d|%d|%d|%d|%s|%s|%s|%s",
        e.Seq, e.TenantID, e.ModelKey, e.Day,
        e.TokensIn, e.TokensOut, e.Requests, e.RetryToks,
        e.StdIn, e.StdOut,
        e.Source, e.PriceVer, e.EventKey, e.PrevHash)
    return hex.EncodeToString(h.Sum(nil))
}

// Append 追加一批：在事务内串行链接，PrevHash = 上一条 EntryHash（创世 = 64 个 '0'）。
func (s *sqliteLedger) Append(tx Tx, entries []LedgerEntry) (int, LedgerHead, error) {
    head, _ := s.headTx(tx)                 // 事务内读取当前链尾
    prev := head.EntryHash
    if prev == "" { prev = genesisHash }    // 空链 → 创世
    added := 0
    for i := range entries {
        e := &entries[i]
        e.Seq = head.Seq + 1
        e.PrevHash = prev
        e.EntryHash = e.computeHash()
        // UNIQUE(event_key) 命中 → 跳过（幂等重放）
        ok, err := s.insertTx(tx, e)
        if err != nil { return added, head, err }
        if !ok { continue }                 // 冲突：不推进链，不计 added
        prev = e.EntryHash
        head = LedgerHead{Seq: e.Seq, EntryHash: e.EntryHash, UpdatedAt: e.CreatedAt}
        added++
    }
    s.putHeadTx(tx, head)
    return added, head, nil
}
```

> **并发安全**：`Append` 全程在**单写事务**内完成（`BEGIN IMMEDIATE`，SQLite 单写者），故 `head` 读取与插入原子；并发调用被 DB 串行化（§8.3）。

#### 7.1.2 校验伪代码

```go
// Verify 顺序扫描全链，校验 seq 连续 + prev 链接 + 哈希自洽；返回首个断链 Seq（-1 = 完好）。
func (s *sqliteLedger) Verify() (int, error) {
    prev := genesisHash
    wantSeq := uint64(1)
    rows := s.scanAll()                     // 按 seq 升序流式
    for rows.Next() {
        e := rows.Read()
        if e.Seq != wantSeq || e.PrevHash != prev || e.computeHash() != e.EntryHash {
            return int(e.Seq), nil          // 首个断链
        }
        prev = e.EntryHash
        wantSeq++
    }
    return -1, rows.Err()
}
```

#### 7.1.3 篡改检测范围

| 篡改类型 | 检测点 |
|---|---|
| 改某条用量（`tokens_in` 等） | 该条 `EntryHash` 变化 → 与存储值不符 → `Verify` 断链 |
| **改计价基（`std_in`/`std_out`/`price_ver`，★ A-49）** | 该条 `EntryHash` 变化（★ A-40 已纳链）→ `Verify` 断链；且 `price_ver` 改动使账单 `b.PriceVersion` 锚定不符 |
| 删某条 | `seq` 不连续 + 后继 `prev_hash` 悬空 |
| 插某条 | `seq` 重复（PK 拒绝）或 `prev_hash` 不匹配 |
| 重排 | `prev_hash` 链接断 |
| 改链尾摘要 | `bills.ledger_head` 锚定对不上（§7.3） |

#### 7.1.4 边界与测试

| 编号 | 边界 | 处理 |
|---|---|---|
| B-7.1-1 | 空账本 | `Verify` 返回 -1（完好）；勿与"断链于 0"混淆 |
| B-7.1-2 | 并发 Append | 单写事务串行化；`seq` 无空洞 |
| B-7.1-3 | 插入冲突（event_key 重复） | 跳过且**不推进链**（`seq` 不浪费） |
| B-7.1-4 | 哈希碰撞计算失败（I/O） | 返回 error，事务回滚 |
| B-7.1-5 | 存量库无 head 记录 | 启动时**全链重建** head（一次性） |
| T-7.1-1 | 正常追加 1000 条 | `Verify=-1` |
| T-7.1-2 | 篡改第 500 条用量 | `Verify=500` |
| T-7.1-3 | 删除第 300 条 | `Verify=301`（后继链接断） |
| T-7.1-4 | 并发 10 goroutine 各 100 条 | 无空洞，`Verify=-1` |
| T-7.1-5 | **篡改第 400 条 `std_in`（★ A-49/A-40）** | `Verify=400`（计价基在链内，改 std 必断链——守护 A-40 的动机）；对照：改第 400 条 `price_ver` 同样 `Verify=400` |

### 7.2 日账单签名（T7，L3）

#### 7.2.1 签名域与算法

```go
// canonicalBill 账单规范序列化（签名域；金额以"分"十进制，明细按 model_key 升序）。
func canonicalBill(b *Bill) []byte {
    var sb strings.Builder
    items := append([]BillItem(nil), b.Items...)
    sort.Slice(items, func(i, j int) bool { return items[i].ModelKey < items[j].ModelKey })
    fmt.Fprintf(&sb, "%s|%s|%s|%s|%d|%s|%s|%s",
        b.ID, b.TenantID, b.Kind, b.Period, b.Total, b.Currency, b.LedgerHead, b.AuditHead)
    for _, it := range items {
        fmt.Fprintf(&sb, "|%s:%d:%d:%d", it.ModelKey, it.StandardTokens, it.TokensIn, it.Amount)
    }
    return []byte(sb.String())
}

// Sign 生成签名（HMAC-SHA256；密钥来源 env/file 引用，R-5 同构）。
func (s *signer) Sign(b *Bill) string {
    mac := hmac.New(sha256.New, s.key)
    mac.Write(canonicalBill(b))
    return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}

// Verify 验签（重算 canonical 并恒定时间比较；不含 Sig 自身）。
func (s *signer) Verify(b *Bill) bool {
    want := s.Sign(&Bill{ /* b 的副本，Sig 置空 */ })
    return hmac.Equal([]byte(want), []byte(b.Sig))
}
```

**签名域要素**：`ID/TenantID/Kind/Period/Total/Currency/LedgerHead/AuditHead` + 明细行 → **覆盖金额、链锚、明细**，任一改动即验签失败。

#### 7.2.2 对外验证端点

`GET /v1/adminext/billing/bills/{id}/verify` → `{valid, sig_alg, price_version, ledger_head, audit_head, recomputed_total?}`（§4.3.2）。

**★ S-4 口径澄清**：`recomputed_total`（独立复算额）**依赖单价表对用户可见**——否则用户无从复算。
- 因此其返回**受 `price_public_url`（R-28）**约束：**非空**（单价公开）→ 返回 `recomputed_total` 供第三方复算（M2 可验证性成立）；**空**（单价不公开）→ 只返回 `valid/sig_alg/price_version/ledger_head/audit_head`，**不返回** `recomputed_total`（避免给出无法自证的数）。
- 无论是否公开，账单**恒**携带 `price_version`（§4.1.6/§5.3）——使"用当时版本单价复算"可行，且杜绝"用新价验旧账"。

#### 7.2.3 边界与测试

| 编号 | 边界 | 处理 |
|---|---|---|
| B-7.2-1 | 密钥轮换 | 账单存 `sig_alg`；轮换期**双密钥**并存（旧账单用旧密钥验） |
| B-7.2-2 | 明细顺序不同 | 规范序列化**强制排序**，与插入序无关 |
| B-7.2-3 | `Total` 被改 | 签名域含 Total → 验签失败 |
| B-7.2-4 | 缺 `LedgerHead` | 拒签（生成时链尾必填） |
| T-7.2-1 | 正常签名→验证 | `valid=true` |
| T-7.2-2 | 改 Total 1 分 | `valid=false` |
| T-7.2-3 | 改明细一行 | `valid=false` |
| T-7.2-4 | 密钥轮换后验旧账 | `valid=true`（旧密钥） |

### 7.3 计费 ↔ 审计双向关联（T7，L3）

> **目标**：任一张账单可 **端到端回溯**到审计链的原始事件，且任一条审计事件可定位到其计入的账单。

```go
// VerifyBillingChain 端到端关联校验（账单 → 账本链 → 审计链）。
func (s *BillingService) VerifyBillingChain(b *Bill) error {
    // 1. 账单锚定的账本链尾必须与当前账本可复现（重放 period 内条目 → 链尾 = b.LedgerHead）
    if !s.store.Ledger().ReproduceHead(b.TenantID, b.Period, b.LedgerHead) {
        return ErrLedgerAnchorMismatch
    }
    // 2. 账单锚定的审计链尾必须出现在 tee-infer 审计链上（GET /audit，前缀匹配）
    if !s.auditAnchorExists(b.AuditHead) { return ErrAuditAnchorMissing }
    // 3. 账本条目 → 审计事件：push 用 event_key 对齐 event_id；pull 用 windowStart 对齐时间窗
    return s.crossRefEvents(b)
}
```

| 关联方向 | 载体 | 强度 |
|---|---|---|
| 账单 → 账本链 | `bills.ledger_head`（生成时链尾） | **强**（重放可复现） |
| 账单 → 审计链 | `bills.audit_head`（生成时审计链尾） | **强**（tee-infer 审计链前缀） |
| 账本条目 → 审计事件（push） | `event_key = push:{event_id}` | **强**（与审计 `event_id` 对齐，`billing.go:124`） |
| 账本条目 → 审计事件（pull） | `event_key = pull:{...}:{windowStart}` | **中**（窗口级对齐；明细由 L2 三元组校验） |
| 审计事件 → 账单 | 按 `[tenant, day]` 反查 `billing_ledger` → `bill_id` | **中**（反查索引） |

**边界与测试**：B-7.3-1 审计链被裁剪（保留期外）→ 锚定不可验，记 `audit_anchor_stale`（不阻断出账，但标记）；B-7.3-2 pull 窗口跨账单边界 → 归日规则统一（B-6.6-5）。T-7.3-1 账单→链→审计 全链绿；T-7.3-2 篡改账本 → 关联断。

> **★ 调用点（A-31）**：`VerifyBillingChain` 此前**全文无调用点**（调用图审计①：定义了机制却无入口）。现接线于 **§6.16 S-10**（出账后即时 + 每日低峰全量巡检，`verifyBillingAssoc`），并保留 §7.2.2 验签端点在返回 `{valid,...}` 后可追加关联校验（可选）。失败**不阻断**已出账（只标记 + 告警）。

### 7.4 权限与防篡改（T7，L3）

| 通道 | 约束 |
|---|---|
| **写账本** | **无 HTTP 写端点**；仅账务域内部（拉取/推送消费/手工补录）写。推送入口 `POST /billing/events` 强制 HMAC 验签（§6.3.1） |
| **读账单** | RBAC：`billing_reader`/`auditor`/`admin`（P-5）；**跨租户访问 403**（token 内 `tenant` 强制） |
| **管理动作** | `POST /plans`、`/subscription`、`/freeze` 需 `admin`；导出需落 `bill_export`；全部落 `admin-service` 审计链（`plan_upsert`/`plan_bind`/`bill_freeze`/`bill_unfreeze`/`bill_issue`/`bill_export`，§4.3.5） |
| **审计白名单** | `auditEventActions`（`admin-service/audit.go`）扩展新动作；未在白名单的动作**拒绝落链** |
| **密钥** | 签名密钥 / HMAC 密钥 / tee token 一律**引用**（`env:`/`file:`，R-5/R-9/R-27），禁内联明文 |
| **落盘加密（★ S-5）** | 账本含 `tenant_id` + 用量画像（**业务敏感**）。P0 依赖**文件系统权限 + WORM**；若合规要求"静态加密"，走 admin-service 存储层加密（对齐既有密钥存储策略）——登记 **U-15**，不阻塞 P0 |

### 7.5 不可变性与 WORM（T7，L3）

| 层 | 机制 |
|---|---|
| 应用层 | `LedgerStore` **只提供 `Append`/`Range`**，无 Update/Delete（§4.1.1） |
| DB 层 | 触发器 `BEFORE UPDATE/DELETE ON billing_ledger → RAISE(ABORT,'immutable')`（§5.1）——防绕过应用层直改 |
| 存储层 | 账本 DB/文件纳入 `admin-service` 的 **WORM** 生命周期（对齐审计链 `audit.go` WORM） |
| 更正方式 | **不就地修改**；以 `source=manual` 的**冲正条目**追加（负向或抵消条目），并落审计 |

> **与审计链同构**：`audit.go` 的哈希链 + WORM 是本项目已验证的防篡改范式；账本沿用同一范式（不同链、不同签名域），避免"两套可信模型"。
>
> **★ 存续边界（S-1）**：三层中，**应用层**（无 Update/Delete 接口）防"经应用改动"，**DB 触发器**防"直连库改动"，**WORM** 防"改文件后重算链"。若部署环境**无法提供 WORM**（如普通文件系统挂载的 SQLite），须显式声明：此时防篡改**降级**为"链可检测 + 触发器阻断"，**不能**抵御有库文件写权限者的整链重算——**须**启用 §7.1 的 HMAC-keyed 链补偿，或迁 PostgreSQL（U-3）并启用其行级不可变表。**WORM 落地情况 = 上线验收项**（§11.3 A-11b，U-14）。

### 7.6 安全不变量清单（T7，L3）

> 供 CI 与评审逐条核验（附录 A/F.2.5 可观测性 & 可实现性）。

| ID | 不变量 | 校验点 / 对应 |
|---|---|---|
| INV-1 | 账本**只追加**（无 UPDATE/DELETE） | DB 触发器 + 接口签名（§5.1/§4.1.1） |
| INV-2 | 哈希链可验证（seq 连续 + prev 链接 + 哈希自洽），**且计价基（`std_in/std_out/price_ver`）进哈希**（★ A-40） | `LedgerStore.Verify`（§7.1.2）+ `computeHash` 序列化冻结（§7.1.1）；指标 #4 |
| INV-3 | **金额不入账本**（账本无金额列） | §5.1 DDL（无 amount 列） |
| INV-4 | **金额不入 `/usage` 域** | M10 / S-3 字段扫描（CI） |
| INV-5 | **retry_toks 不进用户金额** | M9；§6.5.4 |
| INV-6 | 账单**签名可验证** | M8；§7.2 |
| INV-7 | 账务域**不接触明文**（接口只受结构化计数） | §3.1.2 / §4.4 |
| INV-8 | 写路径**单写者 + 审计留痕**（含**通道单写者**：`sync_mode` 选定唯一账本写入者，★ A-12） | §7.4 / §6.4.1 / **§6.3.2 / R-30** |
| INV-9 | **fail-closed**：对账不通 / 单价缺 → 不出账 | §6.6.1 / §6.10.3 |
| INV-10 | **幂等**：`event_key` / `UNIQUE(tenant,kind,period)` | §6.3.4 / §5.3 |

---

## 8. 性能与容量规划（L3）

### 8.1 延迟预算

| 路径 | 目标 | 依据 / 手段 |
|---|---|---|
| 用量/账单查询 API | **p95 < 200ms**（M5） | 索引 `idx_ledger_tenant_day`；汇总走覆盖索引 |
| 拉取（后台） | 单轮 < `pull_interval` 的 50% | 批量 Append（事务内多行）；不进请求路径 |
| 日结（单租户） | < 500ms（≤100 模型 × 30 天） | 一次取数 + 内存计价 |
| 月结（单租户） | < 2s | 月累计重算阶梯 |
| 导出 CSV/PDF | 首字节 < 1s（流式，§6.8） | 流式写，不全量载入 |
| 推理链路 | **零增量**（账务不在热路径） | 数据面仅异步上报（§6.3.3） |

### 8.2 容量估算

| 项 | 估算（示例：1000 租户 × 5 模型） | 说明 |
|---|---|---|
| 账本行数 | 5000 行/日 ≈ 1.8M 行/年 | 租户 × 模型 × 日 |
| 单行大小 | ~200 B | §5.1 DDL |
| 账本年增 | ~360 MB/年 | 含索引 |
| 日账单数 | 1000/日 ≈ 365k/年 | `UNIQUE(tenant,kind,period)` |
| 月账单数 | 1000/月 ≈ 12k/年 | — |

> **保留策略**：账本与账单**长期保留**（计费凭证）；明细数据量增长由**只读归档**（DB 分区/冷表）承载（U-3 企业版）。

### 8.3 基准与热点

| 热点 | 风险 | 手段 |
|---|---|---|
| **SQLite 单写者** | 拉取写 + 日结写 + 查询并发 → 写锁争用 | WAL 模式；批量事务；单写锁串行化。**退路触发门槛（O-2）= 写锁等待 p99 ≥ 100ms**（P-5）→ 启"待处理队列 + 批量提交" |
| `Range` 查询 | 大区间全表扫 | 复合索引 `(tenant_id, day)`；`Limit` 分页 |
| 汇总 `GROUP BY` | 长周期聚合慢 | 索引覆盖 + 只读副本（企业版） |
| 链校验 `Verify`（★ O-6） | 全链扫描 O(N)：**全量 1.8M 行 < 30s**（P-4） | **增量校验（仅新增段，1h，< 50ms）** + **全量每日低峰 04:00**（S-6）——与日结 02:10 / 月结 03:10 **错峰**，避免写锁争用 |

### 8.4 性能测试矩阵（→ §10.5）

| 用例 | 规模 | 指标（★ O-2 量化门槛） |
|---|---|---|
| P-1 拉取吞吐 | 10k 条目/轮 | 单轮耗时 **< 5s**；单写事务 **p99 < 50ms** |
| P-2 查询延迟 | 1.8M 行库 | **p95 < 200ms**（M5） |
| P-3 日结批处理 | 1000 租户 | **总耗时 < 10min**（＜ M3 的 20min 窗口）；单租户 **< 500ms**；**★ A-37：启用 `monthStdBefore` 月累计缓存（§6.5.1）时应降至 < 3min** |
| P-4 链校验 | 1.8M 行 | 全量 **< 30s**；增量 **< 50ms** |
| P-5 **写争用**（SQLite 单写者） | 拉取 + 日结 + 查询并发 | 写锁等待 **p99 < 100ms**；**超阈 → 启待处理队列退路**（§5.6/§8.3，R-β） |

---

## 9. 可观测性（T10，L3）

> **设计深度：L3**。沿用 `tee-infer/metrics.go` 的 `writeCounter` 手写模式（§3.2）；指标源 **`admin`**。全部新指标须由 **T10** 登记进 `scripts/metrics-required.txt`（#9 门禁）。

### 9.1 指标登记表

| # | 指标 | 类型 | 标签 | 登记 | 用途 / 关联 |
|---|---|---|---|---|---|
| 1 | `gateway_admin_billing_requests_total` | counter | `path,code` | required | /billing 域请求量（T6） |
| 2 | `gateway_admin_billing_ledger_entries_total` | counter | `source` | required | 入账条目数（pull/push/manual，T3） |
| 3 | `gateway_admin_billing_ledger_head_seq` | gauge | — | required | 账本链尾序号（单调；T3/T7） |
| 4 | `gateway_admin_billing_ledger_chain_broken` | gauge | — | required | 链校验状态（0 完好 / 1 断裂；**越界即告警**，T7） |
| 5 | `gateway_admin_billing_pull_total` | counter | `result` | required | 拉取次数（ok/error；T3） |
| 6 | `gateway_admin_billing_push_total` | counter | `result` | conditional | 推送消费（ok/reject/frozen；T3） |
| 7 | `gateway_admin_billing_close_duration_seconds` | histogram | `kind` | required | 日结/月结耗时（**M3/M4**） |
| 8 | `gateway_admin_billing_bill_issued_total` | counter | `kind,status` | required | 出账数（daily/monthly × issued/frozen；T5） |
| 9 | `gateway_admin_billing_api_duration_seconds` | histogram | `path` | required | 查询 API 延迟（**M5**） |
| 10 | `gateway_admin_billing_anomaly_total` | counter | `kind,severity` | required | 五类异常（spike/reconcile_diff/quota_warn/pricing_missing/**plan_expired**〔S-9 兼发，A-17〕；**M7**） |
| 11 | `gateway_admin_billing_reconcile_diff` | gauge | `tenant` | required | L2 差异**率**（ratio；0 为达标，★ MET-003 订正：非“三元组合计”） |
| 12 | `gateway_admin_billing_quota_remaining_ratio` | gauge | `tenant` | conditional | 配额剩余比（预警；**M7**） |
| 13 | `gateway_admin_billing_quota_apply_duration_seconds` | histogram | — | required | 配额热生效时延（**M6**） |
| 14 | `gateway_admin_billing_freeze_total` | counter | `kind,severity` | conditional | 冻结/解冻次数（**M7**；T8） |
| 15 | `gateway_admin_billing_export_total` | counter | `format,result` | conditional | 导出次数（csv/pdf；T5） |
| 16 | `gateway_admin_billing_signature_verify_total` | counter | `result` | conditional | 验签结果（valid/invalid；**M8**） |
| 17 | `gateway_admin_billing_clock_skew_total` | counter | — | conditional | 时钟回拨检出（B-6.1-3） |
| 18 | `gateway_admin_billing_pricing_missing_total` | counter | `model_key` | conditional | 单价缺失（`Rate`/`ExtraAmount` 返回 `ErrPricingMissing`；§6.5.1，★ A-46） |
| 19 | `gateway_admin_billing_platform_retry_tokens` | gauge | `tenant` | conditional | **平台成本视图**（retry token 归平台，C-1/§6.5.4） |
| 20 | `gateway_admin_billing_auto_repull_total` | counter | — | conditional | 自动回补重拉次数（O-4/§6.12.3） |
| 21 | `gateway_admin_billing_plan_expiring_total` | counter | `days` | conditional | 套餐到期提醒（P-4/§6.4.2，days=30/7/0）；**唯一生产者 = S-9 `scanExpiries`**（§6.16，A-16） |
| 22 | `gateway_admin_billing_assoc_verify_total` | counter | `result` | conditional | ★ A-34：关联校验结果（pass/fail；S-10 `VerifyBillingChain`，§7.3/§6.16）；**唯一生产者 = S-10 `verifyBillingAssoc`** |
| 23 | `gateway_admin_billing_ledger_error_total` | counter | `op` | conditional | ★ A-52：账本写路径错误（`op=begin|append`；§6.1.1 `pullOnce`）；**唯一生产者 = `incLedgerError`** |
| 24 | `gateway_admin_billing_frozen` | gauge | `tenant` | conditional | ★ 本次回填：租户冻结状态（1=冻结 / 0=解冻）；**§9.3 `BillingFrozenSustained`（冻结持续 >24h）唯一判据**（此前该告警无可用信号） |

> **required vs conditional**：`required` 在 `billing.enabled=true` 时**必须存在**（常驻注册）；`conditional` 为惰性（首次触发才注册），与 `scripts/metrics-required.txt` 语义一致。
>
> **`scripts/metrics-required.txt` 增补（T10 交付）**：新增 `admin gateway_admin_billing_requests_total required` 等上表 `required` 行；`conditional` 行登记为 `conditional`（#9 门禁不判失败）。

#### 9.1.1 唯一生产者对照表（★ O-7：判据指标必查生产者）

> **方法论（调用图审计②）**：每个指标的**判据作用**要求它存在唯一且明确的**生产者调用点**；"登记了指标"≠"有代码发射"（v1.2 中 #11/#14/#15/#16/#17 无生产者，导致 M1 判据可观测但**永为空**）。下表为**契约**：生产者缺失即视为该指标未实现。

| # | 指标 | 唯一生产者（调用点） | 依据 |
|---|---|---|---|
| 1 | `billing_requests_total` | `/billing/*` HTTP 中间件（§4.3.2） | T6 |
| 2 | `billing_ledger_entries_total` | `LedgerStore.Append` 成功后（§6.1.1/§6.2） | T3 |
| 3 | `billing_ledger_head_seq` | `LedgerStore.Append` 后置（§7.1.1） | T3/T7 |
| 4 | `billing_ledger_chain_broken` | `LedgerStore.Verify` 结果（§6.16 调度器 **S-6 → `Verify`**，★ A-48：此前误引 S-5＝`detector.Scan`） | T7 |
| 5 | `billing_pull_total` | `RunMeteringLoop` 单轮结束（§6.1.1） | T3 |
| 6 | `billing_push_total` | Webhook 消费分支（§6.3.1） | T3 |
| 7 | `billing_close_duration_seconds` | `CloseDaily`/`CloseMonthly` 的 `metrics.observeClose`（§6.6.1/§6.7，★ O-7 补） | T5 |
| 8 | `billing_bill_issued_total` | `CloseDaily`/`CloseMonthly` 出账分支（§6.6.1/§6.7） | T5 |
| 9 | `billing_api_duration_seconds` | 查询 API 中间件（§4.3.2） | T6 |
| 10 | `billing_anomaly_total` | `detector.Scan` **返回点**：逐条 `metrics.incAnomaly(kind,severity)`（§6.9.1，★ O-8：此前误记不存在的 `AnomalyDetector.Emit`） | T8 |
| 11 | `billing_reconcile_diff` | `CloseDaily`/`CloseMonthly` 的 `metrics.setReconcileDiff`（§6.6.1/§6.7，★ O-7 补；**M1 判据**） | T7/T13 |
| 12 | `billing_quota_remaining_ratio` | `detector.Scan` ③ 配额预警分支：`metrics.setQuotaRemainingRatio(tenant, rem)`（§6.9.1，★ O-8：此前误记 §6.4.1，实则无发射） | T2 |
| 13 | `billing_quota_apply_duration_seconds` | 配额热生效完成处（§6.4.1，**M6**） | T2 |
| 14 | `billing_freeze_total` | `freezeAndAlert` 内部（§6.10，★ O-7：需 `incFreeze`） | T8 |
| 15 | `billing_export_total` | `Export` 处理器（§6.8） | T5 |
| 16 | `billing_signature_verify_total` | 验签端点（§7.2.2） | T7 |
| 17 | `billing_clock_skew_total` | `pullOnce` 时钟回拨保护：`metrics.incClockSkew()`（**§6.1.1 B-6.1-3**，★ O-8：此前误引 §6.6.1） | T3 |
| 18 | `billing_pricing_missing_total` | `Rate` 缺单价返回 `ErrPricingMissing` 处（§6.5.1，★ A-46：此前误记 `rateModel`，其无缺价分支） | T4 |
| 19 | `billing_platform_retry_tokens` | `aggregateUsage` 归因 retry 时（§6.5.4） | T3 |
| 20 | `billing_auto_repull_total` | `onReconcileWarning`（§6.12.3，★ A-22 接线后具备调用点） | T7 |
| 21 | `billing_plan_expiring_total` | `scanExpiries`（§6.16 S-9，A-16） | T1 |
| 22 | `billing_assoc_verify_total` | ★ A-34：`verifyBillingAssoc`（S-10，§6.16 → `VerifyBillingChain` 出口，逐条 `metrics.incAssocVerify(result)`） | T7 |
| 23 | `billing_ledger_error_total` | `incLedgerError(op)`（§6.1.1 `pullOnce` 的 `Begin`/`Append` 失败分支，★ A-52：此前 `incLedgerError` 已调用但无对应指标登记） | T3 |
| 24 | `billing_frozen` | ★ 本次回填：`FreezeController.Freeze`/`Unfreeze`（状态变更即置 1/0）＋ `AnomalyDetector.SyncFrozenGauge`（S-5 每轮以冻结存储回填，**解决重启后 gauge 归零**） | T8 |

> **★ O-7 强制**：新增/修改指标时**必须同时在 §9.1.1 补生产者行**；评审按调用图审计②核验"指标有唯一生产者"。上表 #7/#11/#14 为 v1.3 显式回填（v1.2 遗漏）。
>
> **★ O-8 强制（v1.4）**：生产者列**不仅须有行，更须有真实发射语句与存在符号**——#10/#12/#17 在 v1.3 的记为**证伪**（#10 记不存在的 `AnomalyDetector.Emit`；#12 记 §6.4.1 实则无发射；#17 引用错 §6.6.1）。v1.4 已回填其真实发射点（§6.9.1 出口 `incAnomaly`、§6.9.1③ `setQuotaRemainingRatio`、§6.1.1 `incClockSkew`）。**判据指标（M 判据相关）生产者缺失 = 未实现**。

### 9.2 日志（结构化，脱敏）

| 事件 | 字段 | 级别 | 脱敏约束 |
|---|---|---|---|
| 拉取失败 | `tenant,from,to,err` | warn | **无明细**（计数级） |
| 入账 | `tenant,model_key,day,tokens_in,tokens_out,source,added` | info | **无内容明文** |
| 出账 | `tenant,kind,period,total,ledger_head,audit_head` | info | 金额仅在账单域日志（不外泄至 `/usage`） |
| 冻结 | `tenant,kind,severity,reason,by` | warn | — |
| 链断裂 | `broken_at` | **error** | 触发告警 |

> **机密边界**：日志**不得**出现推理内容明文 / 租户密钥；仅结构化计数与标识（INV-7）。

### 9.3 告警规则清单（T10）

| 告警 | 条件 | 级别 | 处置 |
|---|---|---|---|
| `BillingLedgerChainBroken` | `ledger_chain_broken == 1` | critical | 停止出账 + 人工 |
| `BillingReconcileDiff` | `reconcile_diff > 0` 且 ratio > 0.1% | critical | 冻结该租户（§6.12.3） |
| `BillingReconcileWarning` | `0 < ratio ≤ 0.1%` | warning | **自动未入账尾段回补重拉**（从游标 `[cursor,now)`，非重叠；★ BUG-001 订正；幂等键 `(tenant,day)`；§6.12.3/O-4）；不冻结 |
| `BillingPricingMissing` | `pricing_missing_total > 0` | critical | 冻结 + 补单价表 |
| `BillingCloseMissed` | 日结超期未完成（M3） | warning | 排查调度 |
| `BillingAnomalySpike`（warning） | `anomaly_total{kind="spike",severity="warning"}`（`ratio≤spike_critical_ratio`） | warning | 人工确认（**不冻结**） |
| `BillingAnomalySpike`（critical） | `anomaly_total{kind="spike",severity="critical"}`（`ratio>spike_critical_ratio`，★ A-25） | critical | **冻结** + 人工（与 §6.9.1/§6.10.1 一致，★ A-30：修正原"恒 warning/不冻结"） |
| `BillingQuotaLow` | `quota_remaining_ratio < 0.2` | warning | 通知租户（§6.11） |
| `BillingFrozenSustained` | 冻结持续 > 24h | warning | 升级 |
| `BillingPullErrorSustained` | `pull_total{result="error"}` 连续 5 轮 | warning | 查 tee-infer 可达性 |
| `BillingAssocVerifyFailed` | ★ A-34：`assoc_verify_total{result="fail"} > 0` | critical | **不冻结**（事后审计性质）；标记账单 `assoc_mismatch` + 人工排查链锚一致性（§7.3 S-10） |
| `BillingQuotaApplySlowP95` | **批 C 增补（M6）**：`histogram_quantile(0.95, sum(rate(quota_apply_duration_seconds_bucket[30m])) by (le)) > 60`（#13 时延 p95 > 60s，持续 10m） | warning | 排查配额下发/回读链路与回读确认预算（§6.4.1 2c）。★ 依赖 #13 的自定义直方图桶（含 60s 边界，见 §9.1 #13 生产者） |
| `BillingCloseDailySlowP95` | **增补（M3）**：`histogram_quantile(0.95, sum(rate(close_duration_seconds_bucket{kind="daily"}[24h])) by (le)) > 1200`（#7 日结耗时 p95 > 20min） | warning | 排查账务域 DB 写入/计价/对账耗时与租户规模（§1.3 M3）。★ 依赖 #7 自定义直方图桶（含 1800 > 1200） |
| `BillingCloseMonthlySlowP95` | **增补（M4）**：同上 `kind="monthly"` 且 `> 3600`（#7 月结耗时 p95 > 60min） | warning | 同上（§1.3 M4）。★ 桶含 7200（> 3600）使 p95 可判定 |

### 9.4 运维大盘（Grafana）

| 面板 | 指标 |
|---|---|
| 用量趋势 | `ledger_entries_total` 按 tenant/model 分（日/月） |
| 账本健康 | `ledger_head_seq`（斜率）+ `ledger_chain_broken` |
| 对账 | `reconcile_diff` 分布 + 告警 |
| 出账 | `bill_issued_total` + `close_duration_seconds` p95（M3/M4） |
| 冻结 | `freeze_total` + 当前冻结租户数 |
| API | `api_duration_seconds` p50/p95/p99（M5） |
| 配额 | `quota_remaining_ratio` Top-N |

### 9.5 Tracing

| Span | 属性 | 说明 |
|---|---|---|
| `billing.pull` | `tenant_count,from,to,added` | 拉取轮次 |
| `billing.rate` | `tenant,period,models,total` | 计价 |
| `billing.close` | `tenant,kind,period,bill_id` | 出账 |
| `billing.reconcile` | `tenant,day,diff` | L2 对账 |
| （跨服务，可选） | `request_id` 传播 | 与 tee-infer 的推理 span 关联（对齐路由 W4 tracing 埋点） |

---

## 10. 测试方案（T11-T14，L3）

> **设计深度：L3**。分层：单元（§10.1）→ 集成（§10.2）→ E2E（§10.3）→ 对账回归（§10.4，零容差）→ 性能（§10.5）→ 安全/兼容（§10.6）。用例总索引见**附录 C**；边界总索引见**附录 B**。

### 10.1 单元测试（T11）

| 组 | 用例 | 覆盖 |
|---|---|---|
| `RatingEngine` | 表驱动：单档/多档累进/系数换算/**入出分轴（A-26）**/`half_up` vs `floor`/缺价/系数缺省/溢出拒绝 | §6.5；B-6.5-1..7 |
| 阶梯 | 跨档边界（恰好 = 上界归低档）/**空阶梯=单档全量（A-24）**/不连续配置拒绝/整档 vs 累进 | B-6.5-4/5；R-17 |
| 取整 | 逐笔 vs 一次取整差异（证明 R-16 必要） | §6.5.3；T-6.5-3 |
| 哈希链 | 构造/篡改检测/删插重排/并发追加 | §7.1.4 |
| 签名 | sign/verify/改 Total/改明细/密钥轮换 | §7.2.3 |
| 幂等 | `event_key` 三 source 规则/重复 Append/**pull 下 retry 归因（A-23）** | §6.3.4；T-6.3-8 |
| 异常检测 | 4 类规则/除零/新租户/**spike 严重级阈值（A-25）**/告警风暴聚合 | §6.9.2 |
| 冻结状态机 | 触发/升级/自动解冻/人工解冻/补账 | §6.10.4 |
| 配置校验 | R-1..R-34 逐条非法拒绝 | §4.2 |

**覆盖率目标**：账务域包 ≥ 80%（对齐项目 TDD 基线）。

### 10.2 集成测试（T12）

| 用例 | 场景 | 断言 |
|---|---|---|
| INT-1 | stub tee-infer → 拉取 → 入账 → 日结 | 账本 == 注入用量；账单金额 == 手算 |
| INT-2 | 推拉双通道同刻（**单写者模型**，A-12） | `sync_mode=pull` 时账本**仅拉取写入**、推送**不产生行**；`sync_mode=push` 时反之；两通道同时写账=**启动即拒**（R-30） |
| INT-3 | 套餐绑定 → 编译 → stub `QuotaApplier` | 下发 `QuotaUpdate` 值正确（含 month 窗口）；**`ApplyCoefficients` 系数表同时下发**（★ A-41/T-6.4-7） |
| INT-4 | 冻结 → 出账被拒（409）→ 解冻 → 缺口补账 | 补齐 |
| INT-5 | L2 对账不一致（`diff>0`） | **不出账（门禁）** + 指标 #11 > 0；**仅 `ratio>0.1%` 冻结**（★ A-22/A-28：修正原"冻结"） |
| INT-6 | 账单导出 csv/pdf | 内容与签名字段完整 |
| INT-7 | 重启缺口扫描 | 漏跑日账单补出 |

### 10.3 E2E 测试（T14）

| 用例 | 链路 |
|---|---|
| E2E-1 | 模拟推理（真机 tee-infer）→ 拉取 → 日结 → `GET /bills` → `/verify`（valid）→ 导出 |
| E2E-2 | 4 档套餐各绑一租户 → 配额生效 → 超限行为符合 `OverQuota` |
| E2E-3 | 篡改账本行 → `/verify` 失败 + 链断裂告警 |
| E2E-4 | `billing.enabled=false` → 与现网逐字节一致（S-6） |

**环境**：docker-compose / kind 起 `tee-infer` + `gateway-admin-service`（附录 F 锚点）。

**自动化（落地）**：`e2e/` 包（构建标签 `//go:build e2e`）以**进程级**方式自动化——`go build` 产出两服务二进制、随机端口子进程启动，驱动**仅经 HTTP** 访问两服务（tee-infer 以 `-engine-url` 空＝本地模拟引擎 + token 模式推理，规避信封握手）。运行：

```
go test -tags e2e ./e2e/ -v -timeout 15m
```

- **覆盖**：**E2E-1**（token 模式推理 → 拉取 → 日结 → `GET /bills` → `/verify`(valid) → 导出）、**E2E-3**（篡改账本行 → `POST /verify-chain` 断裂 + 指标 #4 置 1 + 停出账 409）、**E2E-4**（`enabled=false` 与 `true` 的 `/v1/adminext/usage` 响应**逐字节一致** + 关闭时 `/billing/*` 404）；**E2E-2 为"基础版"**：4 档套餐各绑一租户 → 配额下发并**回读生效** → 超限 429（OverQuota 的**计价差异**——degrade/charge 的超额账单形态——由 §10.1/§10.2 单测与集成覆盖，不在 E2E 重复）。
- **形态差异（如实声明）**：编排用**进程级**而非原文 `docker-compose/kind`（同样跑通"真机 tee-infer + gateway-admin-service"两服务真实链路；进度文档已登记）。

### 10.4 对账回归测试（零容差，T13）★ 出账门禁

> **这是 M1/M2 的直接证据来源**。

| 用例 | 场景 | 断言 |
|---|---|---|
| REC-1 | 生成 N 条已知用量 → 账本 | 三元组 `diff = 0`（M1） |
| REC-2a | ★ A-38：注入少量差异（漏入 1 条，ratio ≈ 0.05%，< 0.1%） | 检出 → **不出账（门禁）** + 自动回补（warning，BillingReconcileWarning）；**不冻结**（验证 A-22 口径：diff>0 不出账但 ratio<0.1% 不冻结） |
| REC-2b | ★ A-38：注入大量差异（漏入 N 条，ratio ≈ 5%，> 0.1%） | 检出 → **不出账（门禁）** + **冻结**（BillingReconcileDiff + freeze_total{kind="reconcile_diff"}）；验证 ratio 阈值边界（0.1% 上下行为不同） |
| REC-3 | 逐笔取整 vs 一次取整 | 金额差异用例；证明 R-16 |
| REC-4 | retry 事件混入 | 用户账单 `retry_toks` 展示但 `Total` 不含（M9） |
| REC-5 | L1 已 blocked（推送停） | L2 仍可从 `/usage` 拉取对账（B-6.12-2） |
| REC-6 | 审计链断裂 | 全局冻结（B-6.12-4） |

**M2 = REC-* 通过数 / 总数**（目标 100%）。

### 10.5 性能测试（T10/T11）

见 §8.4（P-1..P-4）；门槛：查询 p95 < 200ms（M5）、日结批处理 ≤ M3 目标。

### 10.6 安全与兼容测试

| 用例 | 内容 | 关联 |
|---|---|---|
| S-1 | 哈希链篡改检测（改/删/插） | INV-2；§7.1 |
| S-2 | 账单签名伪造（改 Total/明细） | INV-6；M8 |
| **S-3** | **`/usage` 域响应字段扫描：不得含 `amount`/`total`/`price` 等金额字段** | **M10/INV-4；CI 强制** |
| S-4 | 未验签 webhook → 401 | B-6.3-1 |
| S-5 | 越权访问 `/billing`（低角色）→ 403；跨租户 → 403 | §7.4 |
| S-6 | `billing.enabled=false` 与现网**逐字节一致**（端点不注册/`/usage` 不变） | 附录 F.2.4；R-1 |
| S-7 | 版本兼容：旧 `tee-infer` 不识别 `month` 窗口 | B-6.4-3；CI 校验版本 |
| S-8 | 密钥引用（禁内联明文） | R-5/R-9 |

---

## 11. 部署与配置（T15，L3）

### 11.1 部署形态

| 形态 | 存储 | 适用 | 说明 |
|---|---|---|---|
| **单机（P0 默认）** | SQLite（纯 Go） | 中小客户 / 起步 | 账务域内嵌 `gateway-admin-service`（同进程、同 listener） |
| **企业 / 多副本（P1/U-3）** | PostgreSQL | 大客户 | 强并发、只读副本、归档分区 |

> **不新开端口**（R-22）：`/billing` 复用 admin listener（默认 `:19095`）。

### 11.2 配置项

- 完整 Schema 见 **§4.2**（`billing:` 段，R-1..R-34）。
- 敏感值一律**引用**：`admin_token_ref`/`push_secret_ref`（`env:`/`file:`，R-5/R-9）；签名密钥同构（U-5）。
- 热更新：`Reload`（§6.14）；非法配置**拒绝并保留旧值**。

### 11.3 上线验收清单（T15）

| # | 项 | 判据 | 关联 |
|---|---|---|---|
| A-1 | 默认关闭行为一致 | `enabled=false` 与现网逐字节一致（S-6） | 附录 F.2.4 |
| A-2 | 零容差出账 | REC-* 全绿，`diff=0`（M1） | §10.4 |
| A-3 | 计费准确率 | 回归 100%（M2） | §10.4 |
| A-4 | 日结/月结及时 | M3 ≥ 99.9% / M4 100% | §9.3 |
| A-5 | 查询延迟 | p95 < 200ms（M5） | §8.1 |
| A-6 | 配额热生效 | ≤ 60s（M6） | §6.4 |
| A-7 | 异常检测覆盖 | 4 类有指标 + 告警（M7） | §9.3 |
| A-8 | 账单可验证 | 验签 100%（M8） | §7.2 |
| A-9 | 重试归平台 | 账单 `retry_toks` 入 Total = 0（M9） | §6.5.4 |
| A-10 | 金额域隔离 | S-3 全绿（M10） | §10.6 |
| A-11 | 审计留痕 | 管理动作全落审计链 | §7.4 |
| A-12 | 可观测 | 指标登记进 `metrics-required.txt`（#9 门禁绿） | §9.1 |
| A-13 | **WORM 落地确认**（S-1/U-14） | 账本 DB 纳入 WORM 生命周期（或启用 HMAC 链补偿） | §7.5 |
| A-14 | **备份可恢复**（O-3） | 按 §11.4 演练，RPO/RTO 达标 | §11.4 |

### 11.4 备份与恢复（★ O-3）

> 账本是**计费凭证**，不可仅靠 SQLite WAL 崩溃恢复。须定义**备份/恢复**与 **RPO/RTO**。

| 项 | 方案 |
|---|---|
| 备份对象 | `billing.db`（账本+账单+套餐+冻结）**全量快照** + 单价表（`pricing.yaml`，含版本） |
| 备份方式 | SQLite `VACUUM INTO` / 文件快照（**WAL checkpoint 后**）+ 每日一次；备份前 `PRAGMA wal_checkpoint(TRUNCATE)` |
| 一致性 | 快照须**含 `LedgerHead`**；恢复后**启动自检 SC-4**（§6.15.1）校验链尾一致 |
| 保留 | 与账本保留策略同（§8.2，长期）：日备 ×30 + 月备 ×12 |
| **RPO** | **≤ 24h**（日备）；关键期可降 `pull_lookback` 重放补齐（账本可从审计链**重建**，故实际 RPO 可更优） |
| **RTO** | **≤ 1h**（单文件恢复 + 启动自检 + 缺口扫描补账） |
| 恢复演练 | 纳入 E2E（T14 扩展）+ 上线验收 A-14；演练须验证"恢复后 `Verify=-1` + 账单可验签" |

> **可重建性**：账本**唯一真源**在 `tee-infer` 审计链（§3.1.1）；即使 `billing.db` 全失，`pull` 可按 `pull_lookback`/更长窗口**从审计链重建**（`pull` 幂等）。备份是**加速恢复**手段，不是唯一依赖。

---

## 12. 灰度发布（T15，L3）

### 12.1 阶段

| 阶段 | 范围 | `billing.enabled` | 金额展示 | 出口判据 |
|---|---|---|---|---|
| **Stage 0 · Shy（影子出账）** | 全量 | `true`，但 `amount_display=false` | 否（用量账单） | 连续 7 日 `diff=0`（M1）+ 无 critical 异常 |
| **Stage 1 · 内部租户** | 1-2 内部租户 | `true`，`amount_display=true` | 是 | 人工核对账单与手算一致（M2）+ 验签绿 |
| **Stage 2 · 灰度客户** | 5% → 25% → 100% | `true` | 是 | M3/M4/M5 达标，无冻结误报 |

> **P-4 未放行（金额域会签未过，U-1）时**：停留 Stage 0，全量出"**用量账单**"（金额列空，§6.10.3），不进入 Stage 1。

### 12.2 切换开关

| 开关 | 作用 | 默认 |
|---|---|---|
| `billing.enabled` | 总开关（关 = 与现网一致，R-1） | `false` |
| `amount_display` | 金额展示（Stage 0 关） | `false` |
| `anomaly.auto_throttle` | 冻结期自动降配（U-13） | `false` |

### 12.3 回滚

| 场景 | 处置 |
|---|---|
| 出账错误率超阈 | 关 `amount_display` → 回 Stage 0（**账本不动**） |
| 账本/对账异常 | **不关 enabled**（保账本连续）；冻结 + 人工 |
| 完全回退 | 关 `billing.enabled` → 端点/任务注销，`/usage` 逐字节恢复（R-1）；账本**保留只读** |

> **回滚不丢账**：`enabled` 关闭仅停"出账/查询/入账**新任务**"；账本与账单为**持久只读**，重开后可续。

---

## 13. 任务拆解与进度（T0-T15，L3）

### 13.1 任务-设计双向追溯表（附录 F.3 口径）

> **两列含义**：`对应设计章节` = 该任务的完整设计落点（可施工）；`设计深度` = 该章节在附录 F.1 口径下的等级（本文全部 **L3**）。任务编号与 §2.1 一致。

| 任务 | 交付物 | 对应设计章节 | 设计深度 | 估时(人日) | 依赖 | 里程碑 |
|---|---|---|---|---|---|---|
| **T0** | 本文档（详细设计）定稿 | 全文 | L3 | 1 | — | W1 |
| **T1** | 套餐系统（4 档 + 订阅 + 升降级 + 超额策略；**超额 charge 接线 A-43**） | §4.1.2 / §5.2 / §6.4.2 / §6.4.4 / **§6.5.5** / 附录 D | L3 | 3 | T0 | W3 |
| **T2** | 配额编译 + 热下发（含 **month 窗口** tee-infer 扩展 + **模型系数下发通道 A-41**） | §4.1.3 / §4.4 / §6.4 / §6.4.3 / **§6.4.5** | L3 | 4 | T1 | W3 |
| **T3** | 计量接入（拉取/推送/**单写者 `sync_mode` 择一**，A-12）+ retry 标记经请求头传播（A-1）+ **pull 侧 retry 归因**（A-23） | §4.1.5 / §5.1 / §6.1-6.3 / §6.3.3 | L3 | 4 | T0 | W1/W6 |
| **T4** | 计价引擎（单价表 + 系数 + 阶梯 + 取整 + retry 归因；**入出分轴 A-26 / ∞ 档 A-24 / 单位统一+唯一取整 A-44(a)**） | §4.1.4 / §4.2 / §5.4 / §6.5 / 附录 D | L3 | 4 | T3 | W2 |
| **T5** | 账单系统（日结/月结 + 明细 + 导出；**对账门禁 A-22 / 超额单列 A-45 / 状态机 A-50**） | §4.1.6 / §5.3 / §6.6-6.8 | L3 | 4 | T4 | W4 |
| **T6** | 用量/账单查询 API + 余额告警 | §4.3 / §6.11 | L3 | 2 | T5 | W5 |
| **T7** | 数据完整性（账本哈希链 + 账单签名 + 审计联动） | §7.1-7.6 | L3 | 3 | T3 | W4 |
| **T8** | 异常检测（含 **S-9 到期扫描**，A-16）+ 冻结机制 | §4.1.7 / §6.9-6.10 / §6.16(S-9) | L3 | 3 | T5 | W6 |
| **T9** | 管理后台页面（套餐/账单/冻结） | §4.3.4 / §4.3.5 | L3 | 2 | T1/T5 | W5 |
| **T10** | 可观测性（指标/日志/告警/大盘/tracing）+ 门禁登记 | §9.1-9.5 / `scripts/metrics-required.txt` | L3 | 2 | T3/T5 | W7 |
| **T11** | 单元测试（计价/链/签名/异常/冻结/配置） | §10.1 | L3 | 2 | T4/T7/T8 | W7 |
| **T12** | 集成测试（拉取自结/推拉单写者互斥/套餐下发/冻结补账） | §10.2 | L3 | 2 | T3-T8 | W7 |
| **T13** | **对账回归测试（零容差）+ 出账门禁验证** | §10.4 / §6.12 | L3 | 2 | T5/T7 | W8 |
| **T14** | E2E 测试（真机链路 + 验签 + 导出一致性） | §10.3 | L3 | 2 | T5/T6 | W8 |
| **T15** | 文档 + 上线验收（灰度 + 验收清单） | §11.3 / §12 | L3 | 1 | 全部 | W8 |
| | | | **合计** | **41 人日 ≈ 8.2 人周** | | |

> **双向可追溯**：正查（任务→设计）见上表；反查（设计→任务）见 §3.5 模块划分的"任务"列 + §2.1 的"本文档设计章节"列。**无孤儿设计、无孤儿任务**（附录 A 逐项核验）。

### 13.2 里程碑

| 里程碑 | 周 | 内容 | 出口判据 |
|---|---|---|---|
| **M-α 设计冻结** | W1 | T0 定稿评审通过；账本/存储骨架（T3/T7 起步） | 附录 A 全绿；存储选型冻结（P-1） |
| **M-β 计价可用** | W2 | 计价引擎（T4）+ 配置校验（R） | T-6.5-* 绿；R-14/R-16/R-17 生效 |
| **M-γ 套餐热下发** | W3 | 套餐 + 配额编译 + month 窗口 + **系数下发（★ A-41）**（T1/T2） | T-6.4-* 绿（含 **T-6.4-7**）；M6 ≤ 60s |
| **M-δ 出账闭环** | W4 | 日结/月结 + 签名 + 账本链（T5/T7） | T-6.6/6.7/7.2-* 绿；M8；**B-6.14-4 系数重下发** |
| **M-ε 自助与管理台** | W5 | 查询 API + 管理后台（T6/T9） | M5 < 200ms；页面可用 |
| **M-ζ 异常与冻结** | W6 | 异常检测 + 冻结 + 数据面 retry 接线（T8/T3） | T-6.9/6.10/6.3-* 绿；M7/M9 |
| **M-η 可观测与测试** | W7 | 指标/告警 + 单测/集成/E2E（T10-T12/T14） | 门禁绿；覆盖率 ≥ 80% |
| **M-θ 验收上线** | W8 | 对账回归 + 灰度 + 验收（T13/T15） | M1/M2 达标；**A-1..A-52 / O-8 / D-12..D-17 全绿**（★ D-14 同步至本轮修复项；v1.7 追加 A-44..A-52） |

### 13.3 人力与工作量

- **总量**：41 人日 ≈ 8.2 人周（§13.1 逐行合计）。
- **角色**：Go 后端 1-2 人（账务域 + 数据面接线）；测试 1 人（T11-T14）；前端 0.5 人（T9）；SRE 0.5 人（T10/T15）。
- **关键路径**：T3 → T4 → T5 → T7 → T13（账本→计价→出账→完整性→对账门禁）。

---

## 14. 风险与依赖（L3）

### 14.1 风险登记

| # | 风险 | 概率 | 影响 | 缓解 / 退路 |
|---|---|---|---|---|
| R-α | **月窗口依赖 tee-infer 改动**（P-2），跨进程版本耦合（B-6.4-3） | 中 | 月配额不生效 | 同版本部署 + CI 版本校验；退日预算口径（U-2） |
| R-β | **SQLite 单写者**并发（拉取 + 日结 + 查询） | 中 | 写延迟/锁争用 | WAL + 批量事务 + §8.3 基准；退"待处理队列 + 批量提交" |
| R-γ | **单价表维护责任**未定（P-3） | 中 | 无法计价 | 全局缺价 → 用量账单降级；部分缺价 → 冻结（§6.10.3） |
| R-δ | **金额域会签**未过（U-1） | 中 | 阶段受阻 | 停 Stage 0（用量账单），不阻塞账本/对账 |
| R-ε | **retry 明细可见性**（U-10/★ A-23） | 低 | M9 证据弱 | 两路均落地（push 载荷 + pull 按 `IsRetry` 分组聚合）；默认 `sync_mode=pull` 下由 pull 归因，M9 可证；均缺时才归零（偏保守） |
| R-ζ | **日/月阶梯口径差异**（U-11） | 低 | 月账调整项 | 月结以**账本锁定 std 的整月累计**重算阶梯（权威）+ 调整项；★ A-39：std 一律取自账本锁定值，**不得**按当前价格表重算换算（否则中途改价破 `Σ日=月`） |
| R-η | 时钟/时区不一致 | 低 | 归日错 | 统一 UTC+8（R-10）；时钟回拨检出（B-6.1-3） |
| R-θ | 审计链保留期外锚定失效 | 低 | 关联不可验 | 标记 `audit_anchor_stale`（B-7.3-1） |

### 14.2 依赖（开工前置，同 §2.3）

P-1 存储选型冻结 · P-2 month 窗口 · P-3 单价表来源 · P-4 金额域会签 · P-5 RBAC 角色 · P-6 配额下发通道。

---

## 15. 待确认事项（U-1 … U-15，L3）

> **性质区分**：**外部确认**（需产品/财务/法务）＝ U-1/U-3/U-11；**内部裁决**（工程决策，可先行）＝ U-2/U-4/U-5/U-6/U-7/U-8/U-9/U-10/U-12/U-13/U-14/U-15。

| # | 事项 | P0 现状假设 | 影响 | 归属 / 处置 |
|---|---|---|---|---|
| **U-1** | "金额列不出现"约束的作用域（§3.1.3） | 精确化**放行**：金额仅在 `/billing` 域 | 决定能否金额计费 | **产品/财务会签**；未过 → P-4 降级用量账单 |
| **U-2** | 月配额口径（§6.4.3/P-2） | 新增 month 窗口 | 月配额精度 | 工程；未满足 → 日预算 = 月/当月天数 |
| **U-3** | 存储选型（§5.6/P-1） | SQLite（P0）；PostgreSQL（企业版） | 并发/多副本 | **外部（企业版客户）**；P0 SQLite 先行 |
| **U-4** | 单价表来源（§3.4/§5.4） | 控制面配置（非硬编码） | 计价输入 | 工程；可切外部下发 |
| **U-5** | 记账签名算法（§7.2/§3.4） | HMAC-SHA256（可选 Ed25519） | 对外可验证性 | 工程；Ed25519 待需求 |
| **U-6** | 零容差 vs 0.1%（§1.3/§6.12.3） | 硬门禁 0 差异；软告警分级 0.1% | 出账判据 | 工程（已精确定义，登记备查） |
| **U-7** | 套餐继承模型 / 降配语义（§1.4/§6.4.2） | 套餐→租户直线；降配次日生效 | 配额层级 | 工程；对齐 1Panel"三级继承"待产品 |
| **U-8** | 输出拦截 token 计费口径（§2.2/§4.5） | "输入全计、输出按实际产生计" | 跨模块口径 | **跨模块会签**（输出审查 §4.9） |
| **U-9** | `/usage` 扩展 vs 新增 `/billing`（§4.3.1） | **新增 `/billing` 域，不改 `/usage`** | 兼容性 | 工程（已裁决，登记备查） |
| **U-10** | retry 明细可见性（§6.3.4） | **两路都实现**：push 携带 `is_retry` ＋ `aggregateUsage` 按 `IsRetry` 分组（★ A-23） | M9 可证性 | 工程（已裁决：两路落地，默认 pull 下由 pull 归因） |
| **U-11** | 超额独立价 + 迟到数据调整项话术（§6.5.5/§6.7） | 日/月**统一**月累计分档（A-6，可加性已证）；超额按最高档 | 账单口径 | **财务会签**（影响金额口径） |
| **U-12** | 零用量日是否出账（§6.6.3） | 默认**不出**（可配） | 账单噪音 | 工程（可配） |
| **U-13** | 冻结期自动降配（§6.10.2） | 默认**关**（`auto_throttle=false`） | 冻结副作用 | 工程（可配） |
| **U-14** | 账本链**密钥化 / WORM 落地**（§7.1/§7.5，S-1/S-5） | P0 默认**无密钥 SHA-256 链** + 依赖存储 WORM；HMAC-keyed 链为可选强化 | "链可验证"是否等于"防篡改"的边界 | 工程；WORM 未落地场景（可写 `billing.db`）防篡改范围登记备查；企业版可切 HMAC-keyed |
| **U-15** | 账本/账单**落盘加密**（§7.4，S-5） | P0 依赖存储层加密（TDE/磁盘加密）；应用层不另加密 | 静态数据机密性 | 工程；与部署形态绑定，登记备查 |

---

## 16. 变更记录（L3）

| 版本 | 日期 | 变更 | 依据 |
|---|---|---|---|
| v0.1 | 2026-09-29 | 骨架版（含 14 处"待补充"） | 初稿 |
| **v1.0** | **2026-10-01** | **全文重写为开发级详细设计**：① 补齐研发计划 §3.4 8 项 + 骨架 §13 15 行 + 主方案 §4.3.3 任务的**并集**（T0-T15），逐项达 **L3**；② 新增 §4 接口 22 条校验规则（R-1..R-22）、§5 数据模型（账本/套餐/账单/冻结）、§6 流程 15 节（含边界 B-x + 测试 T-x）；③ 新增 §7 完整性（哈希链/签名/双向关联/不变量 INV-1..10）、§9 指标登记表（18 项，source=admin）、§10 测试分层、§13.1 任务-设计**双向追溯表**、§15 待确认 U-1..U-13、附录 A-F；④ 裁决"金额域作用域精确化"（U-1）、"两级对账（L1 既有 + L2 新增）"、"`/usage` 不改、新增 `/billing` 域"（U-9）、"month 窗口扩展"（P-2/U-2）；⑤ 明确**唯一数据面改动** = `BillingNotifier.RecordUsage(isRetry)` 接线（§6.3.3） | 研发计划 §3.4；主方案 v5.5 §4.3；《GA-计费接口设计》；附录 F.2 五项必查 |
| **v1.1** | **2026-10-01** | **应用第 1 轮多角色评审修复**（报告见《...-多角色评审报告-第1轮.md》）：① **A-1 retry 归因重定位**——Wasm 无法提供 token，改由路由追加请求头 `X-Otpmask-Retry-Attempt` → tee-infer 解析并落审计事件 `IsRetry`（证据字段、不进 hash），`BillingNotifier` token 计数**退役**（§6.3.3/§4.4/附录 F）；② **A-2/A-3**：`UsageAgg` 补 `TenantID/Epoch/Period`、`Bill` 补 `PriceVersion`；③ **A-4**：新增 §4.1.8 存储层接口（`Tx/Store/BillStore/FreezeStore/ErrUnique`）；④ **A-5**：新增 §6.4.5 下发通道总表（四类副作用→消费者→失败语义）+ `PolicyApplier.ApplyConcurrency/ApplyCacheTier/ApplyOverQuota`；⑤ **A-6/C-4/P-3**：日/月阶梯**统一为月累计**口径并证**累进可加性**（§6.7）；⑥ **A-7/O-1**：新增 §6.16 后台调度器总表 S-1..S-8；⑦ **A-8**：`ConsumePush` 收敛为**唯一**账本写入路径；⑧ **A-9/A-10**：§4.6 助手函数签名清单、§6.5.1 `StandardTokens` 唯一换算；⑨ **A-11**：§4.3.4 重写为页面级 RBAC + 薄伪代码（T9 达 L3）；⑩ **S-1/S-4/S-5**：§7.1 前提声明（链验证≠防篡改，须 WORM 共存）+ HMAC-keyed 链可选强化 + §7.4 落盘加密行，新增 **U-14/U-15**；⑪ **S-2/S-3**：独立 events 密钥（R-27）+ `bill_export`/`bill_verify` 审计动作；⑫ **O-2..O-6**：量化阈值（写锁/日结/全量校验）+ 启动自检 SC-1..SC-6 + 回补重拉幂等键；⑬ **C-1/C-2/C-3**：`PlatformCostView`、R-29 交叉约束（`charge` 不得全 0 价/免费档）、负向取整对称（`away_from_zero`）；⑭ **P-1/P-4**：`GET /usage/quota` 回读 + 配额回读确认（60s）+ 免费版到期运营闭环（`expires_at` 列 + 指标 #21）；⑮ 校验规则扩至 **R-1..R-29**、新增 §4.1.8/§4.6/§6.4.5/§6.15.1/§6.16、指标 **18→21**（#19 retry tokens/#20 auto_repull/#21 plan_expiring）、§11.4 备份恢复（RPO≤24h/RTO≤1h） | 第 1 轮多角色评审报告（A/S/O/C/P/D 共 40 项）；附录 F.2 五项必查 |
| **v1.3** | **2026-10-01** | **应用第 3 轮多角色评审修复**（报告见《...-多角色评审报告-第3轮.md》；本轮以**调用图审计**+**修复连带面复算**发现 v1.2 修复引入/暴露的新缺陷）：① **A-22（P0）对账判据自相矛盾**——v1.2 中 `CloseDaily` 任意 `diff>0` 即冻结 / 软告警行 `0<ratio≤0.1%` 不冻结 / 注「冻结恒在 `diff>0`」三者两两冲突，且 **`onReconcileWarning` 全文零调用点（死代码）**。现**分离「出账门禁（恒，diff>0 一律不出账）」与「冻结判据（硬，仅 ratio>0.1%）」两个独立判据**，`0<ratio≤0.1%` 走**回补不冻结**软分支并接通 `onReconcileWarning`（§6.6.1/§6.7/§6.12.3），消除三处矛盾并使指标 #20 具备唯一生产者；② **A-23（P0）retry 归因在默认配置下空转**——v1.2 仅定义 push 载荷 `is_retry`（路①），而 **R-30 默认 `sync_mode=pull`** 使 M9 判据永无数据。现**两路都落地**：push 载荷 `is_retry`（路①）+ `aggregateUsage` 按 `IsRetry` 分组（路②，拉取侧归因），`GET /usage` 加 `retry_tokens`（omitempty），补 **T-6.3-8** 证默认配置下 `retry_toks>0`（§6.3.2/§6.3.3/§6.3.4/§6.5.4/§4.4/U-10）；③ **A-21（P1）阶梯计价起点重复计费**——`rateModel` 中 `outStart` 误用 `monthStdBefore`（未加 `stdIn`），使输入段与输出段在月累计轴上**重叠**；改为**串行** `outStart = monthStdBefore + stdIn`（先入后出，§6.5.2）；④ **A-24（P1）顶档 `UpToTokens=0`(∞) 未特判**——`overlap` 对 `up<=0` 现定义 `+∞` 语义，`B-6.5-3` 阶梯为空改为**单档全量**而非 0 金额（§4.6/§6.5.2/§6.5.6）；⑤ **A-25（P1）spike 严重级阈值误用**——`AnomalyDetector` 用 `ReconcileAlertRatio`(0.1%) 判 spike 严重级（跨维度串用），新增 **`spike_critical_ratio`（R-33）** 专用阈值（§6.9.1/§4.2/§6.10.1）；⑥ **O-7（P1）判据指标无生产者**——#7/#11/#14 等无发射调用点（**#11 为 M1 判据**），补 `setReconcileDiff`/`observeClose`/`incFreeze` 显式调用点 + 新增 **§9.1.1 唯一生产者对照表**（契约化）；⑦ **D-11（P2）Go 伪代码编译性**——`LedgerStore` 接口不可另开接收者方法（`ReproduceHead` 收归接口内，§4.1.1）、`ErrPricingMissing` 补 `Error() string`、`rateModel` 去 `modelKey`、`signer` 改字段声明、`extraAmount` 补完整签名（§4.6/§6.5.5）；⑧ 校验规则扩至 **R-1..R-33**（新增 R-33 spike 阈值交叉约束）、测试新增 **T-6.3-8**、指标登记与生产者表 **21 项**（含 §9.1.1 生产者列） | 第 3 轮多角色评审报告（A-21..A-25 / O-7 / D-11）；附录 F.2 五项必查 |
| **v1.4** | **2026-10-01** | **应用第 4 轮多角色评审修复**（报告见《...-多角色评审报告-第4轮.md》；本轮以**修复连带面复算**+**跨修复联立求解**发现 v1.3 修复"主修复点已改、连带子句未改"）：① **A-26（P0）A-21 串行横轴破坏可加性**——A-21 令 `outStart=inBefore+stdIn`（入出**串接**一根轴），使日结各日区间与月结**不一致** → §6.7「无迟到数据 `Σ日=月` 恒等」/T-6.5-7/U-11 三处成**假命题**（反例：两日各 in6/out6 时 Σ日 906 ≠ 月 1230）。**订正为「入/出各占一根**独立**月累计轴」**（`rateModel(stdIn,stdOut,inBefore,outBefore,mp)`；`monthStdBefore` 返回分轴二元组），恢复可加性；补 **T-6.5-9** 分轴可加性回归（含旧串接反向断言）（§6.5.1/§6.5.2/§6.7/§4.6/附录 G-4）；② **A-27（P1）pull retry 归因语义冲突**——A-23 的 `aggregateUsage` 分组与 §4.4「不改既有字段语义」冲突（pull 侧 `tokens_in/out` 含 retry 则 M9 破、剔则违契约）。**订正：`GET /usage` 计量口径的 `tokens_in/out` 剔除 retry（净量）、`retry_tokens` 单列，二者互斥**；§4.4 显式声明"不改语义"**限于标识字段**、token 计数字段为**口径订正**，展示口径逐字节不变（§4.4/§6.3.4/§6.5.4）；③ **O-8（P1）生产者表三行证伪**——§9.1.1 #10/#12/#17 记为**不成立的符号/不存在的发射点**（#10 `AnomalyDetector.Emit` 不存在、#12 §6.4.1 无发射、#17 引用错 §6.6.1）。**回填真实发射点**：#10 → `detector.Scan` 出口 `incAnomaly`（§6.9.1）、#12 → §6.9.1③ `setQuotaRemainingRatio`、#17 → §6.1.1 `incClockSkew`（新增时钟回拨保护代码）（§6.1.1/§6.9.1/§9.1.1）；④ **A-28（P1）A-22 判据未传播**——B-6.12-3/T-6.12-2/§10.2 INT-5/§10.4 REC-2 **仍写"`diff>0`→冻结"**，与 §6.12.3 冲突。**统一为「diff>0 不出账（门禁）；仅 ratio>0.1% 冻结」**（§6.12.4/§10.2/§10.4）；⑤ **A-29（P2）** §6.5.4 数据来源补 **pull 路②**（默认）；⑥ **A-30（P2）** §9.3 `BillingAnomalySpike` **按 severity 分档**（warning 不冻结 / critical 冻结，与 §6.9.1 A-25 一致）；⑦ **A-31（P2）** `VerifyBillingChain` **补调用点**（§6.16 新增 **S-10 关联校验** + R-34，§7.3 接线注）；⑧ **D-12（P2）** §6.5.5 `extraAmount` 超额**入/出分价**（`rateAtTopTier(stdIn,stdOut,mp)` + **入优先占额**约定，消除 U-11 剩余子项）；⑨ 校验规则扩至 **R-1..R-34**（新增 R-34 关联校验周期）、新增调度任务 **S-10**、新增测试 **T-6.5-9**、U-11 登记订正 | 第 4 轮多角色评审报告（A-26..A-31 / O-8 / D-12）；附录 F.2 五项必查 |
| **v1.5** | **2026-10-02** | **应用第 5 轮多角色评审修复**（报告见《...-多角色评审报告-第5轮.md》；本轮聚焦 **A-26 分轴方案的跨层连带面**——热更新/配额/下游消费，共 8 项）：① **A-32（P0）月累计标准 token 计算基准定义**——账本只存原始 token + 价格表可热更新 → 「月累计 std」用哪版系数算的矛盾（方案 a 重算→可加性破 / 方案 b 存 std→缺字段）。**选定方案 b**：`LedgerEntry` 新增 `std_in/std_out/price_ver` 三字段（§5.1/§4.1.1），入账时按当日价格表版本算好写入（§6.2 `aggToEntries`），`monthStdBefore` 直接读 std 字段求和（§6.5.1/§4.6），热更新仅影响新条目 → 月累计恒稳定 → **可加性在热更新下仍成立**（§6.7）；新增 T-6.5-9 「月中调价后仍可加」回归用例；② **A-33（P1）超额计费与配额窗口口径统一**——计费用标准 token、配额若用原始 token → 用户困惑或超额计费形同虚设。**统一为标准 token**：`Plan.MonthlyTokens` 单位 = 标准 token 合计（§6.5.5），tee-infer 月窗口同样按标准 token 计数（§6.4.3）；澄清「合计超额后入优先占额分配」语义（与 A-26 分轴不矛盾：阶梯按各轴独立累计、超额阈值是合计软上限）；新增 T-6.5-10 超额段入优先占额用例；③ **A-34（P1）S-10 关联校验可观测性闭环**——原 S-10 无指标、无告警、失败语义笼统、幂等键不清晰。补 **指标 #22 `billing_assoc_verify_total{result}`**（§9.1）+ **生产者行**（§9.1.1，`verifyBillingAssoc` 出口）+ **告警 `BillingAssocVerifyFailed`**（§9.3，critical 但不冻结，事后审计性质）；§6.16 S-10 行补幂等键 `(bill_id)`、细化失败语义；④ **A-35（P1）净量口径双字段过渡策略**——原 A-27 直接改 `tokens_in/out` 为净量 → 下游消费方（容量规划/外部计费/监控）数值跳变。改为**双字段过渡**：既有 `tokens_in/out` 保留原口径（含 retry，向后兼容），新增 `tokens_in_net/tokens_out_net`（omitempty，净量），账务域 pull 消费 `_net` 字段（§4.4/§6.5.4）；恒等校验 `tokens_in = tokens_in_net + retry_tokens`；⑤ **A-36（P2）spike 检测不足 3 天不告警**——新租户/月首前几天样本太少 → 误报率高。`avgStd` 返回 `daysWithData`（§4.6），入口处 `daysWithData < 3` 直接跳过 spike 检测（§6.9.1）；新增 B-6.9-5 边界条目；⑥ **A-37（P2）monthStdBefore 月累计缓存策略**——每次计价扫全月账本 → 日结复杂度 O(天数×模型数)。设计 `month_accum` 内存缓存（日结后写入、补账时失效、预热），P0 可不做（DB 扫表 30 天可接受），P1 性能优化阶段引入（§6.5.1）；§8.4 P-3 追加缓存启用后的性能目标（< 3min）；⑦ **D-13（P2）StandardTokens 适用范围明确**——A-9「唯一实现」grep 断言不知道该搜哪些地方。在 §4.1.4 `StandardTokens` 注释中明确：✅ 需要调用（Rate/入账/extraAmount/push 归因）；❌ 不需要（配额编译/monthStdBefore/spike 检测——输入已是标准 token）；⑧ **A-38（P2）REC-2 拆 2a/2b 用例**——原「漏入一条」的 ratio 取决于基准量，冻结算例不可执行。拆为 REC-2a（ratio≈0.05%，不出账+回补+不冻结）与 REC-2b（ratio≈5%，不出账+冻结），覆盖 A-22 两分支（§10.4）；⑨ 指标 **21→22**（新增 #22）、边界新增 **B-6.9-5**、测试新增 **T-6.5-10**、REC 用例 **6→7**（REC-2 拆为 2a/2b） | 第 5 轮多角色评审报告（A-32..A-38 / D-13）；附录 F.2 五项必查 |
| **v1.6** | **2026-10-02** | **应用第 6 轮多角色评审修复**（报告见《...-多角色评审报告-第6轮.md》；本轮以**同源性审计**+**声明-实现一致性复算**发现 v1.5 的 A-32 修复**未闭环**）：① **A-39（P0）std 读路径异源**——v1.5 `Rate`/`RateMonthly` 用 `StandardTokens(raw, 当前价表)` **现场重算** std，而 `monthStdBefore` 读**账本锁定** std → 单次调用**两源** → 月中调价即破 `Σ日=月`（反例见**附录 G-5**）。**订正为「std 唯一来源 = 账本锁定值」**：`UsageAgg`/`ModelUsageAgg` 新增 `StdIn/StdOut`，`foldByModel`/`monthAgg` **累加**账本 `std_in/std_out`（不换算），`Rate`/`RateMonthly`/`ExtraAmount` 消费 `mu.StdIn/StdOut`（§4.1.5/§4.6/§6.5.1/§6.5.5/§6.6.1/§6.7）；② **A-40（P1）计价基未入哈希链**——`computeHash` 漏 `std_in/std_out/price_ver` → 计价依据可被就地篡改而 `Verify()` 检不出（违 INV-2）。**补入 3 字段并冻结序列化顺序**，声明 v1.5→v1.6 **破坏性版本边界** + 迁移策略（重建/`chain_epoch`）（§7.1.1/§7.6 INV-2）；③ **A-41（P1）系数下发通道缺失**——A-33 要求 tee-infer 按**标准 token** 计数，但 §6.4.5 无"系数 → tee-infer"通道（§6.4.3 的"tee-infer 内换算 / usageRecord std"两路均不可落地）。**新增第 5 类下发通道** `QuotaApplier.ApplyCoefficients`（`ModelCoef`，仅系数不含单价，INV-3/INV-7）→ tee-infer `reserveQuota` 换算 + `coef_version` 校验（§4.1.3/§4.4/§6.4.1 步骤 2a'/§6.4.5/§6.14 Reload B-6.14-4/§6.4.3 订正"责任悬空"）；④ **A-42（P1）双字段未贯穿聚合**——§6.12.2 `a.TokensIn` 口径二义（M1/L2/M9 不能同保）。**口径唯一化**：`UsageAgg.TokensIn/Out ≡ 净量`，`MeteringSource.Pull` 由 `tokens_in_net → TokensIn` 映射，`reconcileL2` 两侧**同取净量**（§4.1.5/§4.6/§5.1/§5.3/§6.12.2 + T-6.12-5）；⑤ **A-43（P1）`ExtraAmount` 死代码**——函数已定义却**全文无调用点**。**接线于 `CloseMonthly` 步骤 2b**（`OverQuota=charge`），并将其收归 `RatingEngine` 接口（`extraAmount`→`ExtraAmount`，§4.1.4/§6.5.5/§6.7 + T-6.7-3）；⑥ **D-14**：§13.2 M-θ 判据 `A-1..A-31/O-8/D-12` → `A-1..A-43 / O-8 / D-12..D-17`；⑦ **D-15**：附录 B 补 `B-6.4-7`/`B-6.9-5`/`B-6.12-5`/`B-6.14-4` + `B-6.7-1..4`，附录 C 补 `T-6.5-10`/`T-6.4-7`/`T-6.7-*`/`T-6.12-5`、REC-1..6 注"拆 2a/2b 计 7 例"；⑧ **D-16**：`Bill.status` 枚举补 `assoc_mismatch`（§4.1.6/§5.3），§6.16 注释 `chain_assoc_mismatch`→`status=assoc_mismatch` 统一；⑨ **D-17**：附录 G 新增 **G-5**（A-39 反例，回归锚） | 第 6 轮多角色评审报告（A-39..A-43 / D-14..D-17）；附录 F.2 五项必查 |
| **v1.7** | **2026-10-02** | **应用第 7 轮多角色评审修复**（报告见《...-多角色评审报告-第7轮.md》；本轮以**⑨单位/量纲审计**+**⑩基数/作用域审计**发现 v1.6 的 A-43 接线**本体错误**——非"漏改旧代码"而属"新代码本体缺陷"）：① **A-44（P0）`CloseMonthly` 超额并入月账双重错配**——(a) **单位/量纲**：`ExtraAmount` 返回**亚分**（千分之一分）却被 `amtAuthoritative`（`Amount`＝分，int64）直接 `+=`（`Amount += int64` **不可编译**），且制造**第二个取整点**违背 R-16「每账单一次取整」；(b) **基数/作用域**：§6.7 逐模型循环而 `ExtraAmount` 以**单模型**用量比**套餐级** `p.MonthlyTokens` → `Σᵢ max(0,mᵢ−L) ≤ max(0,Σᵢmᵢ−L)` 系统性漏收。**订正**：新增 `RateMu`（返回亚分，不取整）为 `Rate` 的内核（`Rate`＝`roundAmount(RateMu(...))`，**唯一取整点**）；`ExtraAmount` 改为**套餐级合计基数**＋**确定性瀑布归因**（按 `inUsed+outUsed` 降序、同值按 `modelKey` 升序，逐模型从其用量中扣减套餐额度，剩余部分按顶档计价），返回**亚分**；`CloseMonthly` 以 `roundAmount(baseMu)` 得 `amtAuthoritative`，超额单列 **`kind="overage"` 账单**（`roundAmount(overMu)`）（§4.1.4/§4.6/§6.5.1/§6.5.5/§6.7）；② **A-45（P1）** 超额并入月账致 §6.7「无迟到数据调整项=0」**系统性失效**（`CloseDaily` 只调 `Rate` 不含超额）；订正为**独立 `overage` 账单**保 `adjust=0` 语义，`bills.kind` DDL/`Bill.Kind`/`BillQuery.Kind` 补 `overage`（§4.1.6/§5.3/§4.1.8/§6.4.4）；③ **A-46（P2）** §9.1.1 指标 #18 生产者列**证伪**（`rateModel` 无缺价分支）→ 改记「`Rate`/`ExtraAmount` 返回 `ErrPricingMissing` 处（§6.5.1）」（§9.1/§9.1.1）；④ **A-47（P2）** §4.6 `monthStdBefore` 引用**未定义符号 `monthStart`** + 月周期 `day<period` 语义未定义 → 显式定义 `monthStart = period[:7]+"-01"` 与月周期口径（§4.6）；⑤ **A-48（P3）** §9.1.1 指标 #4 生产者**引用错位**（S-5＝`detector.Scan`）→ 改记 S-6 `Verify`（§9.1.1）；⑥ **A-49（P3）** A-40 计价基入链**未被篡改表/测试覆盖** → §7.1.3 补「改计价基 `std_in/std_out/price_ver`」行 + §7.1.4 补 **T-7.1-5**；迁移**选定选项①（重建）**、显式否定选项②（`chain_epoch` 无 DDL/`Verify` 支撑）（§7.1.1/§7.1.3/§7.1.4）；⑦ **A-50（P3）** `UpdateStatus` 迁移集合**漏 `assoc_mismatch`**（D-16 半落地）→ 补「已出账→`assoc_mismatch`」（§4.1.8）；⑧ **A-51（P3）** §6.5.1 A-37 缓存段**自相矛盾**（热更新是否触发缓存失效）→ 删去与 §7.1 陈旧窗口互斥的触发条件、统一为「仅补账/回补触发失效」（§6.5.1）；⑨ **A-52（P3）** `incLedgerError()` **无注册指标** → 新增指标 **#23 `billing_ledger_error_total{op}`**（`op=begin\|append`，§9.1）+ 生产者行（§9.1.1）；指标 **22→23**、测试新增 **T-6.5-11/T-6.5-12/T-6.7-4/T-7.1-5**、边界新增 **B-6.7-5**、附录 A/B/C 同步、附录 G 新增 **G-6**（A-44 反例锚） | 第 7 轮多角色评审报告（A-44..A-52）；附录 F.2 五项必查；⑨单位/⑩基数审计 |
| **v1.2** | **2026-10-01** | **应用第 2 轮多角色评审修复**（报告见《...-多角色评审报告-第2轮.md》；本轮复算原始子句，修复"改了半边"的成组缺陷）：① **A-12（P0）双通道单写者模型**——§6.3.2 弃用"同 `event_key` 去重"（push 事件级键 `push:{event_id}` 与 pull 窗口级键 `pull:...` **结构不同、不可统一**），改为 **`source.sync_mode ∈ {pull,push}` 单写者**：任一租户/周期仅一个通道写账，另一通道只作实时视图（**R-30**）；同步 §6.3.4/§6.3.5/§4.1.5（`SyncMode` const）/§7.6 INV-8，消除重复入账（M1 零容差恢复）；② **A-13**：`foldByModel` 签名改为 `foldByModel(tenant, epoch, period string, entries []LedgerEntry) UsageAgg` 并回填三字段（§4.6/§6.6.1），补 T-6.5-8；③ **A-15**：修正全部双返回单值接收——§6.1.1 `tx, err := s.store.Begin()`、§6.12.2 `led, err := ...Range(...)`、§6.16 `broken, err := ...Verify()`；`sum(aggs[tenant])` 改为 `a := aggs[tenant]` 判空后取 `a.TokensIn/Out/Requests`；④ **A-14**：§4.6 补齐 `ReproduceHead`/`auditAnchorExists`/`crossRefEvents`/`repullInflight`/`pullOnceWindowed` 签名 + 错误哨兵 `ErrFrozen/ErrReconcile/ErrLedgerAnchorMismatch/ErrAuditAnchorMissing`；统一 `s.ledger`→`s.store.Ledger()`；补 `ctx`（§6.12.2/§6.12.3）/`start`（§6.4.1）；⑤ **A-16**：§6.16 新增 **S-9 到期扫描**（周期 `expiry_scan_interval`/幂等键 `(tenant,periodKey)`/single-flight）+ `StartSchedulers` 注册，接通指标 **#21**（唯一生产者）；配 **R-32**；⑥ **A-17**：`Anomaly.Kind`/指标 #10 枚举补 **`plan_expired`**（S-9 兼发）；⑦ **A-18**：新增 `anomaly.auto_throttle`（**R-31**，P0 默认 `false`）+ `schedule.expiry_scan_interval`（R-32）；**收窄** R-2 `driver∈{sqlite,postgres}`（移除无实现的 `file`）、R-17 `tier_mode=progressive`（移除无口径的 `flat`）；⑧ **A-19**：§6.9.1 修 `sev(float64(today)/avg7, ...)` 类型混算 + 去掉 `sev` 局部遮蔽（复用分级函数）；⑨ **A-20**：`onReconcileWarning` 的 `day` 统一为 `string`；⑩ 校验规则扩至 **R-1..R-32**，新增调度任务 **S-9**、测试用例 **T-6.3-7**/**T-6.5-8** | 第 2 轮多角色评审报告（A-12..A-20 / D-9/D-10）；附录 F.2 五项必查 |

---

## 附录 A：L3 覆盖度自检表（对齐附录 F.1/F.2）

> **F.2 五项必查**：广度（是否穷尽子任务）／深度（是否达 L3）／可实现性（伪代码+接口可施工）／向后兼容（默认关闭逐字节一致）／可观测性（指标+告警可判定）。逐任务核验：

| 任务 | 广度 | 深度 | 可实现性 | 向后兼容 | 可观测性 | 判定 |
|---|---|---|---|---|---|---|
| T0 详细设计 | ✅ 并集全覆盖 | ✅ L3 | ✅ | ✅ | ✅ | **L3** |
| T1 套餐系统 | ✅ 4 档+订阅+升降级+超额（**超额 charge 接线 A-43；套餐级合计基数 A-44(b)**） | ✅ §6.4.4/§6.5.5 | ✅ §4.1.2/§5.2 | ✅ 默认无套餐=现状 | ✅ #13 | **L3** |
| T2 配额热下发 | ✅ 含 month 窗口 + **系数下发（A-41）** | ✅ §6.4.3/§6.4.5 | ✅ 复用 `TeeQuotaApplier`（+`ApplyCoefficients`） | ✅ 旧端版本校验 | ✅ #13（M6） | **L3** |
| T3 计量接入 | ✅ 拉/推/归并 + retry 接线（**A-23 两路归因**） | ✅ §6.1-6.3 | ✅ 复用 `aggregateUsage` | ✅ **A-35 双字段过渡**（老字段原口径 + _net 净量） | ✅ #2/#5/#6 | **L3** |
| T4 多模型计价 | ✅ 系数+阶梯+取整+retry（**A-26 分轴/A-24 ∞ 档/A-32 热更新可加性/A-44(a) 单位统一+唯一取整/RateMu**） | ✅ §6.5 | ✅ 纯函数 + **月累计缓存（A-37，P1；A-51 失效触发订正）** | ✅ 无单价=用量账单 | ✅ #18（A-46） | **L3** |
| T5 账单系统 | ✅ 日/月结+明细+导出（**A-22 门禁/A-32 热更新可加/A-45 超额单列 `kind=overage`/A-50 状态机 `assoc_mismatch`**） | ✅ §6.6-6.8 | ✅ §4.1.6 | ✅ 默认不出账 | ✅ #7/#8/#15 + §9.1.1 | **L3** |
| T6 查询+告警 | ✅ 自助 API+余额告警 | ✅ §6.11 | ✅ §4.3 | ✅ **不改 `/usage`**（M10） | ✅ #9/#12 | **L3** |
| T7 数据完整性 | ✅ 链+签名+关联（**S-10 可观测闭环 A-34；计价基入篡改表 A-49**） | ✅ §7.1-7.5 | ✅ §7 伪代码 | ✅ 默认关闭 | ✅ #4/#16/**#22** + INV + §9.1.1 | **L3** |
| T8 异常+冻结 | ✅ Scan 4 类 + 到期（S-9）+ 状态机（**A-25 spike 阈值/A-36 不足3天不告警**） | ✅ §6.9-6.10/§6.16 | ✅ §4.1.7 | ✅ 默认不冻结 | ✅ #10/#11/#14/#21（M7）+ §9.1.1 | **L3** |
| T9 管理后台 | ✅ 套餐/账单/冻结页 | ✅ §4.3.4 | ✅ 薄展示 | ✅ 默认不注册 | ✅ #1 | **L3** |
| T10 可观测性 | ✅ 指标/日志/告警/大盘/tracing | ✅ §9 + **§9.1.1 生产者表（O-7）** | ✅ 沿用 `writeCounter` | ✅ 门禁登记 | ✅ **23** 指标（M7，★ A-52 追加 #23） | **L3** |
| T11 单元测试 | ✅ 8 组 | ✅ §10.1 | ✅ | ✅ | ✅ 覆盖率 ≥80% | **L3** |
| T12 集成测试 | ✅ 7 用例 | ✅ §10.2 | ✅ | ✅ | ✅ | **L3** |
| T13 对账回归 | ✅ **7** 用例（零容差，**A-22 门禁/冻结分离 + A-38 REC-2 拆 2a/2b**） | ✅ §10.4 | ✅ | ✅ | ✅ #11（M1/M2，§9.1.1） | **L3** |
| T14 E2E | ✅ 4 用例 | ✅ §10.3 | ✅ 真机链路 | ✅ S-6 逐字节 | ✅ | **L3** |
| T15 文档+验收 | ✅ 灰度+验收清单 | ✅ §11.3/§12 | ✅ | ✅ 回滚不丢账 | ✅ A-1..A-52 / O-8 / D-12..D-17 | **L3** |

**专项口径适配**：附录 F.1 的"Wasm 适配说明"由 §6.15「运行环境适配（admin-service 进程约束）」承接（本模块不在 Wasm 内运行，仅一处数据面接线，§3.2/§6.3.3）。

---

## 附录 B：边界条件总表（索引）

| 节 | 边界编号 | 摘要 |
|---|---|---|
| §4.3 | B-4.3-1..5 | 低角色写页面/跨租户账单页/套餐编辑并发/`enabled=false` 页面不注册/冻结租户只读 |
| §6.1 | B-6.1-1..8 | 不可达/跨重启/时钟回拨/配置非法/事务失败/超大响应/空响应/重复拉取 |
| §6.3 | B-6.3-1..7 | 未验签/重复 event_id/未知 result/负 token/**推拉单写者**（B-6.3-5，A-12）/冻结收 push/events 密钥同源（附 T-6.3-8 **pull 下 retry 归因**，A-23） |
| §6.4 | B-6.4-1..7 | 套餐不存在/部分成功/旧版 tee-infer/重复绑定/企业不限/降配冲突/**系数与价表版本不符**（B-6.4-7，A-41） |
| §6.5 | B-6.5-1..7 | 缺价/系数 0 负/**阶梯空=单档全量**（B-6.5-3，A-24）/不连续/跨档边界（分轴，A-26）/舍入法/溢出 |
| §6.6 | B-6.6-1..6 | 无用量/**对账不通（门禁恒 no-issue，A-22）**/已存在/中途重启/跨日边界/中途热更新 |
| §6.7 | B-6.7-1..5 | 日账不全/调整项为负/月结重复/调整项取整对称（C-3）/**超额单列账单与月账并存**（B-6.7-5，A-45） |
| §6.8 | B-6.8-1..4 | 超大账单/冻结导出/format 非法/导出必落 `bill_export` 审计 |
| §6.9 | B-6.9-1..5 | 新租户/7 日全 0/告警风暴/误报（spike 严重级用 `spike_critical_ratio`，A-25/R-33）/**样本不足 3 天不告警**（B-6.9-5，A-36） |
| §6.10 | B-6.10-1..4 | 冻结中再异常/自动解冻范围/解冻补账/冻结期改数 |
| §6.11 | B-6.11-1..3 | 每周期一次/已耗尽/不限套餐 |
| §6.12 | B-6.12-1..5 | tee 不可达/L1 blocked/多算/审计链断/**含 retry 窗口净量对账**（B-6.12-5→T-6.12-5，A-42） |
| §6.13 | B-6.13-1..2 | 降级期重启/只读查询 |
| §6.14 | B-6.14-1..4 | 非法配置/价格表热更新/enabled 热切换/**系数重下发**（B-6.14-4，A-41） |
| §6.15 | B-6.15-1..2 | panic 隔离/优雅关闭 |
| §6.16 | S-1..S-10 | 调度器总表（含 **S-9 到期扫描**，A-16；**S-10 关联校验** `VerifyBillingChain`，A-31/R-34）；周期/幂等键/单实例锁/失败语义 |
| §7.1 | B-7.1-1..5 | 空账本/并发/插入冲突/哈希失败/无 head |
| §7.2 | B-7.2-1..4 | 密钥轮换/明细序/改 Total/缺链锚 |
| §7.3 | B-7.3-1..2 | 审计裁剪/pull 跨账单边界 |

---

## 附录 C：测试用例总表（索引）

| 层 | 编号 | 覆盖 |
|---|---|---|
| 单元（§10.1） | 计价/链/签名/幂等/异常/冻结/配置 8 组 | T-6.5-*（含 **T-6.5-8** UsageAgg 回填、**T-6.5-9** 分轴可加性 A-26、**T-6.5-10** 超额入优先占额 A-33、**T-6.5-11** 超额单位与单次取整 A-44①、**T-6.5-12** 超额套餐级合计基数 A-44②）/T-7.1-*（含 **T-7.1-5** 篡改 `std_in` 检否 A-49）/T-7.2-*/T-6.3-*（含 **T-6.3-7** pull 模式下 push 并存不产生账本行、**T-6.3-8** pull 下 retry 归因 A-23）/T-6.4-*（含 **T-6.4-7** 系数下发标准 token 计数 A-41）/T-6.7-*（含 **T-6.7-3** 超额计费接线 A-43、**T-6.7-4** 超额单列 `kind=overage` 账单 A-45）/T-6.9-*/T-6.10-*/T-4.3-*/R-1..34 |
| 集成（§10.2） | INT-1..7 | 拉取自结/**推拉单写者互斥**（INT-2，A-12）/套餐下发（T-6.4-5/**7**）/冻结补账/对账/导出（B-6.8-4）/重启补账 |
| E2E（§10.3） | E2E-1..4 | 全链路/4 档套餐/篡改检测/关闭一致 |
| 对账回归（§10.4） | REC-1..6（**REC-2 拆 2a/2b → 计 7 例**） | 零容差/差异**回补不冻结（2a）**+**冻结（2b）**/取整/retry/L1 blocked/链断（**M1/M2**）；含 **T-6.12-5** 含 retry 窗口净量对账（A-42） |
| 性能（§10.5） | P-1..4 | 拉取/查询/日结/链校验 |
| 安全兼容（§10.6） | S-1..8 | 链篡改/签名伪造/**S-3 金额隔离（M10）**/未验签/越权/S-6 逐字节/S-7 版本/密钥引用 |

---

## 附录 D：套餐与定价模型（含阶梯/系数）

### D.1 四档套餐（P0 默认）

| 套餐 | 月 token（标准） | 并发 | 缓存档 | 模型范围 | 超额策略 | 价格 |
|---|---|---|---|---|---|---|
| **免费 Free** | 1,000,000 | 5 | `exact` | 3 个 | `reject` | 0 元 |
| **基础 Basic** | 10,000,000 | 20 | `exact` | 10 个 | `reject` | 999 元/月 |
| **专业 Pro** | 100,000,000 | 100 | `semantic` | 全部 | `charge`（阶梯） | 9,999 元/月 |
| **企业 Enterprise** | 定制（0=不限） | 定制 | `semantic` | 全部 | 定制 | 协商 |

> 套餐由 `Plan`（§4.1.2）定义，落 `plans` 表（§5.2）；`cache_tier` 与语义缓存 P0-2 的 `CacheTier` 口径对齐（`none|exact|semantic`）。

### D.2 模型系数（`in_coef`/`out_coef`，示例）

| 模型 | in_coef | out_coef | 说明 |
|---|---|---|---|
| GPT-3.5 | 1.0 | 1.0 | 基准（1x） |
| GPT-4 | 10.0 | 10.0 | 10x |
| Embedding | 0.1 | 0.0 | 0.1x（无输出） |

> 系数**仅用于标准 token 换算**（配额与阶梯共用，`RatingEngine.StandardTokens`）；缺省 = 1（B-6.5-2）。

### D.3 阶梯定价（累进，示例）

| 当月标准 token 档 | in_per_1k（元/千标准 token） | out_per_1k（元/千标准 token） |
|---|---|---|
| `[0, 10M]` | 1 | 2 |
| `(10M, 100M]` | 0.8 | 1.6 |
| `(100M, ∞)` | 0.5 | 1.0 |

> **累进**：跨档时低档部分按低档价、超出部分按高档价（§6.5.2）；**最低档含 0**，区间左闭右开（B-6.5-5）。**先累加后取整**（R-16），每账单一次取整。

---

## 附录 E：与旧版 v0.1 的差异订正

| 旧版 v0.1 | 新版 v1.0 | 订正理由 |
|---|---|---|
| 14 处"待补充" | 全部补齐（接口/流程/边界/测试/指标） | 达 L3 可施工 |
| 账务落点未定 | **`gateway-admin-service` 包级子系统**（§3.1.2） | 主方案 §4.3.2 归属；复用鉴权/审计 |
| 存储未定 | SQLite（纯 Go，禁 CGO）；PostgreSQL 企业版（§5.6） | 契合单机 admin |
| 无金额精度规则 | **int64 分 + 千分之一分亚分 + 先累加后取整**（§6.5.3/R-16） | 零容差必需 |
| 无月配额 | **month 窗口**（tee-infer 扩展，§6.4.3） | 套餐月配额 |
| 无重试口径 | **重试归平台成本**（`is_retry` 接线，§6.3.3/§6.5.4） | 主方案 §4.3.2；M9 |
| 无对账分层 | **L1 既有 + L2 新增**（出账门禁，§6.12） | 零容差 vs 0.1% 分层 |
| 无完整性机制 | 账本哈希链 + 账单签名 + 双向关联 + INV-1..10（§7） | 可验证计费 |
| `/usage` 扩展提案 | **不改 `/usage`，新增 `/billing` 域**（§4.3.1/U-9） | 向后兼容 M10 |
| 无指标登记 | 23 项指标入 `metrics-required.txt`（§9.1） | #9 门禁 |

---

## 附录 F：既有计费链路现状复核（代码实证）

> **复核日期**：2026-10-01；**复核方式**：源码行号实证（`file:line`）。本表是 §3.2 资产盘点与 §1.1 缺口论断的证据来源。

| 资产 | 位置（实证） | 现状 |
|---|---|---|
| 计量唯一真源声明 | `gateway/tee-infer-service/billing.go:3-5` | "Higress 只见密文无法计量" |
| 用量记录（租户） | `main.go:265` `recordUsage` | ✅ 生产 |
| 用量记录（模型维度） | `main.go:581` `recordModelUsage` | ✅ 生产 |
| 增量聚合 | `billing.go:53` `aggregateUsage(events,from,to)` | ✅ 生产（按 `action=infer` 聚合，免疫重启） |
| Webhook 推送 | `billing.go:111` `newBillingWebhook`；`:124` `billingEventPayload`；`:141` `block`；`:179` `notify`（HMAC `X-Signature: sha256=`） | ✅ 生产（HMAC+退避重试+`event_id` 幂等+block） |
| 零容差对账（L1） | `reconcile.go:5`（容差 0 依据：同源）；`:37` `reconcileInterval = 5 * time.Minute` | ✅ 生产 |
| 配额引擎 | `main.go:290` `quotaLimit`；`:436` `reserveQuota`；`:352` `quotaWindowKeyFor`；`:364` `validQuotaWindow` | ✅ 生产（minute/day/累计；**无 month**） |
| 套餐→配额编译基座 | `gateway-core/internal/ratelimit/teequota.go:45` `QuotaUpdate`；`:77` `CompileTEEQuota` | ✅ 生产 |
| 配额下发通道 | `gateway-core/internal/api/tee_client.go:16` `TeeQuotaApplier`；`:40-44` `ApplyQuota`（**逐条下发**，任一条失败即错） | ✅ 生产 |
| 数据面计费通知（预留，A-1 退役） | `wasm/otpmask-plugin/routeengine/engine.go:164` `BillingNotifier`；`:633` 传 `-1,-1,false`（注释自认"token 未知"）；`route.go:35` `proxy-wasm-go-sdk`（**Wasm 只见密文**） | ⚠️ **预留**；token 计数职责**退役**（A-1），改由请求头传播重试标记（§6.3.3） |
| 管理面用量代理 | `gateway-admin-service/usage.go:24`"金额列不出现（现仅计量无单价，项目硬约束）"；`:18-22` 503 语义；`:206-209` `handleMeteringReconcile` | ✅ 生产 |
| 管理面路由 | `gateway-admin-service/main.go:124-158`（`/v1/adminext/usage`、`/usage/quota`、`/metering/reconcile` 挂载） | ✅ 生产 |
| 管理面审计动作 | `gateway-admin-service/audit.go:42` `auditActionQuotaSet = "quota_set"` | ✅ 生产 |
| 指标门禁 | `scripts/metrics-required.txt`（source=`tee`/`admin`/`plugin`/`core`） | ✅ 生产（**尚无 `gateway_admin_billing_*`**） |

**结论**：底层（计量/审计链/L1 对账/推送/配额）**已上生产**；本文档所补为**上层账务域**（套餐/计价/账单/查询/异常/完整性），且**唯一数据面改动** = 路由追加 `X-Otpmask-Retry-Attempt` 请求头（§6.3.3，A-1），token 数**仍**只由 `tee-infer` 产生。

---

## 附录 G：关键反例记录（回归锚）

> **用途**：把历轮评审中**证伪了本文档既有论断**的最小反例固化为回归锚，供 §10.1 单元测试（如 T-6.5-9）引用，防止旧口径回归。
> **编号约定**：后缀 = 该反例所属评审轮次（`G-4` = 第 4 轮），与《...-多角色评审报告-第N轮.md》对齐；本附录按"**发现即固化**"原则收录，不保证每一轮都有独立反例条目。

### G-4：A-26「入/出串接横轴」破坏日/月可加性（第 4 轮）

**被证伪论断**：v1.3 §6.7「无迟到数据时 `Σ daily.amount == monthly.amount` 恒等」——该论断当时建立在 A-21 口径 `outStart = monthStdBefore + stdIn` 之上（即输入轴与输出轴**串接**成一根累计轴）。

**阶梯**：`[{UpTo=10: in=1 分/1k, out=10 分/1k}, {UpTo=∞: in=10 分/1k, out=100 分/1k}]`（单位：标准 k-token；`UpTo`/价格仅示意）。
**数据**：某月仅两日，每日 `stdIn=6k, stdOut=6k`。

**① 串接（旧 A-21）**：

- 第 1 日（`monthStdBefore=0`，`outStart=0+6=6`）：入段 `[0,6)` 全在档①（价 1）= `6×1 = 6`；出段 `[6,12)`：`[6,10)` 档①（出价 10）`4×10=40` + `[10,12)` 档②（出价 100）`2×100=200` → 出 `= 240`。**日 1 = 246**。
- 第 2 日（`monthStdBefore=12`，`outStart=12+6=18`）：入段 `[12,18)` 全在档②（价 10）`= 60`；出段 `[18,24)` 全在档②（出价 100）`= 600`。**日 2 = 660**。
- `Σ daily = 246 + 660 = 906`。
- 整月：轴长 `stdIn+stdOut = 24`；入段 `[0,12)` = `[0,10)×1 + [10,12)×10 = 10+20 = 30`；出段从 `stdIn=12` 起 `[12,24)` 全档② `= 12×100 = 1200`；**月 = 1230**。
- **结论**：`906 ≠ 1230`（差额 324）→ 串接口径下「Σ日 = 月」为**假命题**。

**② 分轴（v1.4 订正，A-26）**：

- 输入轴（独立）：月 `[0,12)` = `[0,10)×1 + [10,12)×10 = 30`；日 1 `[0,6)×1 = 6`、日 2 `[6,12)` = `[6,10)×1 + [10,12)×10 = 24` → `Σ = 30` ✅
- 输出轴（独立）：月 `[0,12)` = `[0,10)×10 + [10,12)×100 = 100+200 = 300`；日 1 `[0,6)×10 = 60`、日 2 `[6,12)` = `[6,10)×10 + [10,12)×100 = 40+200 = 240` → `Σ = 300` ✅
- **月 = 330，`Σ日 = 66 + 264 = 330`**，可加性恢复。

**回归断言（T-6.5-9）**：分轴下 `Σ daily.Rate == RateMonthly` **必成立**；对旧串接实现该式**必不成立**（本例 `906 ≠ 1230`）→ 反向断言防止 A-21 回归。

**落点**：§6.5.1/§6.5.2（分轴 `rateModel`）、§6.7（可加性充要条件）、§10.1 T-6.5-9。

### G-5：A-39「计价时用当前价格表重算 std」破坏日/月可加性（第 6 轮）

**被证伪论断**：v1.5 §6.5.1 `Rate` 用 `StandardTokens(mu.TokensIn, mu.TokensOut, mp)` **现场重算** std（`mp` 取自**当前**价格表），而 `monthStdBefore` 读**账本锁定** std → 一次 `rateModel` 调用中**两个不同来源** → 月中调价即破坏 `Σ daily.Rate == RateMonthly`（即 v1.5 的 A-32 修复**未闭环**）。

**阶梯**（单轴示例，仅输入轴，简化）：`[{UpTo=1000: InPer1K=1 分/1k}, {UpTo=∞: InPer1K=2 分/1k}]`（标准 token）。
**系数**：价格表 v1 `in_coef=1.0`；v2 `in_coef=2.0`（月中热更新）。
**数据**：某月仅两日，每日**原始** `tokens_in=1000`（输出为 0，简化）。**入账时**按当日价表算好并锁定：D1（v1）`std_in=1000`；D2（v2）`std_in=2000`。

**① 重算（v1.5 旧口径，异源 —— 证伪）**：

- 日 1（`monthStdBefore=0`，Rate 用**当刻**价表 v1 重算 → `std_in=1000`）：入段 `[0,1000)` 全档①（价 1）= `1 分`。**日 1 = 1**。
- 日 2（`monthStdBefore=1000` 读账本；Rate 用**当刻**价表 v2 重算 → `std_in=2000`）：入段 `[1000,3000)` 全档②（价 2）= `2000/1000×2 = 4 分`。**日 2 = 4**。
- `Σ daily = 1 + 4 = 5`。
- 月结：`RateMonthly` 对**整月原始 token 求和后用当刻价表 v2 重算** → `std = 2000×2 = 4000`；入段 `[0,4000)` = `[0,1000)×1 + [1000,4000)×2 = 1 + 6 = 7 分`。
- **结论**：`Σ日 = 5 ≠ 月 = 7`（差 2）→ 「Σ日 = 月」为**假命题**（v1.5 A-32「修复」未闭环）。

**② 锁定（v1.6 订正，A-39）**：

- `UsageAgg.StdIn` 由 `foldByModel` **累加账本锁定 `std_in`**（D1=1000、D2=2000），`monthStdBefore` 同读账本 → **同源**。
- 日 1 `[0,1000)` 档① = `1`；日 2 `[1000,3000)` 档② = `4`；`Σ daily = 5`。
- 月结：整月锁定 `std_in = 1000+2000 = 3000`；`[0,3000)` = `[0,1000)×1 + [1000,3000)×2 = 1 + 4 = 5 分`。
- **`Σ日 = 月 = 5`**，可加性恢复。

**回归断言（T-6.5-9 扩展）**：`Rate`/`RateMonthly`/`ExtraAmount` 的 std **恒取账本锁定值**（不现场重算）；反向断言：若 `Rate` 改为按当前价表重算 std，本例 `Σ日=5 ≠ 月=7` → 防 A-39 回归。

**落点**：§4.1.5（`UsageAgg.StdIn/StdOut`）、§4.6（`foldByModel` 累加锁定 std）、§6.5.1（`Rate` 消费 `mu.StdIn/StdOut`）、§6.5.5（`ExtraAmount` 同源）、§6.7（月结 = 锁定 std 求和而非重算换算）、§10.1 T-6.5-9。

### G-6：A-44「超额并入月账」的单位错配（±1000×）与逐模型基数漏收（第 7 轮）

**被证伪论断**：v1.6 §6.7 `CloseMonthly` 令 `amtAuthoritative += s.rating.ExtraAmount(...)`——(a) 单位上 `ExtraAmount` 返回**亚分**（千分之一分）却被并入 `Amount`（分）；(b) 基数上 §6.7 **逐模型**循环而 `ExtraAmount` 以**单模型**用量比**套餐级** `Plan.MonthlyTokens`。

**设定**（示意）：`Plan.MonthlyTokens = 1000`（标准 token 合计软上限）；顶档价 `InPer1K = OutPer1K`（此处以「**2 分 / std-token**」示意，等价于 2000 分/1k）；`charge` 套餐。
**数据**：双模型 M1、M2，各 `inUsed=400, outUsed=400`（合计 `inUsed+outUsed=800`）→ **合计 1600**，真实超额 **600**。

**① 逐模型基数（旧 A-43 接线，漏收）**：

- M1：`max(0, 800 − 1000) = 0`；M2：`max(0, 800 − 1000) = 0` → 超额费 **0**。
- **结论**：真实超额 600 标准 token 被**全额漏收**（`Σᵢ max(0,mᵢ−L) = 0 ≤ max(0, Σᵢmᵢ−L) = 600`）。

**② 单位错配（旧 `+= Amount`）**：

- `ExtraAmount` 返回**亚分**：`600 × 2 分/std-token = 1200 分 = 1,200,000 亚分`。
- 旧版 `amtAuthoritative += <亚分值>`（当作分）→ 月账金额被放大 **1000×**（应记 1200 分，实记 1,200,000 分）；且 `Amount += int64` 类型不匹配 → **不可编译**（A-44(a)）。

**③ 订正（v1.7，A-44②瀑布 + 单位统一）**：

- **基数**：套餐级合计 `overTotal = max(0, 1600 − 1000) = 600` > 0。
- **瀑布归属**（按 `inUsed+outUsed` 降序、并列 `modelKey` 升序）：M1、M2 同值 → M1 先吃额，`remaining=1000 → 200`；M2 `consumed=200`，`consumedIn = min(200,400) = 200` → `overIn = 400−200 = 200`、`overOut = 400−(200−200) = 400`；`200+400 = 600 = overTotal` ✅。
- **单位**：`ExtraAmount` 返回**亚分** `1,200,000`；由 `CloseMonthly` **单独一次** `roundAmount(overMu) = 1200 分`（超额账单）；月账 `amtAuthoritative = roundAmount(RateMu(月聚合))`（各取整一次，R-16）——**不把亚分当分相加**。

**回归断言（T-6.5-11 / T-6.5-12 / T-6.7-4）**：① 双模型各 800 时 `ExtraAmount > 0`（旧逐模型法得 0 → 防 A-44② 回归）；② 月账与超额账单**各自独立一次取整**、无一被放大 1000×（防 A-44① 回归）；③ `Σ over_i == overTotal` 且与模型下标顺序无关。反向断言：若改回**逐模型**基数，本例超额费归 0；若把 `ExtraAmount` 亚分值直接 `+= Amount`，月账放大 1000×。

**落点**：§4.1.4（`RateMu`/`ExtraAmount` 签名）、§4.6（`min64`）、§6.5.1（`RateMu` 唯一取整点）、§6.5.5（瀑布归因）、§6.7（超额单列 `kind=overage`）、§10.1 T-6.5-11/T-6.5-12、§10.4 T-6.7-4。
