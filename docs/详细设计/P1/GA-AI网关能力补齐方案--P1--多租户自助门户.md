# GA-AI 网关能力补齐方案 · P1-4 多租户自助门户

> **文档定位（本体与效力，2026-10-09）**
> 本文档为 **P1-4「多租户自助门户」的唯一口径源（本体）**：设计、接口、约束、决策（D-*）、变更记录、验收判据只能在本文件维护。评审报告、验证/测试报告、SOP 等均为**过程留证**，只引本文、不另立口径。
> **上游依据**：《GA-AI网关能力补齐方案》§5.4（功能清单/技术方案/工作量分解/风险与依赖/验收标准）；《GA-AI网关能力补齐--研发计划与进度跟踪》§2.2（P1 全景，P1-4 行：8-10 周）、§4（P1 详细进度，P1-4 行 M4/M5/M6）、§6.1（M4/M5/M6 里程碑）。
> **基准**：v1.3 评审基准 HEAD = `8050608`（2026-10-09）。代码事实分两类引用：(1) 已提交代码以该基准为准；(2) 工作区中 P1-3 在制改动（`auth.go` 内部角色扩展、`authz.go`）**不作为本方案事实依据**，仅在跨文档对齐处标注。

---

## 目录

- [1. 实现目标与范围](#1-实现目标与范围)
- [2. 现状基线与差距分析](#2-现状基线与差距分析)
- [3. 技术架构设计](#3-技术架构设计)
- [4. 核心功能模块划分](#4-核心功能模块划分)
- [5. 关键技术选型](#5-关键技术选型)
- [6. 接口规范定义](#6-接口规范定义)
- [7. 详细开发步骤](#7-详细开发步骤)
- [8. 与现有系统模块的集成方案](#8-与现有系统模块的集成方案)
- [9. 质量保障措施](#9-质量保障措施)
- [10. 资源需求评估](#10-资源需求评估)
- [11. 时间节点规划](#11-时间节点规划)
- [12. 风险评估与应对策略](#12-风险评估与应对策略)
- [13. 附录](#13-附录)

---

## 1. 实现目标与范围

### 1.1 建设目标

当前租户的**开通、配置、用量查询全部依赖管理后台人工操作**（管理面端点均要求 `admin`/`auditor`/`billing_reader` 内部令牌，见 `gateway/gateway-admin-service/auth.go`；`Higress` 控制台账号表由管理员在管理界面维护），无法承接规模化租户增长。P1-4 目标（可验证）：

| 编号 | 目标 | 可验证标准 |
|---|---|---|
| G-1 | 建立**租户自助注册与登录**（邮箱验证） | 新租户无需管理员介入即可完成注册、验证、登录并开始调用 |
| G-2 | 建立**免费版自动开通**（初始套餐 + 配额下发） | 注册验证通过即绑定 `free` 套餐并完成配额编译/下发/回读确认 |
| G-3 | 建立**租户自助 API Key 管理** | 创建/查看（脱敏）/吊销/轮换四类操作可用；明文仅创建时返回一次 |
| G-4 | 建立**租户自助用量与账单查询** | 按日/月查看用量、Token 消耗、账单明细（无金额口径以现网为准） |
| G-5 | 建立**受限策略配置**（白/黑名单、自定义类目动作） | 租户在授权范围内自助配置并落审计 |
| G-6 | 建立**模型接入配置**（可用模型选择 + 默认模型） | 租户可选择可用模型、设置默认模型 |
| G-7 | 建立**租户侧审计日志只读查询（脱敏）** | 仅可查本租户、仅摘要字段、无原文 |
| G-8 | 建立**套餐选择与升级**自助路径 | 租户可选择/升级套餐，配额随之生效（管理员确认或自助生效策略见 D-9） |
| G-9 | **租户数据严格隔离**（API 级） | 租户 A 无法访问租户 B 的任何数据（越权一律 403） |
| G-10 | **全量自助操作审计** | 所有自助写操作（注册/Key/策略/套餐）落审计链，只记指纹与元数据 |

**优先级依据（方案 §5.4）**：租户开通、配置、用量查询需人工操作，运营成本高、无法规模化；补齐自助门户后运营效率可提升 5-10 倍。

### 1.2 功能范围（对齐方案 §5.4.1，共 8 项）

| # | 功能 | 优先级 | 本期（M4-M6） | 本文档章节 |
|---|---|---|---|---|
| F1 | 租户自助注册/登录（邮箱/手机号注册，邮箱验证） | P1 | 交付（首期仅邮箱验证） | §3.2、§6.2、§7.2 |
| F2 | API Key 管理（创建/查看/吊销/轮换） | P1 | 交付 | §3.4、§6.3、§7.3 |
| F3 | 用量与账单查询（按日/月用量、账单明细） | P1 | 交付 | §6.4、§7.4 |
| F4 | 策略配置（白/黑名单、自定义类目动作，受限范围） | P1 | 交付（受限子集） | §3.5、§6.5、§7.5 |
| F5 | 模型接入配置（选择可用模型、配置默认模型） | P1 | 交付（选择与展示；租户级生效见 D-8/§8） | §6.6、§7.6 |
| F6 | 审计日志查询（只读，脱敏展示） | P1 | 交付 | §6.7、§7.7 |
| F7 | 套餐选择与升级 | P1 | 交付 | §6.8、§7.8 |
| F8 | 团队成员管理（邀请成员、角色分配 管理员/开发者/查看者） | **P2** | **不在本期**，仅结构预留 | §6.9、§1.3 |

### 1.3 不在范围内（明确排除）

- **团队成员管理（F8）**：方案 §5.4.1 标注为 **P2**，本期不做，仅在租户用户模型与角色枚举上预留（§6.9）。
- **计费金额口径**：`usage.go` 头注明确「金额列不出现（现仅计量无单价）」。本期账单页**沿用计量口径**，不引入单价/金额，除非 P0-3 已具备单价（见 §8）。
- **多因素认证/SSO/第三方 IdP**：本期复用现有 JWT 体系（方案 §5.4.2「复用现有 JWT 体系」），不做 MFA、OAuth2、SAML。
- **租户侧策略的全局生效**：全局 guardrail/output-guard 配置仍走 `change.go` 的 D8 高敏变更（submitter≠reviewer）。本期租户侧仅能写**租户级 overlay**（范围受限），全局配置不开放。
- **团队/组织层级与计费主体分离**：不做子租户、组织树、账单主体拆分。
- **新建独立前端工程**：前端承载于 higress-console fork 补丁集（C-7），不新建工程。

### 1.4 验收判据（总表，对齐方案 §5.4.5）

- [ ] **V-1** 租户可自助注册并获得免费版配额（`free` 套餐 + 配额下发确认）
- [ ] **V-2** API Key 创建/查看/吊销/轮换功能正常（明文仅展示一次）
- [ ] **V-3** 用量与账单查询：可查看日/月用量、Token 消耗、账单明细
- [ ] **V-4** 策略配置：租户可自助编辑白/黑名单、自定义类目动作（受限范围）并落审计。**本期验收口径 = 「存储可配置 + 落审计」**，**不含租户级生效**（生效依赖 §8 待补齐通道；目标能力未就绪时 `/policy/apply` 返回 503，不静默成功）
- [ ] **V-5** 审计日志查询：可查看本租户审计日志（脱敏展示）
- [ ] **V-6** 数据隔离：租户 A 无法访问租户 B 的任何数据（**API 级**验证，越权矩阵全绿）
- [ ] **V-7** 操作审计：所有自助操作有审计记录（动作清单见附录 D）
- [ ] **V-8** Fail-closed 验证：所有依赖数据源不可达时对应端点返回 503（不静默降级、不返回空数据）

---

## 2. 现状基线与差距分析

### 2.1 现有资产（代码事实）

| 资产 | 位置 | 事实（读取结论） |
|---|---|---|
| 管理门户业务服务 | `gateway/gateway-admin-service/main.go` | Go 单进程**双 listener**：管理面缺省 `:19095`（`/healthz` `/readyz` `/metrics` `/v1/adminext/*`）、broker 缺省 `:19096`（`/llm-broker/{provider}/**`，仅数据面可达）。服务不经外网直暴露（ClusterIP） |
| 鉴权中间件 | `gateway/gateway-admin-service/auth.go` | `authMiddleware` 校验 `Authorization: Bearer <HS256 JWT>`；`verifyInternalToken` 校验签名（经 `cryptoProvider.HMAC`，intl=HMAC-SHA256 / sm=HMAC-SM3）→ 过期 → `aud`/`iss`（若带）→ 角色白名单 → `sub` 非空；`requireReadAccess`（认证即可读）、`requireRole(w,r,"admin")`（写） |
| 角色与租户声明 | `auth.go` | 角色枚举 `admin` / `auditor` / `billing_reader`；`claims` 含 `Sub/Role/Iss/Aud/**Tenant**/IAT/EXP`。**`Tenant` 字段语义（P0-3 §7.4）：非 admin 会话仅可访问声明租户数据，跨租户 → 403（fail-closed）；admin 不受限** |
| 租户隔离实现 | `gateway/gateway-admin-service/billing_api.go` | `tenantAllowed(r, tenant)`：`c.Role==admin` → 放行；否则要求 `tenant != "" && c.Tenant != "" && c.Tenant == tenant`。`handleGetSubscription` 支持「自助：tenant 缺省取令牌内 tenant 声明」 |
| 计费域端点 | `billing_api.go`（`billingAPIBase="/v1/adminext/billing"`） | `GET/POST /plans`、`GET/POST /subscription`、`GET /bills`、`GET /bills/{id}[/verify|/export]`、`GET /ledger`、`POST /close-daily|/close-monthly|/freeze|/unfreeze|/verify-chain`、`POST /events`（HMAC）。默认关闭：`BILLING_ENABLED!=true` 不注册任何端点 |
| 套餐定义 | `gateway/gateway-admin-service/billing/plan_store.go` | `DefaultPlans()`：`free`（月 1,000,000 标准 token / 并发 5 / 缓存 exact / 超额 reject）、`basic`（10M/20）、`pro`（100M/100/semantic/charge）、`enterprise`（不限量/200）。`InitDefaultPlans` 幂等写入。**免费版即 `free` 套餐** |
| 用量与配额 | `gateway/gateway-admin-service/usage.go` | **代理模式**：不落业务数据（计量唯一真源 = tee-infer 审计链）；`GET /v1/adminext/usage`（auditor 可读，透传 `from/to/tenant`）、`POST /v1/adminext/usage/quota`（**admin**，落 G1 审计链 `quota_set`）、`GET /v1/adminext/metering/reconcile`。服务间头 `X-Admin-Token` 前端不可见；数据源未配置/不可达 → **503 fail-closed（不静默返回空）** |
| 安全中心与审计查询 | `gateway/gateway-admin-service/sec_center.go` | `GET /v1/adminext/sec-status`、`/audit-chain`（分页倒序）、`/audit-chain/verify`、`/audit-chain/export`（JSONL 附件 + 链尾摘要头）、`/audit-tee`（tee-infer 审计链代理，支持 `?tenant=` 与 `?verify=1`）。权限：已认证会话（admin/auditor 均可读） |
| 模型目录（只读） | `gateway/gateway-admin-service/model_catalog.go` | `GET /v1/adminext/models`：解析 ai-proxy CR（`spec.defaultConfig.providers`，**不存 token 值**）+ ai-route ConfigMap 目录（`data.data` 单行 JSON）；缺失返回 **200 空列表**。只读 |
| 高敏变更复核（D8） | `gateway/gateway-admin-service/change.go` | `changeAPIBase="/v1/adminext/changes"`；状态机 pending→executed/rejected/failed；**强制 submitter≠reviewer**；动作含 `guardrail_pii_mode`、`output_guard_mode/policy_reload/policy_activate/strategy/category_toggle`、`credential_rotate/delete`；状态流转落 G1 审计链 |
| 凭据托管 | `gateway/gateway-admin-service/broker_secret.go`、`broker.go` | `/v1/adminext/broker-providers`：Key **一律不回显**（POST 2xx 亦不回显），仅暴露不可逆 8 位指纹；文件 Secret（0600 原子写）；写要求 `admin` |
| 凭据只读投递 | `gateway/gateway-admin-service/credential_endpoint.go` | `/v1/adminext/credentials/{name}`；独立读取令牌 + 字段白名单；未配置 = 不注册（fail-closed） |
| 管理面审计链 | `gateway/gateway-admin-service/audit.go` | 自建独立 SHA-256 哈希链（与 tee-infer 链经 `request_id` 关联、互不共享），WORM 只追加；`adminAuditEvent` 含 `Actor/Action/Tenant/Target/KeyFingerprint/RequestID/Result`；**写失败 = fail-closed**（凭据/配额写拒绝 2xx）；只记指纹，绝不明文 |
| JWT 体系 | `gateway/auth-service/jwt.go` | 手写 HS256（RFC 7515，零依赖）；`Claims{Sub,Tenant,IAT,EXP}`；`verifyJWT` 强制 `exp` 必填（防永不过期伪造） |
| 网关数据面鉴权 | 见 `docs/API-参考.md` §2 | 网关 `:10000`：`X-Tenant-ID` 头 + `Authorization: Bearer <JWT>`（C-6，`require_auth` 时无/无效 401；有效 token 以 `tenant` 声明覆盖 `X-Tenant-ID` 防伪造）；`/infer` 内容拦截以 `403` 判定 |
| TEE 租户处置（SaaS） | `gateway/tee-infer-service/tenant_disposition.go`（`//go:build saas`） | `warning/throttled/suspended/terminated` 四态；`/config/tenant-disposition`（管理认证）；内存态，持久化由 D8 事件驱动。**私有化部署不编译** |
| 门户前端 | `fork-patches/higress-console/` | baseline `f8410432`（upstream **v2.2.4**）；补丁集 `higress-console-custom.patch`（新增 `AdminExt*` 控制器/前端页 `admin-ext/{accounts,changes,credentials,models,usage,vendors}`、`security-center`、`services/admin-ext-*.ts`）、`higress-console-billing.patch`（`pages/admin-ext/billing` + `services/admin-ext-billing.ts`）；`whitelist-upstream.txt` 限定只可改上游少数接入点。**补丁集管理，不入库** |
| Console 转发与会话 | `higress-console-custom.patch`（`AdminExtProxyController` / `AdminExtJwtSigner` / `AdminExtSessionService` / `AdminExtRole` / `AdminExtAccountController`） | `/v1/adminext/**` 通用转发**强制控制台登录会话**；转发时以共享密钥签发 HS256（`sub=会话登录名`，`role` 由账号表派生）；**当前 payload 不含 `tenant`**；角色枚举 `admin/auditor/billing_reader` |
| 端口/部署 | `docs/API-参考.md` §1、`docs/GA-部署指南.md` | 端口：网关 `:10000`、auth-service `:19200`、tee-infer `:19090`、admin-service 管理面 `:19095`、broker `:19096` |

### 2.2 差距分析

| 维度 | 现状 | 差距 | 本方案应对 |
|---|---|---|---|
| 租户自助注册 | 无（账号由管理员在控制台账号表维护；无公开注册端点，全仓无邮箱验证/验证码逻辑） | **零基础**：无租户注册表、无邮箱验证、无自助开通 | §3.2 注册/验证/登录三段式 + 租户注册表（§3.3 D-3） |
| 租户身份模型 | `claims.Tenant` 已存在（P0-3 引入），但**签发侧（console）不含 tenant**；无「租户用户」角色 | 租户用户可以登录但无法携带租户上下文；角色枚举缺 `tenant_user` | §3.3 D-2：扩展 `AdminExtJwtSigner` payload 增 `tenant`；角色枚举增 `tenant_user` |
| 数据隔离 | `tenantAllowed` 仅覆盖 billing 读端点（plans/bills/ledger/subscription） | 未覆盖用量/审计/策略/Key 等新端点；无「默认带 tenant_id 过滤」统一中间件 | §3.4 统一 `requireTenantScope`（默认按令牌 `tenant` 过滤，越权 403） |
| API Key 管理 | 无租户级 Key 概念（网关用 C-6 JWT；厂商 Key 由 broker 托管、不回显） | 无创建/查看/吊销/轮换；无「仅展示一次」 | §6.3 新增租户 Key 端点，复用「不回显 + 指纹」既有安全范式 |
| 用量/账单查询 | 已有 `billing/*` 读端点 + `usage` 代理（内部令牌） | 端点仅面向内部角色；账单页在管理面 `admin-ext/billing` | 复用后端读端点，新增租户侧聚合视图与前端租户页（§6.4） |
| 策略配置 | 全局配置走 D8 高敏变更；tee-infer 有全局 guardrail/output-guard | **无租户级策略 overlay 与生效端点** | §3.5 租户级 overlay 存储 + 受限生效路径（依赖登记，见 D-8/§8） |
| 模型接入配置 | `/v1/adminext/models` 只读目录（全局 ai-route） | 无租户级「可用模型/默认模型」选择与生效 | §6.6 租户选择存储 + 展示；生效依赖 P0-1 路由租户限域（D-8） |
| 审计查询（租户侧） | `/audit-tee` 支持 `?tenant=` 但面向内部会话 | 无租户侧脱敏摘要视图；无「只查本租户」强制 | §6.7 租户审计摘要视图（字段白名单） |
| 套餐选择/升级 | `/billing/subscription` 自助读实现；`POST` 绑定为 **admin** | 租户无自助升级路径 | §6.8 租户侧升级请求（管理员确认或自助生效，D-9） |
| 团队成员管理 | 无 | （P2） | §6.9 预留，不实现 |
| 前端承载 | 控制台 fork 强制会话（`/v1/adminext/**`） | 注册页需**免会话**公开入口 | §3.3 D-7：console 新增公开转发控制器（`/adminext-tenant/**`） |

### 2.3 设计硬约束（不可违背）

> 以下约束源自上游方案与项目既有硬规约，任何实现不得绕过。

| 编号 | 约束 | 依据 |
|---|---|---|
| C-1 | **所有租户侧 API 默认带 `tenant_id` 过滤**；过滤器以**令牌内 `tenant` 声明**为准，请求体/查询参数不得作为越权依据 | 方案 §5.4.2「所有 API 默认带 tenant_id 过滤」 |
| C-2 | **租户 A 访问租户 B 一律 403（fail-closed）**；不得存在「缺省租户/空租户」的隐式放行 | 方案 §5.4.2、§5.4.4 |
| C-3 | **审计日志脱敏**：租户侧仅展示摘要字段，不展示原文、不展示可反推原文的摘要（如 `payload_hash` 全量） | 方案 §5.4.2 |
| C-4 | **API Key 明文仅展示一次**；服务端不以明文/可逆形式落盘；列表仅展示不可逆指纹前缀 | 方案 §5.4.2；对齐 `broker_secret.go` 既有范式 |
| C-5 | **所有自助写操作落审计链**（注册、验证、Key CRUD、策略、套餐、登录失败等安全事件） | 方案 §5.4.2「所有自助操作记录审计日志」 |
| C-6 | **管理端超管可接管**：`admin` 可跨租户读取/处置任一租户（客户支持），且接管行为本身留痕 | 方案 §5.4.2 |
| C-7 | **门户/控制台 fork 定制以可重建补丁集管理，不入库**；新增自定义点须登记 `whitelist-upstream.txt` | 项目文档规约（`fork-patches/higress-console/`） |
| C-8 | **复用现有 JWT 体系**（`auth-service/jwt.go` HS256 风格）；不新引入会话/令牌栈 | 方案 §5.4.2 |
| C-9 | **计量/账单唯一真源 = tee-infer 审计链 + billing store**；门户**只读代理**，不新建第二套计量数据 | `usage.go` 头注、`billing_api.go` |
| C-10 | **金额列不出现**（现仅计量无单价）；配额/套餐变更沿用 M6「受理 → 回读确认」与 fail-closed | `usage.go` 头注、`billing_api.go` `ConfirmQuotaApplied` |
| C-11 | 自助注册须**防滥用（规则已定档）**：(1) 邮箱验证（32 字节 CSPRNG 令牌，详见 §3.2）；(2) **同一邮箱限绑定 1 个租户**（按小写归一化邮箱判重）；(3) 同一真实客户端 IP 每日限 5 个注册（IP 取信规则见 §3.2）；(4) 异常注册模式（同域名批量、同段 IP、高失败率）触发告警并可临时收紧阈值；(5) **免费版（`free` 套餐）永久有效、配额定义不随时间缩减**，月度配额按月重置；免费版防滥用由配额上限本身承担，不设有效期 | 方案 §5.4.4 |
| C-12 | 新端点若数据源未配置，一律 **503 fail-closed**，不静默返回空数据（延续 `usage.go`/`sec_center.go` 语义） | 项目既有语义 |
| C-13 | **`tenant_user` 不得进入管理面内部角色白名单**：`auth.go` 的 `validRole`/`verifyInternalToken` 保持仅面向**内部角色**（当前已提交口径为 `admin`/`auditor`/`billing_reader`；随 P1-3 三权分立合并后将扩展为 system_admin/sec_admin/audit_admin 等内部角色——无论如何演进，`tenant_user` 永不入内）。**内部端点自然门禁**：租户令牌经 `verifyInternalToken` 必因 `validRole` 失败被拒（401），故既有内部读端点（`/audit-chain`、`/audit-tee`、`/usage`、`/models`、`/billing/*`、`/changes`）无须为租户另写判断，只要继续挂在 `authMiddleware` 子树即天然拒绝租户会话；禁止把内部端点改挂 `TenantAuthMiddleware` | 代码事实：`auth.go` `validRole`/`verifyInternalToken` |
| C-14 | **租户账号与 Console 会话层单一真源（同步方式已定档）**：Go tenant store 为租户账号**唯一真源**（D-3），Console **不复制租户账号表**。Console 新增 `AdminExtTenantDirectory` 组件：`resolveRole`/`saveSession` 在原生账号表未命中时，经内部端点 `GET /v1/adminext/tenant-directory/lookup?email=<小写归一化邮箱>`（Console→Go，挂 `authMiddleware`，仅 Console 可调用）反查 Go tenant store；命中即建立携带 `tenant`、`role=tenant_user` 的会话。**禁止**落入「未命中 = 原生 admin 兜底」分支与原生 admin 会话回落；目录端点不可达时登录失败（fail-closed，不得放行） | 代码事实：`higress-console-custom.patch` `resolveRole`（未命中 → `AdminExtRole.ADMIN`）、`saveSession`（账号表未命中 → 委托原生会话） |
| C-15 | **租户侧代理端点强制注入令牌 tenant**：用量、审计 tee 代理等租户侧端点**一律丢弃客户端传入的 `tenant` 参数**，以令牌内 `tenant` 声明强制替换后再转发至上游。admin 超管访问租户端点时须显式传入 `target_tenant` 查询参数（端点统一以 `target_tenant` 命名，不以 `tenant` 命名）且落审计留痕（C-6），无参数则拒绝（403） | 纵深防御：消除参数篡改越权路径（对齐 Q2-01） |
| C-16 | **路由层强制双隔离（子树门禁双策略已定档）**：(1) `/v1/adminext/tenant/**` 租户端点在 mux 子树层级统一挂 `TenantAuthMiddleware`（单端点不得零散挂接），该中间件支持**两类凭证**：①租户令牌（`role=tenant_user` 且 `tenant` 非空，走租户签名密钥校验）；②内部 admin 令牌（经 `verifyInternalToken` 校验，必须显式携带 `target_tenant`，强制审计 `actor/target_tenant`，无参数 → 403）；其余凭证一律拒绝。(2) `/v1/adminext/` 下非 `tenant/` 的内部端点统一由 `authMiddleware` 包裹。两类 mux 构造函数分离（`newTenantMux()` / `buildAdminMux()`），禁止交叉注册，纳入代码评审门禁与静态检查 | 防止实现期挂错中间件导致越权（对齐 Q2-02；解决 v1.2「admin 被子树门禁拦截、C-6 不可达」矛盾） |
| C-17 | **前端安全基线（CSRF 模式已定档）**：(1) CSRF 采用**双提交 cookie 模式**——Console 建立会话时生成 32 字节 CSPRNG token（base64url），写入 cookie `otpmask_csrf`（`Secure` + `SameSite=Strict`，**不设 HttpOnly** 供前端读取）；前端在所有写请求（POST/PUT/DELETE）经 `X-CSRF-Token` 头回传，Console 校验 cookie 值与头值常量时间相等，不匹配/缺失 → 403；公开端点（注册/验证/登录/重置）经验证码 + 频率限制防护，登录型 CSRF 由 `SameSite=Strict` 兜底；(2) Console 会话 cookie `admext1.*` 设置 `SameSite=Strict` + `HttpOnly` + `Secure`（部署须全链路 HTTPS）；(3) 注册/登录页增加图形验证码防自动化提交；(4) 前端不得持久化存储 API Key 明文 | Web 安全基础项（对齐 Q2-04/Q2-12） |
| C-18 | **管理面单副本部署约束（部署清单变更已列入开发文件清单）**：因 tenant store（SQLite 多写者）与限流计数均为进程内实现，`gateway-admin-service` 生产部署**必须为单副本**；水平扩展须先迁移存储至共享数据库（P2 规划）。违反本约束 = 数据不一致 + 风控绕过。**现状冲突（开发期必须修复，落点见附录 B）**：`deploy/k8s/gateway-admin-service.yaml` 当前 `replicas: 2`、Helm `deploy/helm/gateway-admin-service/values.yaml` 当前 `replicaCount: 2`，M9 任务须改为 1 并同步 PDB（单副本下保证驱逐即不可用而非静默双副本） | 部署硬约束（对齐 Q2-08/Q-09） |

---

## 3. 技术架构设计

### 3.1 总体架构

```
                    ┌──────────────────────────────────────────────────────────┐
   浏览器           │  自助门户前端（higress-console fork 补丁集，C-7）           │
  （租户用户）───▶   │  · 公开页：注册 / 邮箱验证 / 登录（免会话，/tenant/**）      │
                    │  · 私有页：总览 / API Key / 用量账单 / 策略 / 模型 / 审计     │
                    │  · 复用 admin 组件库（表格/表单/图表）与 admin-ext services  │
                    └───────────────┬───────────────────────┬──────────────────┘
                                    │ 免会话公开转发          │ 会话内转发（自签 JWT）
                     /adminext-tenant/**                    /v1/adminext/**
                                    ▼                        ▼
                    ┌──────────────────────────────────────────────────────────┐
                    │  Console 后端（Java, fork 补丁）                            │
                    │  · TenantPublicController（新增，公开）：注册/验证/登录     │
                    │  · AdminExtProxyController（既有）：/v1/adminext/** 通用转发 │
                    │  · AdminExtJwtSigner（改）：payload 增 tenant（D-2）        │
                    │  · 会话：admext1.* 无状态签名令牌（既有）                   │
                    └───────────────┬───────────────────────┬──────────────────┘
                                    │ Bearer HS256（服务间）   │ Bearer HS256（含 tenant/role）
                                    ▼                        ▼
                    ┌──────────────────────────────────────────────────────────┐
                    │  gateway-admin-service（Go，:19095 管理面 listener）        │
                    │  · TenantAuthMiddleware（新增）：校验 tenant 会话令牌        │
                    │  · tenant_api.go：注册/验证/登录/Key/策略/模型/审计/套餐      │
                    │  · tenant_store.go：租户注册表/用户表/Key 指纹/策略overlay   │
                    │  · 复用：billing_api / usage / sec_center / model_catalog   │
                    │  · requireTenantScope：统一租户过滤（默认 tenant_id）        │
                    └───────┬───────────────┬───────────────┬──────────────────┘
                            │ 绑定套餐       │ 读计量/账单    │ 读模型目录/策略
                            ▼               ▼               ▼
                    ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐
                    │ billing      │ │ tee-infer    │ │ ai-proxy CR / ai-route│
                    │ (SQLite)     │ │ (:19090)     │ │ ConfigMap 目录        │
                    │ plans/bills  │ │ 审计链/用量   │ │ (全局，只读)          │
                    └──────────────┘ └──────────────┘ └──────────────────────┘
```

### 3.2 自助注册与登录链路（数据流）

**注册状态机（4 状态，v1.3 定档）**：

> v1.2 稿曾标「5 状态」但状态表仅 4 状态。v1.3 定档为 **4 状态**：邮箱验证为瞬时令牌校验、不产生独立持久态，`pending` 即涵盖「等待验证」；不设 `verifying` 中间态（极简优先，避免无意义状态）。

| 状态 | 进入条件 | 下一状态 | 失败回退与处理 |
|---|---|---|---|
| `pending` | POST /register 落库成功 | ——（等待邮箱验证） | 注册落库失败 → 500（对前端统一错误，不泄露内部细节） |
| `pending` | POST /verify 令牌校验通过 | `subscription_pending` | 令牌非法/过期/已使用/邮箱不匹配 → 400（状态保持 pending；失败计数见下） |
| `subscription_pending` | billing `Bind` 成功（subscription 写入） | `quota_pending` | `Bind` 失败 → tenant store 状态**回退至 `pending`** ＋ 重新生成验证令牌并发送「请重新验证」邮件 ＋ 告警（两个独立 SQLite 无分布式事务：以 tenant store 为状态真源，billing 侧残留由补偿任务扫描修复，见下） |
| `quota_pending` | 配额下发 ＋ `ConfirmQuotaApplied` 回读成功 | `active` | 配额编译/下发/回读失败 → **保持 `quota_pending`** ＋ 告警；自动重试任务每 10 分钟重放一次（指数退避、上限 6 次），仍失败转人工 SOP。**对齐 M6「回读失败仅告警、不回滚」**（套餐已绑定），但任何场景下不得对外宣称 `active` |
| `active` | —— | —— | ——（终态；冻结/终止等 SaaS 处置另见 tenant_disposition） |

> **billing 关闭时的 verify 语义（v1.3 补全）**：`subscription_pending` 的唯一动作是 billing `Bind`，要求 `BILLING_ENABLED=true`。若计费域关闭，`POST /v1/tenant/verify` 直接返回 **503**（C-12，计费域为注册链路必需依赖），不进入回退循环（否则用户每次验证都回退 pending 且永远无法完成）。
>
> **补偿任务（双 store 一致性兜底）**：后台每 30 分钟扫描一次——(1) billing 中存在 subscription 但 tenant store 无对应租户/状态早于 `subscription_pending` → 标记孤儿记录并告警，按 SOP 人工核销；(2) tenant store 中 `quota_pending` 超过 1 小时 → 触发配额重放；(3) `subscription_pending` 超过 24 小时未推进 → 回退 pending 并重新发验证邮件。扫描结果落日志，不自动删除 billing 数据（防误删）。

**关键参数（v1.3 定档，均可经 §10.3 环境变量覆盖，括号内为缺省值）**：

| 项 | 缺省值 | 说明 |
|---|---|---|
| 验证/重置令牌长度 | 32 字节 CSPRNG | base64url 承载；SHA-256 哈希存储（带全局 pepper，pepper 经 Secret 注入） |
| 邮箱验证令牌 TTL | 24h | 一次性；令牌与小写归一化邮箱强绑定（防交叉使用） |
| 令牌校验失败计数 | 同一邮箱 10 次 / 24h | 超限后该邮箱验证端点返回 429（防令牌爆破；计数承载于 tenant store） |
| 注册 IP 限制 | 同 IP 5 次 / 自然日 | **IP 取信规则**：Go 仅信任 Console 注入的 `X-Forwarded-For` 首段（Console 与 Go 之间为受控内网，Go 不直接采信外网请求）；Console 须在公开转发时附加真实客户端 IP，缺失时回退为 Console Pod IP 并告警 |
| 密码策略 | 长度 ≥10，须含大写/小写/数字/符号四类中至少三类 | 与 console `AdminExtUserRecord.hashPassword` 同强度口径；bcrypt cost=12（对齐既有） |
| 登录失败锁定 | 同邮箱连续 5 次失败锁定 15 分钟 | Go 侧实现（常量时间密码比较），语义对齐 `AdminExtLoginGuard`；锁定期间登录返回 423 |
| 邮件链接基址 | 无缺省（必填） | 公开 Console 外部基址，形如 `https://console.example.com`；验证链接 `/tenant/verify?email=&token=`，邮件 HTML 模板在补丁中交付 |

**链路步骤**：

1. **注册（防枚举已定档：统一 202）**：前端公开页 → `POST /adminext-tenant/register`（Console 公开 controller，**免会话、带图形验证码**）→ 转发 `POST /v1/tenant/register`（Go）→ 校验邮箱格式/密码强度/协议勾选 → 频率限制与异常检测（C-11）→ **不论邮箱是否已存在均返回 `202 Accepted`**：邮箱不存在则写入租户注册表（`status=pending`）→ 生成验证令牌（参数见上表：32 字节 CSPRNG、SHA-256+pepper 哈希存储、一次性、与邮箱绑定、TTL 24h、失败计数）→ 发送验证邮件；邮箱已存在则发送「该邮箱已注册，如非本人操作请忽略」邮件。前端统一提示「如邮箱有效，您将收到验证邮件」。
2. **邮箱验证**：用户点击链接/输入验证码 → `POST /adminext-tenant/verify` → `POST /v1/tenant/verify` → 校验令牌哈希、有效期、一次性与邮箱绑定（验证后令牌立即失效）→ 租户置 `subscription_pending` → **绑定 `free` 套餐**（billing `Bind(Subscription{TenantID, PlanID:"free", EffectiveAt:now, ExpiresAt:0, BoundBy:"self-register"})`）→ 置 `quota_pending` → `QuotaCompiler.Compile(tenant, freePlan)` → `QuotaApplier.ApplyQuota` ＋ `ConfirmQuotaApplied`（M6 回读确认，C-10）→ 成功置 `active` → 落审计链 `tenant_register` / `plan_bind` → 返回租户状态。**失败语义**：见状态机各行；billing 关闭 → 503。**任何 `quota_pending` 及以前阶段不得对外宣称 `active`**（G-2/V-1）。
3. **登录/会话建立（跨服务归属，唯一口径）**：`POST /adminext-tenant/login` → `POST /v1/tenant/login` → Go 侧校验密码哈希（常量时间比较）＋ 登录失败锁定（参数见上表）→ Go **只返回校验结果与租户元数据**（`tenant_id/role/status`，**不签发任何会话令牌**）→ Console 侧 `AdminExtSessionService` 校验通过后，经 **`AdminExtTenantDirectory` 反查 Go tenant store（C-14，lookup 端点）确认 tenant/role** → 建立 `admext1.*` 会话（cookie 由 Java 生成，见 `higress-console-custom.patch`）＋ 同时下发 CSRF cookie `otpmask_csrf`（C-17）。**Go 不下发 Console cookie**；目录反查失败 → 登录失败（fail-closed）。
4. **后续自助调用**：前端私有页 → `/v1/adminext/tenant/**`（经 `AdminExtProxyController` 会话转发，自签 JWT 携带 `tenant`/`role`，写请求带 `X-CSRF-Token`，C-17）→ Go 侧子树门禁 `TenantAuthMiddleware` 双策略校验（C-16）→ `requireTenantScope` 强制租户过滤与代理参数注入（C-1/C-15）→ 命中新增租户端点或既有 `billing_api`/`usage`/`sec_center`/`model_catalog` 能力。
5. **审计**：所有写操作经 `adminAuditChain.append` 落链（C-5，动作清单见附录 D）；落链失败 fail-closed（对齐 `usage.go handleQuota`）。

### 3.3 关键设计决策（D-*）

| 编号 | 决策 | 选项 | 结论与理由 |
|---|---|---|---|
| **D-1** | **后端归属** | (a) 新建独立「门户服务」；(b) 扩展 `gateway-admin-service` | **选 (b)**。`gateway-admin-service` 已具备 RBAC、租户声明、billing store、G1 审计链、模型目录、用量代理、双 listener（`main.go`），新建服务会重复鉴权/审计/存储三套基建；方案 §5.4.2 亦明确「扩展现有 gateway-admin-service」 |
| **D-2** | **租户身份与角色** | (a) 复用 `admin/auditor`；(b) 新增 `tenant_user` 角色 + 令牌强制 `tenant` 声明 | **选 (b)**。现有角色面向内部运维；租户需最小权限且必须携带 `tenant`。扩展 console `AdminExtRole` 与 `AdminExtJwtSigner` payload 增 `tenant`（当前签发不含，见 §2.1）。**`tenant_user` 仅存在于租户专用校验链（`TenantAuthMiddleware`），永不并入 `auth.go validRole` 内部角色白名单（C-13）**；内部端点挂 `authMiddleware` 子树即天然拒绝租户令牌，无须另写判断。Console `resolveRole` 经 C-14 目录反查对租户账号返回 `tenant_user`（禁止落入未命中 `admin` 兜底）。**不改动既有内部角色语义** |
| **D-3** | **租户数据存储** | (a) 复用 Java 账号表；(b) 复用 billing SQLite store；(c) 新建独立 tenant store | **选 (c)**。租户注册表/用户表/Key 指纹/策略 overlay 与计费域语义不同（计费域有哈希链与冻结状态机，混入会污染口径与迁移）；新建独立 SQLite 文件（同 driver，零新依赖），套餐绑定**经 billing 接口调用**而非跨库事务（沿用 M6「受理→回读确认」） |
| **D-4** | **API Key 存储形态** | (a) 可逆加密存储；(b) 单向指纹存储 | **选 (b)**。单向 SHA-256 指纹**无解密面**，安全性优于可逆加密；满足「仅展示一次」。完全对齐 `broker_secret.go`「不回显 + 8 位指纹」既有范式（C-4） |
| **D-5** | **API Key 形态** | (a) 不透明随机串 + 网关新增 key 校验；(b) 签发长效 HS256 JWT | **选 (b)**。网关 `/infer` 现有鉴权即 JWT（插件 `jwt.go`，`docs/API-参考.md` §2），复用零改造；服务端仅存 `jti` 与指纹用于列表/吊销。**密钥域与签发通道（v1.3 定档）**：数据面插件经 **CPS（cryptop sidecar）KeyRef 验签，缺省句柄 = `otpmask/jwt/v1`**（插件 `cryptoclient.go`，可被插件配置 `jwt_secret_ref` 覆盖）。故租户 API Key **必须由 auth-service 用 CPS 中同一 KeyRef 的密钥签发**：auth-service 改造为启动时从 CPS 获取该 KeyRef 密钥（CPS 未预置/不可达 = fail-closed 拒启动），不再使用自带 flag 随机密钥；admin-service 经 auth-service **新增内部签发端点**（见 §6.3）请求签发，不自行签名。`Claims` 同步扩展 `jti`/`role`（现 auth-service `Claims{Sub,Tenant,IAT,EXP}`，插件侧 `jwtClaims` 同构；jti 为吊销标识）。**TTL**：缺省 90 天可配（env 覆盖），短 TTL 是吊销实时性兜底——「长效」与「短 TTL」以此取值平衡，`expires_at` 强制回传 |
| **D-6** | **前端承载** | (a) 独立前端工程；(b) higress-console fork 补丁集 | **选 (b)**。方案 §5.4.2「复用 admin 组件库」、C-7「补丁集管理不入库」；fork 已含账号/安全中心/账单页与 `admin-ext-*.ts` services，租户视图可复用同构页面 |
| **D-7** | **注册公开入口归属** | (a) 门户直连 Go 服务；(b) Console 新增公开转发 controller | **选 (b)**。既有 `/v1/adminext/**` 转发被 `ApiStandardizationAspect` 强制登录会话，注册/验证必须免会话；在 console 新增 `/adminext-tenant/**` 公开 controller 转发，保持「前端唯一入口 = console」，不额外暴露 Go 服务到外网 |
| **D-8** | **策略/模型的租户级生效** | (a) 直接复用全局 D8 变更；(b) 租户级 overlay + 受限生效端点 | **选 (b)**。租户**不得**触碰全局 guardrail/output-guard（否则越权改他人策略）。本期落地「租户级 overlay 存储 + 受限生效」，其**网关/tee-infer 侧按租户限域生效**为新增依赖（P0-1 路由 / tee-infer 租户策略），在 §8 明确登记为**待补齐依赖**，不伪造端点 |
| **D-9** | **套餐升级生效方式** | (a) 租户自助即时生效；(b) 生成待管理员确认的升级请求 | **M4/M5 选 (b)，M6 视风控评估再放开 (a)**。付费/降级涉及计费口径与风控，默认「租户发起 → 管理员确认」（复用 `handleBindSubscription` 的 admin 路径）；免费档内的套餐展示与查询完全自助 |
| **D-10** | **租户审计视图脱敏** | (a) 直接透传 `/audit-tee`；(b) 字段白名单摘要视图 | **选 (b)**。新建租户审计视图，仅返回 `timestamp/action/result/model/tokens_in/out/cache_hit/is_retry/request_id` 等摘要，**剔除 `payload_hash` 等可关联字段**，且强制 `tenant` 过滤（C-1/C-3） |
| **D-11** | **越权防护落点** | (a) 各 handler 各自判断；(b) 统一中间件 + handler 二次校验 | **选 (b)**。新增 `requireTenantScope` 中间件做**默认拒绝**（无 `tenant` 声明即 403），handler 内对显式传入的 `tenant` 参数做二次相等校验（双保险），与 `billing_api.tenantAllowed` 保持同一语义便于回归 |

### 3.4 租户隔离与数据边界（三层）

| 层 | 机制 | 实现点 | 说明 |
|---|---|---|---|
| L1 令牌层 | **租户端点**（`/v1/adminext/tenant/**`）经子树门禁 `TenantAuthMiddleware` 双策略校验：①租户令牌须含非空 `tenant` 且 `role=tenant_user`；②内部 admin 令牌（无 tenant）须显式携带 `target_tenant`，否则 403。两类之外的凭证（无令牌、内部非 admin 角色、未知角色）一律拒绝 | `TenantAuthMiddleware`（新增，C-16） | 防「无租户」隐式放行（C-2）。**限定于租户端点**；其他内部角色不经此层访问租户端点 |
| L2 中间件层 | `requireTenantScope(w,r,requested)`：以令牌 `tenant` 为准，**租户侧代理端点强制替换** `tenant` 参数为令牌值（不允许透传客户端传入值，C-15）；非代理端点校验 `requested != "" && requested != token.tenant` → 403。**admin 路径**：子树门禁已验明 admin 身份，`requireTenantScope` 以 `target_tenant` 为操作租户，**强制落审计**（`actor=admin, target_tenant=...`）；无 `target_tenant` 在 L1 即 403（防全量枚举） | 复用 `billing_api.tenantAllowed` 语义并泛化 + 代理层注入 | 默认带 `tenant_id` 过滤（C-1）；纵深防御消除参数篡改（C-15） |
| L3 存储层 | **租户域表**（`tenant_store.go` 的租户表/用户表/Key 表/策略 overlay/模型配置）所有查询/写入 SQL 恒带 `WHERE tenant_id = ?`；写入恒以解析后的操作租户（租户令牌或 admin target_tenant）赋值。**范围限定于租户域表**（billing 的 `plans` 全局表、`subscriptions` 多租户表由既有查询参数过滤，不适用本层强断言） | `tenant_store.go`、billing 查询 | 防止应用层遗漏造成越权（纵深防御） |
| 例外 | `admin` 超管跨租户（客户支持）：L1 验明、L2 强制审计 `actor/target_tenant`、L3 以目标租户赋值 | `TenantAuthMiddleware` admin 分支 + `requireTenantScope` | C-6 |

---

### 3.5 tenant store 数据模型（v1.3 新增，DDL 级）

> 本节为 D-3 独立 SQLite tenant store 的完整数据模型，SQLite 方言。库文件打开时统一 `PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;`。写并发由 C-18 单副本约束保证。所有表均含租户归属（除 tenants 本身），查询恒带 `tenant_id`（L3 存储层）。

**表总览（7 张表）**：

| 表 | 用途 | 与租户关系 |
|---|---|---|
| `tenants` | 租户注册表（状态机真源） | —— |
| `tenant_users` | 租户用户（本期 1 租户 1 用户；F8 团队成员 P2 复用） | 多 : 1 |
| `mail_action_tokens` | 邮箱验证/密码重置令牌（purpose 区分） | 多 : 1 |
| `api_keys` | Key 元数据、jti、指纹、吊销态 | 多 : 1 |
| `policy_overlays` | 策略 overlay 当前态（每租户 1 行，版本化） | 1 : 1 |
| `model_configs` | 可用模型/默认模型（每租户 1 行） | 1 : 1 |
| `register_rate` | 注册频率计数（邮箱/IP，按日滚动） | —— |

**① tenants（租户注册表）**

| 列 | 类型 | 约束 | 说明 |
|---|---|---|---|
| tenant_id | TEXT | PK | 格式 `t-YYYYMMDD-NNNN`（NNNN 当日序号，单副本下原子分配） |
| tenant_name | TEXT | NOT NULL，长度 2-64（rune） | 租户显示名 |
| status | TEXT | NOT NULL，CHECK ∈ pending/subscription_pending/quota_pending/active | 状态机（§3.2） |
| email_norm | TEXT | NOT NULL，UNIQUE | 小写+trim 归一化邮箱；**同邮箱限 1 租户**判重列 |
| created_at / updated_at | INTEGER | NOT NULL | Unix 秒 |

索引：`CREATE INDEX idx_tenants_status ON tenants(status);`

**② tenant_users（租户用户表）**

| 列 | 类型 | 约束 | 说明 |
|---|---|---|---|
| user_id | TEXT | PK | `u-` + 12 位随机 |
| tenant_id | TEXT | NOT NULL，REFERENCES tenants(tenant_id) | 归属租户 |
| email_norm | TEXT | NOT NULL | 与 tenants.email_norm 一致（owner） |
| password_hash | TEXT | NOT NULL | bcrypt cost=12；禁止存明文 |
| tenant_role | TEXT | NOT NULL DEFAULT 'tenant_admin'，CHECK ∈ tenant_admin/tenant_developer/tenant_viewer | **P2 字段**：本期恒 owner=tenant_admin，角色粒度 F8 启用；本期不据此放行额外权限 |
| status | TEXT | NOT NULL DEFAULT 'active' | P2 预留 disabled |
| created_at / updated_at | INTEGER | NOT NULL | |

约束：`CREATE UNIQUE INDEX uq_user_tenant_email ON tenant_users(tenant_id, email_norm);`

**③ mail_action_tokens（邮箱类动作令牌，统一表）**

| 列 | 类型 | 约束 | 说明 |
|---|---|---|---|
| id | INTEGER | PK AUTOINCREMENT | |
| tenant_id | TEXT | NOT NULL | 注册阶段允许尚在 pending 的租户 |
| email_norm | TEXT | NOT NULL | **邮箱绑定**：校验时必须与请求邮箱相等（防交叉使用） |
| purpose | TEXT | NOT NULL，CHECK ∈ register/reset | register TTL 24h；reset TTL 1h（独立令牌，不互用） |
| token_hash | TEXT | NOT NULL | SHA-256(token ‖ pepper) hex；pepper 经 Secret 注入，全局不轮转（轮转作 P2） |
| consumed | INTEGER | NOT NULL DEFAULT 0 | **一次性**：校验成功即置 1 |
| fail_count | INTEGER | NOT NULL DEFAULT 0 | 同邮箱同 purpose 达 10/24h → 429 |
| expires_at | INTEGER | NOT NULL | Unix 秒 |
| created_at | INTEGER | NOT NULL | |

索引：`CREATE INDEX idx_tokens_email_purpose ON mail_action_tokens(email_norm, purpose);`

**④ api_keys（API Key 元数据）**

| 列 | 类型 | 约束 | 说明 |
|---|---|---|---|
| key_id | TEXT | PK | `k-` + 6 位随机 hex |
| tenant_id | TEXT | NOT NULL，REFERENCES tenants(tenant_id) | 归属 |
| name | TEXT | NOT NULL，长度 1-64 | 同租户 active Key 名称唯一（见部分索引） |
| jti | TEXT | NOT NULL，UNIQUE | JWT 内 jti（24 位随机），吊销标识 |
| fingerprint | TEXT | NOT NULL | SHA-256(完整 Key 字符串) hex；列表展示前 8 位 |
| status | TEXT | NOT NULL DEFAULT 'active'，CHECK ∈ active/revoked | |
| created_by | TEXT | NOT NULL | user_id |
| created_at / last_used_at / revoked_at | INTEGER | last_used_at/ revoked_at 可空 | last_used_at 由数据面回写（P2：经审计链异步聚合） |
| expires_at | INTEGER | NOT NULL | 签发时间 ＋ TTL（缺省 90 天） |

索引：`CREATE UNIQUE INDEX uq_active_key_name ON api_keys(tenant_id, name) WHERE status='active';`
吊销数据面消费：不另建表——数据面经内部端点（§6.3 note）按 `revoked_at` 增量拉取 jti，实时消费未就绪前以短 TTL 兜底（§8 依赖）。

**⑤ policy_overlays（策略 overlay，每租户一行）**

| 列 | 类型 | 约束 | 说明 |
|---|---|---|---|
| tenant_id | TEXT | PK，REFERENCES tenants(tenant_id) | |
| version | INTEGER | NOT NULL DEFAULT 1 | 乐观锁：PUT 须带 If-Match=version，冲突 409 |
| whitelist / blacklist | TEXT | NOT NULL DEFAULT '{"entries":[]}' | JSON：`entries: [{id, kind ∈ literal/regex, value, created_at}]` |
| category_actions | TEXT | NOT NULL DEFAULT '{}' | JSON：`{<内置类目>: <block/mask/allow>}`；类目键须在内置集合 |
| updated_at | INTEGER | NOT NULL | |

条目约束（服务端强制，防 DoS）：单条目 value 长度 ≤256 字节；白/黑名单各 ≤ 套餐上限（缺省 free/basic 50 条、pro 200、enterprise 500，经 env 可覆盖）；`regex` 条目服务端必须编译通过（Go RE2，限 100ms 编译/求值预算，拒绝回溯型灾难性模式——RE2 无线性回溯风险仍设长度上限）。**仅存条目数变化入审计，不存具体词**（附录 D）。

**⑥ model_configs（模型配置，每租户一行）**

| 列 | 类型 | 约束 | 说明 |
|---|---|---|---|
| tenant_id | TEXT | PK，REFERENCES tenants(tenant_id) | |
| allowed_models | TEXT | NOT NULL DEFAULT '[]' | JSON 模型 ID 数组；**授权交集**：⊆ 全局目录（/v1/adminext/models）∩ 当前套餐 `Plan.ModelScopes`（空 = 全部） |
| default_model | TEXT | 可空 | 非空时必须 ∈ allowed_models，否则 400 |
| version | INTEGER | NOT NULL DEFAULT 1 | 乐观锁 |
| updated_at | INTEGER | NOT NULL | |

**⑦ register_rate（注册频率计数）**

| 列 | 类型 | 约束 | 说明 |
|---|---|---|---|
| bucket_key | TEXT | PK | `ip:<date>` 或 `email:<date>` |
| count | INTEGER | NOT NULL | IP 桶 >5 / email 桶（判重另由 tenants UNIQUE 兜底）→ 429 |
| updated_at | INTEGER | NOT NULL | 自然日滚动，过期桶惰性清理 |

---

## 4. 核心功能模块划分

> **编号说明**：本章 `M1`-`M9` 为**实现模块**编号，与 §11/上游计划中的 `M4/M5/M6`（**里程碑**，第 4/5/6 月）**语义不同**，勿混用。§7 的步骤小标题沿用模块编号（如「M1/M2」）。

| 模块 | 职责 | 落点（文件/目录） | 交付类型 |
|---|---|---|---|
| M1 租户身份与会话 | 注册表/用户表、密码哈希、邮箱验证令牌、`tenant_user` 角色、租户 JWT 签发/校验 | `gateway/gateway-admin-service/tenant_store.go`、`tenant_auth.go`（新增） | Go 代码 |
| M2 自助注册/登录 API | 注册、验证、登录、登出、密码重置（受限）；邮箱发送适配、频率限制 | `gateway/gateway-admin-service/tenant_api.go`（新增） | Go 代码 |
| M3 API Key 管理 | 创建（明文仅一次）/列表（指纹）/吊销/轮换；长效 JWT 签发；`jti` 吊销表 | `gateway/gateway-admin-service/tenant_key.go`（新增） | Go 代码 |
| M4 用量/账单聚合 | 复用 `usage.go`/`billing_api.go` 读端点，新增租户聚合视图（日/月、Token、账单明细） | `tenant_api.go` + `billing_api.go`（复用） | Go 代码 |
| M5 策略与模型配置 | 租户级 overlay（白/黑名单、类目动作）、可用模型/默认模型选择 | `gateway/gateway-admin-service/tenant_policy.go`（新增） | Go 代码 |
| M6 租户审计查询 | 摘要视图 + `tenant` 强制过滤（D-10） | `tenant_audit.go`（新增） | Go 代码 |
| M7 套餐自助 | 套餐列表/当前订阅/升级请求；`free` 自动绑定 | `tenant_api.go` + `billing_api.go`（复用） | Go 代码 |
| M8 Console fork 定制 | 公开转发 controller（`/adminext-tenant/**`）、`AdminExtJwtSigner` 增 `tenant`、`AdminExtRole` 增 `tenant_user`、租户前端页与 services | `fork-patches/higress-console/tenant-portal.patch` | 前端/后端补丁 |
| M9 路由与配置接线 | `main.go` 注册新端点、`TenantAuthMiddleware` 挂载、env 配置项 | `gateway/gateway-admin-service/main.go`（改）、`config.go`（改） | Go 代码 |

---

## 5. 关键技术选型

### 5.1 选型对照

| 维度 | 选型 | 依据/版本 | 理由 |
|---|---|---|---|
| 后端语言/框架 | Go（net/http，标准库 `ServeMux`） | 与 `gateway-admin-service` 同栈 | 复用既有路由/中间件/审计（D-1） |
| 认证 | HS256 JWT（复用 `cryptoProvider.HMAC`；对齐 `auth-service/jwt.go`） | 既有 | C-8；不新增令牌栈 |
| 角色 | `admin` / `auditor` / `billing_reader` / **`tenant_user`**（新增，**仅租户专用校验链**，不入 `auth.go validRole` 全局白名单，C-13） | console `AdminExtRole` + `TenantAuthMiddleware` 扩展 | 最小权限（D-2） |
| 存储 | SQLite（与 `billing` 同 driver，独立文件） | `gateway-admin-service/billing` 已用 SQLite | 零新依赖；隔离计费口径（D-3） |
| 密码存储 | 加盐哈希（对齐 console `AdminExtUserRecord.hashPassword` 语义） | 既有 | 一致的安全基线 |
| Key 存储 | SHA-256 指纹 + `jti` | 对齐 `broker_secret.go` | 无解密面（D-4） |
| 邮件发送 | SMTP（新增 env：host/port/user/pass/from） | 新增适配层 | 邮箱验证必需；无 SMTP 时端点 503 fail-closed（C-12） |
| 前端 | higress-console fork 补丁集（React/umd，复用 admin-ext 组件） | 既有 fork | C-7；复用组件库（D-6） |
| 审计 | 既有 `adminAuditChain`（G1，SHA-256 链，fail-closed） | 既有 | C-5；不新建审计栈 |
| 限流/风控 | 复用既有 QPS 限流 + 注册频率限制（内存滑动窗口，对齐 `AdminExtLoginGuard`） | 既有范式 | C-11。**部署约束**：内存滑动窗口为**进程内**实现，管理面多副本部署时按副本计数、可被绕过；本期须明确管理面为**单副本**部署，或改用共享存储（billing SQLite 或 Redis）承载计数（在 §10.2 标注） |

### 5.2 被否方案与理由

| 方案 | 否决理由 |
|---|---|
| 新建独立「门户后端服务」 | 与 `gateway-admin-service` 的鉴权/审计/存储/RBAC 三重复制，运维成本高（D-1） |
| 复用 billing store 存租户/Key | 计费域含哈希链与冻结状态机，混入非计费数据污染口径与迁移（D-3） |
| API Key 可逆加密存储 | 存在解密面与密钥管理负担；单向指纹即满足「仅展示一次」且更安全（D-4） |
| 不透明随机 Key + 网关新增 key-auth | 网关现有鉴权为 JWT，新增 key 校验链路属额外改造面（D-5） |
| 直接复用 `/audit-tee` 透传 | 含 `payload_hash` 等字段，不满足租户脱敏（C-3，D-10） |
| 租户直接发全局 D8 策略变更 | 跨越租户边界、可改他人策略，违反隔离硬约束（C-2，D-8） |
| 新建独立前端工程 | 违反 C-7（补丁集管理不入库）与「复用 admin 组件库」（D-6） |
| 自建会话/令牌体系 | 违反 C-8（复用现有 JWT） |

---

## 6. 接口规范定义

> 统一约定：管理面 listener `:19095`；JSON 请求/响应；错误遵循既有 503 fail-closed（C-12）与 4xx 语义（`docs/API-参考.md` §7）。`/v1/tenant/**` 为**公开**前缀（注册/验证/登录/密码重置，不校验会话身份，强制验证码与频率限制）；`/v1/adminext/tenant/**` 为**租户会话**前缀（子树门禁双策略，C-16）；`/v1/adminext/tenant-directory/**` 为 **Console 内部**前缀（authMiddleware）。所有写操作落审计链（C-5，动作清单见附录 D）。

### 6.1 通用约定

| 项 | 说明 |
|---|---|
| 认证（公开） | `/v1/tenant/*`：无需令牌；请求经 Console `/adminext-tenant/**` 公开转发（D-7），图形验证码必校 |
| 认证（租户会话） | `/v1/adminext/tenant/*`：`Authorization: Bearer <HS256 JWT>`；①租户令牌 `claims{role=tenant_user, tenant=...}` 或 ②内部 admin 令牌 ＋ `target_tenant`；`TenantAuthMiddleware` 双策略校验（C-16） |
| CSRF 防护（已定档） | **双提交 cookie 模式**：cookie `otpmask_csrf`（非 HttpOnly）与请求头 `X-CSRF-Token` 常量时间比对；所有租户写操作（POST/PUT/DELETE）必校，缺失/不符 → 403；会话 cookie `admext1.*`：`SameSite=Strict` + `HttpOnly` + `Secure`（C-17） |
| 租户过滤 | 令牌 `tenant` 为唯一权威；代理端点**强制替换**客户端 `tenant` 参数（C-15）；admin 路径以 `target_tenant` 为准；非代理端点校验参数与令牌相等（L2） |
| 服务间令牌（三类，勿混用） | (1) Console → Go：`Authorization: Bearer <HS256 JWT>`，共享密钥 `AdminExtConfig.getJwtSecret()`（前端不可见，`AdminExtProxyController` 自签，payload 含 tenant/role）；(2) Go → tee-infer：头 `X-Admin-Token`（`usage.go`/`sec_center.go`）；(3) 租户会话：Console 会话层 `admext1.*` cookie（无状态 HMAC，非 JWT）。**不存在 `X-Svc-Token` 头**（旧稿误称，已更正） |
| X-Request-ID | 长度 ≤64 字节，字符集限 `[a-zA-Z0-9_-]`；服务端校验不通过则生成新 ID 覆盖；Console 代理层须透传（§7.8 M8 step2） |
| 幂等/并发 | 写操作采用「唯一约束 ＋ 冲突 409」；overlay/配置类写带版本乐观锁；套餐绑定对齐 M6「受理 → 回读确认 ≤60s」 |
| 脱敏 | 响应不含原文、不含 Key 明文、不含金额（C-3/C-10） |

### 6.2 注册 / 登录（F1）

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| POST | `/v1/tenant/register` | 公开（验证码必校） | 请求 `{email, password, tenant_name, agree_terms, captcha_id, captcha_code}`；**防枚举定档：统一返回 `202 Accepted`** `{accepted:true}`，无论邮箱是否已存在（已存在 → 发送「已注册」提示邮件，不写新数据）；频率超限 → 429；验证码失败 → 400 |
| POST | `/v1/tenant/verify` | 公开 | 请求 `{email, token}`；校验令牌（哈希/TTL 24h/一次性/邮箱绑定）；成功且配额回读确认通过 → `active` ＋ 绑定 `free`；**配额未确认 → `status=quota_pending`（非 active）**；**billing 域关闭 → 503**；返回 `{tenant_id, plan_id:"free", status}`；令牌错误/过期 → 400；失败计数超限 → 429 |
| POST | `/v1/tenant/login` | 公开（验证码必校） | 请求 `{email, password, captcha_id, captcha_code}`；**成功返回 `{tenant_id, role:"tenant_user", status, expires_at}`（不返回令牌——Console 校验通过后自行建立 `admext1.*` 会话，C-14）**；凭据错误 → 401；锁定中 → 423；非 active 租户 → 403（quota_pending 提示联系支持） |
| POST | `/v1/adminext/tenant/logout` | tenant_user | Console 侧清除 `admext1.*` 与 `otpmask_csrf`；Go 落审计 `tenant_logout`；返回 200 |
| POST | `/v1/tenant/password-reset` | 公开 | 请求 `{email, captcha_id, captcha_code}`；**始终 202**（不泄露存在性）；重置令牌（purpose=reset，TTL ≤1h，一次性，独立于 register 令牌）；同 email 限 1 次/15min（防邮件轰炸）→ 超限仍 202 不发信 |
| POST | `/v1/tenant/password-reset/confirm` | 公开 | 请求 `{email, token, new_password}`；校验重置令牌（同 §3.5 规则）→ 按密码策略设置新密码 → 令牌置 consumed → **吊销该用户全部既有会话**（会话吊销机制见下注）→ 落审计 `password_reset`；令牌错误/过期 → 400；新密码不符策略 → 400 |

**注册请求要点**：

```json
{ "email": "a@corp.com", "password": "P@ssw0rd!", "tenant_name": "示例科技",
  "agree_terms": true, "captcha_id": "cap-8f31", "captcha_code": "7K2D" }
```

字段约束（服务端强制）：`email` RFC5322 校验后 trim+lowercase，≤254 字符；`password` 长度 10-128，须含大小写字母＋数字＋符号四类中至少三类；`tenant_name` rune 长度 2-64，去除控制字符；`agree_terms` 必须为 true，否则 400。

**注册与验证响应要点**：

```json
// POST /v1/tenant/register 202（无论邮箱是否存在，响应体恒定）
{ "accepted": true }

// POST /v1/tenant/verify 200
{ "tenant_id": "t-20261009-0001", "status": "active", "plan_id": "free",
  "quota": { "monthly_tokens": 1000000, "concurrency": 5, "applied": true } }
```

> **验证失败语义**：令牌过期/错误 → `400`；邮件未配置（SMTP 缺失）→ `503`（C-12，不静默成功）；**配额下发/回读确认未通过 → 租户 `status=quota_pending` 并告警（不返回 `active`）**。
>
> **会话归属（唯一口径）**：Console cookie（`admext1.*`）**只由 Console `AdminExtSessionService` 生成**；Go `/v1/tenant/login` 只做凭据校验与结果返回，**不下发 Console cookie**。租户账号须可按 C-14 在 Console 会话层解析（`tenant` + `role=tenant_user`），其单一真源与同步方式见 §8 依赖登记。

### 6.3 API Key 管理（F2）

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| POST | `/v1/adminext/tenant/keys` | tenant_user | 创建；请求 `{name, expire_days?}`；**响应含明文 Key 一次**；服务端仅存 `jti` + SHA-256 指纹 + 元数据 |
| GET | `/v1/adminext/tenant/keys` | tenant_user | 列表（仅 `id/name/fingerprint` 前 8 位/`created_at`/`last_used_at?`/`status`）；**无明文** |
| POST | `/v1/adminext/tenant/keys/{id}/rotate` | tenant_user | 轮换：旧 Key 置 `revoked`，返回**新明文一次** |
| DELETE | `/v1/adminext/tenant/keys/{id}` | tenant_user | 吊销（幂等）；返回 `{id, status:"revoked"}` |

**创建响应（明文仅此一次）**：

```json
{ "id": "k-3f9c2a", "name": "prod-agent", "fingerprint": "9d4a1b7f",
  "api_key": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9....",   // 仅此一次返回
  "expires_at": 1790000000, "note": "请立即保存；服务端不保存明文" }
```

> **Key 形态（D-5）**：以租户身份签发的长效 HS256 JWT（`claims{sub:tenant_user_id, tenant, role:"api", jti, iat, exp}`）。网关 `/infer` 复用现有 C-6 校验链（插件 `jwt.go` 仅解析 Sub/Tenant/IAT/EXP，`role/jti` 为扩展字段不影响验签）。吊销 = `api_keys.status=revoked`；数据面经内部吊销拉取端点（§6.11）增量消费 `jti`，实时消费未就绪前以短 TTL 兜底（§8）。
>
> **签发通道（v1.3 定档，CPS KeyRef）**：签发密钥**不本地配置**，auth-service 启动时从 CPS 读取 KeyRef **`otpmask/jwt/v1`**（不可达/取密钥失败 = fail-closed 拒绝启动）；admin-service 创建 Key 时调用 auth-service **新增内部签发端点**（契约见 §6.11），严禁用 `ADMIN_SVC_JWT_SECRET` 自签（数据面验签密钥与之不同，自签必然验签失败）。`Claims` 扩展 `jti/role` 须与 auth-service/jwt.go 同步改造。
>
> **TTL**：缺省 90 天（env 可配，上限 365 天）；吊销实时性不足的窗口期由 TTL 收敛；`expires_at` 明确回传。
>
> **前端明文处理规范（C-17）**：创建后明文仅在模态框内显示、提供一键复制按钮、**不存入任何持久化存储**（localStorage/sessionStorage/IndexedDB 均禁止）、关闭模态框即从内存清除、前端日志/错误上报过滤 Key 明文（正则匹配脱敏）。列表页仅展示指纹，绝不明文。

### 6.4 用量与账单查询（F3）

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/v1/adminext/tenant/usage` | tenant_user | 日/月聚合：`from/to/granularity(day|month)`；透传 tee-infer 用量（**强制本租户**）；无金额（C-10） |
| GET | `/v1/adminext/tenant/bills` | tenant_user | 账单列表（`kind/from/to/limit`），复用 `handleBills` 查询但租户固定 |
| GET | `/v1/adminext/tenant/bills/{id}` | tenant_user | 账单明细；**归属校验失败 → 404**（不泄露他租户账单存在性） |
| GET | `/v1/adminext/tenant/bills/{id}/export` | tenant_user | 明细导出（`text/csv`） |

**用量响应要点**：

```json
{ "tenant": "t-20261009-0001", "granularity": "day",
  "series": [ { "date": "2026-10-07", "tokens_in": 12000, "tokens_out": 8000, "requests": 42 } ],
  "plan": { "plan_id": "free", "monthly_tokens": 1000000, "used_tokens": 120000 } }
```

**账单 CSV 导出（公式注入防护，C-17）**：

- 响应头：`Content-Type: text/csv; charset=utf-8`、`Content-Disposition: attachment; filename="bill-<id>.csv"`、`X-Content-Type-Options: nosniff`；文件首写 UTF-8 BOM（`\uFEFF`，防 Excel 误判编码）。
- **逐单元格消毒**：字段值首字符为 `=`、`+`、`-`、`@`、Tab、CR 之一时，前缀单引号 `'` 转义；字段内双引号双写、整体以双引号包裹；CR/LF 统一替换为空格。所有列均服务端固定（不接受客户端指定列名/排序表达式），从源头杜绝注入。

> **查询约束**：`from/to` 窗口须设上限（缺省 ≤ 92 天），`series` 与 `bills` 列表须分页（`limit`+`offset`/游标，缺省 ≤ 500）；数据源（tee-infer `/usage`）不可达 → 503（C-12）。**租户身份注入（C-15）**：租户侧用量端点**强制丢弃**客户端传入的 `tenant` 参数，以令牌内 `tenant` 声明替换后再转发 tee-infer，从根本上消除参数篡改越权风险（不依赖上游 tee-infer 的 `tenant` 过滤，纵深防御）。

### 6.5 策略配置（F4，受限范围）

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/v1/adminext/tenant/policy` | tenant_user | 本租户 overlay：白名单/黑名单/类目动作（只读视图 + 可编辑范围标注） |
| PUT | `/v1/adminext/tenant/policy` | tenant_user | 更新 overlay；**仅允许受限子集**（见下）；非法类目/超范围 → 400；落审计 |
| POST | `/v1/adminext/tenant/policy/apply` | tenant_user | 提交生效；若目标需租户限域生效（D-8）而网关/tee 侧能力未就绪 → `503` + 明确原因（不静默成功） |

**受限范围（对齐方案 §5.4.1「受限范围」）**：

| 项 | 允许 | 不允许 |
|---|---|---|
| 白名单（放行词/模式） | 增删本租户自定义项（上限受套餐约束） | 修改全局词库、全局策略版本 |
| 黑名单（拦截词/模式） | 增删本租户自定义项 | 删除平台内置类目/内置字典 |
| 类目动作 | 在内置类目集合内选择动作（如 `block`/`mask`） | 新增类目、修改全局 `guardrail_pii_mode` 等全局动作 |

**GET 响应 / PUT 请求体（同一结构）**：

```json
{ "version": 3,
  "whitelist": { "entries": [
      { "id": "e-1", "kind": "literal", "value": "内部项目代号", "created_at": 1791500000 } ] },
  "blacklist": { "entries": [
      { "id": "e-2", "kind": "regex", "value": "AKIA[0-9A-Z]{16}", "created_at": 1791500100 } ] },
  "category_actions": { "pii_id_card": "mask", "pii_phone": "mask", "violence": "block" } }
```

**PUT 请求要点**：必须携带头 `If-Match: <version>`（服务端当前版本不一致 → 409 `{error:"version_conflict", current:n}`）；全量替换语义（未传入的列表清空，故前端须先 GET 回显再提交）；服务端逐项执行 §3.5 条目约束（长度/条数/regex 编译），任一不合法整单 400、不落库；返回更新后完整结构（含新 version）。`POST /policy/apply` 请求体 `{}`，响应 `{applied:true, version:n}`；生效链路未就绪 → 503 `{error:"tenant_scope_unavailable"}`。

> **生效边界（如实登记）**：全局 `guardrail_pii_mode`/`output_guard_*` 仍走 `change.go` D8（submitter≠reviewer）。租户 overlay 的**租户级生效**依赖 tee-infer/P0-1 提供按租户限域能力（§8 依赖表，D-8）。

### 6.6 模型接入配置（F5）

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/v1/adminext/tenant/models` | tenant_user | 可用模型列表（源自 `/v1/adminext/models` 目录，按套餐/授权过滤展示） |
| GET | `/v1/adminext/tenant/models/config` | tenant_user | 当前配置：`allowed_models[]` + `default_model` |
| PUT | `/v1/adminext/tenant/models/config` | tenant_user | 设置可用模型集合与默认模型；默认模型必须在允许集合内 → 否则 400；落审计 |

**GET `/tenant/models` 响应**：

```json
{ "models": [
  { "id": "gpt-4o-mini", "name": "GPT-4o mini", "enabled_in_catalog": true,
    "allowed_by_plan": true, "selected": true },
  { "id": "deepseek-chat", "name": "DeepSeek Chat", "enabled_in_catalog": true,
    "allowed_by_plan": false, "selected": false } ] }
```

**GET `/tenant/models/config` 响应 / PUT 请求体**：

```json
{ "version": 2, "allowed_models": ["gpt-4o-mini", "deepseek-chat"],
  "default_model": "gpt-4o-mini" }
```

PUT 校验：`If-Match` 版本乐观锁（同 §6.5）；`allowed_models` 去重，每个 ID 须存在于全局目录且 ∈ 套餐 ModelScopes（交集外的 ID → 400 并回带被拒 ID 列表）；`default_model` 为空（清除）或必须 ∈ 提交后的 allowed_models；空 allowed_models 允许（表示暂不可调用），但 default_model 须同时清空。审计动作 `model_config_update`，记录变更后的 allowed_models 与 default_model（模型 ID 非敏感数据）。

> **生效边界（如实登记）**：模型**选择与展示**本期交付；**租户级路由限域**（仅允许所选模型）依赖 P0-1 路由的租户维度能力（§8）。

### 6.7 审计日志查询（F6，只读脱敏）

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/v1/adminext/tenant/audit` | tenant_user | 本租户审计摘要（`from/to/action/result/limit/offset`）；**强制租户过滤**（D-10）；仅摘要字段 |

**摘要字段白名单**：`timestamp`、`action`、`result`、`model`、`tokens_in/out`、`cache_hit`、`is_retry`、`request_id`。

**响应要点**：

```json
{ "total": 128, "limit": 50, "offset": 0,
  "items": [ { "timestamp": 1791500200, "action": "infer", "result": "success",
      "model": "gpt-4o-mini", "tokens_in": 312, "tokens_out": 180,
      "cache_hit": false, "is_retry": false, "request_id": "req-7f2a..." } ] }
```

查询参数约束：`from/to` 缺省近 30 天、最大 92 天；`action` 须在附录 D 枚举内（含 infer），否则 400；`result ∈ success/denied/error`；`limit` 缺省 50、上限 200。SQL 强制 `WHERE tenant_id = ?`（D-10），任何来源的请求都不接受覆盖。

**显式剔除**：`payload_hash`、任何可关联原文的摘要、他租户标识、内部链路细节（C-3）。

### 6.8 套餐选择与升级（F7）

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/v1/adminext/tenant/plans` | tenant_user | 套餐列表（`free/basic/pro/enterprise`，读 `billing/plan_store.go`） |
| GET | `/v1/adminext/tenant/subscription` | tenant_user | 当前订阅（复用 `handleGetSubscription` 自助语义） |
| POST | `/v1/adminext/tenant/subscription/upgrade` | tenant_user | 发起升级/降级**请求**（M4/M5 需管理员确认，D-9）；返回 `{request_id, status:"pending"}` |

> **前置依赖**：本组端点读 `billing/plan_store.go`，**要求 `BILLING_ENABLED=true`**（否则 `billing` 域不注册，frozen 语义同 `billing_api.go`）。若计费域关闭，租户套餐端点一律 `503`（C-12），不返回空列表（与 §9.1「`BILLING_ENABLED=false` 时租户计费端点不注册/503」口径一致）。
>
> **套餐升降级计费规则（D-9 补充）**：(1) **升级**：管理员确认后立即生效，当月配额按剩余天数折算（计量口径：剩余月配额 = 新月配额 × 剩余天数 / 当月总天数）；(2) **降级**：次月 1 日生效（避免当月配额纠纷），当月仍按原套餐执行；(3) 升级/降级记录入审计链与账单明细（动作 `plan_upgrade` / `plan_downgrade`）；(4) 免费版不可降级（已是最低档）。

### 6.9 团队成员管理与租户注销（F8/P2，仅预留）

> **团队成员管理（F8，P2）**：本期不实现。预留：租户用户表支持 `tenant_role ∈ {tenant_admin, tenant_developer, tenant_viewer}`；`tenant_user` 为会话基角色，`tenant_role` 决定租户内权限粒度。接口草案：`GET/POST /v1/adminext/tenant/members`、`PUT/DELETE /v1/adminext/tenant/members/{id}`（**P2 交付**，本文件不作为本期验收口径）。
>
> **租户注销（P2 预留）**：本期不实现完整注销流程。预留设计：(1) 租户可主动发起注销，进入 30 天宽限期（可恢复）；(2) 宽限期内租户状态为 `deleting`，API 调用仍可用但所有写操作受限；(3) 宽限期满后删除租户业务数据（Key/策略/用户表），但保留审计摘要（用于合规追溯）与账单记录；(4) 注销操作需二次确认（密码 + 邮箱验证码），落审计 `tenant_delete`。**数据保留策略**：审计摘要保留 ≥ 180 天（合规要求），账单保留 ≥ 5 年（财务要求）。

### 6.10 错误码（复用管理面既有语义）

| HTTP | 场景 |
|---|---|
| 400 | 参数非法（邮箱格式、密码强度、令牌格式、默认模型不在允许集合、策略超范围） |
| 401 | 未认证 / 登录失败（凭据错误） |
| 403 | 越权：令牌缺 `tenant` 声明、跨租户访问（C-2）；非 tenant_user 角色访问租户端点 |
| 404 | 目标资源不存在或**不属于本租户**（不泄露存在性，如他租户账单） |
| 409 | 唯一性冲突（邮箱已注册、Key 名称冲突） |
| 423 | 账号锁定（登录失败锁定，对齐 `AdminExtLoginGuard`） |
| 429 | 频率超限（注册/登录/验证码） |
| 503 | 数据源未配置或不可达（SMTP/tee-infer/billing/策略生效端点未就绪）——**不静默降级**（C-12） |
| 500 | 代理上游 5xx，或审计落链失败（写操作 fail-closed） |

### 6.11 内部配套端点（Console / 数据面使用，非租户直连）

> 本组端点注册在内部 listener，经 `authMiddleware`（Console → Go 服务间令牌）或内部网络隔离保护；租户浏览器不可直达。

| 方法 | 路径 | 调用方 | 契约 |
|---|---|---|---|
| GET | `/v1/adminext/tenant-directory/lookup` | Console | 请求 `?email=<归一化邮箱>`；命中 → 200 `{tenant_id, status, tenant_role:"tenant_user"}`；未命中 → 404（**禁止 Console 兜底 admin**，C-14）；目录不可达 → 503，登录失败（不放行） |
| POST | `http://<auth-service>:19200/v1/issue`（**扩展**） | admin-service | 现有 `{tenant}` 扩展为 `{tenant, sub, role, jti, ttl_seconds?}`；响应 `{token}`；密钥取自 CPS `otpmask/jwt/v1`；auth-service 校验调用方内部令牌；CPS 不可达时服务已 fail-closed 不启动 |
| GET | `/v1/adminext/key-revocations` | 数据面插件/同步器 | 请求 `?since=<unix秒>`；响应 `{revoked:[{jti, revoked_at}], server_time:n}`；只返回 revoked 态 jti；数据面据此增量更新本地吊销集（轮询间隔 ≤60s，§8）；未对接前 Key TTL 作为兜底窗口 |
| GET | `/v1/adminext/captcha` | Console | 图形验证码签发：响应 `{captcha_id, image:"data:image/png;base64,..."}`；答案存内存（TTL 5min，一次性，单副本约束内有效）；同 IP 限 30 次/h |

---

## 7. 详细开发步骤

> 依赖顺序：租户存储/鉴权 → 注册登录 → Key → 用量账单 → 策略/模型 → 审计 → 套餐 → Console 补丁 → 安全与风控。每步含**可验证点**。严格工程序（项目硬规约）：需求梳理 → 方案设计 → 文件清单 → 编码 → 静态检查（`go build`/`go vet`）→ 单测 → 分批提交。

### 7.1 前置（W0）

> v1.3 已将原二选一决策**全部定档**，W0 不再含待决项，只做「配置/环境核验」并留存核对记录。

1. 冻结本文件 §6 接口契约与 §3.3 决策（本文件即口径）；建立 §10.3 环境变量基线。
2. 核验 SMTP 可用性与发件人配置（缺失则注册/验证/重置链路 503，不可上线）；核验 `BILLING_ENABLED=true` 且 4 档套餐已初始化（`InitDefaultPlans`）。
3. 核验 Console fork 可重建补丁（`baseline.txt=f8410432`，`scripts/fork-patch-check.ps1`）。
4. **核验 Key 签发通道**：CPS 中 KeyRef `otpmask/jwt/v1` 存在且 auth-service 可读（不可达须 fail-closed 拒启动）；auth-service `/v1/issue` 扩展契约（§6.11）与调用方鉴权就位。
5. **核验账号目录**：`tenant-directory/lookup` 端点可达；Console 侧已去除未命中 admin 兜底（C-14），联调验证未命中 = 登录失败。
6. **核验越权拒绝点**（C-13）：内部端点 `validRole` 白名单不含 `tenant_user`，租户令牌经自然门禁 401；形成逐端点回归清单。
7. **核验双 mux 隔离**（C-16）：`newTenantMux()` 子树与 `buildAdminMux()` 分离；代码评审门禁规则（租户端点只允许挂在租户 mux）。
8. **核验 CSRF 双提交 cookie**（C-17）：`otpmask_csrf` 注入/校验中间件、`admext1.*` 安全属性（Strict/HttpOnly/Secure）；图形验证码端点联调。
9. **核验算法口径**：租户 JWT 恒 HS256（与 P1-5 一致），CRYPTO_PROFILE=sm 不改变租户 JWT 算法；SM3 仅用于内部令牌链。
10. **核验部署单副本约束**（C-18）：部署文件调整任务已纳入 M9 文件清单；上线前 k8s/Helm 必须为 1 副本。

**验证**：契约冻结记录 + 环境核对表逐项签字（SMTP/billing/fork/CPS KeyRef/账号目录/越权拒绝点/双 mux/CSRF/算法口径/副本数），任一项不通过不进入 M1。

### 7.2 M1/M2 租户存储与注册登录（W1-W3，核心）

1. `tenant_store.go`：按 §3.5 建立 7 张表（tenants/tenant_users/mail_action_tokens/api_keys/policy_overlays/model_configs/register_rate），密码 bcrypt cost=12，令牌哈希存储。
2. `tenant_auth.go`：`TenantAuthMiddleware`（双策略：租户令牌 role=tenant_user＋tenant 非空 / admin 令牌＋target_tenant）、`requireTenantScope`、CSRF 双提交 cookie 校验、图形验证码校验。
3. `tenant_api.go`：`register`（统一 202 防枚举）/`verify`（billing 关闭 503）/`login`（不返令牌）/`logout`/`password-reset`/`password-reset/confirm`；验证通过绑定 `free` 并复用 `QuotaCompiler`/`QuotaApplier`+`ConfirmQuotaApplied`；30 分钟补偿任务。
4. `main.go`/`config.go`：双 mux 挂载（`newTenantMux()` 挂 `/v1/tenant/*`＋`/v1/adminext/tenant/*`，`buildAdminMux()` 不变）；注册内部配套端点（§6.11）；新增 env（见 §10.3）。

**验证**：单测覆盖注册（202 恒定响应）/验证（4 状态）/登录/锁定/限流/令牌一次性/邮箱绑定；端到端：注册→收信→验证→登录（Console 建会话）→带租户调用；**审计链含 `tenant_register`/`plan_bind`**（V-1/V-7）。

### 7.3 M3 API Key（W3-W4）

1. `tenant_key.go`：创建（签发长效 JWT + 存 `jti`/指纹）、列表、轮换、吊销。
2. 落审计（只记指纹，对齐 `broker_secret.go`）。

**验证**：创建响应含明文一次、列表无明文、吊销后失效、轮换后旧 Key 失效（V-2）。

### 7.4 M4 用量与账单（W4-W5）

1. `tenant_api.go`：聚合视图（日/月、Token、账单明细），复用 `usage.go` 与 `billing_api.go` 查询，恒定租户。
2. 账单归属校验失败返回 404（不泄露存在性）。

**验证**：与 tee-infer/`billing` 口头径一致（V-3）；跨租户账单访问 → 404/403（V-6）。

### 7.5 M5 策略与模型（W5-W6）

1. `tenant_policy.go`：overlay CRUD（受限范围校验）+ 模型选择；落审计。
2. `POST /policy/apply`：目标能力未就绪 → 503（不伪造生效）。

**验证**：白/黑名单与类目动作可配且超范围被拒（V-4）；默认模型不在允许集合被拒（§6.6）。

### 7.6 M6 租户审计视图（W6）

1. `tenant_audit.go`：摘要视图 + 字段白名单 + 强制租户过滤（D-10）。

**验证**：仅返回本租户摘要、无 `payload_hash`（V-5）；跨租户查询为空/403（V-6）。

### 7.7 M7 套餐自助（W6-W7）

1. `plans/subscription/upgrade` 端点；升级请求生成待确认单（D-9）。
2. 管理员确认复用 `handleBindSubscription`（含回读确认与审计）。

**验证**：套餐列表/当前订阅可查；升级请求落审计并可被管理员处理。

### 7.8 M8 Console fork 定制（W5-W8，与后端并行）

1. `AdminExtJwtSigner` payload 增 `tenant`（新增 `sign(..., tenant, ...)` 重载）；`AdminExtRole` 增 `tenant_user`；登录时 **`AdminExtUserStore.resolveRole` 经 `tenant-directory/lookup` 反查 Go tenant store**，命中返回 `tenant_user`＋tenant（**禁止未命中兜底 admin，禁止 Console 复制账号表**，C-14）。
2. 新增公开 `TenantPublicController`（`/adminext-tenant/**`，免会话转发）；透传 `X-Request-ID`（现 `AdminExtProxyController` 仅注入 `Authorization`+`Content-Type`，须补齐）；接入图形验证码（注册/登录页必带）。
3. 会话与 CSRF：登录成功建立 `admext1.*` 会话（SameSite=Strict/HttpOnly/Secure）并下发 `otpmask_csrf` 双提交 cookie；前端服务层封装 `X-CSRF-Token` 自动回带；登出清理两类 cookie。
4. 前端：租户视图页面 + `services/tenant-portal.ts`；菜单入口；中英文 i18n；Key 明文处理遵循 §6.3 前端规范。
5. 生成 `fork-patches/higress-console/tenant-portal.patch`。**whitelist 语义精确化（C-7）**：`whitelist-upstream.txt` 只登记「**被修改的上游跟踪文件**」（如 `_defaultProps.tsx`、`locales/{en-US,zh-CN}/translation.json`）；新增文件无需登记。
6. **CI 注册第 4 补丁（Q2 遗留补齐）**：`.github/workflows/admin-portal.yml` 在现有 3 补丁（custom/billing/trace）后追加 apply `tenant-portal.patch`；`scripts/verify-fork-rebuild.ps1` 同步登记第 4 补丁的存在性与可应用性校验，确保补丁链可重建。

**验证**：`fork-patch-check.ps1` 与 CI 四补丁链均通过；公开页免会话可达、私有页需会话；CSRF 缺 token 写请求 403；目录反查不可达时登录失败；跨租户前端不可见他租户数据。

### 7.9 安全与风控收尾（W8-W9）

1. 越权矩阵测试（租户 A/B 交叉、无 `tenant` 声明、`admin` 接管留痕）。
2. 注册风控：频率限制 + 异常注册检测 + 免费版配额限制（C-11）。
3. 渗透测试与安全评审（对齐方案 §5.4.4）；文档（接入 + 运维 + 变更记录）。

**验证**：越权矩阵全绿（V-6）；风控触发告警；安全评审通过。

---

## 8. 与现有系统模块的集成方案

| 集成对象 | 集成方式 | 关键约束 |
|---|---|---|
| **gateway-admin-service（宿主）** | 新增 `tenant_*.go` 模块并在 `main.go` 注册；复用 `authMiddleware`/`requireReadAccess`/`requireRole`/审计链 | 不改既有端点契约；新增端点默认 503 fail-closed（C-12） |
| **P0-3 计费（billing）** | 复用 `Plans().Bind`、`QuotaCompiler`/`QuotaApplier`/`ConfirmQuotaApplied`、`handleGetSubscription`、`handleBills` | 单一真源（C-9）；金额列不出现（C-10）；对齐 M6 回读确认 |
| **P0-1 路由（模型目录/ai-route）** | 复用 `/v1/adminext/models`；租户「可用模型/默认模型」存储 | **租户级路由限域为新增依赖**（D-8/§6.6）；不改全局 ai-route |
| **P1-2 tracing** | 门户请求携带 `X-Request-ID`；排障面板按 `request_id` 关联（复用 P1-2 §6.3 契约） | 门户不自建 trace 存储；跨模块只读 |
| **P1-7 全流量审计** | 复用 tee-infer 审计链（`/audit-tee`）作为租户审计数据源 | 本方案不改留存策略；租户侧仅摘要（D-10） |
| **gateway/auth-service JWT** | 租户 Key 经 auth-service 新增内部签发端点（§6.11）签发；密钥从 CPS KeyRef `otpmask/jwt/v1` 取，**恒 HS256**（CRYPTO_PROFILE=sm 不改变租户 JWT 算法，与 P1-5「JWT 不国密化」对齐；SM3 仅用于内部令牌链） | C-8；不新引入令牌栈；不复制密钥 |
| **Console（higress-console fork）** | 新增公开转发 controller + 登录经 tenant-directory 反查 + 租户前端页 + CSRF/会话 cookie | C-7 补丁集管理；不破坏既有 `/v1/adminext/**` 会话强制 |
| **tee-infer（租户处置/策略）** | 复用 `/config/tenant-disposition`（SaaS）作为处置展示；策略 overlay 生效依赖新增租户限域端点 | **依赖项如实登记**：租户级策略/模型生效端点为待补齐能力 |
| **SMTP 邮件服务** | 新增发信适配（env 配置） | 未配置 → 注册/验证端点 503（C-12） |

**依赖登记（v1.3 收敛为 5 项精确接口，均已定档，无待决项）**：

| # | 依赖（精确接口） | 归属 | 未就绪时行为 |
|---|---|---|---|
| 1 | 租户级策略限域生效端点（`POST` overlay，按 tenant 隔离生效） | tee-infer / P0-1（新增） | `/policy/apply` → 503，不伪造生效 |
| 2 | 租户级模型路由限域（按 `model_configs.allowed_models` 生效） | P0-1（新增） | 模型选择可存可展示，数据面未限域；列入上线前依赖 |
| 3 | jti 吊销增量消费（数据面轮询 `GET /v1/adminext/key-revocations?since=`，间隔 ≤60s） | 数据面（新增对接） | 吊销窗口由 Key TTL（90 天可缩短）兜底，风险已登记 |
| 4 | 账号目录反查（Console 调 `GET /v1/adminext/tenant-directory/lookup?email=`） | admin-service（新增，本方案交付） | 端点不可达 = 登录失败；无 Console 侧二选一同步方案 |
| 5 | Key 签发端点（admin-service 调 auth-service `POST /v1/issue` 扩展契约，CPS `otpmask/jwt/v1`） | auth-service（本方案扩展） | CPS 不可达 auth-service fail-closed 不启动；Key 创建 503 |

---

## 9. 质量保障措施

### 9.1 测试分层（对齐项目 DoD）

| 层级 | 内容 | 目标 |
|---|---|---|
| 单元测试 | 注册/验证/登录、密码哈希、令牌校验、`requireTenantScope`、Key 指纹/吊销、摘要脱敏白名单、策略范围校验 | 新增/修改文件覆盖率 **> 80%**（项目 DoD） |
| 集成测试 | Console（会话/公开转发）↔ Go 服务 ↔ billing/tee-infer；注册→绑定 `free`→配额下发确认 | 端到端链路通 |
| **越权矩阵测试** | 租户 A/B 交叉访问每个租户端点；无 `tenant` 声明；`admin` 接管留痕 | 越权零放行（V-6） |
| E2E | 注册→验证→登录→建 Key→调用→查用量/账单→查审计 | V-1~V-5 |
| 安全测试 | Key 不回显、审计脱敏、注册风控、密码强度、锁定 | 安全评审通过 |
| 兼容测试 | 既有端点（`/billing/*`、`/usage`、`/audit-chain`）行为逐字节不变；`BILLING_ENABLED=false` 时租户计费端点不注册 | R-1/M10 同款约定 |

**越权矩阵（验收基线，V-6；由 §7.9/§9.1 测试逐格断言）**：

**维度定义**：访问主体（5 类）× 目标端点（7 类租户端点 + 2 类内部端点）× 攻击场景（5 种）。以下为核心矩阵（全部须断言）：

**Ⅰ. 主体 × 端点 粗粒度矩阵**

| 访问主体 \ 目标 | 租户端点（本租户） | 租户端点（他租户参数） | 内部读端点（`/audit-chain`/`/usage`/`/models` 等） | 内部写端点（`/usage/quota`/`/billing/freeze` 等） |
|---|---|---|---|---|
| 租户 A 会话（`tenant=A`） | 200 | 403（C-1/C-15） | **401（validRole 自然门禁拒绝，C-13）** | 401 |
| 无 `tenant` 声明的租户令牌 | 403（L1） | 403 | 401 | 401 |
| 内部 `auditor`（无 `tenant`） | 403 | 403 | 200（只读，行为不变） | 403 |
| 内部 `admin`（无 `tenant`） | 403（无 target_tenant 时拒绝，防全量枚举） | 403（同上） | 200 | 200 |
| 内部 `admin` + `target_tenant=B` | —— | 200（接管留痕，C-6） | 200 | 200 |
| 匿名（无令牌） | 401 | 401 | 401 | 401 |

**Ⅱ. 攻击场景矩阵（针对租户 A 会话 `tenant=A`）**

| 场景 | 测试方法 | 预期 | 依据 |
|---|---|---|---|
| 参数篡改 | `GET /tenant/usage?tenant=B` | 403 或强制返回 A 的数据（C-15 强制注入，不返回 403 也不返回 B 的数据） | C-15 |
| 路径遍历 | `GET /tenant/keys/../audit-chain` | 404 或 403（路由层隔离，C-16） | C-16 |
| HTTP 方法逃逸 | `GET /tenant/keys/k-3f9c2a/rotate`（rotate 仅 POST） | 405 Method Not Allowed（注意：`GET /tenant/keys` 是合法列表端点，须 200，不得误判为逃逸） | 方法级路由 |
| JWT 算法混淆 | 改 `alg: none` 或弱密钥签名 | 401 | 鉴权中间件 |
| 空 tenant 参数 | `GET /tenant/audit?tenant=` | 返回 A 的数据（强制注入，C-15），不得返回全量 | C-15 |

**Ⅲ. 各租户端点逐项验证（7 类端点，每类至少 1 个越权用例）**

| 端点组 | 本租户 | 他 tenant 参数 | 空 tenant | admin 接管 |
|---|---|---|---|---|
| `/tenant/keys`（Key 管理） | 200 | 403 / 仅本租户 | 403 | 200 + 留痕 |
| `/tenant/usage`（用量） | 200 | 强制注入本租户（C-15） | 强制注入本租户 | 200 + 留痕 |
| `/tenant/bills`（账单） | 200 | 404（不泄露存在性） | 403 | 200 + 留痕 |
| `/tenant/policy`（策略） | 200 | 403 | 403 | 200 + 留痕 |
| `/tenant/models`（模型） | 200 | 403 | 403 | 200 + 留痕 |
| `/tenant/audit`（审计） | 200 | 强制注入本租户（C-15） | 强制注入本租户 | 200 + 留痕 |
| `/tenant/plans`/`/subscription`（套餐） | 200 | 403 | 403 | 200 + 留痕 |

**Ⅳ. V-8 fail-closed 覆盖矩阵（v1.3 新增，逐端点 × 数据源不可达）**

> 原则：任何外部依赖（SMTP / billing store / tenant store / CPS / tee-infer / auth-service / 策略生效端点）不可达、超时、返回非预期时，**拒绝服务或明确报错，禁止静默成功/放行/空结果兜底**。矩阵每格须有故障注入用例并断言状态码与审计记录。

| 端点 \ 故障源 | SMTP | billing store/域关闭 | tenant store | CPS（`otpmask/jwt/v1`） | tee-infer | auth-service |
|---|---|---|---|---|---|---|
| POST `/tenant/register` | **503**（不建租户） | 202 可受理（verify 才依赖） | 500/重试 | —— | —— | —— |
| POST `/tenant/verify` | —— | **503**（域关闭）；quota 未确认 → quota_pending | 500 | 503（配额链取密钥失败） | 503 | 503 |
| POST `/tenant/login` | —— | 非 active → 403 | 500 | —— | —— | —— |
| POST `/tenant/password-reset` | **503**（不静默成功） | —— | 500 | —— | —— | —— |
| POST `/tenant/password-reset/confirm` | —— | —— | 500；写会话吊销失败 → 500 | —— | —— | —— |
| POST `/tenant/keys` | —— | —— | 500 | —— | —— | **503**（签发不可达，不返 Key） |
| GET `/tenant/usage`·`/bills` | —— | 503 | 500 | —— | **503** | —— |
| GET `/tenant/bills/{id}/export` | —— | 503 | 500 | —— | 503 | —— |
| PUT `/tenant/policy`·POST `/policy/apply` | —— | —— | 500；乐观锁版本冲突 409 | —— | **503**（生效端点未就绪） | —— |
| PUT `/tenant/models/config` | —— | 503（需套餐交集） | 500 | —— | —— | —— |
| GET `/tenant/audit` | —— | —— | 500 | —— | **503** | —— |
| GET `/tenant/plans`·`/subscription`·POST upgrade | —— | **503**（域关闭不返空列表） | 500 | —— | —— | —— |
| GET `/tenant-directory/lookup`（内部） | —— | —— | 503/500（Console 视登录失败） | —— | —— | —— |
| 启动阶段（auth-service） | —— | —— | —— | **拒启动**（fail-closed） | —— | —— |

**故障注入用例清单（测试实现方式）**：

1. **SMTP**：指向未监听端口 / 返回 5xx / 握手超时（≤2s）→ 断言 503，无租户/令牌落库。
2. **billing 域关闭**：`BILLING_ENABLED=false` 启动 → 计费相关端点全部 503（或未注册），其他端点不受影响。
3. **tenant store I/O**：SQLite 文件权限只读 / 磁盘满（注入 driver wrapper 返回 IOErr）→ 写操作 500 且审计记录失败原因。
4. **CPS**：mock CPS 返回 404/超时/空 payload → auth-service 启动失败；运行中轮转拉取失败保留旧密钥并告警（不切换到空密钥）。
5. **tee-infer**：上游 5xx / 延迟 >5s / 返回结构缺字段 → 503，禁止用空 series 冒充成功。
6. **auth-service 签发**：连接拒绝 / 返回非 200 / token 为空 → Key 创建 503，api_keys 不留半成品（事务回滚）。
7. **超时预算**：所有外部调用显式超时（SMTP 5s、HTTP 上游 10s、CPS 3s），用慢响应注入验证不无限挂起。
8. **补偿任务**：人为制造 active 未绑套餐 / 配额未确认 / 绑定未生效三类异常 → 30 分钟扫描任务各产生一条修复或告警记录。

### 9.2 完成定义（DoD，对齐主计划 §8.3）

- [ ] 详细设计评审通过（本文件）
- [ ] 代码开发完成 + Code Review 通过
- [ ] 单元测试覆盖率 > 80%
- [ ] 集成测试 / E2E 通过
- [ ] **越权矩阵测试全绿**（V-6）
- [ ] 安全评审通过（对齐 §5.4.4）
- [ ] 文档齐全（API 文档 + 运维文档 + 变更记录）
- [ ] 生产灰度验证通过
- [ ] 主进度表状态更新为 ✅

---

## 10. 资源需求评估

### 10.1 人力（对齐方案 §5.4.3，合计 6-8.5 人周）

| 任务（对齐 §5.4.3） | 人周 | 角色 |
|---|---|---|
| 后端 API + 权限隔离 | 2-3 | 后端 Go |
| 自助注册 + API Key 管理 | 1 | 后端 Go |
| 用量与账单页面 | 1-1.5 | 前端 + 后端 Go |
| 策略配置页面 | 0.5-1 | 前端 + 后端 Go |
| 审计日志查询（租户侧） | 0.5-1 | 前端 + 后端 Go |
| 测试 + 安全审计 | 1 | 测试 + 安全 |
| **合计** | **6-8.5** | |

> **总工作量**：M+（约 6-8 人周，取中值 7 人周）。工作量低于从零开发，因管理门户 M1-M3 已交付账号体系/安全中心/审计链查询等基础资产（方案 §5.4.3 说明）。
>
> **v1.3 新增工作量（第二轮整改补交付项）**：图形验证码（端点＋前端接入）0.5 人周；CSRF 双提交 cookie 中间件 0.3；账号目录 lookup 端点＋Console 反查改造 0.5；V-8 故障注入测试（8 类）0.5；30 分钟补偿任务 0.3；§3.5 数据模型实现本已含在 M1 内不重复计。**合计追加约 2 人周（区间 1.5-2.5），修正后总量 8-11 人周，中值 9.5 人周。**
>
> **人力-日历对账（v1.3 新增）**：主计划给 P1-4 的窗口为 **3 个自然月（约 12-13 周）**。按中值 9.5 人周测算：
>
> | 配置 | 有效产能（扣除联调/评审/缓冲约 30%） | 预计日历周期 | 是否适配 3 个月窗口 |
> |---|---|---|---|
> | A：1 名 Go 全投入 ＋ 0.5 名前端 | Go 8.5 周可完成量；前端为瓶颈（M8 约 3 人周 → 6 周日历） | 约 11-12 周 | 紧适配，无缓冲 |
> | B（**建议**）：2 名 Go（M1/M2 一人、M3-M7 一人）＋ 1 名前端 | 关键路径约 7-8 周 | 约 9-10 周 | 适配，留 2-3 周联调/灰度缓冲 |
>
> 建议 W0 按配置 B 立项并明确负责人（§10.1 当前负责人均未分配，为启动前必办项）。

### 10.2 基础设施/外部依赖

| 项 | 说明 | 形态 |
|---|---|---|
| SQLite（tenant store） | 与 billing store 同 driver，独立文件；**单副本部署（C-18）**，水平扩展需 P2 迁移 | 复用/新增 |
| tenant store 备份 | 每日快照备份，保留 30 天；与 billing store 同一时间点快照（保证双 store 时间一致性）；恢复 SOP 文档 | 新增运维要求 |
| SMTP 邮件服务 | 邮箱验证发信 | 新增外部依赖 |
| Console fork 构建 | 补丁集重建 | 复用既有流水线 |
| billing/tee-infer | 复用现有部署 | 无新增 |
| 部署约束 | `gateway-admin-service` 生产部署**必须单副本**（C-18：因 SQLite 多写者 + 内存限流） | 硬约束 |

### 10.3 环境变量基线（v1.3 新增）

> 启动时校验：必填项缺失/非法 → fail-closed 拒启动并打印缺失项名称（不打印值）。布尔值仅接受 `true`/`false`。

**A. 存储与密钥**

| 变量 | 必填 | 缺省 | 说明 |
|---|---|---|---|
| `TENANT_STORE_PATH` | 否 | `data/tenant.db` | tenant store SQLite 文件路径；目录不存在则创建（0700） |
| `TENANT_TOKEN_PEPPER` | **是** | 无（拒启动） | ≥32 字节随机串；邮件令牌哈希 pepper |
| `CPS_KEYREF_JWT` | 否 | `otpmask/jwt/v1` | 租户 JWT 签名密钥在 CPS 的 KeyRef（auth-service 消费） |
| `AUTH_SERVICE_URL` | **是** | 无 | auth-service 基址，如 `http://ai-gateway-auth-service:19200`；Key 签发依赖 |

**B. 令牌 TTL / 限流 / 锁定**

| 变量 | 必填 | 缺省 | 说明 |
|---|---|---|---|
| `EMAIL_VERIFY_TTL_HOURS` | 否 | `24` | 注册验证令牌有效期 |
| `PASSWORD_RESET_TTL_HOURS` | 否 | `1` | 重置令牌有效期 |
| `PASSWORD_RESET_EMAIL_INTERVAL_MIN` | 否 | `15` | 同邮箱重置发信最小间隔 |
| `MAIL_TOKEN_FAIL_LIMIT` | 否 | `10` | 同邮箱同 purpose 24h 校验失败上限 → 429 |
| `LOGIN_MAX_FAIL` | 否 | `5` | 触发锁定的连续失败次数 |
| `LOGIN_LOCK_MIN` | 否 | `15` | 锁定时长 |
| `REGISTER_IP_DAILY_LIMIT` | 否 | `5` | 同 IP 每日注册上限 |
| `API_KEY_DEFAULT_TTL_DAYS` | 否 | `90` | Key 缺省有效期 |
| `API_KEY_MAX_TTL_DAYS` | 否 | `365` | Key 有效期硬上限 |
| `TENANT_POLICY_LIMITS` | 否 | `{"free":50,"basic":50,"pro":200,"enterprise":500}` | 各套餐白/黑名单条目上限（双侧分别计数） |
| `TENANT_COMPENSATE_INTERVAL_MIN` | 否 | `30` | 补偿任务扫描间隔 |

**C. 验证码**

| 变量 | 必填 | 缺省 | 说明 |
|---|---|---|---|
| `TENANT_CAPTCHA_ENABLED` | 否 | `true` | 注册/登录图形验证码开关（生产禁止关闭） |
| `TENANT_CAPTCHA_TTL_MIN` | 否 | `5` | 验证码答案内存 TTL |
| `TENANT_CAPTCHA_IP_RATE_PER_HOUR` | 否 | `30` | 同 IP 验证码签发上限 |

**D. SMTP 与邮件链接**

| 变量 | 必填 | 缺省 | 说明 |
|---|---|---|---|
| `SMTP_HOST` / `SMTP_PORT` | **是**（开放注册时） | 无 / `587` | SMTP 地址 |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | 视服务商 | 无 | 认证凭据（密码经 Secret 注入） |
| `SMTP_FROM` | **是** | 无 | 发件人地址 |
| `SMTP_TLS` | 否 | `true` | 强制 STARTTLS；证书校验不可关闭 |
| `PORTAL_BASE_URL` | **是** | 无 | 门户外部基址（如 `https://gateway.example.com`），邮件验证/重置链接拼接用，须 https |

---

## 11. 时间节点规划

> 对齐主计划 §4（P1-4 行）与 §6.1（M4/M5/M6）。

| 里程碑 | 时间 | 交付（对齐计划 §4） | 验收点 |
|---|---|---|---|
| **M4** | 第 4 月 | **后端 API + 注册/Key 管理** | 注册/验证/登录可用；Key CRUD 可用；免费版配额下发（V-1/V-2） |
| **M5** | 第 5 月 | **用量 + 账单 + 策略配置** | 用量/账单查询（V-3）；受限策略配置（V-4） |
| **M6** | 第 6 月 | **审计查询 + 优化** | 租户审计摘要（V-5）；越权矩阵（V-6）；操作审计闭环（V-7）；上线门户 v1（对齐 M6「门户 v1」） |

**关键路径**：租户存储/鉴权 → 注册验证（含免费版配额）→ API Key → 用量/账单 → 策略/模型 → 审计 → Console fork 补丁 → 安全与风控。

---

## 12. 风险评估与应对策略

| ID | 风险（对齐方案 §5.4.4 + 新增） | 影响 | 概率 | 应对 |
|---|---|---|---|---|
| R-1 | **租户数据隔离不彻底（越权访问）** | 高 | 低 | L1/L2/L3 三层隔离；`requireTenantScope` 默认拒绝；越权矩阵测试 + 渗透测试（V-6，D-11） |
| R-2 | **管理门户 fork 升级冲突** | 中 | 中 | 以补丁集管理（`baseline.txt` 固定 v2.2.4）；定期同步上游；`fork-patch-check.ps1` 门禁（C-7，D-6） |
| R-3 | **自助注册滥用** | 中 | 高 | 邮箱验证 + 免费版配额限制 + 注册频率限制/异常检测（C-11） |
| R-4 | **前端复杂度高（页面多）** | 中 | 中 | 分阶段交付：先注册+Key+用量，后策略+审计（对齐 §5.4.4；§11 里程碑） |
| R-5 | **服务端存储 Key 泄露** | 高 | 低 | 单向指纹存储（无解密面）+ 明文仅展示一次 + 绝不明文入日志（C-4） |
| R-6 | **租户级策略/模型生效端点未就绪** | 中 | 高 | 明确列为依赖（§8）；未就绪时 `/policy/apply` 503 不静默成功；M6 前完成依赖对接（D-8） |
| R-7 | **API Key 吊销即时性** | 中 | 中 | 短 TTL 自然过期兜底；吊销表校验收口（§6.3、§8） |
| R-8 | **新增端点遗漏审计链或越权** | 高 | 低 | 写操作强制 `adminAuditChain.append`（fail-closed）；复用 `billing_api.tenantAllowed` 语义并回归 |
| R-9 | **既有端点行为回归** | 中 | 中 | 新增端点默认不注册/503；兼容测试断言既有 `/billing/*`、`/usage`、`/audit-chain` 逐字节不变 |
| R-10 | **SMTP 不可用阻塞注册** | 中 | 中 | 发信失败 fail-closed（503）；运维文档标注 SMTP 为部署前置 |
| R-11 | **`tenant_user` 误并入全局角色白名单 → 租户可读既有内部读端点（跨租户泄露）** | 高 | 低 | C-13：`validRole` 保持内部角色集合（当前 3 角色，随 P1-3 演进）；租户令牌经自然门禁 401；越权矩阵（§9.1）逐格断言 |
| R-12 | **Console 账号解析兜底 `admin` 或目录不可达仍放行** | 高 | 低 | C-14 定档：登录经 tenant-directory 反查；未命中/不可达 = 登录失败，禁止兜底与复制账号表；联调故障注入（§9.1-V8 第 1/4 项） |
| R-13 | **租户 API Key 密钥域错配（与数据面验签密钥不一致）→ Key 全部不可用** | 高 | 低 | 已定档 CPS KeyRef `otpmask/jwt/v1` ＋ auth-service 签发（§6.11）；集成测试含「Key 调 `/infer` 成功」用例；CPS 不可达 fail-closed |
| R-14 | **配额下发/回读确认失败被当作注册成功** | 中 | 中 | 验证端点在配额未确认时返回 `status=quota_pending` 并告警（§6.2），不得对外宣称 `active` |

---

## 13. 附录

### 附录 A：需求 → 设计 → 验收 追溯矩阵

| 功能（方案 §5.4.1） | 本文档设计 | 验收判据 |
|---|---|---|
| F1 租户自助注册/登录 | §3.2/§6.2/§7.2 | V-1 |
| F2 API Key 管理 | §3.3(D-4/D-5)/§6.3/§7.3 | V-2 |
| F3 用量与账单查询 | §6.4/§7.4 | V-3 |
| F4 策略配置（受限） | §3.3(D-8)/§6.5/§7.5 | V-4 |
| F5 模型接入配置 | §6.6/§7.5 | （并入 V-4 体系；生效依赖 §8） |
| F6 审计日志查询（只读脱敏） | §3.3(D-10)/§6.7/§7.6 | V-5 |
| F7 套餐选择与升级 | §3.3(D-9)/§6.8/§7.7 | V-1/V-3 |
| F8 团队成员管理（P2） | §6.9（预留，不实现） | 本期不验收 |
| 数据隔离 | §2.3(C-1/C-2)/§3.4/§6.10 | V-6 |
| 操作审计 | §2.3(C-5)/§7.2-§7.5 | V-7 |
| 复用 JWT 体系 | §3.3(D-2)/§5.1 | C-8 |
| fork 补丁集管理 | §3.3(D-6/D-7)/§7.8 | C-7 |
| 免费版初始套餐 | §2.1(plan_store)/§3.2/§6.2 | V-1 |
| 管理端超管可接管 | §2.3(C-6)/§3.4 | —— |

### 附录 B：新增文件清单（预估）

| 文件 | 类型 | 说明 |
|---|---|---|
| `gateway/gateway-admin-service/tenant_store.go` | Go | 租户注册表/用户表/Key 指纹/策略 overlay 存储 |
| `gateway/gateway-admin-service/tenant_store_test.go` | Go | 存储单测（隔离/唯一性） |
| `gateway/gateway-admin-service/tenant_auth.go` | Go | `TenantAuthMiddleware`/`requireTenantScope`/`tenant_user` 角色 |
| `gateway/gateway-admin-service/tenant_auth_test.go` | Go | 鉴权/越权单测 |
| `gateway/gateway-admin-service/tenant_api.go` | Go | 注册/验证/登录/用量/账单/套餐端点 |
| `gateway/gateway-admin-service/tenant_api_test.go` | Go | API + 越权矩阵测试 |
| `gateway/gateway-admin-service/tenant_key.go` | Go | API Key 创建/列表/轮换/吊销 |
| `gateway/gateway-admin-service/tenant_key_test.go` | Go | Key 生命周期单测 |
| `gateway/gateway-admin-service/tenant_policy.go` | Go | 策略 overlay + 模型配置 |
| `gateway/gateway-admin-service/tenant_policy_test.go` | Go | 受限范围校验单测 |
| `gateway/gateway-admin-service/tenant_audit.go` | Go | 租户审计摘要视图（脱敏） |
| `gateway/gateway-admin-service/tenant_audit_test.go` | Go | 脱敏/租户过滤单测 |
| `gateway/gateway-admin-service/main.go`（改） | Go | 注册租户端点 + 中间件挂载 |
| `gateway/gateway-admin-service/config.go`（改） | Go | 新增 env（SMTP/tenant store/限流） |
| `gateway/gateway-admin-service/auth.go`（改） | Go | **仅新增审计动作/`requireInternalRole` 等辅助（C-13）**；`validRole`/`verifyInternalToken` 保持仅三角色，**不并入 `tenant_user`** |
| `gateway/gateway-admin-service/audit.go`（改） | Go | 新增审计动作常量（注册/Key/策略/套餐） |
| `fork-patches/higress-console/tenant-portal.patch` | Patch | 公开转发 controller + 登录目录反查 + JwtSigner 增 tenant + CSRF/会话 + 租户前端页 |
| `fork-patches/higress-console/whitelist-upstream.txt`（改） | 文本 | 仅登记被修改的上游跟踪文件（C-7） |
| `deploy/k8s/gateway-admin-service.yaml`（改） | YAML | **M9：`replicas: 2 → 1`；同步 PDB（单副本下 PDB minAvailable 须为 0 或移除，避免滚动更新死锁）** |
| `deploy/helm/gateway-admin-service/values.yaml`（改） | YAML | **M9：`replicaCount: 2 → 1`；PDB 模板同步** |
| `.github/workflows/admin-portal.yml`（改） | CI | apply 链追加第 4 补丁 `tenant-portal.patch`（M8） |
| `scripts/verify-fork-rebuild.ps1`（改） | 脚本 | 登记并校验第 4 补丁可应用性 |

**路由注册骨架（newTenantMux，C-16 双 mux 结构）**：

```go
// newTenantMux 构建租户域 mux，独立于 buildAdminMux；在 main.go 中：
//   tenantMux := newTenantMux(deps...)
//   rootMux.Handle("/v1/tenant/", tenantMux)                 // 公开子树（内部按端点决定是否要会话）
//   rootMux.Handle("/v1/adminext/tenant/", tenantMux)       // 租户会话子树（统一过门禁）
//   adminMux := buildAdminMux(...)                          // 既有内部 mux，行为不变
func newTenantMux(d Deps) *http.ServeMux {
    m := http.NewServeMux()

    // —— 公开端点（/v1/tenant/*）：无令牌，验证码 + 频率限制 ——
    m.HandleFunc("POST /v1/tenant/register", d.with(d.handleRegister))
    m.HandleFunc("POST /v1/tenant/verify", d.with(d.handleVerify))
    m.HandleFunc("POST /v1/tenant/login", d.with(d.handleLogin))
    m.HandleFunc("POST /v1/tenant/password-reset", d.with(d.handlePasswordReset))
    m.HandleFunc("POST /v1/tenant/password-reset/confirm", d.with(d.handleResetConfirm))

    // —— 租户会话端点：子树门禁双策略 + CSRF（写） + scope ——
    auth := chain(d.TenantAuthMiddleware, d.requireTenantScope)
    m.HandleFunc("POST /v1/adminext/tenant/logout",
        chain(auth, d.csrfCheck)(d.handleLogout))
    m.HandleFunc("POST /v1/adminext/tenant/keys",
        chain(auth, d.csrfCheck)(d.handleKeyCreate))
    m.HandleFunc("GET /v1/adminext/tenant/keys",
        auth(d.handleKeyList))
    m.HandleFunc("POST /v1/adminext/tenant/keys/{id}/rotate",
        chain(auth, d.csrfCheck)(d.handleKeyRotate))
    m.HandleFunc("DELETE /v1/adminext/tenant/keys/{id}",
        chain(auth, d.csrfCheck)(d.handleKeyRevoke))
    m.HandleFunc("GET /v1/adminext/tenant/usage", auth(d.handleUsage))
    m.HandleFunc("GET /v1/adminext/tenant/bills", auth(d.handleBills))
    m.HandleFunc("GET /v1/adminext/tenant/bills/{id}", auth(d.handleBillDetail))
    m.HandleFunc("GET /v1/adminext/tenant/bills/{id}/export", auth(d.handleBillExport))
    m.HandleFunc("GET /v1/adminext/tenant/policy", auth(d.handlePolicyGet))
    m.HandleFunc("PUT /v1/adminext/tenant/policy",
        chain(auth, d.csrfCheck)(d.handlePolicyPut))
    m.HandleFunc("POST /v1/adminext/tenant/policy/apply",
        chain(auth, d.csrfCheck)(d.handlePolicyApply))
    m.HandleFunc("GET /v1/adminext/tenant/models", auth(d.handleModels))
    m.HandleFunc("GET /v1/adminext/tenant/models/config", auth(d.handleModelConfigGet))
    m.HandleFunc("PUT /v1/adminext/tenant/models/config",
        chain(auth, d.csrfCheck)(d.handleModelConfigPut))
    m.HandleFunc("GET /v1/adminext/tenant/audit", auth(d.handleAudit))
    m.HandleFunc("GET /v1/adminext/tenant/plans", auth(d.handlePlans))
    m.HandleFunc("GET /v1/adminext/tenant/subscription", auth(d.handleSubscriptionGet))
    m.HandleFunc("POST /v1/adminext/tenant/subscription/upgrade",
        chain(auth, d.csrfCheck)(d.handleSubscriptionUpgrade))

    // —— 内部配套端点（Console/数据面）：挂 admin mux 侧，经 authMiddleware ——
    // 见 buildAdminMux 注册：tenant-directory/lookup、key-revocations、captcha
    return m
}
```

> 评审门禁：租户端点只允许在 `newTenantMux()` 注册；code review 发现租户端点挂入 `buildAdminMux()` 或反之，一律打回（C-16）。

### 附录 C：变更记录

| 版本 | 日期 | 变更 |
|---|---|---|
| v1.0 | 2026-10-08 | 首版。基准 HEAD `c2f9c6e`；覆盖方案 §5.4 全部 8 项功能（F8 为 P2 预留）与 7 项验收判据（V-1~V-7）；确立 D-1..D-11 设计决策；登记 §8 三项待补齐依赖。 |
| v1.1 | 2026-10-08 | **多角色评审（第 1 轮）整改回写**（报告：`GA-AI网关能力补齐方案--P1--多租户自助门户-多角色评审报告-第1轮.md`；问题 20 项 / 整改 19 项 / 待确认 1 项）。主要变更：新增硬约束 C-13（`tenant_user` 不入全局角色白名单 + 既有内部读端点须显式拒绝租户会话）与 C-14（租户账号 Console 会话层单一真源）；D-2/D-5 补充密钥域与 TTL；§3.2 明确会话签发归属与配额未生效语义；§3.4 L1/L3 限定作用域；§4 补编号说明；§5.1/附录B 修正角色扩展落点（**不再改 `auth.go validRole`**）；§6.1 更正服务间令牌（三类别名，删除 `X-Svc-Token`）；§6.2/§6.3/§6.4/§6.8 补充失败/密钥/分页/BILLING_ENABLED 语义；§7.1 增 W0 前置 4-6；§7.8 增 `X-Request-ID` 透传与 whitelist 精确语义；§8 增两项依赖登记；§9.1 新增越权矩阵验收基线；§10.1 增前端占比提示；§12 增 R-11~R-14。 |
| v1.2 | 2026-10-08 | **多角色评审（第 2 轮）整改回写**（报告：`GA-AI网关能力补齐方案--P1--多租户自助门户-多角色评审报告-第2轮.md`；问题 18 项 / 整改 18 项）。主要变更：新增硬约束 C-15（代理端点强制注入令牌 tenant，防参数篡改越权）、C-16（路由层双中间件强制隔离）、C-17（前端安全基线：CSRF/cookie 安全/验证码/Key 不持久化）、C-18（管理面单副本部署约束，覆盖存储与限流）；§3.2 补充注册状态机（5 状态 + 失败回退策略 + 双 store 一致性处理）与验证令牌安全规范；§6.1 补 CSRF 防护与 X-Request-ID 规范；§6.2 补密码重置确认端点 + 重置令牌规则；§6.3 补前端 Key 明文处理规范；§6.4 强化代理层 tenant 强制注入说明；§6.8 补套餐升降级计费规则；§6.9 扩展 P2 预留（租户注销 + 数据保留策略）；§7.1 增 W0 前置 7-9（路由隔离/CSRF/国密对齐）；§8 补国密模式双算法兼容策略；§9.1 越权矩阵扩展为三维（主体×端点×场景）并逐项覆盖 7 类租户端点；§1.4 新增 V-8（Fail-closed 验证）；§10.2 补 tenant store 备份策略与部署约束；新增附录 D（审计动作清单）。 |
| v1.3 | 2026-10-09 | **第二轮问题全面修复 + 完整 L3 化**（第 3 轮评审报告：`GA-AI网关能力补齐方案--P1--多租户自助门户-多角色评审报告-第3轮.md`）。基准更新为 HEAD `8050608`，并声明工作区 P1-3 在制改动（auth.go/authz.go）不作事实依据。**关闭全部挂起决策（无待决项）**：CSRF 定档双提交 cookie（`otpmask_csrf`＋`X-CSRF-Token` 常量时间比较）；注册防枚举定档统一 202；账号真源同步定档 Go tenant store 唯一真源 ＋ Console 经 `tenant-directory/lookup` 反查（禁止复制账号表/未命中 admin 兜底）；Key 签发定档 CPS KeyRef `otpmask/jwt/v1` ＋ auth-service `/v1/issue` 扩展；免费版定档永久有效、配额不缩减；超管跨租户统一 `target_tenant` 命名。**新增/重写**：§3.5 tenant store 完整数据模型（7 表 DDL/索引/约束）；§3.4 与 C-16 双 mux（`newTenantMux()`/`buildAdminMux()`）双策略对齐；§3.2 修正为 4 状态机（去 verifying）＋billing 关闭 503＋30 分钟补偿任务＋登录不返令牌；§6.2-§6.8 全端点补请求/响应 schema 与字段约束；§6.11 内部配套端点契约（目录反查/签发扩展/吊销拉取/验证码）；账单 CSV 公式注入防护；§9.1 修正方法逃逸示例、新增 V-8 fail-closed 逐端点覆盖矩阵与 8 类故障注入用例；§10.1 追加工作量（中值修正为 9.5 人周）与人力-日历对账（建议配置 B）；§10.3 环境变量基线（27 项）；附录 B 补路由注册骨架与部署/CI 文件项；附录 D 补 `plan_downgrade`（13 动作）。 |

### 附录 D：审计动作清单（V-7 验收依据）

> 所有自助写操作必须落管理面审计链（G1，SHA-256 链，fail-closed）。审计事件结构同既有 `adminAuditEvent`：`Actor/Action/Tenant/Target/KeyFingerprint/RequestID/Result`。以下为完整动作清单：

| 动作 ID | 触发端点 | 模块 | Target 字段 | KeyFingerprint | 敏感字段处理 |
|---|---|---|---|---|---|
| `tenant_register` | POST /v1/tenant/verify（验证通过时） | M2 | tenant_id | — | 邮箱仅存哈希前缀（8 位），不存明文 |
| `tenant_login` | POST /v1/tenant/login | M2 | — | — | 失败落审计（含失败原因）；成功落审计 |
| `tenant_logout` | POST /v1/adminext/tenant/logout | M2 | — | — | — |
| `password_reset` | POST /v1/tenant/password-reset/confirm | M2 | — | — | 密码不明文入审计 |
| `api_key_create` | POST /v1/adminext/tenant/keys | M3 | key_id | SHA-256 前 8 位指纹 | 明文绝不入审计链 |
| `api_key_rotate` | POST /v1/adminext/tenant/keys/{id}/rotate | M3 | key_id | 新 Key 指纹 | 同上 |
| `api_key_revoke` | DELETE /v1/adminext/tenant/keys/{id} | M3 | key_id | 旧 Key 指纹 | 同上 |
| `policy_update` | PUT /v1/adminext/tenant/policy | M5 | policy_overlay | — | 仅存变更摘要（类目数/条目数变化），不存具体词 |
| `policy_apply` | POST /v1/adminext/tenant/policy/apply | M5 | policy_overlay | — | 仅存申请状态 |
| `model_config_update` | PUT /v1/adminext/tenant/models/config | M5 | default_model | — | 仅存模型 ID 列表 |
| `plan_upgrade` | POST /v1/adminext/tenant/subscription/upgrade（确认升级时） | M7 | plan_id | — | 当月折算口径不入审计 |
| `plan_downgrade` | POST /v1/adminext/tenant/subscription/upgrade（降级请求确认时） | M7 | plan_id | — | 次月 1 日生效；记录生效日 |
| `plan_bind` | 验证通过自动绑定 free 套餐 | M7 | plan_id | — | 对齐 billing 既有 `auditActionPlanBind` |

> 验收判据 V-7：以上 **13 个动作**全部存在审计记录，字段符合上表规定，明文/敏感字段绝不出现。

---

> 文档结束。本文档为 P1-4 的唯一口径源；后续评审/验证/测试报告均为过程留证，只引本文。
