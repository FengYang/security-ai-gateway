# GA-AI 网关能力补齐方案 · P1-4 多租户自助门户 · 多角色评审报告（第 1 轮）

> **留证性质**：本报告为**过程留证**，只引不做口径。评审与整改对象为
> `docs/详细设计/P1/GA-AI网关能力补齐方案--P1--多租户自助门户.md`（以下简称「本体」，唯一口径源）。
> 本体经本轮评审后版本回写为 **v1.1**（见本体「附录 C 变更记录」）。

---

## 1. 评审信息

| 项 | 内容 |
|---|---|
| 评审对象（本体） | `docs/详细设计/P1/GA-AI网关能力补齐方案--P1--多租户自助门户.md`（v1.0 → 整改后 v1.1） |
| 评审类型 | 多角色系统性设计评审（架构/逻辑/性能/安全/扩展/可维护/需求/表述） |
| 评审轮次 | 第 1 轮 |
| 基准 | HEAD `c2f9c6e`（与本体声明一致） |
| 上游依据 | 方案 §5.4（`docs/GA-AI网关能力补齐方案.md` L945-1020）；研发计划 §2.2 / §4 / §6.1（`docs/详细设计/GA-AI网关能力补齐--研发计划与进度跟踪.md` L77-90、L375-404、L426+） |
| 代码事实来源（实读） | 见 §5「读过文件」 |
| 结论摘要 | 问题 20 项（P0×1 / P1×3 / P2×9 / P3×7）；整改 19 项；待确认 1 项（仓库级） |

---

## 2. 角色分工与主要发现

| 角色 | 关注维度 | 主要发现（问题 ID） |
|---|---|---|
| 架构师 | 架构设计缺陷 / 与需求相符 | Q-01 租户令牌并入全局角色白名单的越权路径；Q-03 租户账号真源与 Console 会话层不一致；Q-04 登录/会话跨服务归属不清；Q-13 V-4 验收口径；Q-15 模块编号歧义 |
| 后端开发 | 逻辑漏洞 / 接口完整 | Q-02 API Key 密钥域未定义；Q-05 配额未生效语义；Q-07 服务间令牌命名混乱；Q-19 §6.8 前置未标注 |
| 前端开发 | 集成自洽 / 可维护 | Q-06 `X-Request-ID` 未透传（与 P1-2 契约冲突）；Q-14 前端工作量；Q-17 补丁集/whitelist 表述 |
| 测试工程师 | 验收可测性 | Q-12 越权矩阵未固化为验收基线；Q-13 V-4 口径 |
| 产品经理 | 需求符合 / 验收可达 | Q-13 V-4 不可验收风险；Q-14 工作量现实性；Q-08 注册枚举 |
| 运维/DevOps | 可运维 / 可扩展 | Q-09 内存限流多副本失效；Q-11 用量聚合无分页/窗口上限；Q-18 本体文档未纳入版本管理 |
| 安全工程师 | 安全隐患 | Q-01 跨租户读泄露；Q-02 密钥域错配；Q-07 认证头混用；Q-08 账号枚举；Q-09 风控绕过；Q-10 TTL 无上限 |

**对本体验证性断言（重点怀疑点）的核对结论**（基于实读代码）：

| 本体断言 | 核对结论 |
|---|---|
| 全仓无 SMTP / 邮件发送 | **成立**。全仓无 `net/smtp`、`SendMail`、`javax.mail`、`JavaMailSender`、`spring-boot-starter-mail` 命中（命中的「email」仅为 PII 类目/无关文本）。 |
| 无租户注册表 / tenant store | **成立**。`gateway/` 下无租户注册/用户/Key 存储代码。 |
| console JWT 不含 `tenant` | **成立**。`AdminExtJwtSigner.sign` payload 仅 `sub/role/iss/aud/iat/exp`。 |
| 角色枚举缺 `tenant_user` | **成立**。`gateway/` 与 `fork-patches/` 均无 `tenant_user`（仅本体引入）。 |
| `auth.go` 角色枚举 = admin/auditor/billing_reader；claims 含 `Tenant` | **成立**（`auth.go` L33-52）。 |
| `tenantAllowed` 仅覆盖 billing 读端点 | **成立**（`billing_api.go` L809-818）。 |
| `usage.go` 代理不改数据层；未配置 → 503 | **成立**（`usage.go` 头注 + `requireDataSource`）。 |
| `model_catalog.go` 缺失返回 200 空列表 | **成立**（`model_catalog.go` L295-340）。 |
| `audit.go` 写失败 = fail-closed | **成立**（`audit.go append` 返回 error；`broker_secret.go`/`usage.go` 拒 2xx）。 |
| tee-infer 审计含 `payload_hash` / `is_retry` | **成立**（`tee-infer-service/audit.go` L35、L86）。 |
| `free` 套餐 1M/并发 5/exact/reject | **成立**（`billing/plan_store.go DefaultPlans`）。 |
| Console `/v1/adminext/**` 强制登录会话、自签 JWT | **成立**（`higress-console-custom.patch` `AdminExtProxyController`）。 |
| 新增/修改文件（`tenant_*`、`tenant-portal.patch` 等）不存在 | **成立**（本体为设计稿）。 |

> 结论：本体 §2.1「现状基线与代码事实」**整体准确**，未发现与代码不符的臆造；本轮发现集中在**设计缺口与表述歧义**，而非现状失真。

---

## 3. 问题清单

| ID | 维度 | 角色 | 严重度 | 问题描述 | 影响范围 | 改进建议 |
|---|---|---|---|---|---|---|
| Q-01 | 架构设计缺陷 / 安全隐患 | 架构师 / 安全 | **P0** | 本体 D-2 与附录 B 拟「`auth.go` 角色枚举增 `tenant_user`」，即把租户角色并入全局白名单。而 `auth.go` 的 `verifyInternalToken` 以 `validRole` 为唯一角色闸门，既有内部读端点（`/audit-chain`、`/audit-tee`、`/usage`、`/models`、`/billing/plans`、`/changes` GET）**仅要求已认证**（`requireReadAccess`）。一旦并入，租户令牌即可读 G1 全量审计链与（无 `tenant` 参数时）全租户用量，形成跨租户泄露 | 租户数据隔离（V-6）、G-9/C-2 | 明确 **C-13**：`tenant_user` 不入 `validRole`；租户令牌仅经新增 `TenantAuthMiddleware` 校验；既有内部读端点加 `requireInternalRole` 显式拒绝租户会话（或在路由层隔离）；越权矩阵逐格断言 |
| Q-02 | 安全隐患 / 逻辑漏洞 | 后端 / 安全 | **P1** | D-5 认定租户 API Key 为「长效 HS256 JWT，网关 `/infer` 复用现有 C-6 校验链」，但**未定义签发主体与密钥域**。数据面 `/infer` 验签密钥来自 `auth-service`（`:19200`，`docs/API-参考.md` §2），与 `gateway-admin-service` 的 `ADMIN_SVC_JWT_SECRET`（`auth.go` 内部服务令牌）**并非同一密钥**；若由 admin-service 用内部密钥签发，则网关验签必然失败 | F2/V-2 不可实现或误用内部密钥 | 明确由 `auth-service` 签发或登记密钥共享通道；`role:"api"` 须与 `auth-service` `Claims{Sub,Tenant,IAT,EXP}` 对齐（现无 `role/jti`）；登记为 §8 依赖 |
| Q-03 | 架构设计缺陷 | 架构师 | **P1** | 租户账号真源在 Go `tenant_store`，但 Console 会话层（`AdminExtSessionService.saveSession` / `AdminExtUserStore.resolveRole`）**要求账号在 Console 账号表**；未命中时 `resolveRole` **兜底返回 `admin`**、`saveSession` **回落原生 admin 会话**。本体未定义两存储的单一真源与同步，租户将无法获得携带 `tenant` 的会话，或错误获得 `admin` 角色 | 越权（跨租户）、登录不可用 | 明确 **C-14**：租户账号必须可在 Console 会话层解析出 `tenant`+`tenant_user`；禁止落入 `admin` 兜底；同步方式（写账号表 or Console 反查 Go tenant store）须显式定义并登记 §8 |
| Q-04 | 逻辑漏洞 | 架构师 / 后端 | **P1** | 本体 §3.2 step3 叙述「Go `/v1/tenant/login` 成功签发租户会话令牌 → Console 建立 `admext1.*` 会话」，但 `admext1.*` 会话**只能由 Java `AdminExtSessionService` 生成**（HMAC serverKey），Go 无法下发 Console cookie。跨服务登录/会话归属不清 | 登录链路不可落地；实现返工 | 明确：Go 只做凭据校验与返回，Console 侧建会话；在 §6.2 增「会话归属」唯一口径 |
| Q-05 | 逻辑漏洞 | 后端 / 架构 | P2 | 注册验证端点在配额下发/回读确认失败时语义未定义（既有 M6「回读确认失败仅告警、不回滚」），可能对外返回 `active` 而配额实际未生效 | G-2/V-1 失真 | 失败时租户置 `status=quota_pending` 并告警，不返回 `active` |
| Q-06 | 与需求不符（集成自洽） | 前端 / 架构 | P2 | §8 声称「门户请求携带 `X-Request-ID`，与 P1-2 按 `request_id` 关联」，但 `AdminExtProxyController.proxy()` 仅注入 `Authorization`+`Content-Type`，**未透传** `X-Request-ID`（实读 patch L740-756） | 与 P1-2 契约不自洽；排障无法关联 | M8 增 `X-Request-ID` 透传并纳入验收 |
| Q-07 | 文档表述歧义 / 安全隐患 | 后端 / 安全 | P2 | §6.1 称服务间令牌为 `X-Svc-Token`；实际为三类：Console→Go 的 `Authorization: Bearer`（HS256）、Go→tee 的 `X-Admin-Token`、Console 会话 `admext1.*` cookie。命名虚构易致误接线/认证绕过 | 实现误解、排障困难 | §6.1 如实列三类令牌及头名/密钥来源，删除 `X-Svc-Token` |
| Q-08 | 安全隐患 | 安全 / 产品 | P2 | `/v1/tenant/register` 邮箱已存在返回 409（泄露账号存在性），与 `password-reset` 的 202 防枚举口径不一致 | 账号枚举 | 明确二选一：保留 409（标注可接受）或改统一 202 + 邮件分支 |
| Q-09 | 安全隐患 / 可扩展性 | 运维 / 安全 | P2 | 注册/登录频率限制采用**进程内内存滑动窗口**（对齐 `AdminExtLoginGuard`），管理面多副本下按副本计数、可被绕过 | 风控失效（C-11） | 明确单副本部署，或用共享存储（billing SQLite/Redis）承载计数 |
| Q-10 | 安全隐患 | 安全 | P3 | D-5「长效 JWT」与「短 TTL 自然过期兜底」自相矛盾，且未设 TTL 上限 | 吊销实时性/持久化越权窗口 | 设 TTL 上限（缺省 90 天，可配），并回传 `expires_at` |
| Q-11 | 性能瓶颈 | 运维 / 后端 | P2 | §6.4 用量聚合透传 tee-infer `/usage`（增量聚合），未定义查询窗口上限与分页；大时间窗/多维度查询无界 | 门户/数据源压力、超时 | 窗口 ≤92 天、列表分页（≤500），数据源不可达 503 |
| Q-12 | 可维护性不足（验收） | 测试 | P2 | §9.1 仅以「越权矩阵测试」一句话表述，未固化矩阵内容，无法作为可断言验收基线 | V-6 验收不可复现 | 补「访问主体 × 目标端点」越权矩阵表 |
| Q-13 | 与需求不符 | 产品 / 架构 | P2 | V-4「策略配置」未区分「可配置（存储）」与「生效」；而生效依赖 §8 未就绪通道（D-8），本期可能无法验收「生效」 | 验收判据不可达 | V-4 口径明确为「存储可配置 + 落审计」，不含生效；`/policy/apply` 未就绪 503 |
| Q-14 | 与需求不符（资源） | 产品 / 前端 | P2 | §10.1 将前端与后端合列；M8 实含公开 controller、`JwtSigner`/`AdminExtRole` 改造、账号真源同步、7-8 页面、services、菜单/i18n、补丁重建门禁，前端 2-3.5 人周偏紧 | 进度风险 | W0 复核 M8 人力；或将策略/审计页面按 R-4 分阶段后移 |
| Q-15 | 文档表述歧义 | 架构师 | P3 | §4 模块编号 `M1..M9` 与 §11/上游 `M4/M5/M6`（里程碑）在同文档内语义冲突 | 阅读/沟通歧义 | §4 增编号说明，明确「模块 vs 里程碑」 |
| Q-16 | 文档表述歧义 | 架构师 / 安全 | P3 | §3.4 L1「令牌必须含 `tenant`，无声明一律 403」与「例外：admin 跨租户」及既有内部角色冲突 | 规则边界不清 | L1 限定为「租户端点」；内部角色不要求 `tenant` |
| Q-17 | 可维护性不足 | 前端 / 运维 | P3 | §1.3/C-7「补丁集管理，不入库」表述不准：入库的是 `fork-patches/*.patch`，不入库的是 `vendor/` fork 源码（`.gitignore` 忽略 `vendor/`）；且新增文件无需登记 whitelist，仅修改上游跟踪文件需登记 | 交付/门禁误解 | 精确表述补丁集与 whitelist 语义（§7.8.4） |
| Q-18 | 可维护性不足（仓库级） | 运维 | P3 | 本体因 `.gitignore` 全局忽略 `*.md` 且 P1 目录未豁免，**未纳入版本管理**，与「唯一口径源/留证」定位矛盾（P0 详设已豁免，P1 未豁免） | 口径源不可追溯 | 仓库级：`.gitignore` 豁免 `docs/详细设计/P1/`（超出本体范围，见 §6） |
| Q-19 | 文档表述歧义 | 后端 | P3 | §6.8 套餐端点未标注 `BILLING_ENABLED=false` 时的行为，与 §9.1「租户计费端点不注册」口径未在同一处对齐 | 实现歧义 | §6.8 补 503/不注册前置说明 |
| Q-20 | 文档表述歧义 | 后端 / 安全 | P3 | §3.4 L3「所有查询/写入 SQL 恒带 `WHERE tenant_id=?`」过度承诺：billing `plans`（全局表）、`subscriptions`（多租户表，`ListSubscriptions` 无租户列）不适用 | 纵深防御预期失真 | L3 作用范围限定为「租户域表」 |

**严重度统计**：P0 × 1；P1 × 3；P2 × 9；P3 × 7；**合计 20 项**。

---

## 4. 逐项整改记录

> 整改对象：本体 v1.0 → v1.1（单轮全部整改，落点到章节/表格/字段）。

| ID | 整改落点（本体） | 整改内容 |
|---|---|---|
| Q-01 | §2.3 约束表（新增 C-13）；§3.3 D-2；§5.1 角色行；附录 B `auth.go` 行 | 新增 C-13：`tenant_user` 不入 `validRole`；既有内部读端点须显式拒绝租户会话（`requireInternalRole`）；D-2 明确「仅租户专用校验链」；附录 B 将 `auth.go` 改动改为「仅新增辅助，不并入 `tenant_user`」 |
| Q-02 | §3.3 D-5；§6.3 新增「密钥域」段；§8 依赖登记 | 明确 `/infer` 验签密钥来自 `auth-service`，与 `ADMIN_SVC_JWT_SECRET` 不同域；须由 `auth-service` 签发或登记共享通道；`role:"api"` 与 `Claims` 对齐说明 |
| Q-03 | §2.3（新增 C-14）；§3.2 step3；§6.2 会话归属；§8 依赖登记 | 新增 C-14「租户账号 Console 会话层单一真源」；step3 明确禁止 `resolveRole` 兜底 `admin`；§8 登记「账号真源与同步」依赖 |
| Q-04 | §3.2 step3；§6.2「会话归属（唯一口径）」 | 明确 Console cookie 只由 `AdminExtSessionService` 生成，Go 不下发 cookie |
| Q-05 | §1.4 V-4 前置；§3.2 step2；§6.2 verify 行 + 失败语义 | 新增 `status=quota_pending` 语义；配额未确认不返回 `active` |
| Q-06 | §7.8 step2 | 新增「`X-Request-ID` 透传」要求并指出与现 `AdminExtProxyController` 的差距 |
| Q-07 | §6.1「服务间令牌」行 | 重写为三类令牌如实说明，删除虚构的 `X-Svc-Token` |
| Q-08 | §6.2 register 行 | 标注 409 泄露存在性，给出「统一 202」备选，W0 定档 |
| Q-09 | §5.1 限流/风控行 | 新增部署约束：单副本或共享存储承载计数 |
| Q-10 | §3.3 D-5；§6.3「TTL」段 | 明确 TTL 上限（缺省 90 天，可配） |
| Q-11 | §6.4「查询约束」段 | 窗口 ≤92 天、分页 ≤500、数据源不可达 503、`tenant` 由中间件注入 |
| Q-12 | §9.1 新增「越权矩阵」表 | 固化「访问主体 × 目标端点 × 依据」5×3 矩阵 |
| Q-13 | §1.4 V-4 | V-4 口径明确为「存储可配置 + 落审计」，不含生效 |
| Q-14 | §10.1 新增「前端占比提示」 | 指出前端 2-3.5 人周偏紧，建议 W0 复核/分阶段 |
| Q-15 | §4 新增「编号说明」 | 明确模块编号 vs 里程碑编号语义不同 |
| Q-16 | §3.4 L1 行 | L1 限定为租户端点；内部角色不要求 `tenant` |
| Q-17 | §7.8 step4 | 精确化补丁集入库范围与 whitelist 语义 |
| Q-19 | §6.8 新增「前置依赖」段 | 补 `BILLING_ENABLED=true` 前置与 503 口径 |
| Q-20 | §3.4 L3 行 | L3 作用范围限定为「租户域表」 |
| （附） | §7.1 前置 W0 | 新增前置 4-6（密钥域/账号真源/越权拒绝点） |
| （附） | §12 风险表 | 新增 R-11~R-14（对应 Q-01/Q-03/Q-02/Q-05） |
| （附） | 附录 C | 追加 v1.1 行，注明评审来源 |

---

## 5. 复查与维度覆盖

**维度覆盖**：架构设计缺陷（Q-01/Q-03/Q-04）｜逻辑漏洞（Q-02/Q-04/Q-05/Q-20）｜性能瓶颈（Q-11）｜安全隐患（Q-01/Q-02/Q-07/Q-08/Q-09/Q-10）｜可扩展性问题（Q-03/Q-09）｜可维护性不足（Q-12/Q-17/Q-18）｜与需求不符（Q-06/Q-13/Q-14）｜文档表述歧义（Q-07/Q-15/Q-16/Q-19/Q-20）。**八维全覆盖**。

**角色覆盖**：架构师 / 后端开发 / 前端开发 / 测试工程师 / 产品经理 / 运维-DEVOPS / 安全工程师。**七角色全覆盖**。

**复查点**：
- Q-01/Q-02/Q-03 为「安全边界」类，本体已以硬约束 C-13/C-14 与 D-5/§6.3 固化，并进入越权矩阵与 §7.1 前置，可被回归测试断言。
- Q-13/Q-14 为「验收/资源」类，已改口径与提示，属可执行整改。
- 未发现本体整改后与代码事实冲突（整改均在「设计缺口/表述」层面，不改现有代码行为，亦未改变 D-1..D-11 已定决策核心范围）。

**读过文件（实读，用于事实核对）**：
- 本体：`docs/详细设计/P1/GA-AI网关能力补齐方案--P1--多租户自助门户.md`
- 上游：`docs/GA-AI网关能力补齐方案.md`（§5.4）；`docs/详细设计/GA-AI网关能力补齐--研发计划与进度跟踪.md`（§2.2/§4/§6.1）
- 代码：`gateway/gateway-admin-service/{main.go,auth.go,config.go,billing_api.go,usage.go,sec_center.go,model_catalog.go,change.go,credential_endpoint.go,broker_secret.go,audit.go}`；`gateway/gateway-admin-service/billing/plan_store.go`；`gateway/auth-service/jwt.go`；`gateway/tee-infer-service/audit.go`
- 前端 fork：`fork-patches/higress-console/{baseline.txt,whitelist-upstream.txt,higress-console-custom.patch}`
- 其它：`.gitignore`；`docs/API-参考.md`
- 检索核对：全仓 `net/smtp|SendMail|javax.mail|JavaMailSender`（无命中）；`gateway/` 与 `fork-patches/` 的 `tenant_user`（无命中）；`highress-console-custom.patch` 的 `AdminExtJwtSigner|AdminExtRole|AdminExtProxyController|resolveRole|saveSession`。

---

## 6. 未整改待确认项

| ID | 项 | 未整改原因 | 建议处置 |
|---|---|---|---|
| Q-18 | 本体文档未纳入版本管理（`.gitignore` 全局忽略 `*.md`，P1 目录未豁免） | **仓库级配置**，非本体文档可自洽整改；本任务限定「只改本体 + 新建本报告」，不越界修改 `.gitignore` | 建议后续在仓库 `.gitignore` 增加 `!docs/详细设计/P1/` 豁免（与 P0 详设同策略），使「唯一口径源」可追溯 |

> 其余 19 项均已在本体内完成整改（见 §4 与本体 v1.1 变更记录）。

---

## 7. 结论

1. 本体 §2.1 现状基线**准确**：无 SMTP、无租户注册表、Console JWT 不含 `tenant`、角色枚举缺 `tenant_user` 等断言**均与实读代码一致**，未发现臆造。
2. 本轮识别 **20 项**问题，**1 项 P0 阻断级**（`tenant_user` 并入全局角色白名单导致既有内部读端点对租户放行、跨租户泄露），已通过硬约束 C-13 及越权矩阵固化处置方向；**3 项 P1**（Key 密钥域、账号单一真源、会话归属）均已明确整改口径。
3. 整改后本体 v1.1 在**隔离、密钥、会话、验收、资源、表述**六方面自洽性显著提升，且**未改变已定 D-1..D-11 决策的核心范围**（仅在不改变范围的前提下补齐缺口与限定作用域）。
4. 建议进入下一门禁：按 §7.1 W0 完成 6 项前置确认（SMTP/billing/fork/密钥域/账号真源/越权拒绝点）后启动编码；编码阶段以 §9.1 越权矩阵为回归基线。

---

## 8. 变更记录

| 版本 | 日期 | 变更 |
|---|---|---|
| v1.0 | 2026-10-08 | 首轮多角色评审报告：识别问题 20 项（P0×1/P1×3/P2×9/P3×7），完成本体单轮整改 19 项，登记待确认 1 项（Q-18 仓库级）；本体回写 v1.1。 |
