# GA-AI 网关能力补齐方案 · P1-4 多租户自助门户 · M8/M9 Console 侧实施规格

| 项 | 内容 |
|---|---|
| 定位 | 本体 §7.8（M8 Console fork 定制）/ §7.9 的 **Console 侧实施规格**（交付件） |
| 口径来源 | 本体《GA-AI网关能力补齐方案--P1--多租户自助门户.md》**v1.3** |
| 当前状态 | Console 侧**代码与补丁未实施**（当前工作区 `vendor/higress-console` 为骨架，不具备实施条件，见 §1）；Go 侧配套已交付（见 §6） |
| 关联资产 | `fork-patches/higress-console/`（`baseline.txt`=f8410432、`whitelist-upstream.txt`、3 个补丁）、`scripts/fork-patch-check.ps1`、`scripts/verify-fork-rebuild.ps1`、`.github/workflows/admin-portal.yml` |

---

## 1. 环境前置（当前工作区**不满足**）

| 前置 | 要求 | 当前状态 |
|---|---|---|
| Console fork 工作区 | `vendor/higress-console` **完整** git 工作树（含 `backend/**` Java 与 `frontend/src` 全量） | ⚠️ 骨架：无 `backend/**/*.java`、无 `frontend/node` |
| 上游基线 | 可 `git cat-file -e f8410432^{commit}`（v2.2.4） | 需 fork 环境 clone |
| JDK | `.tools/jdk-17.0.20.1+1`（`verify-fork-rebuild.ps1` 前置） | ✅ 就位 |
| Node | fork 内置 `frontend/node/npm.cmd`（CI 用 `setup-node 16`） | ⚠️ 缺失 |
| 网络 | 可 clone `https://github.com/higress-group/higress-console.git` | 视环境 |

> `vendor/` 与 `.tools/` 均被 `.gitignore` 忽略（不入库），入库的唯一交付物是**补丁**与门禁脚本。

**实施前置动作**：在具备上述条件的环境执行 `git clone --branch v2.2.4 https://github.com/higress-group/higress-console.git vendor/higress-console`，并补齐 fork 内置 node 运行时。

---

## 2. Java 侧改动清单（§7.8 step1）

| # | 文件（fork 内路径） | 改动 |
|---|---|---|
| J-1 | `.../adminext/AdminExtJwtSigner.java` | payload 增 `tenant` 声明；新增 `sign(sub, role, tenant, ...)` 重载（保持既有签名不变，向后兼容） |
| J-2 | `.../adminext/AdminExtRole.java` | 枚举增 `tenant_user` |
| J-3 | `.../adminext/AdminExtUserStore.java` | `resolveRole`：登录时经 **`GET /v1/adminext/tenant-directory/lookup?email=<归一化邮箱>`** 反查 Go tenant store；命中 → `tenant_user` + `tenant`；**未命中一律登录失败，禁止兜底 admin**（C-14）；目录不可达（5xx/网络）→ 登录失败（不放行） |
| J-4 | `.../adminext/TenantPublicController.java`（**新增**） | 公开转发 `/adminext-tenant/**` → Go `/v1/tenant/**`（**免会话**；验证码必带） |
| J-5 | `.../adminext/AdminExtProxyController.java` | 补齐 `X-Request-ID` 透传（现仅注入 `Authorization`+`Content-Type`） |
| J-6 | 会话层 `AdminExtSessionService` | 登录成功建立 `admext1.*` 会话 cookie（`SameSite=Strict` + `HttpOnly` + `Secure`）并下发双提交 `otpmask_csrf` cookie（**非** HttpOnly）；登出清理两类 cookie |

**约束**：
- **禁止** Console 复制租户账号表（单一真源 = Go tenant store，C-14）；
- 目录反查失败时**不得**降级放行。

---

## 3. 前端改动清单（§7.8 step2–4）

| # | 项 | 说明 |
|---|---|---|
| F-1 | 租户视图页面 | 注册/登录、Key 管理、用量/账单、策略、模型、审计、套餐（分阶段：先注册+Key+用量，后策略+审计） |
| F-2 | `services/tenant-portal.ts` | 封装租户 API 调用；**自动回带 `X-CSRF-Token`**（读 `otpmask_csrf` cookie） |
| F-3 | 菜单入口 | `frontend/src/pages/_defaultProps.tsx`（**上游跟踪文件 → 须登记 whitelist**） |
| F-4 | 中英文 i18n | `frontend/src/locales/{en-US,zh-CN}/translation.json`（**上游跟踪文件 → 须登记 whitelist**） |
| F-5 | 图形验证码接入 | 注册/登录页接入 Go `GET /v1/adminext/captcha`（经公开转发），提交时携带 `captcha_id`/`captcha_code` |
| F-6 | Key 明文处理 | 明文仅创建/轮换响应展示一次；**不入日志/localStorage**（§6.3 前端规范） |

**C-7 whitelist 语义精确化**：`whitelist-upstream.txt` **只登记「被修改的上游跟踪文件」**（如 `_defaultProps.tsx`、`locales/*/translation.json`）；**新增文件无需登记**。

---

## 4. 第 4 补丁生成 SOP

```powershell
# 0) 前置：fork 工作区存在且干净、baseline 可达
git -C vendor/higress-console fetch origin
git -C vendor/higress-console status --porcelain        # 必须为空

# 1) 白名单校验 + 导出既有定制补丁（会重新生成 higress-console-custom.patch）
pwsh -File scripts/fork-patch-check.ps1

# 2) 生成第 4 补丁（tenant-portal；与 custom/billing/trace 同分工，独立成文件）
git -C vendor/higress-console diff f8410432..HEAD -- <tenant 相关新增/修改路径> `
  > fork-patches/higress-console/higress-console-tenant-portal.patch

# 3) 若 Console 侧改动了新的「上游跟踪文件」，需同步补入 whitelist-upstream.txt
#    （仅登记上游跟踪文件；新增文件不登记）
```

**要点**：
- 补丁必须**可从上游纯净基线重建**（`apply` 无 conflict）；分片导出时各补丁之间**不得重叠同一文件同一 hunk**；
- 补丁链一致性由 §5 门禁保证；
- 现有 `fork-patch-check.ps1` 默认只导出一份补丁（`higress-console-custom.patch`）；若第 4 补丁需纳入该脚本的自动导出，需在 fork 环境扩展其导出路径（**待确认项**，见 §8）。

---

## 5. CI 与本地门禁登记（第 4 补丁）

| # | 文件 | 改动 |
|---|---|---|
| C-1 | `.github/workflows/admin-portal.yml` | 在现有 3 补丁 `git apply` 之后追加 `git apply .../higress-console-tenant-portal.patch`；产物断言追加租户页 chunk（如 `admin-ext/tenant.html`、对应 `p_*` chunk） |
| C-2 | `scripts/verify-fork-rebuild.ps1` | 步骤 0 前置检查加入第 4 补丁存在性；步骤 2 追加 `git apply`；步骤 5 追加租户页 chunk 断言 |

> **登记前置**：C-1/C-2 一旦引用第 4 补丁，该补丁文件**必须已存在且可 apply**，否则门禁立即变红。
> 因此**建议**：补丁产出与门禁登记**同批提交**（本仓库当前无 remote，CI 未首跑；本地 `verify-fork-rebuild.ps1` 需完整 fork 环境）。

---

## 6. 已完成的 Go 侧配套（本方案交付）

| 端点 | 说明 | 状态 |
|---|---|---|
| `GET /v1/adminext/tenant-directory/lookup?email=` | Console 登录目录反查数据源（§6.11 / §8 依赖 4）；命中 → `200 {tenant_id, status, tenant_role:"tenant_user"}`；未命中 → `404`（**禁止兜底 admin**）；邮箱非法 → `400`；目录不可达 → `503` | ✅ 已交付（`tenant_directory.go`，含单测） |

> 该端点是 M8 Java 侧 J-3 的**依赖前置**，已先行交付，消除 Console 侧实施的 Go 阻塞。

---

## 7. 验证判据（§7.8）

| # | 判据 |
|---|---|
| V-1 | `scripts/fork-patch-check.ps1` 通过（白名单无越界、补丁可导出） |
| V-2 | CI 四补丁链通过（`admin-portal.yml`）；本地 `verify-fork-rebuild.ps1` clean-room 重建通过（apply → mvn compile+test → npm ci+build → chunk 断言） |
| V-3 | 公开页免会话可达；私有页需会话 |
| V-4 | CSRF：写请求缺 `X-CSRF-Token`/`otpmask_csrf` → 403 |
| V-5 | 目录反查不可达 → Console 登录失败（不放行） |
| V-6 | 跨租户前端不可见他租户数据 |
| V-7 | 金额列仅出现在账单页（既有 `check-billing-amount-scope.ps1` 门禁保持通过） |

---

## 8. 依赖与风险

| # | 项 | 类型 | 处置 |
|---|---|---|---|
| R-1 | **环境缺失**（完整 fork + node 运行时） | 阻塞 | 需在具备条件的环境执行 §1 前置动作 |
| R-2 | 第 4 补丁与 `fork-patch-check.ps1` 的自动导出路径是否需扩展 | 待确认 | fork 环境确认后定；当前按"独立补丁文件"处理 |
| R-3 | 补丁链一致性（4 补丁 apply 顺序/文件不重叠） | 风险 | §5 门禁 + §7 V-2 |
| R-4 | whitelist 精确化（C-7） | 约束 | 仅登记上游跟踪文件；新增文件不登记 |
| R-5 | Console 侧会话/CSRF 与 Go 侧 `admext1.*`/`otpmask_csrf` 契约 | 联调 | 对齐本体 §6.1/§6.2（Go 侧已按此实现） |

---

> 本文档为 M8/M9 Console 侧的实施规格与移交依据；Console 侧代码/补丁的最终交付以 §5 门禁（四补丁链）通过为准。
