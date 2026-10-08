# GA-AI 网关能力补齐方案 · P0-3 —— T9 计费页面交付与 fork 集成说明

> **性质**：T9（管理后台计费页面）**只读 + 写操作（M1）** 的交付物与集成说明。
> **形态裁定**：经用户确认采用**方案 B（最小可用）+ 路径 A（前端-only 交付）**；M0 修复基线，M1 增写操作。
> **日期**：2026-10-08 ｜ **依据**：详设 §4.3.2/§4.3.4/§4.3.5；《GA-AI网关能力补齐--研发计划与进度跟踪.md》§3.4。

---

## 1. 范围与形态

- **交付**：控制台 **计费中心** 页面 `/admin-ext/billing`，含三个标签页：
  1. **账单中心**：账单列表 + 明细展开（金额列**仅本页**出现，§3.1.3）；按租户/类型过滤。
  2. **套餐与订阅**：套餐列表 + 当前租户订阅查询 + 订阅绑定（admin）。
  3. **冻结管理**：租户冻结/解冻（admin）。
- **写操作（M1）**：套餐 upsert（审计 `plan_upsert`）、订阅绑定（`plan_bind`）、冻结/解冻（`bill_freeze`/`bill_unfreeze`）——由**后端 `requireRole("admin")` 强制**并落审计链；前端不做角色隐藏（无身份信息，§4.3.4 D10），越权由后端 403。
- **角色（M2）**：已放行 `billing_reader`（Go `auth.go` + 控制台签发侧 Java/账号页）；写端点仍仅 `admin`，租户隔离沿用（非 admin 受令牌 `tenant` 约束）。
- **不改上游逻辑**：仅新增文件 + 修改白名单文件（菜单/locale）。

## 2. 交付物清单

| 类别 | 路径 | 说明 |
|---|---|---|
| 页面 | `frontend/src/pages/admin-ext/billing/index.tsx` | 计费中心页（Tabs：账单 / 套餐订阅 / 冻结） |
| 服务 | `frontend/src/services/admin-ext-billing.ts` | `/v1/adminext/billing/*` 客户端（读 + 写） + 类型 |
| 菜单 | `frontend/src/pages/_defaultProps.tsx` | 新增 `menu.adminExtBilling` → `/admin-ext/billing`（白名单文件） |
| i18n | `frontend/src/locales/{zh-CN,en-US}/translation.json` | `menu.adminExtBilling` + `adminExt.billing.*`（白名单文件） |
| **补丁** | `fork-patches/higress-console/higress-console-billing.patch` | **前端增量补丁**（5 文件 / 855 行；读+写） |

## 3. fork 集成方案（叠加顺序）

本补丁为**增量补丁**，须在既有定制补丁的**前端部分**之后应用（其上下文基于已打补丁的树）：

```
# 1) 上游基线（v2.2.4）
git clone --depth 1 --branch v2.2.4 https://github.com/higress-group/higress-console.git
# 2) 既有定制补丁（M0 已修复为**原子可应用**，无需 --include）
git -C higress-console apply <repo>/fork-patches/higress-console/higress-console-custom.patch
# 3) 本增量补丁
git -C higress-console apply <repo>/fork-patches/higress-console/higress-console-billing.patch
# 4) 构建
cd higress-console/frontend && npm ci && npm run build
```

> CI/本地脚本已接入**两份补丁的按序应用**：`.github/workflows/admin-portal.yml` 与 `scripts/verify-fork-rebuild.ps1`（断言含 `admin-ext/billing.html` 与 `p_admin-ext-billing-index-*.js`）。

- 补丁已于本地通过 `git apply --check`（在主补丁基线上原子应用）与**完整构建**验证（§4）。
- 已接入 `admin-portal.yml`（按序 apply 两份补丁 + 产物断言）与 `verify-fork-rebuild.ps1`；`fork-patch-check.ps1` 仅守护**主补丁**白名单（计费补丁为纯新增前端文件）。

## 4. 验证证据（本机实测）

| 项 | 命令 | 结果 |
|---|---|---|
| 补丁一致性 | `git apply --check`（在**主补丁基线** fork-m0b 上） | OK（读+写增量补丁可原子应用） |
| 类型检查 | `npx tsc --noEmit` | 计费相关文件 **0 错误**；全仓仅 1 条既有错误（`TS2688 dompurify`，与本次无关） |
| **完整构建（读+写）** | `npm ci && npm run build` | **webpack compiled successfully（exit 0）** |
| 产物编入 | 构建输出 | `build/admin-ext/billing.html`、`build/js/p_admin-ext-billing-index-*.js`、`build/css/p_admin-ext-billing-index-*.css`（与 `security-center` 同范式） |

**环境注意（非缺陷）**：本机项目路径含中文“方案”，ICE 在 Windows 下对绝对路径归一化失配，直接构建报
`Path .../public/avatar.png is not in cwd`（与页面无关）。以 `subst X: <frontend>` 映射 ASCII 盘符后**构建成功**。
根因 = 中文路径 + ICE 路径校验，**非本页引入**。

### 4.1 页面契约测试（T-4.3-1..4，M3）

| 用例 | 内容 | 载体 | 结果 |
|---|---|---|---|
| T-4.3-1 | 页面级 RBAC 矩阵（读 200 / 写 403 / 未认证 401） | `billing_api_contract_test.go::TestBillingContractT4_3_1_RBACMatrix` | ✅ |
| T-4.3-2 | `enabled=false` → 计费端点全部 404 | `…T4_3_2_DisabledAllEndpoints404` | ✅ |
| T-4.3-3 | 写动作落审计链（`plan_upsert`/`plan_bind`/`bill_freeze`） | `…T4_3_3_WriteAuditTrail` | ✅ |
| T-4.3-4 | 金额列仅账单页（源扫描门禁） | `scripts/check-billing-amount-scope.ps1`（接入 `admin-portal.yml` + `verify-fork-rebuild.ps1`） | ✅（正例 PASS / 反例 FAIL） |
| E2E-5（M4） | 真实双服务链路：套餐 upsert→绑定→订阅读回；`billing_reader` 读 200 / 跨租户·写 403；冻结→出账 409→解冻；审计链含 `plan_upsert`/`plan_bind`/`bill_freeze` | `e2e/billing_e2e_test.go`（`ADMIN_AUDIT_FILE` 启用 G1 链） | ✅（E2E-1..5 **5/5 PASS**，17.9s） |

> T-4.3-4 说明：控制台无 JS 测试运行器，故以**源扫描**实现（对齐 tee-infer S-3 的 CI 强制思路）——扫描 `frontend/src/pages/admin-ext/**` 与 `frontend/src/services/**`，金额 token（`fenToYuan`/`amountFen`）仅允许出现于账单页/服务。

## 5. fork 基线/重建链漂移 —— 已修复（M0，2026-10-08）

**原问题**：`baseline.txt`=36aa9c6 ≠ 上游 v2.2.4 当前提交 `f8410432`；既有补丁 2 个 backend 文件失配 → **不可原子应用**（前端部分可）。

**M0 处置**：
1. `baseline.txt` 重钉到 `f8410432`；`admin-portal.yml`、`scripts/verify-fork-rebuild.ps1` 同步更新（`$baseRev`）。
2. 删除 2 条**过时** hunk：上游已自行修复 #761（[WasmPluginServiceTest](file:///c:/Users/Robin/Desktop/%E6%96%B9%E6%A1%88/security-ai-gateway/vendor/higress-console/backend/sdk/src/test/java/com/alibaba/higress/sdk/service/WasmPluginServiceTest.java#L161-L176) 改为**版本无关**断言）；`plugin-snapshot.lock.json` 上游已不存在。对应 `whitelist-upstream.txt` 条目一并移除。
3. 剔除 `frontend/yarn.lock`（本地 `npm ci` 副产物，非定制点）。
4. 从 `f8410432` 重定基并重导 `higress-console-custom.patch`（35 文件 / 5051 行）。

**验证**：
- 纯净 `f8410432` 上 `git apply --check` → **原子通过**（此前失败）；
- `scripts/fork-patch-check.ps1 -BaseRev f8410432` → **PASS**（白名单合规 + 重导出一致）；
- 前端构建已在**同一前端内容**上验证通过（见 §4）；后端 `mvn compile/test` 由 CI（JDK17）执行（本机无 `mvn/java`）。

> 已于 **M1** 完成：本增量补丁按序接入 `admin-portal.yml`（+ `verify-fork-rebuild.ps1`），CI 一并构建并断言计费页产物。

## 6. 里程碑与后续

**T9 完整态里程碑**：M0 fork 基线修复 ✅ → M1 写页面+授权 ✅ → M2 `billing_reader` ✅ → M3 契约测试 ✅ → **M4 验收（E2E-5 + 文档）✅**。

后续（可选）：
- 与既有用量页（`/admin-ext/usage`）的口径衔接与自助场景打磨。
- 生产环境 UI 回归：**手册已就绪** —— 《…-T9计费页面UI回归手册.md》（含 7 组检查项/证据留痕/记录模板）；待具备控制台运行栈（Java 后端 + 会话 + `billing_reader` 账号）的环境照单执行。
