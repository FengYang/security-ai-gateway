# GA-AI 网关能力补齐方案 · P0-3 —— T9 计费页面交付与 fork 集成说明

> **性质**：T9（管理后台计费页面）**最小可用只读版**的交付物与集成说明。
> **形态裁定**：经用户确认采用**方案 B（最小可用只读页）+ 路径 A（前端-only 交付）**。
> **日期**：2026-10-08 ｜ **依据**：详设 §4.3.2/§4.3.4/§4.3.5；《GA-AI网关能力补齐--研发计划与进度跟踪.md》§3.4。

---

## 1. 范围与形态

- **交付**：控制台 **计费中心（只读）** 页面 `/admin-ext/billing`，含两个标签页：
  1. **账单中心**：账单列表 + 明细展开（金额列**仅本页**出现，§3.1.3）；支持按租户/类型过滤。
  2. **套餐与订阅**：套餐列表 + 当前租户订阅查询。
- **只读**：不改 `billing_reader` 角色（复用既有读端点授权：`auditor`/`admin`；写操作仍由 admin 经 API 完成，符合 §4.3.5 的 P-5 回退）。
- **不改上游逻辑**：仅新增文件 + 修改白名单文件（菜单/locale）。

## 2. 交付物清单

| 类别 | 路径 | 说明 |
|---|---|---|
| 页面 | `frontend/src/pages/admin-ext/billing/index.tsx` | 计费中心页（Tabs：账单/套餐订阅） |
| 服务 | `frontend/src/services/admin-ext-billing.ts` | `/v1/adminext/billing/*` 只读客户端 + 类型 |
| 菜单 | `frontend/src/pages/_defaultProps.tsx` | 新增 `menu.adminExtBilling` → `/admin-ext/billing`（白名单文件） |
| i18n | `frontend/src/locales/{zh-CN,en-US}/translation.json` | `menu.adminExtBilling` + `adminExt.billing.*`（白名单文件） |
| **补丁** | `fork-patches/higress-console/higress-console-billing.patch` | **前端增量补丁**（5 文件） |

## 3. fork 集成方案（叠加顺序）

本补丁为**增量补丁**，须在既有定制补丁的**前端部分**之后应用（其上下文基于已打补丁的树）：

```
# 1) 上游基线（v2.2.4）
git clone --depth 1 --branch v2.2.4 https://github.com/higress-group/higress-console.git
# 2) 既有定制补丁（前端部分）——见 §5 后端漂移说明
git -C higress-console apply --include='frontend/*' <repo>/fork-patches/higress-console/higress-console-custom.patch
# 3) 本增量补丁
git -C higress-console apply <repo>/fork-patches/higress-console/higress-console-billing.patch
# 4) 构建
cd higress-console/frontend && npm ci && npm run build
```

- 补丁已于本地通过 `git apply --check -R`（可逆）与**完整构建**验证（§4）。
- 未改动 `scripts/fork-patch-check.ps1` / `admin-portal.yml`（见 §5：重建链当前受后端漂移阻塞，需先修复后端后再决定是否把本补丁纳入流水线）。

## 4. 验证证据（本机实测）

| 项 | 命令 | 结果 |
|---|---|---|
| 补丁一致性 | `git apply --check -R higress-console-billing.patch` | OK（补丁与工作树一致） |
| 类型检查 | `npx tsc --noEmit` | 我的文件（`admin-ext/billing`、`_defaultMenuProps` 相关）**0 错误**；全仓仅 1 条既有错误（`TS2688 dompurify`，与本次无关） |
| **完整构建** | `npm ci && npm run build` | **webpack compiled successfully（exit 0）** |
| 产物编入 | 构建输出 | `build/admin-ext/billing.html`、`build/js/p_admin-ext-billing-index-*.js`、`build/css/p_admin-ext-billing-index-*.css`（与 `security-center` 同范式） |

**环境注意（非缺陷）**：本机项目路径含中文“方案”，ICE 在 Windows 下对绝对路径归一化失配，直接构建报
`Path .../public/avatar.png is not in cwd`（与页面无关）。以 `subst X: <frontend>` 映射 ASCII 盘符后**构建成功**。
根因 = 中文路径 + ICE 路径校验，**非本页引入**。

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

> 遗留可选：本增量补丁 `higress-console-billing.patch` 纳入 `admin-portal.yml`（例如按序 apply 两份补丁）——可作为 M1 的一部分。

## 6. 后续（T9 完整态，未做）

- 页面契约测试（T-4.3-1..4：页面级 RBAC 矩阵、`enabled=false` 404、写动作落审计、金额列仅账单页快照）。
- 套餐/订阅/冻结**写页面**（admin）与 `billing_reader` 角色放行（§4.3.5）。
- 与既有用量页（`/admin-ext/usage`）的口径衔接与自助场景打磨。
