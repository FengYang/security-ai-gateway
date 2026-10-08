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

## 5. 独立待办：控制台 fork 基线/重建链漂移（不在 T9 范围）

实测（克隆上游 v2.2.4 后）：

1. `baseline.txt` 记录 `36aa9c6`，而**当前**上游 v2.2.4 提交为 `f8410432` → `fork-patch-check.ps1` 的 `base..HEAD` 失效。
2. 既有补丁**不能原子应用**，仅 2 个 backend 上游文件：
   - `backend/sdk/.../WasmPluginServiceTest.java`：`patch does not apply`
   - `backend/sdk/.../resources/plugins/plugin-snapshot.lock.json`：`No such file or directory`
3. 前端部分可干净应用（`git apply --check --include='frontend/*'` OK）。

**建议（另行立项）**：更新 `baseline.txt` 至上游当前提交；复核上述 2 个"上游缺陷修复"是否已被上游合并（若是则从补丁删减）；恢复补丁**原子可应用**后，再把本增量补丁纳入 `admin-portal.yml` 流水线。

## 6. 后续（T9 完整态，未做）

- 页面契约测试（T-4.3-1..4：页面级 RBAC 矩阵、`enabled=false` 404、写动作落审计、金额列仅账单页快照）。
- 套餐/订阅/冻结**写页面**（admin）与 `billing_reader` 角色放行（§4.3.5）。
- 与既有用量页（`/admin-ext/usage`）的口径衔接与自助场景打磨。
