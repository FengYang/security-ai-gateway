> 中文版 ｜ [English](./README.en.md)

# P2-4 T-1.10：多副本 / 共享库部署 overlay（默认单副本不变）

> 本目录是**可选 overlay**。基础清单 `deploy/k8s/**` **零改动**（默认部署语义绝对不变），
> 只有显式 `kubectl apply -k deploy/k8s-overlays/multicluster` 才切到 2 副本形态。

## 1. 用法与启用前置

```bash
# 默认（不变，C-18 单副本硬约束）
kubectl apply -k deploy/k8s

# 本 overlay
kubectl apply -k deploy/k8s-overlays/multicluster
```

### 1.0 原子切换单元（**不可拆开用**，team-lead 裁决①）

> **本 overlay 是「副本数提升 + 共享库切换」的原子切换单元：两者必须同时生效。**
> **不存在**「只加副本、不切共享库」的中间形态——因为基础 PVC
> `gateway-admin-tenant-store` 是 `ReadWriteOnce`（`deploy/k8s/gateway-admin-service.yaml:355-368`），
> **2 副本 + SQLite 卷 ⇒ 第二副本必然 Pending（不可调度）**，该中间形态本身即不可用。

| 形态 | 副本数 | tenant store | 第二副本可调度 | 是否交付价值 |
|------|--------|-------------|---------------|-------------|
| 默认部署（不 apply overlay） | 1 | SQLite | — | ✅ 单副本形态，正常 |
| **仅加副本、不切 PG**（无此交付物） | 2 | SQLite | ❌ **Pending**（RWO） | ❌ **无价值**：不可用形态，仅制造「以为可以只加副本」的误用风险 |
| **本 overlay（原子切换）** | 2 | **PG 共享库**（SQLite 卷已移除） | ✅ 可调度 | ✅ 目标形态 |

**因此**：`ReadWriteOnce` 卷下**必须先切共享库（PG）**，才能提升副本数；
`kubectl apply -k deploy/k8s-overlays/multicluster` 是**唯一**进入 2 副本形态的入口，
**不要**手工只改 `replicas` 或只删 PVC（会出现双写者或副本不可调度）。

**启用前置（缺一不可）：**

| # | 前置 | 说明 |
|---|------|------|
| 1 | T-1.6 存储迁移工具已完成 SQLite → PG 迁移 + 对账 | `admin-service migrate -action plan/import/verify`；未完成即切 2 副本 = 多写者数据不一致 |
| 2 | 共享 PG 实例就绪 | 安全计数器共享库（captcha / login_attempts / mfa / 发信限频）与 tenant store 的目标库 |
| 3 | Secret `otpmask-shared-pg` 已由 KMS/Vault 注入 | **凭据禁止入库**；创建命令见 `secret-shared-pg.example.yaml`（该文件为模板，勿 apply） |
| 4 | tenant store PG 装配已接通 | ✅ **已满足**（T-1.2b，2026-10-26 落地：`main.go` → `openTenantStoreForConfig`，PG 非空走 PG、PG 打开失败 fail-closed 拒启动）。口径见 §4 |

**迁移顺序（硬要求，不可颠倒）：**

```
① 旧形态（单副本 + SQLite 卷）内：先用【新版本】完成一次启动（schema 自动升级）
   └─ 否则新表在源库缺失 → export 会丢表
     （迁移工具已加 fail-closed 校验，并写入 migrate 帮助文本；跳过此步即被拒）
② 仍在旧形态内：admin-service migrate -action plan|export|import|verify
   └─ 源 SQLite 路径由 -from 显式给出、目标 PG 由 -to 给出（迁移工具不读 env）
③ verify 对账通过后：kubectl apply -k deploy/k8s-overlays/multicluster
   └─ PG DSN 生效 + 移除 SQLite 卷 + 副本 2
```

反序（先移除 SQLite 卷再迁移）→ 源 SQLite 文件不可达，迁移无法执行、数据不可见；
跳过①（未先用新版本启动升 schema）→ 新表不在源库，迁移**丢表**。

目录位置说明：任务书建议的 `deploy/k8s/overlays/...` 会因 kustomize 的
`cycle detected`（base 不能是 overlay 的祖先目录）而无法构建，故置于 `deploy/k8s` 的
**同级**目录 `deploy/k8s-overlays/`，以 `../../k8s` 引用基础清单（kustomize 标准布局）。

## 2. 差异评审清单（改了什么 / 为什么 / 对默认部署的影响）

| 文件 | 改动 | 为什么 | 对默认部署影响 |
|------|------|--------|----------------|
| `kustomization.yaml` | 新增 overlay 入口（bases=基础清单 + patches） | 把 2 副本形态与默认形态隔离 | **无**（`deploy/k8s/kustomization.yaml` 未引用本目录） |
| `patch-admin-replicas.yaml` | `replicas: 1 → 2`；`strategy.maxSurge=0 / maxUnavailable=1` | 多副本是 P2 多集群/高可用的目标形态；`maxSurge=0` 保证滚动升级时**新旧 Pod 不并存**，杜绝共享库切换窗口内的双写者 | **无**（仅在本 overlay 生效） |
| `patch-admin-pdb.json.yaml` | **仅** `gateway-admin-service` 这一个 PDB：`maxUnavailable: 0` → `minAvailable: 1`（RFC6902 先删后加，目标按 kind/name/namespace 精确定位） | 基础清单中 admin PDB 位于 `deploy/k8s/gateway-admin-service.yaml:375-385`（**不在 `pdb.yaml`**），语义是「驱逐须运维显式介入」（单副本下正确）。2 副本下保留会**永久阻断**节点 drain / 滚动升级（allowedDisruptions=0）；改 `minAvailable=1` 后 2 副本允许 1 个自愿干扰，**正常驱逐不被阻断**，同时保底 1 副本承载写入 | **无**（基础文件未改；patch 只在 overlay 内应用。语义对照见 §2.1） |
| `patch-admin-security-pg-env.yaml` | 注入 `SECURITY_STORE_PG_DSN`、`TENANT_STORE_PG_DSN`（**均为 Secret 引用，无明文**）；显式写 `TENANT_CAPTCHA_IP_RATE_PER_HOUR=30`、`LOGIN_MAX_FAIL=5`、`LOGIN_LOCK_MIN=15`（均为代码默认值，仅作口径留档） | 共享库是多副本下 captcha 限流 / 登录锁定 / MFA / 发信限频 / 租户数据一致性的前提；空值 = 原进程内实现（默认零变化） | **无**（基础清单不含这两个 env，默认仍为进程内实现 + SQLite） |
| `patch-admin-tenant-store-pg.yaml` | 移除 tenant store 的 SQLite 卷与挂载（`volumeMounts` / `volumes` 列表项 `$patch: delete`） | tenant store 已切 PG 后不再需要本地 SQLite；基础 PVC `gateway-admin-tenant-store` 为 `ReadWriteOnce`，继续挂载会让**第二副本跨节点即 Pending**，叠加 `replicas=2 + maxSurge=0` 会卡住滚动升级。PVC **保留不删**（回退路径可用，且该卷为加密卷） | **无**（仅在本 overlay 生效；基础清单零改动） |
| `patch-core-snapshot.yaml` | `GATEWAY_CORE_STORE_SNAPSHOT_PATH=/var/lib/otpmask-core/store-snapshot.json`；审计卷 `emptyDir → PVC`；新增快照卷 | 落实基础清单自身 TODO「生产须改为持久卷（WORM）」；T-1.7 快照持久化开关默认关闭（空=纯内存） | **无**（基础清单该 env 不存在） |
| `pvc-core-store.yaml` | 新增 PVC `gateway-core-audit-worm`、`gateway-core-store-snapshot`（各 1Gi，RWO，不写死 storageClassName） | 判据 7 审计链持久性 + T-1.7 快照持久性；不绑死环境专有 SC | **无**（新增资源，不进基础 kustomization） |
| `secret-shared-pg.example.yaml` | Secret 形态模板（占位值） | 说明注入方式，**禁止明文凭据入库** | **无**（不在 resources 内） |

**对默认部署的净影响：0。** 已用 `kubectl kustomize` 对基础目录与 overlay 分别构建比对，
基础清单文件本次提交**零改动**（`git diff --stat deploy/k8s` 为空）。

### 2.1 PDB 语义与适用边界（核实结论）

**先纠正一处口径**：基础清单里有**两处** PDB，二者性质不同，本次**均未改动**：

| 位置 | 对象 | 语义 | 本次改动 |
|------|------|------|----------|
| `deploy/k8s/pdb.yaml` | `embedding-service-pdb` / `tee-infer-service-pdb` / `envoy-gateway-pdb` | 三个均为 `minAvailable: 1`（常规保底，与副本数无关） | **未改动**（本 overlay 的 PDB patch 不涉及它们） |
| `deploy/k8s/gateway-admin-service.yaml:375-385` | `gateway-admin-service` | `maxUnavailable: 0`（C-18 单副本硬约束配套：驱逐须运维显式介入） | **未改动**；本 overlay 用 RFC6902 **仅在 overlay 内**改这一条 |

因此「基础 `pdb.yaml` 已同步调整为 `minAvailable: 1`」这一说法**不成立**：
`pdb.yaml` 本来就是 `minAvailable: 1`（无需调整），而 admin PDB 位于
`gateway-admin-service.yaml` 且**仍为 `maxUnavailable: 0`**——这是**有意保持**的，
因为基础形态是单副本，`maxUnavailable: 0` 正是「驱逐须显式介入」的表达，
若在基础清单改成 `minAvailable: 1`，反而会**悄悄放宽**默认部署的干扰预算。

**基础与 overlay 的语义是否等价？**（按 allowedDisruptions = max(0, minAvailable - 期望可用数) 推算）

| 形态 | 基础（未应用 overlay） | overlay 应用后 | 是否等价 |
|------|------------------------|----------------|----------|
| 单副本（默认部署） | `maxUnavailable: 0` → disruptions = 0 | `minAvailable: 1` + replicas=1 → disruptions = max(0, 1-1) = 0 | ✅ **行为等价**（都阻止自愿驱逐，均不会放开写者独占） |
| 2 副本（overlay 目标形态） | `maxUnavailable: 0` → disruptions = 0（**永久阻断 drain/滚动**） | `minAvailable: 1` → disruptions = 1（正常驱逐可进行） | ❌ 不等价（这正是 overlay 必须改 PDB 的原因） |

**适用边界（重要）**：

- 默认部署（未 apply overlay）：仍为 `maxUnavailable: 0` + 单副本 → 自愿驱逐被阻断，
  节点 drain 必须运维显式介入（C-18 原意，**未被本次提交改变**）。
- 本 overlay：replicas=2 + `minAvailable: 1` → 允许 1 个自愿干扰，**正常驱逐不被阻断**。
- ⚠️ **单副本 + `minAvailable: 1` 同样会阻止自愿驱逐**（disruptions = 0）。
  即：把本 overlay 误用到 1 副本环境，**不会**放宽干扰预算，但会因同一 overlay 的
  `replicas=2` patch 一并变成 2 副本 —— 故本 overlay 必须与 §1 的前置条件
  （T-1.6 迁移完成、PG 就绪、tenant store PG 装配接通）**成套使用**，
  且**不得**在未完成前置的单副本环境单独应用。

## 3. 口径留档

### 3.1 验证码签发限流（P3-5）
`TENANT_CAPTCHA_IP_RATE_PER_HOUR ≤ 0 = 关闭签发限流`（内存 / PG 两端一致，
`config.go:225-226`，默认值 30）。**生产禁止置 0**；多副本下只有走 PG 共享库，
按 IP 的计数才是全局一致的（进程内计数会被副本数放大）。

### 3.2 登录失败锁定：共享库降级期间按副本数放大（P2-1 裁决）
- 正常（PG 共享库在线）：`LOGIN_MAX_FAIL` 为**全局**计数，与副本数无关。
- **降级期间**（PG 不可达 → 回退进程内实现）：每个副本各自计数，攻击者实际可尝试次数
  ≈ `副本数 × LOGIN_MAX_FAIL`（本 overlay 2 副本 ≈ 2×）。这是 P2-1 裁决记录在案的
  **已知风险**，不得靠放宽阈值掩盖。
- 因此本 overlay **不修改** `LOGIN_MAX_FAIL=5` / `LOGIN_LOCK_MIN=15`，只做显式留档；
  若确需在多副本下调阈值，须走 P2-1 裁决的变更记录并同步更新监控。

**监控要求（多副本部署必配）：**

| 监控项 | 建议口径 | 动作 |
|--------|----------|------|
| 共享库降级（PG 不可达/回退进程内） | 新增告警：降级信号持续 > 5m 即 **critical**（与 S1(7) 进程内态清单同源） | 立即恢复 PG；恢复前按副本数折算锁定强度 |
| 登录失败速率 | `rate(login_fail_total[5m])` 按副本数折算：2 副本下阈值按 `2 × LOGIN_MAX_FAIL` 观察 | 超阈值 → 人工介入 |
| 副本就绪数 | `kube_deployment_status_replicas_ready` 长期 < 2 → warning | 排查 PVC/PG 未就绪导致的 Pending |
| 验证码签发限流命中 | captcha 限流拒绝计数按 IP 聚合异常升高 → warning | 排除绕过与爆破 |

## 4. tenant store PG：装配已接通（2026-10-26 实读核实）+ 本 overlay 的落地动作

### 4.1 装配侧事实（实读代码，非记忆）

装配线 **T-1.2b 已落地**（主库提交 `5cc0d6b`，2026-10-26），核实结论：

| 项 | 事实 | 出处 |
|----|------|------|
| 双方言打开入口 | `OpenTenantStoreWithDialect(sqlutil.Postgres, dsn, true, pepper)`；SQLite 分支 `OpenTenantStore(path, ...)` 逐字不变 | `gateway/gateway-admin-service/tenant_store.go:454-466` |
| env 驱动的方言选择 | `TENANT_STORE_PG_DSN` 非空 → PG；否则 `TENANT_STORE_PATH` 非空 → SQLite；两者都空 → 门户未启用 | `config.go:198-215`、`tenant_store_open.go:26-34` |
| 装配入口 | `main.go:299-305` → `openTenantStoreForConfig(cfg)`（原 `OpenTenantStore(cfg.tenantStorePath, ...)` 固定 SQLite 的缺口已补） | `main.go:297-305` |
| **fail-closed** | PG 打开/建表失败 → `log.Fatalf` **拒启动**，不静默退回本地存储 | `main.go:302-305`、`tenant_store_open.go:12-16` |
| **PG 优先** | 两者都配时 `cfg` 两项**都保留**，运行时按 PG 选择 ⇒ 基础清单的 `TENANT_STORE_PATH` 可保留（惰性 env） | `tenant_store_pg_wiring_test.go` 用例④ |
| pepper 保障 | `TENANT_TOKEN_PEPPER` 由基础清单以 `secretKeyRef`（非 optional）注入，缺失/过短即 fail-closed | `deploy/k8s/gateway-admin-service.yaml:114-118`、`config.go:205-211` |
| PG 侧建表 | `openPostgresTenantStore` 执行 DDL 建表（`create=true`），**不写本地 SQLite 文件** | `tenant_store.go:460-466` |

### 4.2 本 overlay 的落地动作（本次提交）

1. `patch-admin-security-pg-env.yaml`：**解注释** `TENANT_STORE_PG_DSN`（Secret 引用，无明文凭据）；
2. `patch-admin-tenant-store-pg.yaml`（**由 `.example` 转为已启用**）：移除 tenant store 的
   SQLite 卷与挂载（`$patch: delete`，`volumeMounts` 的 merge key 是 `mountPath`、
   `volumes` 的是 `name`——**只写 `name` 会报 "does not contain declared merge key"**）。

**为什么必须成对切换**：基础 PVC `gateway-admin-tenant-store` 为 `ReadWriteOnce`
（`deploy/k8s/gateway-admin-service.yaml:355-368`）。切 PG 后该卷不再承载数据，
继续挂载会让第二副本跨节点即 Pending；叠加 `replicas=2 + maxSurge=0 + maxUnavailable=1`，
滚动升级会卡在「1 可用」无法推进。⇒ PG 形态下卷与挂载**成对移除**。

**PVC 保留不删**：回退路径可用（回退到 SQLite 形态时原卷与数据仍在），且该卷为加密卷
（`storageClassName: tee-encrypted`），残留 SQLite 不违反明文落盘约束。验收通过后由运维
手工删除（属环境操作，不在本仓库资产内）。

### 4.3 与旧版口径的差异（**事实更正**）

上一版本 README 记的「装配入口仍是固定 SQLite（`main.go:300`）、代码中无 `TENANT_STORE_PG_DSN`
读取点」**已不成立**（T-1.2b 落地）。同时纠正一处曾经的误判：

> 旧文案称「`TENANT_STORE_PATH` 置空会关闭整个租户门户」——**错误**。
> T-1.2b 后判定为「`TENANT_STORE_PATH` 与 `TENANT_STORE_PG_DSN` **都空**才关闭」，
> 故 `TENANT_STORE_PATH` 置空 + PG DSN 非空 = 门户启用且走 PG。

### 4.4 回退方式

从 `kustomization.yaml` 的 `patchesStrategicMerge` 移除 `patch-admin-tenant-store-pg.yaml`，
并同步注释掉 `patch-admin-security-pg-env.yaml` 中的 `TENANT_STORE_PG_DSN`
→ 回到 SQLite 单副本形态（卷与挂载随基础清单自动回到原状）。

## 5. 校验方式与结果（本机）

| 项 | 方式 | 结果 |
|----|------|------|
| kustomize 构建 | `kubectl kustomize deploy/k8s-overlays/multicluster`（kubectl v1.14 内置 kustomize v2） | ✅ 通过，28 个文档 |
| 全域构建 | `kubectl kustomize` × 6 目录（`deploy/k8s`、`k8s-overlays/multicluster`、`k8s-overlays/trust`、`monitoring`、`monitoring/central`、`monitoring-overlays/remote-write-mtls`） | ✅ 全部通过（26 / 28 / 28 / 25 / 11 / 25 文档） |
| 合并结果结构校验 | PyYAML 解析构建产物，断言 25 项（base 7 + overlay 17 + 凭据 1） | ✅ **FAIL=0**（base：replicas=1、tenant-store 卷/挂载仍在、PDB `maxUnavailable=0`、无 `TENANT_STORE_PG_DSN`；overlay：replicas=2、`maxSurge=0/maxUnavailable=1`、两个 DSN 均为 `secretKeyRef` 无明文、tenant-store 卷/挂载已移除而 PVC 保留、PDB 仅 `minAvailable:1`、core 快照 env + WORM PVC） |
| YAML 语法 | 逐文件 `yaml.safe_load_all` + 内嵌 YAML 单独解析 | ✅ 通过 |
| 明文凭据扫描 | 断言 overlay 内无 `postgres://...:password@` 形态（占位符白名单） | ✅ 通过 |
| 部署资产自检脚本 | `python scripts/check-central-aggregation-assets.py` | ✅ **PASS=69 / FAIL=0 / SKIP=22，退出码 0**（SKIP 项含 promtool 未安装 → 明确标注**未做**规则语法校验） |
| 基础清单零改动 | `git diff HEAD --stat -- deploy/k8s deploy/higress deploy/monitoring/{prometheus,grafana,alertmanager,kustomization,slo-prometheusrule}.yaml` | ✅ 为空 |
| `$patch: delete` 兼容性 | kustomize v2 实测：strategic merge 列表项删除 | ✅ 可用；**注意 merge key 差异**：`volumeMounts` 的 patchMergeKey 是 **`mountPath`**（不是 `name`），`volumes` 才是 `name`——只写 `name` 会报 `does not contain declared merge key: mountPath` |

**未做 / 待环境就绪（如实标注，不得视为已验证）：**

- ❌ **未做集群验证**：本机无 Kubernetes 集群，未执行 `kubectl apply` / server-side 校验 /
  dry-run（kubectl v1.14 无 `--dry-run=server`）。
- ❌ **未做 kustomize v4/v5 构建验证**：本机只有 kubectl v1.14 内置的 kustomize v2。
  `bases` / `patchesStrategicMerge` / `patchesJson6902` 在新版标记为 deprecated 但仍可用；
  若环境报 unknown field，把 `bases` 改名为 `resources` 即可（README/文件头已注明）。
- ❌ **未验证 PVC 可绑定**：未指定 storageClassName，实际 SC 与 WORM/加密语义按环境基线确认。
- ❌ **未验证 PG 连通与迁移**：需 T-1.6 迁移 + 对账 + PG 就绪后实测。
- ❌ **未做 PG 真机验证**：tenant store 装配口径已按代码核实（§4.1），但**未在真机 PG 上跑过**
  双副本并发读写与 `verify` 对账 → 属「待环境就绪」项。
- ❌ **未做 2 副本一致性验证**：副本间租户数据/登录锁定/captcha 限流一致性需在集群实测。
- ❌ **未验证 promtool 规则语法**：本机无 promtool（自检脚本已明确 SKIP，未假装通过）。

