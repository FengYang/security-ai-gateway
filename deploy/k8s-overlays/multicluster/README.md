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

**启用前置（缺一不可）：**

| # | 前置 | 说明 |
|---|------|------|
| 1 | T-1.6 存储迁移工具已完成 SQLite → PG 迁移 + 对账 | `admin-service migrate -action plan/import/verify`；未完成即切 2 副本 = 多写者数据不一致 |
| 2 | 共享 PG 实例就绪 | 安全计数器共享库（captcha / login_attempts / mfa / 发信限频）与 tenant store 的目标库 |
| 3 | Secret `otpmask-shared-pg` 已由 KMS/Vault 注入 | **凭据禁止入库**；创建命令见 `secret-shared-pg.example.yaml`（该文件为模板，勿 apply） |
| 4 | tenant store PG **装配已接通** | 见 §4；未接通前第二副本因 `tenant-store` PVC 为 `ReadWriteOnce` 而 **Pending**（安全阀，overlay 不生效） |

目录位置说明：任务书建议的 `deploy/k8s/overlays/...` 会因 kustomize 的
`cycle detected`（base 不能是 overlay 的祖先目录）而无法构建，故置于 `deploy/k8s` 的
**同级**目录 `deploy/k8s-overlays/`，以 `../../k8s` 引用基础清单（kustomize 标准布局）。

## 2. 差异评审清单（改了什么 / 为什么 / 对默认部署的影响）

| 文件 | 改动 | 为什么 | 对默认部署影响 |
|------|------|--------|----------------|
| `kustomization.yaml` | 新增 overlay 入口（bases=基础清单 + patches） | 把 2 副本形态与默认形态隔离 | **无**（`deploy/k8s/kustomization.yaml` 未引用本目录） |
| `patch-admin-replicas.yaml` | `replicas: 1 → 2`；`strategy.maxSurge=0 / maxUnavailable=1` | 多副本是 P2 多集群/高可用的目标形态；`maxSurge=0` 保证滚动升级时**新旧 Pod 不并存**，杜绝共享库切换窗口内的双写者 | **无**（仅在本 overlay 生效） |
| `patch-admin-pdb.json.yaml` | **仅** `gateway-admin-service` 这一个 PDB：`maxUnavailable: 0` → `minAvailable: 1`（RFC6902 先删后加，目标按 kind/name/namespace 精确定位） | 基础清单中 admin PDB 位于 `deploy/k8s/gateway-admin-service.yaml:375-385`（**不在 `pdb.yaml`**），语义是「驱逐须运维显式介入」（单副本下正确）。2 副本下保留会**永久阻断**节点 drain / 滚动升级（allowedDisruptions=0）；改 `minAvailable=1` 后 2 副本允许 1 个自愿干扰，**正常驱逐不被阻断**，同时保底 1 副本承载写入 | **无**（基础文件未改；patch 只在 overlay 内应用。语义对照见 §2.1） |
| `patch-admin-security-pg-env.yaml` | 注入 `SECURITY_STORE_PG_DSN`（Secret 引用）；显式写 `TENANT_CAPTCHA_IP_RATE_PER_HOUR=30`、`LOGIN_MAX_FAIL=5`、`LOGIN_LOCK_MIN=15`（均为代码默认值，仅作口径留档） | 共享库是多副本下 captcha 限流 / 登录锁定 / MFA / 发信限频一致性的前提；空值 = 原进程内实现（默认零变化） | **无**（基础清单不含该 env，默认仍为进程内实现） |
| `patch-core-snapshot.yaml` | `GATEWAY_CORE_STORE_SNAPSHOT_PATH=/var/lib/otpmask-core/store-snapshot.json`；审计卷 `emptyDir → PVC`；新增快照卷 | 落实基础清单自身 TODO「生产须改为持久卷（WORM）」；T-1.7 快照持久化开关默认关闭（空=纯内存） | **无**（基础清单该 env 不存在） |
| `pvc-core-store.yaml` | 新增 PVC `gateway-core-audit-worm`、`gateway-core-store-snapshot`（各 1Gi，RWO，不写死 storageClassName） | 判据 7 审计链持久性 + T-1.7 快照持久性；不绑死环境专有 SC | **无**（新增资源，不进基础 kustomization） |
| `secret-shared-pg.example.yaml` | Secret 形态模板（占位值） | 说明注入方式，**禁止明文凭据入库** | **无**（不在 resources 内） |
| `patch-admin-tenant-store-pg.yaml.example` | 可选补丁（默认不启用）：tenant store 切 PG 后移除 SQLite 卷 | 与 PG DSN 成对切换，防止「半切换」 | **无**（不在 patches 内） |

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

## 4. tenant store PG：装配依赖（**未完成，写在明处**）

现状核实（2026-10，本次提交时点）：

- 双方言打开入口已就绪：`OpenTenantStoreWithDialect(sqlutil.Postgres, dsn, ...)`
  （`gateway/gateway-admin-service/tenant_store.go:397`；方言常量 `postgres` / `sqlite`，
  `sqlutil/sqlutil.go:24-26`）。
- 但**装配入口仍是固定 SQLite**：`main.go:300` 调用 `OpenTenantStore(cfg.tenantStorePath, ...)`
  → `OpenTenantStoreWithDialect(sqlutil.SQLite, ...)`。
- 结论：**当前不存在** env 驱动的 tenant store 方言选择（代码中无 `TENANT_STORE_PG_DSN`
  一类读取点；相对照，`SECURITY_STORE_PG_DSN` 已在 `config.go:230` 读取并在 `main.go:316` 装配）。

因此本 overlay **不启用** tenant store PG env（在 `patch-admin-security-pg-env.yaml` 中
以注释形式预留 `TENANT_STORE_PG_DSN`）：

- 现在置该 env **无任何效果**，却会让运维误判「已是共享库」——比不配更危险；
- 安全阀：基础清单的 `tenant-store` PVC 为 `ReadWriteOnce`，在 tenant store 仍是 SQLite 时
  **第二副本无法调度（Pending）**，不会出现双写者。即本 overlay 可提前合入但**不生效**，
  直到装配接通 + `patch-admin-tenant-store-pg.yaml.example` 启用。

装配线需要做的事（本任务为部署线，不写 Go 代码）：

1. `config.go` 增读 `TENANT_STORE_PG_DSN`（空 = SQLite，保持默认零变化）；
2. `main.go:300` 按 DSN 是否为空选择 `sqlutil.Postgres` / `sqlutil.SQLite` 调用
   `OpenTenantStoreWithDialect`；
3. 完成后取消两处注释（env + `patch-admin-tenant-store-pg.yaml.example`）并做 ≥2 副本一致性验证。

## 5. 校验方式与结果（本机）

| 项 | 方式 | 结果 |
|----|------|------|
| kustomize 构建 | `kubectl kustomize deploy/k8s-overlays/multicluster`（kubectl v1.14 内置 kustomize v2） | ✅ 通过，28 个文档 |
| 合并结果结构校验 | PyYAML 解析构建产物，断言 replicas/strategy/env/PDB/volumes/PVC | ✅ 全部符合预期（PDB 仅 `minAvailable: 1`，无 `maxUnavailable`；core `policy-audit` 仅 `persistentVolumeClaim`，无 `emptyDir`） |
| YAML 语法 | 逐文件 `yaml.safe_load_all` | ✅ 通过 |
| 明文凭据扫描 | 断言 overlay 内无 `postgres://...:password@` 形态 | ✅ 通过 |
| 基础清单零改动 | `git diff --stat deploy/k8s` | ✅ 为空 |

**未做 / 待环境就绪（如实标注，不得视为已验证）：**

- ❌ **未做集群验证**：本机无 Kubernetes 集群，未执行 `kubectl apply` / server-side 校验 /
  dry-run（kubectl v1.14 无 `--dry-run=server`）。
- ❌ **未做 kustomize v4/v5 构建验证**：本机只有 kubectl v1.14 内置的 kustomize v2。
  `bases` / `patchesStrategicMerge` / `patchesJson6902` 在新版标记为 deprecated 但仍可用；
  若环境报 unknown field，把 `bases` 改名为 `resources` 即可（README/文件头已注明）。
- ❌ **未验证 PVC 可绑定**：未指定 storageClassName，实际 SC 与 WORM/加密语义按环境基线确认。
- ❌ **未验证 PG 连通与迁移**：需 T-1.6 完成 + PG 就绪后实测。
- ❌ **未验证 tenant store PG 装配**（见 §4，代码侧尚未接通）。
