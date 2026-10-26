# P2-4 验收取证脚本（表一 6 条 · 一键留证）

> 用途：把附录 §6 **表一「验收取证待环境就绪」6 条**的取证动作脚本化。
> 环境一到，一条命令出证据，不用再逐个回忆「哪个 env 变量、哪个包、哪条命令」。
>
> 权威登记：[附录-验收前置与待环境就绪清单](../verify/multicluster/2026-10-26-p2-4-附录-验收前置与待环境就绪清单.md) §6。
> 收口报告：[T-6.3 验收评审报告](../verify/multicluster/2026-10-26-p2-4-T-6.3-验收评审报告.md)。

## 1. 映射表（表一 6 条 → 6 个脚本）

| 登记项 | 脚本 | 能自动化的部分 | **只能人工的部分** |
|---|---|---|---|
| `PRE-A-17` | `e1-pg-gates.sh` | 跑全部 PG 门控用例 + 断言无 SKIP + 采集 PG 版本/表清单 | 判定用例失败是否属实现缺陷 |
| `PRE-B-1~4` | `e2-pg-drill.sh` | 库侧事实（权限/加密/复制/归档/表）+ `migrate plan\|verify` | 双跑切换、PITR 恢复、主从切换（要动库） |
| `PRE-B-5` | `e3-multicluster.sh` | 两集群可达性/工作负载/cluster 标签/registry 心跳采样 | 注册审批、V-4 跨集群查询量级对比 |
| `PRE-B-6` | `e4-replica-consistency.sh` | 副本数、共享库指向、并发探测 | PG 断连降级实测、锁定阈值折算、captcha 全局计数 |
| `PRE-B-7` | `e5-failover.sh` | **委派** `scripts/drills/d5-admin-geo-failover.sh` 并把证据归位 | 分区期间写入侧唯一性判断 |
| `PRE-B-9` | `e6-batch2-assets.sh` | NP 三档 apply/探测/**回滚**、接收端 HTTP 码、Secret 卷 0440/0400 读权限 | 跨命名空间放行项的现场核对 |

**为什么有的项只做到"编排 + 待填清单"**：双跑切换、PITR、主从切换都要在客户的库上做破坏性动作，
脚本替人做等于绕过变更管控。这类项脚本只把机器可采的事实钉住，人工结论留 `TODO(人工)` 占位。

## 2. 退出码（与 `scripts/drills/_lib.sh` 同一套语义）

| 码 | 含义 | 能否作为验收证据 |
|---|---|---|
| 0 | 通过（skip 项不拦截，但会在报告里列出） | ✅ 可 |
| 1 | 存在失败步骤 | ❌ 须先修 |
| 2 | 参数/初始化错误 | ❌ |
| 3 | **环境前置不满足**（= 没跑成） | ❌ **绝不可当闭环证据** |

> `3` 与 `0` 的严格区分是这套脚本的核心纪律：**没跑 ≠ 通过**。

## 3. 用法

```bash
# 单条
./scripts/p24-evidence/e1-pg-gates.sh --dsn 'postgres://u:p@h:5432/db?sslmode=require'
./scripts/p24-evidence/e6-batch2-assets.sh --tier all --secret-dir ./certs

# 全部（不含需要显式确认的破坏性项）
./scripts/p24-evidence/run-all.sh --dsn "$PG_DSN"

# 先看会做什么（不产生任何变更）
./scripts/p24-evidence/e1-pg-gates.sh --dry-run
```

## 4. 证据归位

- 默认输出 `<repo>/docs/verify/multicluster/evidence/<PRE 编号>/<时间戳>/`，内含
  `steps.jsonl`（逐步记录，机器可读）、`report.json`（结论 + 退出码 + 耗时）、`evidence.md`（人工补填骨架）。
- **脚本只写文件不提交**。归档由执行人决定：`cd docs && git add verify/multicluster/evidence/<...>`。
- ⚠️ **`--dry-run` 的产物不是证据**：其 `report.json` 里 `executed=false`，`evidence.md` 首行也标注
  「dry-run 不得作为验收证据」。清理：`rm -rf docs/verify/multicluster/evidence/<PRE 编号>`。

## 5. 与 `scripts/drills/` 的关系

- 共用公共库 `scripts/drills/_lib.sh`（退出码、步骤记录、证据骨架、dry-run 语义）——**不复制第二套**。
- `scripts/drills/d1~d5` 是**演练编排**（关注故障注入与 RTO 测量）；
  本目录是**验收取证**（关注"表一那 6 条到底拿没拿到证据"）。
  `PRE-B-7` 的演练本体就是 `d5`，本目录只做委派 + 归位，避免两套实现漂移。
- 证据落点不同：drills 默认 `scripts/drills/.runs/`（不进库）；本目录默认 `docs/.../evidence/`（随 docs 归档）。

## 6. 已知限制（写在这里，不留给现场发现）

- `e1` 要求 Go ≥ 1.26（`gateway/go.mod`）：本机 Windows Go 1.20 无法编译 → 在 `.248` 或 CI 跑。
- `e4` 的并发探测用 `kubectl port-forward`，高并发下 port-forward 本身可能成为瓶颈，
  它只用于"看有没有个别副本异常"，**不能当作性能压测**。
- `e6` 的 `--tier` 默认不测：apply NP 会改变真实网络行为，必须显式确认（三档加性，且残留会污染后续判断）。
- 全部脚本**未在本机真实集群验证过**（本机无 K8s）——它们的 dry-run 与语法已验证，
  真实执行路径属 `PRE-B-9`/`PRE-B-5` 的取证内容本身。
