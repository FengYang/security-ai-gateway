> English ｜ [中文](./README.md)

# P2-4 acceptance-evidence scripts (Table 1's 6 items · one-click evidence capture)

> Purpose: script the evidence-capture actions of Appendix §6 **Table 1 "acceptance-evidence pending environment readiness" 6 items**.
> When the environment is ready, one command produces evidence, no need to recall "which env var, which package, which command".
>
> Authoritative registration: [Appendix - acceptance prerequisites and pending-environment-readiness list](../verify/multicluster/2026-10-26-p2-4-附录-验收前置与待环境就绪清单.md) §6.
> Closing report: [T-6.3 acceptance review report](../verify/multicluster/2026-10-26-p2-4-T-6.3-验收评审报告.md).

## 1. Mapping table (Table 1's 6 items → 6 scripts)

| Registered item | Script | Part that can be automated | **Part that can only be done manually** |
|---|---|---|---|
| `PRE-A-17` | `e1-pg-gates.sh` | Run all PG gate cases + assert no SKIP + collect PG version/table list | Judge whether a failed case is an implementation defect |
| `PRE-B-1~4` | `e2-pg-drill.sh` | DB-side facts (permissions/encryption/replication/archive/tables) + `migrate plan\|verify` | Dual-run switchover, PITR recovery, primary-replica switchover (touches the DB) |
| `PRE-B-5` | `e3-multicluster.sh` | Two-cluster reachability/workloads/cluster label/registry heartbeat sampling | Registration approval, V-4 cross-cluster query magnitude comparison |
| `PRE-B-6` | `e4-replica-consistency.sh` | Replica count, shared-library target, concurrent probing | PG-disconnect degradation test, lockout-threshold scaling, captcha global counting |
| `PRE-B-7` | `e5-failover.sh` | **Delegates** `scripts/drills/d5-admin-geo-failover.sh` and places evidence | Uniqueness judgment on the write side during partitioning |
| `PRE-B-9` | `e6-batch2-assets.sh` | NP three-tier apply/probe/**rollback**, receiver HTTP codes, Secret-volume 0440/0400 read permission | On-site confirmation of cross-namespace allow items |

**Why some items only reach "orchestration + to-be-filled checklist"**: dual-run switchover, PITR, primary-replica switchover all do destructive actions on the customer's DB;
the script doing it for you equals bypassing change control. For such items the script only nails down the machine-collectable facts, manual conclusions left as `TODO(manual)` placeholders.

## 2. Exit codes (same semantics as `scripts/drills/_lib.sh`)

| Code | Meaning | Can it serve as acceptance evidence |
|---|---|---|
| 0 | Passed (skip items do not block, but are listed in the report) | ✅ Yes |
| 1 | A failed step exists | ❌ Must fix first |
| 2 | Parameter/initialization error | ❌ |
| 3 | **Environment prerequisite not met** (= did not run) | ❌ **Never treat as closed-loop evidence** |

> The strict distinction between `3` and `0` is this suite's core discipline: **not run ≠ passed**.

## 3. Usage

```bash
# Single item
./scripts/p24-evidence/e1-pg-gates.sh --dsn 'postgres://u:p@h:5432/db?sslmode=require'
./scripts/p24-evidence/e6-batch2-assets.sh --tier all --secret-dir ./certs

# All (excluding destructive items needing explicit confirmation)
./scripts/p24-evidence/run-all.sh --dsn "$PG_DSN"

# First see what it will do (no changes produced)
./scripts/p24-evidence/e1-pg-gates.sh --dry-run
```

## 4. Evidence placement

- **Real execution** defaults output to `<repo>/docs/verify/multicluster/evidence/<PRE number>/<timestamp>/`, containing
  `steps.jsonl` (step-by-step records, machine-readable), `report.json` (conclusion + exit code + elapsed), `evidence.md` (manual-fill skeleton).
- **The script only writes files, does not commit**. Archiving is decided by the executor: `cd docs && git add verify/multicluster/evidence/<...>`.
- ⚠️ **`--dry-run` artifacts auto-divert to `scripts/drills/.runs/ga-multicluster-drills/p24-evidence/` (not into repo)**,
  will not pollute the docs evidence dir — this is deliberate: once a dry-run result lands in `evidence/`, a successor easily mistakes it for "already evidenced".
  Its `report.json` has `executed=false`.
- ⚠️ **`exit 3` (environment not ready) will normally write docs** (it records a "environment not ready at that time"). Such dirs'
  `report.json` is `"result":"env_unmet","exit_code":3`, **should be deleted before archiving**, otherwise it is misread as evidence:
  `rm -rf docs/verify/multicluster/evidence/<PRE number>`.

## 5. Relationship with `scripts/drills/`

- Shares the common library `scripts/drills/_lib.sh` (exit codes, step recording, evidence skeleton, dry-run semantics) — **do not duplicate a second set**.
- `scripts/drills/d1~d5` are **drill orchestration** (focus on fault injection and RTO measurement);
  this directory is **acceptance evidence** (focus on "did we actually get evidence for those 6 items in Table 1").
  `PRE-B-7`'s drill body is `d5`; this directory only delegates + places, avoiding two implementations drifting.
- Evidence landing differs: drills default to `scripts/drills/.runs/` (not into repo); this directory defaults to `docs/.../evidence/` (archived with docs).

## 6. Known limitations (written here, not left for on-site discovery)

- `e1` requires Go ≥ 1.26 (`gateway/go.mod`): local Windows Go 1.20 cannot compile → run on `.248` or CI.
- `e4`'s concurrent probing uses `kubectl port-forward`; under high concurrency port-forward itself may become a bottleneck,
  it is only for "seeing whether any individual replica is abnormal", **cannot be used as a performance stress test**.
- `e6`'s `--tier` defaults to not testing: applying NP changes real network behavior, must be explicitly confirmed (three tiers are additive, and residue pollutes later judgment).
- All scripts **not verified on a real cluster locally** (no K8s locally) — their dry-run and syntax have been verified,
  the real execution path belongs to the evidence content of `PRE-B-9`/`PRE-B-5` itself.
