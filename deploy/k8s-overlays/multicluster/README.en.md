> English ｜ [中文](./README.md)

# P2-4 T-1.10: Multi-replica / shared-library deployment overlay (default single-replica unchanged)

> This directory is an **optional overlay**. The base manifests `deploy/k8s/**` are **unchanged** (the default deployment semantics are absolutely unchanged); only explicitly running `kubectl apply -k deploy/k8s-overlays/multicluster` switches to the 2-replica form.

## 1. Usage and enablement prerequisites

```bash
# Default (unchanged, C-18 single-replica hard constraint)
kubectl apply -k deploy/k8s

# This overlay
kubectl apply -k deploy/k8s-overlays/multicluster
```

### 1.0 Atomic switch unit (**cannot be split**, team-lead ruling ①)

> **This overlay is an atomic switch unit of "replica count increase + shared-library switch": the two must take effect together.**
> There is **no** intermediate form of "just add replicas, don't switch the shared library" — because the base PVC
> `gateway-admin-tenant-store` is `ReadWriteOnce` (`deploy/k8s/gateway-admin-service.yaml:355-368`),
> **2 replicas + SQLite volume ⇒ the second replica will necessarily be Pending (unschedulable)**; such an intermediate form is itself unusable.

| Form | Replicas | tenant store | Second replica schedulable | Delivers value |
|------|--------|-------------|---------------|-------------|
| Default deployment (don't apply overlay) | 1 | SQLite | — | ✅ Single-replica form, normal |
| **Only add replicas, don't switch PG** (no such deliverable) | 2 | SQLite | ❌ **Pending** (RWO) | ❌ **No value**: unusable form, only creates the misuse risk of "thinking you can just add replicas" |
| **This overlay (atomic switch)** | 2 | **PG shared library** (SQLite volume removed) | ✅ Schedulable | ✅ Target form |

**Therefore**: under a `ReadWriteOnce` volume you **must switch the shared library (PG) first** before raising the replica count;
`kubectl apply -k deploy/k8s-overlays/multicluster` is the **only** entry point into the 2-replica form.
**Do not** manually change only `replicas` or only delete the PVC (that would create dual writers or an unschedulable replica).

**Enablement prerequisites (all required):**

| # | Prerequisite | Description |
|---|------|------|
| 1 | T-1.6 storage migration tool has completed SQLite → PG migration + reconciliation | `admin-service migrate -action plan/import/verify`; switching to 2 replicas before completion = multi-writer data inconsistency |
| 2 | Shared PG instance is ready | Target library for the secure counter shared library (captcha / login_attempts / mfa / send-rate-limit) and the tenant store |
| 3 | Secret `otpmask-shared-pg` has been injected via KMS/Vault | **Credentials must not be stored in the repo**; creation command see `secret-shared-pg.example.yaml` (this file is a template, do not apply) |
| 4 | tenant store PG wiring is connected | ✅ **Already satisfied** (T-1.2b, landed 2026-10-26: `main.go` → `openTenantStoreForConfig`, non-empty PG routes to PG, PG open failure = fail-closed, refuse to start). See §4 for the wording |

**Migration order (hard requirement, do not reverse):**

```
① Inside the old form (single replica + SQLite volume): first complete one startup with the [new version] (schema auto-upgrades)
   └─ Otherwise new tables are missing from the source library → export loses tables
     (the migration tool already added fail-closed validation and wrote it into the migrate help text; skipping this step is rejected)
② Still inside the old form: admin-service migrate -action plan|export|import|verify
   └─ Source SQLite path given explicitly via -from, target PG given via -to (the migration tool does not read env)
③ After verify reconciliation passes: kubectl apply -k deploy/k8s-overlays/multicluster
   └─ PG DSN takes effect + SQLite volume removed + replicas 2
```

Reverse order (remove the SQLite volume before migrating) → the source SQLite file is unreachable, migration cannot run, data invisible;
skipping ① (did not first start with the new version to upgrade schema) → new tables absent from the source library, migration **loses tables**.

Directory location note: the `deploy/k8s/overlays/...` suggested by the task spec would fail kustomize's
`cycle detected` (the base cannot be an ancestor directory of an overlay), so it is placed in a **sibling** directory of `deploy/k8s`,
`deploy/k8s-overlays/`, referencing the base manifests via `../../k8s` (standard kustomize layout).

## 2. Diff review checklist (what changed / why / impact on default deployment)

| File | Change | Why | Impact on default deployment |
|------|------|--------|----------------|
| `kustomization.yaml` | New overlay entry (bases=base manifests + patches) | Isolate the 2-replica form from the default form | **None** (`deploy/k8s/kustomization.yaml` does not reference this directory) |
| `patch-admin-replicas.yaml` | `replicas: 1 → 2`; `strategy.maxSurge=0 / maxUnavailable=1` | Multi-replica is the P2 multi-cluster / high-availability target form; `maxSurge=0` guarantees that during rolling updates **old and new Pods never coexist**, eliminating dual writers during the shared-library switch window | **None** (only takes effect within this overlay) |
| `patch-admin-pdb.json.yaml` | **Only** this one PDB for `gateway-admin-service`: `maxUnavailable: 0` → `minAvailable: 1` (RFC6902 delete-then-add, target precisely located by kind/name/namespace) | The admin PDB in the base manifest is at `deploy/k8s/gateway-admin-service.yaml:375-385` (**not in `pdb.yaml`**), its semantics being "eviction requires explicit ops intervention" (correct under single replica). Under 2 replicas keeping it would **permanently block** node drain / rolling updates (allowedDisruptions=0); changing to `minAvailable=1` allows 1 voluntary disruption under 2 replicas, **normal eviction is not blocked**, while guaranteeing 1 replica serves writes | **None** (base file unchanged; patch only applied within overlay. Semantics comparison see §2.1) |
| `patch-admin-security-pg-env.yaml` | Inject `SECURITY_STORE_PG_DSN`, `TENANT_STORE_PG_DSN` (**both Secret references, no plaintext**); explicitly write `TENANT_CAPTCHA_IP_RATE_PER_HOUR=30`, `LOGIN_MAX_FAIL=5`, `LOGIN_LOCK_MIN=15` (all code defaults, kept only as wording record) | Shared library is the prerequisite for captcha rate limiting / login lockout / MFA / send-rate-limit / tenant-data consistency under multi-replica; empty value = original in-process implementation (default zero change) | **None** (base manifest does not contain these two env vars, default remains in-process implementation + SQLite) |
| `patch-admin-tenant-store-pg.yaml` | Remove the tenant store's SQLite volume and mount (`volumeMounts` / `volumes` list items `$patch: delete`) | Once the tenant store has switched to PG, the local SQLite is no longer needed; the base PVC `gateway-admin-tenant-store` is `ReadWriteOnce`, keeping it mounted would make the **second replica Pending across nodes**, and combined with `replicas=2 + maxSurge=0` would stall the rolling update. PVC **kept, not deleted** (rollback path usable, and the volume is encrypted) | **None** (only takes effect within this overlay; base manifest zero change) |
| `patch-core-snapshot.yaml` | `GATEWAY_CORE_STORE_SNAPSHOT_PATH=/var/lib/otpmask-core/store-snapshot.json`; audit volume `emptyDir → PVC`; add snapshot volume | Fulfills the base manifest's own TODO "production must use a persistent volume (WORM)"; T-1.7 snapshot persistence switch defaults to off (empty = pure memory) | **None** (this env var does not exist in the base manifest) |
| `pvc-core-store.yaml` | New PVCs `gateway-core-audit-worm`, `gateway-core-store-snapshot` (1Gi each, RWO, no hardcoded storageClassName) | Criterion 7 audit-chain durability + T-1.7 snapshot durability; do not hardcode environment-specific SC | **None** (new resource, not added to base kustomization) |
| `secret-shared-pg.example.yaml` | Secret shape template (placeholder values) | Document the injection method, **forbid plaintext credentials in repo** | **None** (not in resources) |

**Net impact on the default deployment: 0.** Verified by building the base directory and the overlay separately with `kubectl kustomize` and comparing;
the base manifest files had **zero changes** in this commit (`git diff --stat deploy/k8s` is empty).

### 2.1 PDB semantics and applicable boundary (verification conclusion)

**First, correct one point of wording**: there are **two** PDBs in the base manifest, of different natures, and neither was changed this time:

| Location | Object | Semantics | Change this time |
|------|------|------|----------|
| `deploy/k8s/pdb.yaml` | `embedding-service-pdb` / `tee-infer-service-pdb` / `envoy-gateway-pdb` | All `minAvailable: 1` (regular floor, independent of replica count) | **Unchanged** (this overlay's PDB patch does not touch them) |
| `deploy/k8s/gateway-admin-service.yaml:375-385` | `gateway-admin-service` | `maxUnavailable: 0` (companion to C-18 single-replica hard constraint: eviction requires explicit ops intervention) | **Unchanged**; this overlay uses RFC6902 to change only this one entry **within the overlay** |

Therefore the statement "the base `pdb.yaml` was synced to `minAvailable: 1`" does **not hold**:
`pdb.yaml` was already `minAvailable: 1` (no adjustment needed), while the admin PDB is located in
`gateway-admin-service.yaml` and **remains `maxUnavailable: 0`** — this is **intentionally preserved**,
because the base form is single-replica, and `maxUnavailable: 0` is exactly the expression of "eviction requires explicit intervention";
if you changed it to `minAvailable: 1` in the base manifest, you would instead **silently loosen** the disruption budget of the default deployment.

**Are the base and overlay semantics equivalent?** (per allowedDisruptions = max(0, minAvailable − expected available))

| Form | Base (overlay not applied) | After overlay applied | Equivalent |
|------|------------------------|----------------|----------|
| Single replica (default deployment) | `maxUnavailable: 0` → disruptions = 0 | `minAvailable: 1` + replicas=1 → disruptions = max(0, 1-1) = 0 | ✅ **Behavior equivalent** (both block voluntary eviction, neither loosens the writer exclusivity) |
| 2 replicas (overlay target form) | `maxUnavailable: 0` → disruptions = 0 (**permanently blocks drain/rolling**) | `minAvailable: 1` → disruptions = 1 (normal eviction proceeds) | ❌ Not equivalent (this is exactly why the overlay must change the PDB) |

**Applicable boundary (important):**

- Default deployment (overlay not applied): still `maxUnavailable: 0` + single replica → voluntary eviction blocked,
  node drain must be explicitly intervened by ops (original intent of C-18, **not changed by this commit**).
- This overlay: replicas=2 + `minAvailable: 1` → allows 1 voluntary disruption, **normal eviction not blocked**.
- ⚠️ **Single replica + `minAvailable: 1` also blocks voluntary eviction** (disruptions = 0).
  That is: misapplying this overlay to a 1-replica environment **will not** loosen the disruption budget, but because the same overlay's
  `replicas=2` patch also applies, it becomes 2 replicas — therefore this overlay must be used **as a set** with the prerequisites of §1
  (T-1.6 migration complete, PG ready, tenant store PG wiring connected),
  and **must not** be applied alone in a single-replica environment where the prerequisites are unmet.

## 3. Wording records

### 3.1 Captcha issuance rate limiting (P3-5)
`TENANT_CAPTCHA_IP_RATE_PER_HOUR ≤ 0 = disable issuance rate limiting` (consistent on both memory and PG sides,
`config.go:225-226`, default 30). **Production must not set 0**; under multi-replica only by routing through the PG shared library
is the per-IP count globally consistent (in-process count gets multiplied by the replica count).

### 3.2 Login-failure lockout: multiplied by replica count during shared-library degradation (P2-1 ruling)
- Normal (PG shared library online): `LOGIN_MAX_FAIL` is a **global** count, independent of replica count.
- **During degradation** (PG unreachable → fall back to in-process implementation): each replica counts independently, so the attacker's actual allowed attempts
  ≈ `replica count × LOGIN_MAX_FAIL` (this overlay's 2 replicas ≈ 2×). This is a **known risk** recorded in the P2-1 ruling,
  and must not be masked by loosening thresholds.
- Therefore this overlay **does not modify** `LOGIN_MAX_FAIL=5` / `LOGIN_LOCK_MIN=15`, it only makes the wording explicit;
  if a threshold change is genuinely needed under multi-replica, it must go through the P2-1 ruling's change record and update monitoring accordingly.

**Monitoring requirements (mandatory for multi-replica deployments):**

| Monitoring item | Suggested wording | Action |
|--------|----------|------|
| Shared-library degradation (PG unreachable / fell back to in-process) | New alert: degradation signal persisting > 5m = **critical** (same source as S1(7) in-process-state inventory) | Restore PG immediately; before restoration, scale lockout strength by replica count |
| Login-failure rate | `rate(login_fail_total[5m])` scaled by replica count: under 2 replicas observe threshold as `2 × LOGIN_MAX_FAIL` | Exceeds → manual intervention |
| Replica readiness | `kube_deployment_status_replicas_ready` persistently < 2 → warning | Investigate Pending caused by unready PVC/PG |
| Captcha issuance rate-limit hits | captcha rate-limit rejection count aggregated by IP rising abnormally → warning | Rule out bypass and brute force |

## 4. tenant store PG: wiring connected (verified by actual read on 2026-10-26) + this overlay's landing actions

### 4.1 Wiring-side facts (read from code, not memory)

The wiring **T-1.2b has landed** (main repo commit `5cc0d6b`, 2026-10-26), verification conclusion:

| Item | Fact | Source |
|----|------|------|
| Dual-dialect open entry | `OpenTenantStoreWithDialect(sqlutil.Postgres, dsn, true, pepper)`; the SQLite branch `OpenTenantStore(path, ...)` is verbatim unchanged | `gateway/gateway-admin-service/tenant_store.go:454-466` |
| env-driven dialect selection | `TENANT_STORE_PG_DSN` non-empty → PG; else `TENANT_STORE_PATH` non-empty → SQLite; both empty → portal not enabled | `config.go:198-215`, `tenant_store_open.go:26-34` |
| Wiring entry | `main.go:299-305` → `openTenantStoreForConfig(cfg)` (the original gap where `OpenTenantStore(cfg.tenantStorePath, ...)` fixed SQLite is filled) | `main.go:297-305` |
| **fail-closed** | PG open / table-create failure → `log.Fatalf` **refuses to start**, does not silently fall back to local storage | `main.go:302-305`, `tenant_store_open.go:12-16` |
| **PG priority** | When both configured, both `cfg` fields **are kept**, runtime selects by PG ⇒ the base manifest's `TENANT_STORE_PATH` can be kept (lazy env) | `tenant_store_pg_wiring_test.go` case ④ |
| pepper guarantee | `TENANT_TOKEN_PEPPER` is injected by the base manifest via `secretKeyRef` (non-optional); missing/short → fail-closed | `deploy/k8s/gateway-admin-service.yaml:114-118`, `config.go:205-211` |
| PG-side table creation | `openPostgresTenantStore` executes DDL to create tables (`create=true`), **does not write a local SQLite file** | `tenant_store.go:460-466` |

### 4.2 This overlay's landing actions (this commit)

1. `patch-admin-security-pg-env.yaml`: **uncomment** `TENANT_STORE_PG_DSN` (Secret reference, no plaintext credentials);
2. `patch-admin-tenant-store-pg.yaml` (**converted from `.example` to enabled**): remove the tenant store's
   SQLite volume and mount (`$patch: delete`; `volumeMounts`' merge key is `mountPath`,
   `volumes`' is `name` — **writing only `name` raises "does not contain declared merge key"**).

**Why the switch must be paired**: the base PVC `gateway-admin-tenant-store` is `ReadWriteOnce`
(`deploy/k8s/gateway-admin-service.yaml:355-368`). After switching to PG this volume no longer carries data,
keeping it mounted would make the second replica Pending across nodes; combined with `replicas=2 + maxSurge=0 + maxUnavailable=1`,
the rolling update would stall at "1 available" and cannot proceed. ⇒ Under the PG form the volume and mount are **removed as a pair**.

**PVC kept, not deleted**: the rollback path remains usable (when rolling back to the SQLite form the original volume and data are still there), and the volume is encrypted
(`storageClassName: tee-encrypted`); residual SQLite does not violate the plaintext-on-disk constraint. After acceptance passes, ops deletes it manually (an environment operation, not part of this repo's assets).

### 4.3 Difference from the old wording (**fact correction**)

The previous README's statement "the wiring entry still hard-codes SQLite (`main.go:300`), and the code has no `TENANT_STORE_PG_DSN`
read point" **no longer holds** (T-1.2b landed). Also correct a past misjudgment:

> The old text said "setting `TENANT_STORE_PATH` empty closes the entire tenant portal" — **wrong**.
> After T-1.2b it is judged as "only when **both** `TENANT_STORE_PATH` and `TENANT_STORE_PG_DSN` are empty is the portal closed",
> so `TENANT_STORE_PATH` empty + PG DSN non-empty = portal enabled and routes through PG.

### 4.4 Rollback method

Remove `patch-admin-tenant-store-pg.yaml` from `kustomization.yaml`'s `patchesStrategicMerge`,
and correspondingly comment out `TENANT_STORE_PG_DSN` in `patch-admin-security-pg-env.yaml`
→ return to the SQLite single-replica form (the volume and mount automatically return to original via the base manifest).

## 5. Verification methods and results (local)

| Item | Method | Result |
|----|------|------|
| kustomize build | `kubectl kustomize deploy/k8s-overlays/multicluster` (kubectl v1.14 built-in kustomize v2) | ✅ Passed, 28 documents |
| Whole-tree build | `kubectl kustomize` × 6 dirs (`deploy/k8s`, `k8s-overlays/multicluster`, `k8s-overlays/trust`, `monitoring`, `monitoring/central`, `monitoring-overlays/remote-write-mtls`) | ✅ All passed (26 / 28 / 28 / 25 / 11 / 25 documents) |
| Merged-output structure check | PyYAML parse the build output, assert 25 items (base 7 + overlay 17 + credentials 1) | ✅ **FAIL=0** (base: replicas=1, tenant-store volume/mount still present, PDB `maxUnavailable=0`, no `TENANT_STORE_PG_DSN`; overlay: replicas=2, `maxSurge=0/maxUnavailable=1`, both DSNs are `secretKeyRef` no plaintext, tenant-store volume/mount removed while PVC kept, PDB only `minAvailable:1`, core snapshot env + WORM PVC) |
| YAML syntax | Per-file `yaml.safe_load_all` + separately parse embedded YAML | ✅ Passed |
| Plaintext credential scan | Assert no `postgres://...:password@` form in the overlay (placeholder whitelist) | ✅ Passed |
| Deployment-asset self-check script | `python scripts/check-central-aggregation-assets.py` | ✅ **PASS=69 / FAIL=0 / SKIP=22, exit code 0** (SKIP items include promtool not installed → explicitly labeled **not done**, rule-syntax check) |
| Base manifest zero change | `git diff HEAD --stat -- deploy/k8s deploy/higress deploy/monitoring/{prometheus,grafana,alertmanager,kustomization,slo-prometheusrule}.yaml` | ✅ Empty |
| `$patch: delete` compatibility | kustomize v2 actual test: strategic-merge list-item deletion | ✅ Usable; **note the merge-key difference**: `volumeMounts`' patchMergeKey is **`mountPath`** (not `name`), `volumes`' is `name` — writing only `name` raises `does not contain declared merge key: mountPath` |

**Not done / pending environment readiness (stated as-is, must not be treated as verified):**

- ❌ **No cluster verification**: no Kubernetes cluster locally, did not run `kubectl apply` / server-side validation /
  dry-run (kubectl v1.14 has no `--dry-run=server`).
- ❌ **No kustomize v4/v5 build verification**: only kubectl v1.14 built-in kustomize v2 locally.
  `bases` / `patchesStrategicMerge` / `patchesJson6902` are marked deprecated in newer versions but still usable;
  if the environment reports an unknown field, rename `bases` to `resources` (noted in README/file headers).
- ❌ **No PVC bindability verification**: storageClassName unspecified, actual SC and WORM/encryption semantics to be confirmed against the environment baseline.
- ❌ **No PG connectivity and migration verification**: requires T-1.6 migration + reconciliation + PG ready before real testing.
- ❌ **No real-PG verification**: the tenant store wiring wording was verified against code (§4.1), but **never run on a real PG**
  for dual-replica concurrent read/write and `verify` reconciliation → belongs to the "pending environment readiness" items.
- ❌ **No 2-replica consistency verification**: inter-replica tenant-data / login-lockout / captcha rate-limit consistency needs cluster testing.
- ❌ **No promtool rule-syntax verification**: no promtool locally (self-check script explicitly SKIPs, does not pretend to pass).
