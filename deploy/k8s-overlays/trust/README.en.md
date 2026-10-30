> English ｜ [中文](./README.md)

# P2-4 T-4.3: Cross-cluster channel trust — **audit-chain export endpoint** (per-cluster side)

> Provides the deployment-side wiring for the audit-chain export endpoint implemented in T-4.2: switch, credential references, source whitelist,
> optional network boundary. **Zero impact on the default deployment**: `deploy/k8s/**` is unchanged; this overlay must be applied explicitly.

## 1. Correspondence with the T-4.2 export-endpoint switches (aligned line-by-line with code wording)

| Component | T-4.2 switch | Semantics (T-4.2 code original wording) | Value source in this overlay |
|------|------------|----------------------------|----------------------|
| gateway-core | `GATEWAY_CORE_AUDIT_EXPORT_ENABLED` | Only `1\|true\|yes\|on` enables; otherwise = route not registered → 404 | Set `"1"` (actively enable) |
| gateway-core | `GATEWAY_CORE_AUDIT_EXPORT_CIDRS` | Source IP CIDR whitelist; **empty when enabled → refuse to start** (fail-closed) | ConfigMap `gateway-core-audit-export/cidrs` |
| gateway-core | `GATEWAY_CORE_AUDIT_EXPORT_TOKEN` | Static Bearer token; **empty = deny-all (all 403)** | Secret `otpmask-audit-export/export-token` |
| gateway-core | `GATEWAY_CORE_AUDIT_EXPORT_MAX` | Max rows per single export (protects the inference plane) | Set `10000` |
| tee-infer-service | `-audit-export-enabled` | Unset = route not registered → 404 (default off) | Append arg `"-audit-export-enabled"` |
| tee-infer-service | `-audit-export-cidrs` | Source CIDR whitelist; **empty when enabled → refuse to start** | Append arg `$(AUDIT_EXPORT_CIDRS)` ← ConfigMap |
| tee-infer-service | `-audit-export-token` | Static Bearer token; **empty = deny-all** | Append arg `$(AUDIT_EXPORT_TOKEN)` ← Secret (**does not appear in the ps command line**) |
| tee-infer-service | `-audit-export-max` | Max rows per single export | Append arg `"10000"` |

**T-2.3 dependency**: `TokenAuthorizer` is a **temporary integration wording**. After T-2.3 "cluster identity credentials (issue/verify/rotate/revoke)"
lands, it should replace the token auth; at that point this overlay's TOKEN reference gets replaced/deleted accordingly.

**Why tee uses JSON6902 instead of strategic merge**: the container `args` is a **string list with no merge key**,
strategic merge would **replace the whole args** → existing parameters (`-sig-key`/`-attest-token`/`-output-guard`/
`-cmaas-url`/`-cmaas-model`/`-dev-mode`) get cleared → service cannot start. So the patch only does "append".

## 2. Enablement steps

```bash
# ① Inject source whitelist (placeholder values must be replaced; not replaced → invalid CIDR → application-layer refuse to start)
kubectl -n otpmask apply -f deploy/k8s-overlays/trust/configmap-audit-export-cidrs.yaml
kubectl -n otpmask patch configmap gateway-core-audit-export \
  --type=merge -p '{"data":{"cidrs":"10.20.0.0/16"}}'
kubectl -n otpmask patch configmap tee-infer-audit-export \
  --type=merge -p '{"data":{"cidrs":"10.20.0.0/16"}}'

# ② Inject token (plaintext credentials forbidden in repo; template see secret-audit-export.example.yaml, do not apply)
kubectl -n otpmask create secret generic otpmask-audit-export \
  --from-literal=export-token="$(vault kv get -field=export-token secret/otpmask/audit-export)"

# ③ Apply overlay (open endpoint + reference credentials)
kubectl apply -k deploy/k8s-overlays/trust
```

## 3. Default-deny wording (three layers; any layer missing = deny)

| Layer | Mechanism | Default behavior |
|----|------|----------|
| Application layer: switch | `*_AUDIT_EXPORT_ENABLED` unset → **route not registered** → 404 | Endpoint does not exist (zero new attack surface) |
| Application layer: source | CIDR whitelist empty → **refuse to start**; non-matching source → 403 | No "enable = fully open" |
| Application layer: authorization | Token empty → **deny-all** (all 403) | No token = all denied |
| Network layer (optional) | `networkpolicy-audit-export-ingress.yaml` deny-by-default ingress + whitelist | **Disabled by default** (see §4) |

## 4. Network boundary: why "disabled by default" for that NetworkPolicy

- The export endpoint and the business endpoint share the **same port** (gateway-core `8085`, tee-infer `19090`), and NetworkPolicy is
  L3/L4, **cannot whitelist the export by URL path** while allowing the business → can only converge the source as a whole;
- Converging the whole port would simultaneously constrain: plugin table pull (via Higress McpBridge DNS registry), admin-service policy push,
  gateway-core→tee quota push, envoy→tee inference forwarding, Prometheus scrape;
- **If the allowlist is incomplete it accidentally harms the data plane** (plugin table pull fails → keeps old table; quota/scrape fails → observability gap);
- And the true namespace/labels of the Higress-side Pods belong to the **P1-8 domain**, this task must not modify `deploy/higress/**`
  → will not fabricate labels.

Therefore: `networkpolicy-audit-export-ingress.yaml` is delivered separately as **optional defense-in-depth**,
before enabling you must complete its file-header "pre-enablement checklist" (7 items) item by item, and it is recommended to first apply in a test cluster and observe for 15 minutes,
reverting immediately with `kubectl delete networkpolicy` if anything is abnormal.

### 4.1 Three tiers (classified by "whom to allow", added 2026-10-26)

A single policy cannot cover all forms (single cluster / multi-cluster / collector outside the cluster), so **three tiers** are provided,
see [`networkpolicy-tiers/`](networkpolicy-tiers/README.md) (includes the **port matrix** and selection criteria):

| Tier | Allowed source | Applicable |
|---|---|---|
| 1 minimal | Only necessary intra-namespace calls | Single cluster, no cross-cluster collection |
| 2 standard | ＋ plugin namespace ＋ central collector (pod label) | Multi-cluster + central aggregation (**recommended**) |
| 3 permissive | ＋ source CIDR range (`ipBlock`) | Collector has no label / outside cluster / via SNAT |

- **Use only one tier per workload**: NetworkPolicy is **additive**, stacking equals taking the wider tier, and "tier" loses meaning.
- Choose one of this §4 single-file policy **or** the three tiers (single file ≈ predecessor of tier 2); new deployments use the three tiers directly.
- The three tiers are also **disabled by default** (not in the kustomization `resources`); you need `kubectl apply -f` per tier.

## 5. The channel boundary on the cluster side lives on the central side

Cross-cluster collection is a **new trust surface**, so its network-boundary convergence is on the **central side**
(`deploy/monitoring/central/trust/networkpolicy-central-collector-egress.yaml`:
collector egress deny-by-default + whitelist allowing each cluster's export port), **not touching each cluster's existing data-plane policy**.

## 6. Red line (must read before reusing this overlay): string-list `args` always use JSON6902 append

**K8s strategic merge patch for "list fields without patchMergeKey" is whole-replacement, not append.**
The container `args` is exactly such a field (elements are plain strings, cannot merge by key) → when submitting an args patch with `patchesStrategicMerge`,
**the existing parameters in the base manifest get wiped entirely**.

The instance in this overlay (`deploy/k8s/tee-infer-service.yaml` has 12 existing parameters):
`-sig-key` / `-attest-token` / `-output-guard` / `-output-guard-policy-dir` /
`-cmaas-url` / `-cmaas-model` / `-dev-mode` —— if wholly replaced:

- Signature-key / attestation-token parameters vanish → startup guard or signature verification fails directly;
- `-cmaas-url` / `-cmaas-model` vanish → upstream model address lost;
- `-dev-mode` vanishes → under production form the **startup guard refuses to start** (paradoxically "safer", but still a fault).

**Correct approach (already adopted by this overlay)**: `patchesJson6902` append, **only add, never replace**:

```yaml
patchesJson6902:
- target: {group: apps, version: v1, kind: Deployment, name: tee-infer-service, namespace: otpmask}
  path: patch-tee-infer-audit-export.json.yaml
```

```yaml
- op: add
  path: /spec/template/spec/containers/0/args/-
  value: "-audit-export-enabled"
```

**Red lines (self-check item by item before writing a new overlay):**

1. To **add parameters** to a container → only use `patchesJson6902`'s `add ... /args/-`; **forbid** using
   `patchesStrategicMerge` to change `args` (would replace the whole block).
2. Before using JSON6902's **index path** (`containers/0/args/-`), first confirm the target container is indeed the 0th,
   and the list is non-empty; if the base manifest reorders containers, this patch would hit the wrong container → **must re-review this patch when changing the base manifest**.
3. Lists with a merge key (e.g. container `env` (key=name), `volumeMounts` (key=mountPath),
   `volumes` (key=name)) are safe to use with strategic merge; but **also confirm the key value**,
   otherwise "same-name overwrite" rather than "new addition" occurs.
4. After merging you **must verify**: in the `kubectl kustomize <overlay>` output, **all existing parameters are still present**
   (this overlay verified: original 12 parameters all retained + 8 new ones added).

## 7. Pending environment readiness (assets in this directory cannot be verified locally)

- ❌ No cluster verification (no K8s/PG locally): endpoint actually enabled, 403/404 behavior not tested.
- ❌ No verification of each cluster's source CIDR (customer/central collector actual egress IP) against the NetworkPolicy ipBlock match.
- ❌ No verification of the Higress plugin source allowlist (P1-8 domain, needs on-site confirmation).
- ❌ No verification of the token rotation flow (manual rotation before T-2.3).
- ⚠️ This overlay is an application that **actively opens a new endpoint**; if there is no export requirement, **do not apply**.
