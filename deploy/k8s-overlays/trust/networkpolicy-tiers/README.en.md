> English ｜ [中文](./README.md)

# Cross-cluster network boundary: three-tier NetworkPolicy ＋ port matrix

> **Disabled by default**. This directory is not in the `resources` of `deploy/k8s-overlays/trust/kustomization.yaml`,
> you need explicit `kubectl apply -f networkpolicy-tiers/<tier>.yaml` to apply a single tier.
>
> **Why "tiers" instead of one policy**: the export endpoint and the business endpoint share the **same port** (gateway-core `8085`,
> tee-infer `19090`), and NetworkPolicy is L3/L4, **cannot whitelist the export by URL path** while allowing the business ⇒
> can only converge the source as a whole. But "whom to allow" varies with the deployment form (single cluster / multi-cluster / collector outside cluster),
> a one-size-fits-all would **accidentally harm the data plane** (plugin table pull fails → keeps old table; quota/scrape fails → observability gap).

## 1. Port matrix (single source of truth, do not alias)

| Port | Component | Purpose | Direction | Cross-cluster |
|---|---|---|---|---|
| **8085** | `gateway-core` (`OTP_CORE_ADDR`, default `:8085`) | Business API, policy pull, **audit-chain export** `/v1/internal/audit/chain/export`, `/metrics` | Ingress | ✅ Central collector |
| **19090** | `tee-infer-service` (helm `port`, default `19090`) | Inference forwarding, TEE quota push, **audit-chain export (tee)**, `/metrics` | Ingress | ✅ Central collector |
| **9443** | `remote-write-mtls-gateway` (central) | **remote-write's only cross-cluster write entry**: mutual TLS + mandatory client-cert verification, only `/api/v1/write` | Ingress | ✅ **Each cluster's Prometheus** (the only port that may be opened to the public) |
| **9090** | `prometheus-central` (central) | remote-write receive (**after tightening, only the proxy may connect directly**), query API (Grafana) | Ingress | ❌ **No longer directly cross-cluster** (always via 9443) |
| **9090** | per-cluster `prometheus` | Local scrape and query | Local | ❌ **Not cross-cluster** (writing to central is **egress** to central 9443) |
| **8080** | `remote-write-mtls-gateway` (central) | Proxy's own `/healthz`, `/stub_status` | Ingress | ❌ Only kubelet / same namespace |
| 19099 | `alert-relay` (example placeholder) | Alert webhook forwarding | Egress | Optional |

**Traffic direction (who connects to whom)**

| Source | Target | Port / path | Description |
|---|---|---|---|
| Each cluster's Prometheus | Central `remote-write-mtls-gateway` | `9443/api/v1/write` | Egress; **mutual TLS** (sender side carries client cert); form A customer receiver see `central/receivers/` |
| Central `remote-write-mtls-gateway` | Central `prometheus-central` | `9090/api/v1/write` | In-cluster plaintext loopback (TLS terminated at previous hop); tightened NP limits to **proxy-only ingress** |
| Central collector | Each cluster `gateway-core` | `8085/v1/internal/audit/chain/export?schema=admin|core` | Ingress to the collected cluster; Bearer + source CIDR whitelist |
| Central collector | Each cluster `tee-infer-service` | `19090/…?schema=tee` | Same as above |
| Grafana (central) | Central `prometheus-central` | `9090/api/v1/query` | In-cluster (must keep this when tightening NP, otherwise dashboards break) |
| Prometheus (each cluster) | Local `gateway-core` / `tee-infer` | `8085/metrics`, `19090/metrics` | In-cluster scrape |

> **Note**: `8085`/`19090`'s **business traffic and export traffic share the port** — this is why network-range allowance also allows the business plane.
> The application-layer path-level boundary is in T-4.2 (source CIDR whitelist + Bearer token, **empty = deny**); network policy is only the second net.

> **Why `9443` is not in these three files**: 9443 belongs to the **central cluster side** ingress boundary
> (`deploy/monitoring-overlays/remote-write-mtls-server/networkpolicy-mtls-gateway-ingress.yaml`),
> while the three tiers here govern the **per-cluster data-plane ingress** (8085/19090). The two responsibilities do not overlap,
> do not stuff 9443 into the three-tier templates just for "uniformity", otherwise each cluster would get an empty allow pointing to a non-existent port.

## 2. Three-tier comparison

| Tier | File | Allowed source | Applicable | Consequence of missing allow | Cost of over-allowing |
|---|---|---|---|---|---|
| **1 minimal** | `tier1-minimal.yaml` | Only same namespace: Prometheus scrape, admin→core, core→tee, envoy→tee | Single cluster, no central aggregation, plugin and gateway in same namespace | None (these are all there is in this form) | None |
| **2 standard** (recommended) | `tier2-standard.yaml` | Tier 1 ＋ plugin namespace (`REPLACE_WITH_HIGRESS_NAMESPACE`) ＋ central collector (`otpmask.io/role=central-collector`) | Multi-cluster + central audit aggregation | Plugin table pull fails (keeps old table), audit export blocked | Any pod in the plugin namespace can connect to core:8085 |
| **3 permissive** | `tier3-permissive.yaml` | Tier 2 ＋ **source CIDR range** (`10.20.0.0/16` example) | Collector has no pod label / outside cluster / source becomes fixed range after SNAT | Collector cannot connect, export fully broken | **Any host in the same range can connect to 8085/19090** (L3, no pod-identity distinction) |

**Selection criteria (ask in order)**

1. Only deploying single cluster, not connecting central audit aggregation? → **Tier 1**
2. Central collector deployed as a Pod, and has `otpmask.io/role=central-collector` label? → **Tier 2**
3. Collector outside cluster / no label / source reduced to only a range? → **Tier 3** (and tighten the CIDR to /32 or the smallest range)
4. Unsure → **Do not enable first**. The application-layer CIDR + token already deny by default (empty = refuse), network policy is defense-in-depth, not a required layer.

## 3. Enablement and rollback

```bash
# ① Pre-enablement check (tiers 2/3 mandatory, must not apply if any missing)
#    a) Plugin's real namespace (belongs to P1-8 domain, this task does not fabricate pod labels)
kubectl get pods -A --show-labels | grep -i higress | head
#    b) Whether the central collector label exists
kubectl -n otpmask get pods -l otpmask.io/role=central-collector
#    c) Whether application-layer whitelist and this policy's allow items are consistent (inconsistent = the two nets fight each other)
kubectl -n otpmask get configmap gateway-core-audit-export -o jsonpath='{.data.cidrs}'

# ② Single-tier apply (apply only one tier at a time)
kubectl apply -f deploy/k8s-overlays/trust/networkpolicy-tiers/tier2-standard.yaml

# ③ Observe for 15 minutes (rollback immediately if any of these four is abnormal)
#    - Plugin table pull: no "table fetch failed" in plugin logs; rate limiting/routing not using old table
#    - TEE quota: quota push succeeds, inference no 5xx spike
#    - Scrape: Prometheus target up count not dropped
#    - Audit export: central side can see newly added chain records

# ④ Rollback (located by label, second-level restore of allow)
kubectl delete networkpolicy -n otpmask -l otpmask.io/netpol-tier=2-standard
```

**Verify connectivity (start a temporary pod from inside the target cluster)**

```bash
kubectl -n otpmask run netpol-probe --rm -it --restart=Never --image=curlimages/curl -- \
  curl -sS -o /dev/null -w '%{http_code}\n' --max-time 5 http://gateway-core.otpmask.svc:8085/metrics
# Expect 200; if unreachable, distinguish "policy blocked" from "service itself unreachable":
#   kubectl -n otpmask get endpoints gateway-core
```

## 4. Relationship with the old single-file policy

`deploy/k8s-overlays/trust/networkpolicy-audit-export-ingress.yaml` is the **predecessor of tier 2**
(similar content, but only one file, no tier label). The two are **mutually exclusive, do not apply both at once**:
K8s NetworkPolicy is **additive** (multiple policies take the union), applying both at once equals taking the wider tier, and "tier" loses meaning.

- New deployment → use the three tiers directly (this directory)
- Already using the old file → may keep using; on migration first `kubectl delete -f` the old file then apply tier 2

## 5. Verification status (not done = not done)

- ❌ **None of the three tiers applied on a real K8s cluster**: no K8s locally; `kubectl apply` / server-side dry-run not executed.
- ❌ **No connectivity test done**: the probe command above is a **to-be-executed checklist**, not a passed conclusion.
- ⚠️ **`REPLACE_WITH_HIGRESS_NAMESPACE` must be replaced**: when not replaced, `namespaceSelector` matches no namespace
  → equivalent to **not allowing the plugin** (fail-closed, correct direction but will harm the data plane).
- ⚠️ **Tier 3's `10.20.0.0/16` is an example value**: `ipBlock.cidr` is format-validated by the API, cannot be a placeholder;
  applying directly equals allowing a range you **may not own**. Confirm the collector's actual egress IP after SNAT before replacing.
- ⚠️ **CNI differences**: some CNIs (e.g. some Calico modes) are inconsistent in handling `namespaceSelector` + `podSelector` combinations,
  and in handling hostNetwork pods; policy semantics follow the target cluster's CNI, needs on-site confirmation.
