> English ｜ [中文](./README.md)

# P2-4 T-4.4: Central aggregation deployment assets

> **Deploy only in the central cluster that undertakes cross-cluster aggregation**, alongside the per-cluster stack (`deploy/monitoring/**`), non-interfering.
> This directory is **not** in `deploy/monitoring/kustomization.yaml` → the output of `kubectl apply -k deploy/monitoring`
> is **exactly the same** as before this commit (zero impact on the default deployment).

## 1. Asset list

| File | Content |
|------|------|
| `kustomization.yaml` | Central asset entry: `kubectl apply -k deploy/monitoring/central` |
| `prometheus-central.yaml` | Central Prometheus (`--web.enable-remote-write-receiver`, 90d retention) + central alert rules + NetworkPolicy + PVC |
| `alertmanager-central.yaml` | Central Alertmanager: group_by / inhibit dedup by `cluster` dimension |
| `grafana-central-dashboards.yaml` | Unified dashboards: ① cross-cluster overview ② per-cluster drill-down (per-cluster `cluster` variable) |
| `grafana-central-datasources.yaml` | Grafana central data source `Prometheus-Central` (same uid, dashboards reference by uid) |
| `remote-write-sender.example.yaml` | **Per-cluster** remote-write sender snippet template (with mTLS config slots), not in kustomization (authoritative version see `deploy/monitoring-overlays/remote-write-mtls/`) |
| `receivers/` | **Sender-snippet library for four receiver types** (native Prometheus / Thanos Receive / Grafana Mimir / VictoriaMetrics) ＋ selection matrix; not in kustomization, take one per the central side's actual form |
| `trust/` | **T-4.3 channel-trust** subdirectory: central-side cert-reference examples + collector egress deny-by-default policy + landing-form description |

## 2. `cluster` label wording (unified wording, do not alias)

- **Source**: each cluster's Prometheus `global.external_labels.cluster=<cluster-id>`; on remote-write
  send this external label is attached to **every sample**, so the central side naturally carries the `cluster` dimension.
  Existing anchor: `deploy/monitoring/prometheus.yaml:41-43` (comment "multi-cluster aggregation and alert dedup (M12)").
- **The central side does no rewrite/rename**, so `label_values(cluster)`, `by (cluster)`,
  `cluster=~"$cluster"`, Alertmanager `equal: [cluster]` are all directly usable.
- **Do not use** aliases like `cluster_id` / `k8s_cluster`.
- **Different dimension from T-4.1/T-4.2's `schema=admin|tee|core`**:
  `cluster` = source cluster of the metric (this directory), `schema` = audit-chain type (audit side,
  `GET /v1/adminext/audit-chain/query?cluster=<id>&schema=<admin|tee|core>`).
  The two can be combined and used side by side, neither replaces the other.
- ⚠️ A cluster missing `external_labels.cluster` → its alerts fall into the `cluster=""` group, dashboards/dedup fail.
  Must **confirm per cluster** before go-live.

## 3. Alert dedup design (avoid N-cluster repeated bombardment)

| # | Means | Location | Semantics |
|---|------|------|------|
| ① | **Fleet-level aggregation (primary means)** | Default route `group_by: [alertname, severity, service]` (**excludes cluster**) | Same alertname triggered simultaneously in N clusters → merged into **1** notification, body lists affected clusters with `{{ range .Alerts }}` |
| ② | Security alerts grouped by cluster | `category=security` route `group_by: [alertname, cluster, service]` | Security events need per-cluster locating/handling, **traceability prioritized over dedup** |
| ③ | Inhibition | `inhibit_rules`: critical inhibits same `cluster`'s warning; `CentralClusterTargetsDown` inhibits that cluster's downstream warnings | Avoid cascading bombardment |

Notification recipients: `ops-fleet` (default) / `ops-critical` / `sec-oncall` / `ops-multicluster`.
⚠️ webhook URL is a placeholder address (`alert-relay.otpmask.svc.cluster.local:19099`),
replace with the actual on-call system before go-live (consistent with the existing `deploy/monitoring/alertmanager.yaml` convention).

## 4. Deployment and wiring steps

```bash
# ① Central cluster: deploy central assets
kubectl apply -k deploy/monitoring/central

# ② Central cluster: mount central data source to Grafana (one-time; dashboards report datasource not found if not mounted)
kubectl -n otpmask patch deployment grafana --type=json -p '[
  {"op":"add","path":"/spec/template/spec/volumes/-",
   "value":{"name":"grafana-central-datasources",
            "configMap":{"name":"grafana-central-datasources"}}},
  {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-",
   "value":{"name":"grafana-central-datasources",
            "mountPath":"/etc/grafana/provisioning/datasources/central","readOnly":true}}
]'
kubectl -n otpmask rollout restart deployment/grafana

# ③ Central cluster: import dashboards (drop grafana-central-dashboards' two JSONs into Grafana
#    provisioning dashboards dir, or import in UI)

# ④ Each cluster: merge remote-write sender snippet
#    Authoritative assets: deploy/monitoring-overlays/remote-write-mtls/
#      (cert-mount overlay + prometheus-remote-write-snippet.yml, with mTLS config slots)
#    Must set a unique external_labels.cluster, then restart that cluster's Prometheus
```

## 4.1 Central-side receiver: **default form B ＋ four supported targets** (not "choose one of two")

> **Wording correction (2026-10-26)**: the original statement "form A / form B **choose one**" framed "switching receiver" as
> "product-roadmap fork". In reality the **sender is the same** (Prometheus remote-write), the difference is only in
> target address / path / auth header / tenant header — therefore changed to: **default form B, form A is a supported topology**,
> when the customer already has a monitoring stack just replace the three values per the corresponding snippet, **no choosing sides, no change to our assets needed**.

This project does **not** self-build a central receiver (GSLB / self-built collector both not adopted).

| | **Form B (default)**: we deliver the central stack | **Form A**: customer's existing monitoring stack (one of four) |
|---|---|---|
| Deployment action | `kubectl apply -k deploy/monitoring/central` + Grafana mount data source + import dashboards | Do not deploy our central assets, only merge the sender snippet |
| remote_write target | `https://<proxy address>:9443/api/v1/write` (**via mTLS termination proxy, not direct 9090**) | Take snippet per receiver (see below) |
| Snippet source | `remote-write-sender.example.yaml` | `receivers/remote-write-target-<target>.example.yaml` |
| mTLS termination | **We deliver**: `deploy/monitoring-overlays/remote-write-mtls-server/` (mutual TLS + `ssl_verify_client on`; after tightening 9090 only proxy may enter) | Customer side or customer gateway bears it (same for all four receivers, native Prometheus also does not verify client cert) |
| Alert dedup | This directory's `alertmanager-central.yaml` already implements §3 wording | Customer Alertmanager must adopt §3 wording of this doc (otherwise N-cluster repeated bombardment) |

**Four supported receivers** (`receivers/` directory, differences see its README selection matrix):

| Receiver | Path | Extra config required |
|---|---|---|
| Native Prometheus | `/api/v1/write` | Start must carry `--web.enable-remote-write-receiver` |
| Thanos Receive | `/api/v1/receive` | Request header `THANOS-TENANT` (header name follows `--receive.tenant-header`) |
| Grafana Mimir | `/api/v1/push` | Request header `X-Scope-OrgID` (mandatory when multi-tenant enabled, rejected if missing) |
| VictoriaMetrics | `/api/v1/write` (single) / `/insert/<accountID>/prometheus/api/v1/write` (cluster) | Success code is **204**; `extra_label` and `external_labels` choose one, do not duplicate |

> **remote_write target address is always a placeholder** (`REPLACE_WITH_CENTRAL_WRITE_ENDPOINT`),
> our assets **do not hardcode any intranet address**. When the placeholder is not replaced, Prometheus config validation will **refuse to start**
> (`promtool check config` errors), will not silently drop metrics.

## 5. T-4.3 channel trust (**receiver-side proxy delivered, evidence pending environment**)

The remote-write channel's mTLS has two halves, this directory only owns "central Prometheus itself", the other two halves are in the overlay and the sender side:

- **Receiver side (filled this time)**: `deploy/monitoring-overlays/remote-write-mtls-server/` —
  Prometheus native **does not verify client cert** (`--web.config.file` can only do server-side TLS + basic_auth,
  no `ssl_verify_client` semantics), so put an nginx in front for TLS termination and mandatory client-cert verification:
  externally `9443` (only `/api/v1/write`) → in-cluster plaintext loopback `9090`.
  Companion `replace-central-write-np.tighten.yaml` tightens 9090 from "whole same namespace open" to "only proxy + Grafana".
- **Sender side**: `deploy/monitoring-overlays/remote-write-mtls/` (client-cert mount + `tls_config`).
- **Certificate**: `gen-ca.sh` outputs CA / server / client in one go, both sides share the same CA.
- **Still not done** (stated as-is): the proxy **has not run on a real cluster** — `nginx -t`, real mutual handshake through the proxy,
  Secret-volume `0440`+`fsGroup:101` real-device behavior, whether Grafana still works after tightening NP, all pending environment evidence
  (register `PRE-B-9` / `PRE-A-11`). **Before tightening NP you must first open a write through the proxy once on a real cluster**, otherwise you cannot distinguish
  "policy blocked" from "proxy not open".
- **Wording before tightening unchanged**: 9090 still open to the `otpmask` namespace, only suitable for intranet/leased-line;
  cross-public-network writes must first do the three steps above (start proxy → open → tighten).

## 6. Self-check scripts

```bash
python3 scripts/check-central-aggregation-assets.py            # default checks two asset dirs
python3 scripts/check-central-aggregation-assets.py -v         # output PASS details
python3 scripts/check-central-aggregation-assets.py --promtool /path/to/promtool
python3 scripts/check-mtls-proxy-assets.py                     # mTLS termination proxy dedicated assertions (§5)
```

Check items: ① YAML parseable (incl. ConfigMap embedded YAML) ② plaintext-credential scan (template/placeholder whitelist)
③ dashboard JSON valid + `cluster` variable + expression contains cluster dimension ④ Alertmanager contains cluster dimension
⑤ central Prometheus remote-write receiver enabled ⑥ promtool rule syntax (**no promtool → explicitly SKIP, do not pretend to pass**)
⑦ (dedicated script) proxy `ssl_verify_client on` / client CA binding / only `/api/v1/write` reachable / non-root + read-only root.

Exit code: `0` = all pass (SKIP explicitly listed) / `1` = a FAIL exists / `2` = environment or input error.

## 7. Verification results (local, 2026-10)

| Item | Method | Result |
|----|------|------|
| YAML syntax | Per-file + embedded YAML `yaml.safe_load_all` | ✅ PASS |
| kustomize build | `kubectl kustomize deploy/monitoring/central` (kubectl v1.14 built-in kustomize v2) | ✅ Passed, 11 documents |
| Dashboard JSON | `json.loads` + variable/dimension assertions (2 dashboards) | ✅ PASS |
| Alertmanager cluster dimension | Parse embedded config, assert group_by/inhibit equal contains cluster | ✅ PASS |
| remote-write receiver switch | Assert Deployment args contain `--web.enable-remote-write-receiver` | ✅ PASS |
| Plaintext-credential scan | Regex scan (template/REPLACE_ placeholder whitelist) | ✅ PASS |
| Default stack zero impact | `git status deploy/monitoring` only added `central/`; existing files unchanged | ✅ PASS |
| Summary | `PASS=42 FAIL=0 SKIP=5` | ✅ Exit code 0 |

**Pending environment readiness (stated as-is, not done = not done):**

- ❌ **promtool rule-syntax check not executed**: no promtool locally, script outputs SKIP (not treated as pass).
  Central rules follow the existing promtool-checking convention (ref `billing-prometheusrule-promtool-test.yaml`),
  rerun the script after environment ready to auto-supplement the check.
- ❌ **No cluster verification**: no Kubernetes/PG locally, did not run `kubectl apply` / server-side dry-run;
  whether central Prometheus can really receive each cluster's writes, whether dashboards can fetch data, all untested.
- ❌ **No kustomize v4/v5 build verification**: local only kubectl v1.14 (kustomize v2).
- 🖥 **T-4.3 mTLS receiver side encoded and delivered, not evidenced on cluster**: proxy assets
  (`deploy/monitoring-overlays/remote-write-mtls-server/`) delivered and passed static assertions +
  kustomize build, but `nginx -t`, real mutual handshake, Secret-volume permission combination, Grafana connectivity after tightening NP
  **all untested** → register `PRE-B-9` / `PRE-A-11`, **do not fill PASS before evidenced**.
  Before executing the three steps "start proxy → open → tighten", 9090 is still an intranet plaintext channel, enabling cross-public-network is a violation.
- ❌ **Each cluster's `external_labels.cluster` not confirmed per cluster**: missing config will cause `cluster=""` grouping.
- ❌ **Grafana data-source mount untested**: the `kubectl patch` command is given statically, not executed on a cluster.
- ⚠️ **Rule-precision limitation**: `CentralRemoteWriteStalled` uses
  `prometheus_remote_storage_highest_timestamp_in_seconds` which is the receiver side's **global metric, no cluster dimension**,
  can only discover "some cluster stopped writing", cannot locate the specific cluster; per-cluster precise criteria depend on the cluster expectation list
  (T-2.1 registry), not fabricated this period, temporarily rely on the dashboard per-cluster page for manual confirmation.
