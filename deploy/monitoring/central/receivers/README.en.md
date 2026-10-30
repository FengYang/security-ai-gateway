> English ｜ [中文](./README.md)

# Central-side receiver: sender snippets for four target forms

> **This directory is not in `kustomization.yaml`'s `resources`** → **zero impact** on the default deployment,
> and does not participate in `kubectl apply -k deploy/monitoring/central`. It is a **sender-snippet library**:
> based on which receiver the central side actually adopts, take the corresponding one and merge into each cluster's `prometheus.yml`.
>
> **Wording change (2026-10-26)**: the original doc wrote "form A / form B **choose one**", framing "switching receiver" as
> "product-roadmap fork". In reality the **sender is the same** (Prometheus remote-write), only the target address,
> path, auth header, tenant header differ — therefore changed to: **default form B (our central stack) ＋ four supported receivers**,
> when the customer already has a monitoring stack just replace the three values (url / auth / tenant header) per the corresponding snippet, **no "choosing sides"**.

## 1. Selection matrix

| Receiver | Snippet file | Write path | Auth (native) | Tenant / multi-tenant isolation | Typical scenario |
|---|---|---|---|---|---|
| **Native Prometheus** | `remote-write-target-prometheus.example.yaml` | `/api/v1/write` | **None** (must front a proxy for mTLS/auth) | No tenant concept, distinguished by `external_labels.cluster` | Our central stack (form B default), customer's existing single-instance Prometheus |
| **Thanos Receive** | `remote-write-target-thanos.example.yaml` | `/api/v1/receive` | **None** (front proxy) | Request header `THANOS-TENANT` (default tenant `default-tenant`) | Customer's existing Thanos long-term storage / global view |
| **Grafana Mimir** | `remote-write-target-mimir.example.yaml` | `/api/v1/push` | **None** (front gateway injects tenant header) | **Mandatory** request header `X-Scope-OrgID`, rejected if missing | Customer using Grafana stack (Loki/Mimir/Tempo) |
| **VictoriaMetrics** | `remote-write-target-victoriametrics.example.yaml` | Single `/api/v1/write`; cluster `vminsert` `/insert/<accountID>/prometheus/api/v1/write` | Optional `-httpAuth.*` or front `vmauth` | `?extra_label=cluster=<id>` or accountID path | Customer using VM for low-cost long-term storage |

> **Commonality**: none of the four receivers solve "who is writing" auth (Mimir/Thanos tenant header is **routing** not **auth**,
> can be arbitrarily forged). Hence **cross-public-network must use mTLS**, the `cluster` label is still uniquely provided by the sender-side `external_labels.cluster`.

## 2. Three values that must be replaced (per cluster)

| Placeholder | Replace with | Consequence of missing |
|---|---|---|
| `REPLACE_WITH_CENTRAL_WRITE_ENDPOINT` | Full receiver URL (with path) | Config validation refuses to start (does not silently drop metrics) |
| `REPLACE_WITH_CLUSTER_ID` | This cluster's unique ID (recommend = registry `cluster_id`) | Falls to `cluster=""`, dashboard/alert-dedup fail |
| `REPLACE_WITH_CENTRAL_SERVER_NAME` | Receiver cert SAN (mandatory under mTLS) | Handshake verification fails, writes fully broken |
| `REPLACE_WITH_TENANT` (Thanos/Mimir/VM only) | Tenant identifier | Mimir: request rejected; Thanos: falls to default tenant; VM: label pollution |

## 3. Smoke check (verify the channel before merging)

```bash
# ① Channel writable (use minimal sample, do not pollute the real series; any receiver supporting remote-write works)
printf '# TYPE rw_probe gauge\nrw_probe 1\n' | curl -sS -o /dev/null -w '%{http_code}\n' \
  --data-binary @- -H 'Content-Type: text/plain' \
  -H 'X-Scope-OrgID: REPLACE_WITH_TENANT' \
  --cert client.crt --key client.key --cacert ca.crt \
  'https://<host>/api/v1/push'

# ② Config syntax (Prometheus itself)
promtool check config prometheus.yml

# ③ Whether the write actually arrived (query at receiver)
#    Native/Mimir/Thanos/VM all queryable: count by (cluster) ({__name__="rw_probe"})
```

**Expected**: ① `200` (or Mimir `200`／Thanos `200`／VM `204`); ② `SUCCESS`; ③ can query `cluster=<id>` samples.
If any is not met, **do not** proceed to the traffic-cutover drill — an unopened channel cut over would misjudge "invisible" as "no failure".

## 4. Structure of each snippet (why they look almost identical)

The four snippets differ only in `url`, `headers`, `query`; everything else (`queue_config` / `write_relabel_configs` /
`tls_config`) is identical — this way you can **review by diff**, avoiding "changed one place wrong when copy-pasting".

```bash
# When reviewing, only look at the differences
diff -u remote-write-target-prometheus.example.yaml remote-write-target-mimir.example.yaml
```

## 5. Relationship with the mTLS overlay

- Cert mount: `deploy/monitoring-overlays/remote-write-mtls/` (Secret three keys + read-only volume)
- Cert generation: same-dir `gen-ca.sh` (self-signed) or enterprise CA signing (`--mode csr`)
- **Do not** hardcode credentials other than the cert path in this directory's snippets; Bearer/password all go through `credentials_file` (Secret mount)

## 6. Pending environment readiness (stated as-is)

- ❌ **None of the four receivers had real-device connectivity verification**: no K8s locally, no Thanos/Mimir/VM instances,
  the §3 smoke steps above are a **to-be-executed checklist**, not a passed conclusion.
- ⚠️ **Mimir's `X-Scope-OrgID` semantics** written per Mimir's official multi-tenancy wording;
  under **single-tenant mode** (`-multitenancy_enabled=false`) this header may be omitted, but **do not** therefore turn off the auth proxy.
- ⚠️ **Thanos's tenant header name** depends on the receiver's `--receive.tenant-header` config (default `THANOS-TENANT`);
  if the customer changed that parameter, the header name in the snippet must be synced.
- ⚠️ **VM cluster version's accountID path** differs from the single-instance path; both are given as comments in the snippet, **choose one per actual version**.
