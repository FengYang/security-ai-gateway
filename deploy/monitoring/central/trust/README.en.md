> English ｜ [中文](./README.md)

# P2-4 T-4.3: Central-side channel-trust assets (**central cluster**)

> Companion with `deploy/monitoring/central/` (central aggregation stack). This directory provides the trust assets for the **cross-cluster channel**,
> not the central aggregation stack's own manifests (those are in the parent directory).

## 1. Central-side receiver: **default form B ＋ four supported targets** (not "choose one of two")

> **Wording correction (2026-10-26)**: originally wrote "choose one", framing "switching receiver" as "product-roadmap fork".
> In reality the sender is the same (Prometheus remote-write), the difference is only in target address/path/auth header/tenant header.
> Current wording: **default form B; form A is a supported topology**, four receiver snippets see
> [`../receivers/`](../receivers/README.md).

This project does **not** self-build a central receiver (GSLB/self-built collector both not adopted).

| | Form A: customer's existing Prometheus | Form B: our delivered central stack |
|---|---|---|
| Component | Customer environment's existing Prometheus / monitoring platform (with its own remote-write receiver) | `deploy/monitoring/central/` (central Prometheus + Alertmanager + dashboards) |
| Deployment action | **Do not deploy our central assets**; only connect our central assets' dashboards/alert config over | `kubectl apply -k deploy/monitoring/central` + Grafana mount data source + import dashboards |
| remote_write target address | `https://<customer receiver>/api/v1/write` | `http(s)://prometheus-central.<central namespace>.svc.cluster.local:9090/api/v1/write` |
| Cert issuance | Issued by **customer CA** (our sender side holds its CA) | Issued by a CA agreed between us and the customer, both sides share the same CA |
| mTLS termination location | Borne by the customer receiver itself or its front gateway | **Prometheus native does not verify client cert → must front an mTLS termination proxy** (see §2) |
| cluster label | Still attached by each cluster's `external_labels.cluster` (customer receiver must preserve this label) | Same as left (central Prometheus does not rewrite labels) |
| Alert dedup | Customer Alertmanager side must configure per §4 wording of this doc | Our central's alertmanager-central.yaml already implements that wording |
| Enablement step difference | ① Customer side opens receiver and provides CA/endpoint → ② Our clusters fill URL + cert → ③ Customer side configures dashboards/dedup | ① Deploy central assets → ② Configure mTLS proxy and CA → ③ Each cluster fills URL + cert → ④ Import dashboards |

> Regardless of form, **the remote_write target address must be filled per environment** (placeholder
> `REPLACE_WITH_CENTRAL_WRITE_ENDPOINT`), our assets **do not hardcode any intranet address**.

## 2. Receiver-side mTLS: Prometheus native does not verify client cert

`--web.enable-remote-write-receiver` exposes an **unauthenticated** write endpoint. Therefore the form B production deployment must:

1. Front the central Prometheus with a **proxy that does mTLS termination and client-cert verification** (gateway/Envoy/Nginx all fine),
   only allowing senders holding a trusted-CA-signed client cert;
2. Prometheus only listens on the in-cluster network, accessed by the proxy via local loopback/in-cluster address;
3. Between proxy and Prometheus is plaintext in-cluster (acceptable, premise is same trust domain, same node/network domain).

**Cert Secret reference example** (sender and receiver share the same CA):

| Side | Secret | Key | Consumer |
|----|--------|-----|--------|
| Sender (each cluster) | `otpmask-remote-write-mtls` | `ca.crt` / `tls.crt` / `tls.key` | `deploy/monitoring-overlays/remote-write-mtls` (Prometheus mounts to `/etc/prometheus/mtls`) |
| Receiver (central) | Consumed by the mTLS proxy (`otpmask-remote-write-mtls-ca` or equivalent) | `ca.crt` | Proxy's client-cert verification config |

Template: `deploy/monitoring-overlays/remote-write-mtls/secret-remote-write-mtls.example.yaml`
(**not in resources, do not apply**; real certs issued/injected by KMS/cert-manager, credentials forbidden in repo).

## 3. Central collector egress boundary (deny-by-default + whitelist allow)

`networkpolicy-central-collector-egress.yaml`: applies **deny-by-default egress** to Pods labeled `otpmask.io/role=central-collector`,
only allowing:

- DNS (kube-system 53);
- Each cluster's **export-endpoint ports** (gateway-core 8085 / tee-infer 19090), source ranges listed per cluster.

This is the network boundary for **cross-cluster audit collection** (new trust surface converged on the central side, not touching the data plane's existing policies).
Deny-by-default wording: targets not in the whitelist are all denied egress; empty whitelist range → that cluster's collection unreachable.

> Note: the central audit collector (`otpmask.io/role=central-collector`) is a **customer-environment component**,
> we do not deliver this component itself; this policy applies a boundary to it by label contract, and when the label does not exist the policy naturally idles.

## 4. Alert dedup and cluster wording (consistent with the central stack)

See `../README.md` sections 2 and 3 (`cluster` label wording + three-layer dedup). Under form A,
the customer-side Alertmanager must adopt the same wording, otherwise N-cluster repeated bombardment occurs.

## 5. Pending environment readiness (assets in this directory cannot be verified locally)

- ❌ No cluster verification (no K8s locally): mTLS proxy selection and config untested; cert issuance/injection untested.
- ❌ No verification of `REPLACE_WITH_CENTRAL_WRITE_ENDPOINT` connectivity and cert SAN match.
- ❌ No verification of NetworkPolicy taking effect on the customer's actual CNI (some CNIs need extra enabling).
- ⚠️ The central collector itself (`otpmask.io/role=central-collector`) is provided by the customer environment, its identity and
  egress ranges need to be confirmed against the §3 whitelist.
