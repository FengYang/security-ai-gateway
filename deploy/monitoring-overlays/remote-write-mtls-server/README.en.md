> English ｜ [中文](./README.md)

# P2-4 T-4.3 (receiver side) · PRE-A-4: central remote-write mTLS termination proxy

> Companion: sender side [`../remote-write-mtls/`](../remote-write-mtls/README.md) (each cluster's Prometheus mounts a client cert).
> This document solves the **other half**: how the central receiver side actually verifies "who you are".
>
> **Gap background**: Prometheus's `--web.config.file` can only do "server-side TLS + basic_auth",
> **there is no `ssl_verify_client` semantics** ⇒ the client cert is effectively useless at Prometheus.
> Writing without a client cert still works, meaning mTLS only did one-way — this is exactly the core gap of `PRE-A-4`.

## 1. Data path

```
Each cluster's Prometheus ──[client cert]──► 9443 this proxy ──[plaintext, same namespace]──► prometheus-central:9090
                     mutual TLS verification                   only /api/v1/write
```

- **9443**: the only externally-facing write entry, mutual TLS (`ssl_verify_client on`).
- **9090**: the central Prometheus itself; after tightening, **only the proxy and Grafana may access** (see §3 step ②).
- **8080**: the proxy's own `/healthz`, `/stub_status`, **does not allow cross-cluster sources**.

## 2. Assets

| File | Content | In `resources` |
|------|------|:---:|
| `nginx-mtls-proxy.yaml` | ConfigMap(`nginx.conf`) + Deployment + Service(9443/8080) | ✅ |
| `kustomization.yaml` | overlay entry; `images:` can change to internal image source | — |
| `secret-mtls-server.example.yaml` | Secret template for server cert + client CA | ❌ Template, do not apply |
| `replace-central-write-np.tighten.yaml` | **Same-name replace** central NP: 9090 only proxy + Grafana | ❌ Manual execution required |
| `networkpolicy-mtls-gateway-ingress.yaml` | 9443 cross-cluster source allow (by egress IP) | ❌ Execute after filling CIDR |

Proxy container wording: non-root (UID 101), `readOnlyRootFilesystem`, drop ALL capabilities,
`automountServiceAccountToken: false`, `seccompProfile: RuntimeDefault`.

## 3. Enablement (three steps, order cannot be reversed)

```bash
# ⓪ Certificate: same CA as the sender side (gen-ca.sh outputs CA / server / client all at once)
(cd deploy/monitoring-overlays/remote-write-mtls && ./gen-ca.sh --out ./certs)

# ① Inject server-cert Secret (note use generic: kubernetes.io/tls only installs two keys, cannot hold ca.crt)
kubectl -n otpmask create secret generic otpmask-remote-write-mtls-server \
  --from-file=tls.crt=./certs/server.crt \
  --from-file=tls.key=./certs/server.key \
  --from-file=ca.crt=./certs/ca.crt \
  --dry-run=client -o yaml | kubectl apply -f -

# ② Start the proxy
kubectl apply -k deploy/monitoring-overlays/remote-write-mtls-server
kubectl -n otpmask rollout status deploy/remote-write-mtls-gateway

# ③ Tighten 9090 only after the path is open (NP is additive ⇒ can only whole-object replace, cannot stack)
kubectl apply -f deploy/monitoring-overlays/remote-write-mtls-server/replace-central-write-np.tighten.yaml

# ④ Allow 9443 only after filling each cluster's egress IP
kubectl apply -f deploy/monitoring-overlays/remote-write-mtls-server/networkpolicy-mtls-gateway-ingress.yaml
```

> **Why ③ must come after ②**: after tightening, 9090 is closed to the whole same namespace,
> if the proxy is not yet open, writes will have **no alternative path**. Open first, tighten later, so there is a baseline to compare against when something fails.

## 4. Verification

**Tested locally (no cluster, only static and certificate layer)**

| Item | Method | Status |
|---|---|---|
| Cert chain / EKU / SAN | `gen-ca.sh` self-check + `openssl verify` | ✅ See sender-side README §4 |
| Mutual handshake (cert layer) | `openssl s_server -Verify 1` + `s_client -cert` | ✅ Client `verify return:1`; no cert rejected |
| YAML / config assertions | `python3 scripts/check-central-aggregation-assets.py` + `scripts/check-mtls-proxy-assets.py` | ✅ (`ssl_verify_client on`, CA binding, write-path-only, etc. asserted item by item) |
| kustomize build | `kubectl kustomize deploy/monitoring-overlays/remote-write-mtls-server` | ✅ (local kubectl v1.14 built-in kustomize v2) |

**Pending environment readiness (not done = not done, must not fill PASS) — register `PRE-B-9` + `PRE-A-11`**

- ❌ `nginx -t` syntax check: no nginx locally, Docker engine not started ⇒ static assertions passing does **not** equal syntax passing.
- ❌ Proxy real forwarding: the three groups "write with cert succeeds / without cert rejected / wrong CA rejected" not actually tested.
- ❌ Secret volume `0440` + `fsGroup: 101` vs `readOnlyRootFilesystem` real-device behavior.
- ❌ Whether central Grafana query is affected after tightening NP (depends on confirming Grafana's real Pod labels).

## 5. Troubleshooting reference table (nginx-side status codes)

| Symptom | Meaning | Handling |
|---|---|---|
| Connection directly dropped / `400 No required SSL certificate was sent` | Client did not present cert | Sender side `tls_config.cert_file/key_file` mounted, volume readable |
| `495` | Client cert verification failed (not this CA / incomplete chain / expired) | Same CA on both sides; `openssl verify -CAfile ca.crt client.crt` |
| `496` | No client cert presented (under `ssl_verify_client on` equivalent to reject) | Same as above, first check sender-side config |
| `497` (HTTP hits HTTPS port) | Plaintext hits 9443 | url must be `https://…:9443/api/v1/write` |
| `404` | Path is not exactly `/api/v1/write` | Check url trailing slash or used `/api/v1/push` |
| `405` | Not POST | remote_write only sends POST; GET is a manual probe typo |
| `502 / 504` | Proxy→upstream unreachable | Is central Prometheus Running; is 9090 blocked by its own NP |

## 6. Relationship with the port matrix / NP three tiers

- `9443` is registered as the **only** mTLS write entry ([port matrix](../../k8s-overlays/trust/networkpolicy-tiers/README.md) §1).
- `9443` does not appear in the NP three-tier templates: the three tiers govern the **per-cluster data-plane ingress** (8085/19090),
  while 9443 is on the **central cluster side**. The two do not overlap, do not mix-fill.
- The central-side 9090 tightening is handled by `replace-central-write-np.tighten.yaml`, **not** the three-tier template's responsibility.

## 7. Certificate rotation (no CRL, rely on short cycle + re-sign)

Current wording: **no CRL/OCSP**, rely on 90-day validity. Therefore "revoke" = change CA or re-sign, steps:

1. **Re-sign client cert under the same CA** (most common): only update the sender-side Secret, this proxy needs no restart (`ssl_client_certificate` is still the same CA).
2. **Change CA** (only means when a client cert is leaked):
   - First concatenate the old and new CA PEMs into this Secret's `ca.crt` (nginx treats it as the trust set) → `kubectl apply` → restart proxy;
   - Then re-issue new-CA-signed client certs per cluster;
   - After all switched, converge this Secret's `ca.crt` back to the single new CA → restart.
   - ⚠️ Reversing the order will **instantly interrupt writes across the whole cluster** (old certs no longer trusted).
3. Server-cert rotation: just change this Secret's `tls.crt/tls.key` and restart the proxy;
   the sender-side `server_name` is determined by the cert SAN; if changing SAN you must sync-change each cluster's `server_name`.

## 8. Known boundaries (write into the design, not leave for on-site discovery)

- **No request-level auth**: the proxy only proves "this client holds a valid cert", does not distinguish cluster identity ⇒
   an authenticated client can forge `external_labels.cluster` to write dirty data.
   Per-cluster write admission needs a map by cert CN (`map $ssl_client_s_dn`) → currently **not done**,
   belongs to a later enhancement (only meaningful after aligning with T-2.1 registry's cluster_id).
- **Single replica**: during proxy downtime each cluster retries in its queue (sender side `max_backoff=60s`, `capacity=10000`),
   no loss but delay; high availability needs scaling + front L4 LB.
- **HTTP/2**: `http2 on` needs nginx ≥ 1.25.1; image pinned to `1.27-alpine`, changing the image must check the version.
- **Grafana allow is guessed by label**: `app: grafana` taken from `deploy/monitoring/grafana.yaml:545`,
   if the central cluster uses a different label it must be changed before ③, otherwise the dashboard breaks directly after tightening.
