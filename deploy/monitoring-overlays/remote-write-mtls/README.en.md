> English ｜ [中文](./README.md)

# P2-4 T-4.3: remote-write mTLS sender side (per-cluster Prometheus)

> Companion with `deploy/monitoring/central/trust/README.md` (central side).
> This overlay only mounts the client cert; **the target address and tls_config snippet are merged into prometheus.yml by ops**.
>
> **Two certificate-source paths (no longer "wait for customer CA")**:
> - **Path 1 built-in self-signed CA (default, works offline)**: `gen-ca.sh --out <dir>` generates CA + server + client cert in one go,
>   directly usable for POC/intranet/MVP;
> - **Path 2 enterprise CA injection (optional)**: `gen-ca.sh --out <dir> --mode csr` only generates private key and CSR,
>   handed to the customer CA for signing, then placed back as `server.crt` / `client.crt` / `ca.crt`.
>
> The **sender-side config is identical** for both paths (both read `/etc/prometheus/mtls/{ca.crt,tls.crt,tls.key}`),
> changing CA does not change the config.

## 1. Assets

| File | Content |
|------|------|
| `kustomization.yaml` | overlay entry (`bases: ../../monitoring`) |
| `patch-prometheus-tls-volume.yaml` | Prometheus Deployment: mount `otpmask-remote-write-mtls` → `/etc/prometheus/mtls` (0400, readOnly) |
| `prometheus-remote-write-snippet.yml` | Snippet to merge into prometheus.yml: `external_labels.cluster` + `remote_write` (url/tls_config/authorization) |
| `secret-remote-write-mtls.example.yaml` | Client-cert Secret template (**not in resources, do not apply**) |
| `gen-ca.sh` | **Certificate generator**: `self-signed` (self-signed CA) / `csr` (enterprise CA) two modes; includes chain, EKU, SAN, private-key-permission self-check |

## 2. Enablement steps

```bash
# ① Generate cert (choose one)
#    Path 1 · built-in self-signed CA (offline, POC ready)
./gen-ca.sh --out ./certs
#    Path 2 · enterprise CA (only outputs CSR, handed to customer CA for signing)
./gen-ca.sh --out ./certs --mode csr
#      → after signing, place back ./certs/{server.crt,client.crt,ca.crt}, then run:
#        openssl verify -CAfile ./certs/ca.crt ./certs/server.crt ./certs/client.crt

# ② Inject client-cert Secret (forbidden in repo)
#    Must use three --from-file keys: `create secret tls` cannot hold ca.crt,
#    `create secret generic` has no --cert/--key/--ca-file flags
kubectl -n otpmask create secret generic otpmask-remote-write-mtls \
  --from-file=tls.crt=./certs/client.crt \
  --from-file=tls.key=./certs/client.key \
  --from-file=ca.crt=./certs/ca.crt \
  --dry-run=client -o yaml | kubectl apply -f -

# ③ Mount cert volume
kubectl apply -k deploy/monitoring-overlays/remote-write-mtls

# ④ Merge config snippet (ConfigMap data is a string, strategic merge cannot safely rewrite → manual/pipeline merge)
#    - global.external_labels.cluster: <this cluster's unique ID>
#    - remote_write: url / tls_config / authorization (see snippet, with placeholders)
#    After merge: kubectl -n otpmask rollout restart deployment/prometheus
```

## 3. Key wording

- **Target address configurable**: the snippet's `url: REPLACE_WITH_CENTRAL_WRITE_ENDPOINT` is a placeholder,
  **does not hardcode any intranet address**. Form B (our central stack) **must point to the mTLS termination proxy 9443**:
  `https://remote-write-mtls-gateway.<ns>.svc.cluster.local:9443/api/v1/write`,
  the proxy only allows the exact path `/api/v1/write` and enforces client cert; connecting directly to `prometheus-central:9090` is only for
  "intranet / leased-line temporary state where NP is not yet tightened", must not be a delivered form.
  Proxy-side assets see [`../remote-write-mtls-server/`](../remote-write-mtls-server/README.md).
  The four receiver types of form A (native Prometheus / Thanos / Mimir / VM) see
  [`deploy/monitoring/central/receivers/`](../../monitoring/central/receivers/README.md).
- **cluster label wording**: `external_labels.cluster` is the central side's `by (cluster)`, dashboard variable,
  Alertmanager `equal: [cluster]`'s only source, must be unique per cluster (recommend = registry cluster_id).
- **mTLS verification**: `server_name` must match the receiver cert SAN, `insecure_skip_verify: false` fixed.
- **Certificate purpose separation**: server `EKU=serverAuth`, client `EKU=clientAuth`, **no dual-purpose certs**
  (dual-purpose would let a "client cert" impersonate a server).
- **Tenant header is not authentication**: Mimir's `X-Scope-OrgID`, Thanos's `THANOS-TENANT` are **routing** semantics,
  can be forged; real "who is writing" is guaranteed by the mTLS client cert.
- **Auth**: the Bearer token goes through `credentials_file` (Secret mount), **plaintext in prometheus.yml forbidden**.
- **Validity**: default 90 days (rotation-cycle wording); `gen-ca.sh --days` can change, >90 triggers a warning.
- **Private-key permission**: the script asserts `600` on POSIX, fails if not met; Windows filesystems have no POSIX permission semantics
  → the script explicitly warns and requires regeneration on Linux (**does not pretend to pass**).

## 4. Verification status (distinguish "tested locally" from "pending environment")

**Tested (local, OpenSSL 3.5.7, ECDSA P-256, 2026-10-26)**

| Item | Method | Result |
|---|---|---|
| Cert chain | `openssl verify -CAfile ca.crt server.crt client.crt` | ✅ Both OK |
| Server SAN | `openssl x509 -noout -ext subjectAltName` | ✅ Covers `prometheus-central.otpmask.svc.cluster.local` / `.svc` / `localhost` |
| EKU separation | `-ext extendedKeyUsage` | ✅ Server `serverAuth`, client `clientAuth` |
| **Mutual mTLS handshake** | `openssl s_server -Verify 1` + `s_client -cert` | ✅ Client cert `verify return:1` (CN=otpmask-prometheus-writer) |
| **No cert rejected** | Same, `s_client` without `-cert` | ✅ Server `peer did not return a certificate` |
| Overwrite protection | Second run without `--force` | ✅ Exit code 3 (refuse to overwrite CA private key) |
| `--force` backup | Second run with `--force` | ✅ Old artifacts moved to `.bak-<timestamp>` |
| Enterprise CA mode | `--mode csr` | ✅ Only produces `server.csr`/`client.csr`, does not sign |
| Private-key permission | `stat -c %a` | ⚠️ On Windows is 644 (no POSIX semantics) → script warned; **must re-check to 600 on Linux** |

**Pending environment readiness (not done = not done)**

- ❌ **K8s cert-volume mount not tested**: no K8s locally, Secret creation and `/etc/prometheus/mtls` mount not executed.
- ❌ **Prometheus real write not tested**: the merged `prometheus.yml` syntax and real remote-write connectivity not verified.
- ⚠️ `defaultMode: 0400` and Prometheus running as `nobody(65534)` → Secret-volume readability for that user needs real-device testing
  (K8s Secret volume is owned root:root by default, 0400 means nobody cannot read → adjust per CNI/runtime,
  or switch to CSI Secret Store). **This item must be verified immediately after environment is ready.**
- ⚠️ **Real handshake only covers the cert layer**: `s_server` verifies "cert chain and purpose correct", not equal to
  "receiver proxy (nginx/envoy) config correct" — the proxy-side `ssl_verify_client on` and CA binding still need on-site confirmation.
