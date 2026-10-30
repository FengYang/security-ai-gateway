> English ｜ [中文](./README.md)

# hello-plugin — Higress Wasm plugin (M1 milestone)

Verifies the complete lifecycle of a Go Wasm plugin in Higress: loading, config reading, request/response interception, logging.

## Build (Go 1.24+ native wasm)

```powershell
# Pull dependencies
go mod tidy

# Compile wasm (Go native wasip1 target, no tinygo needed)
GOOS=wasip1 GOARCH=wasm go build -o hello-plugin.wasm .

# Or use tinygo (smaller artifact, requires tinygo installed)
tinygo build -o hello-plugin.wasm -scheduler=none -target=wasi main.go
```

## Plugin config example

```yaml
message: "hello from otpmask gateway"
log_level: "info"
```

## Verification checklist (M1 all passed ✅)

- [x] `main.wasm` successfully produced (7.2MB, Go native wasm)
- [x] Higress/Envoy loads the plugin, logs show "plugin started" and "config loaded"
- [x] When a request passes, logs show "received request header", httpbin echoes `X-Otpmask-Hello: true` header
- [x] When a response passes, logs show "received response header"
- [x] After modifying config (message) and restarting, it takes effect (log shows new config)

### Verification log sample

```
wasm log: [hello-plugin] hello-plugin: config loaded message="hello from otpmask gateway" log_level="debug"
wasm log: [hello-plugin] hello-plugin: received request header, message="hello from otpmask gateway"
wasm log: [hello-plugin] hello-plugin: host=127.0.0.1:10000 path=/get
wasm log: [hello-plugin] hello-plugin: received response header, message="hello from otpmask gateway"
```

### Local debug commands

```powershell
# Start (envoy + httpbin + wasm)
docker compose up -d

# View wasm logs
docker logs -f hello-plugin-envoy-1

# Direct connect httpbin (no plugin) for comparison
curl.exe -s http://127.0.0.1:12345/get

# Via gateway (with plugin)
curl.exe -s http://127.0.0.1:10000/get

# Cleanup
docker compose down
```
