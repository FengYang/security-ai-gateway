# hello-plugin — Higress Wasm 插件（M1 里程碑）

验证 Go Wasm 插件在 Higress 中的完整生命周期：加载、配置读取、请求/响应拦截、日志。

## 构建（Go 1.24+ 原生 wasm）

```powershell
# 拉取依赖
go mod tidy

# 编译 wasm（Go 原生 wasip1 目标，无需 tinygo）
GOOS=wasip1 GOARCH=wasm go build -o hello-plugin.wasm .

# 或使用 tinygo（产物更小，需安装 tinygo）
tinygo build -o hello-plugin.wasm -scheduler=none -target=wasi main.go
```

## 插件配置示例

```yaml
message: "hello from otpmask gateway"
log_level: "info"
```

## 验证清单（M1 已全部通过 ✅）

- [x] `main.wasm` 成功产出（7.2MB，Go 原生 wasm）
- [x] Higress/Envoy 加载插件，日志出现 "插件启动" 与 "配置已加载"
- [x] 请求经过时日志出现 "收到请求头"，httpbin 回显 `X-Otpmask-Hello: true` 头
- [x] 响应经过时日志出现 "收到响应头"
- [x] 修改配置（message）后重启生效（日志显示新配置）

### 验证日志样例

```
wasm log: [hello-plugin] hello-plugin: 配置已加载 message="hello from otpmask gateway" log_level="debug"
wasm log: [hello-plugin] hello-plugin: 收到请求头, message="hello from otpmask gateway"
wasm log: [hello-plugin] hello-plugin: host=127.0.0.1:10000 path=/get
wasm log: [hello-plugin] hello-plugin: 收到响应头, message="hello from otpmask gateway"
```

### 本地调试命令

```powershell
# 启动（envoy + httpbin + wasm）
docker compose up -d

# 查看 wasm 日志
docker logs -f hello-plugin-envoy-1

# 直连 httpbin（无插件）对比
curl.exe -s http://127.0.0.1:12345/get

# 经网关（有插件）
curl.exe -s http://127.0.0.1:10000/get

# 清理
docker compose down
```
