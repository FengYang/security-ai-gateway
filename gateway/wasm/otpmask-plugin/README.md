# otpmask-plugin — OTP-Mask 加解密 Wasm 插件（M2 里程碑）

在 Higress/Envoy 网关侧实现 OTP-Mask 向量加解密 MVP。

## 功能

- **请求侧加密**：明文向量 `{"vectors": [[...]]}` → OTP-Mask 加密 → 密文请求 `{"cipher_vectors": [...], "nonce": "hex", "model": "mock"}`
- **响应侧解密**：密文响应 `{"cipher_output": [...], "nonce": "hex"}` → 解密 → 明文响应 `{"output": [...]}`
- **MemKeyStore**：请求级 seed + nonce 回溯，响应解密后一次性删除
- **复用**：`cipher/mask`（HMAC-SHA256 掩码流，`secagg` 同款密码学核心）

## 关键设计

- 掩码模 R = 2^32（与 `secagg.DefaultModulus` 对齐）
- seed 256 位（满足 `mask.MinSeedLen=32`），每请求独立签发
- 明文/密文均 mod R 校验，越界拒绝

## 构建与运行

```powershell
# 构建（仓库根执行）
$env:GOOS='wasip1'; $env:GOARCH='wasm'
go build -buildmode=c-shared -o gateway/wasm/otpmask-plugin/main.wasm ./gateway/wasm/otpmask-plugin

# 启动验证环境（envoy + mock-infer）
cd gateway/wasm/otpmask-plugin
docker compose up -d

# 端到端加解密闭环验证
python e2e_test.py

# MB 级 body 承载能力 PoC
python body_poc.py
```

## 验证结果（M2 全部通过 ✅）

### 加解密闭环（e2e_test.py）

```
[1] 网关响应: {"output":[100,200,300]}
[2] PASS 解密还原 = 明文 [100, 200, 300]
```

链路密文确认（mock-infer 收到的 body，与明文完全不同）：
```json
{"cipher_vectors": [[10210258, 900937237, 642988164], [10210200, 900937080, 642987908]],
 "nonce": "3b8fdbfa3e8acb0ef293a6bad343fb0f", "model": "mock"}
```

### Wasm body 承载能力（body_poc.py）

| Body 大小 | 向量数 | 端到端延迟 | 还原 |
|---|---|---|---|
| 64KB | 2,730 | 74.5ms | PASS |
| 256KB | 10,922 | 249.4ms | PASS |
| 1MB | 43,690 | 946.0ms | PASS |

> 注：延迟为端到端（含 Python mock-infer JSON 序列化 + 本机 Docker 网络），非纯网关增量延迟。生产网关增量延迟目标（P99 < 20ms）需在 M3 用对比实验（直连 vs 经网关）单独度量。

## 工程注意（standalone Envoy 验证环境的踩坑）

1. **body 替换与 Content-Length**：proxywasm 在 body 阶段无法修改 header（`bad argument`/`not found`）。解法：在 **header 阶段移除 Content-Length**，Envoy 自动改用 chunked 传输完整密文（mock 需支持 chunked 解码）。
2. **大 body 限制**：Envoy 默认 buffer 1MB，超过返回 413。解法：加 `envoy.filters.http.buffer` filter（`max_request_bytes`）。
3. **Go 1.24 原生编译**：须用 `proxy-wasm-go-sdk@go-1.24` 分支 + `-buildmode=c-shared`。

## 文件

| 文件 | 说明 |
|---|---|
| `main.go` | 插件入口（wrapper：headers 移除 CL / body 加解密） |
| `crypto.go` | 向量 OTP-Mask 加解密（复用 `cipher/mask`） |
| `keystore.go` | MemKeyStore（请求级 seed + nonce 回溯） |
| `protocol.go` | mock 加解密协议 JSON 编解码 |
| `mock_infer.py` | 模拟云端密态推理服务（chunked 兼容） |
| `e2e_test.py` | 端到端加解密闭环验证 |
| `body_poc.py` | MB 级 body 承载能力 PoC |
| `envoy.yaml` / `docker-compose.yaml` | 本地验证环境 |

## 生产迁移路径

- M4：Tokenizer + Embedding 独立服务接入（真实文本 → 向量）
- M6：TEE KeyService 替换 MemKeyStore（密钥生命周期 + 远程证明）
- 协议演进：mock JSON → 4.2 南向私有二进制协议（Protobuf + 签名）
