# OTP-Mask 安全 AI 网关 API 参考


## 1. 服务与端口

| 服务 | 地址 | 用途 | 认证 |
| --- | --- | --- | --- |
| 网关（Envoy + otpmask 插件） | `:10000` | 应用层推理入口（文本 → SSE） | `X-Tenant-ID` 租户头；`Authorization: Bearer <JWT>`（C-6 可选/强制） |
| auth-service | `:19200` | JWT 签发/校验（租户鉴权，C-6） | 无（内部网络） |
| embedding-service | `:18080` | 文本 → token/向量（内部可信域） | 无（内部网络） |
| tee-infer-service | `:19090` | 密钥签发 / 南向推理 / 治理面 | `X-Attest-Token`（内部） |
| vllm-adapter | `:19190` | 明文推理引擎接口（TEE 内） | 无（TEE 内网） |

## 2. 通用约定

请求头：

| 头 | 作用域 | 说明 |
| --- | --- | --- |
| `Content-Type: application/json` | 网关 /embed 类 | JSON 请求体 |
| `X-Tenant-ID` | 网关 /infer | 租户标识；缺失时归入 `default` 租户（隔离独立，不与其他租户串用） |
| `Authorization: Bearer <token>` | 网关 /infer | 租户鉴权 JWT（HS256，C-6）：有效 token 以 `tenant` 声明覆盖 `X-Tenant-ID`（防伪造）；插件配置 `require_auth=true` 时无/无效 token 返回 401 |
| `X-Attest-Token` | tee-infer /key/issue | 远程证明令牌（MVP 共享令牌；生产为 TDX Quote 交换） |

错误码约定：`4xx` 为客户端可纠正错误（消息为中文描述）；`503` 为 TEE 链路不可用（fail-closed，不降级明文）；`413` 为请求体超限。

## 3. 网关 API（:10000）

### 3.1 推理（SSE 流式）

`POST /infer`

请求体：

```json
{ "text": "hello secure ai" }
```

响应：`text/event-stream`，逐 token 一行，`[DONE]` 结束：

```
data: {"token":"g"}

data: {"token":"g"}

data: {"token":"g"}

data: [DONE]

```

| 状态码 | 含义 |
| --- | --- |
| 200 | SSE 流开始（首行即第一个 token） |
| 403 | 内容安全拦截（PII/SQL 注入/提示注入），响应体 `内容安全拦截（<类别>）` |
| 413 | 请求体超过 16MB（Envoy buffer 限制） |
| 503 | TEE 链路不可用（fail-closed） |

示例：

```bash
curl -X POST http://127.0.0.1:10000/infer \
  -H 'Content-Type: application/json' -H 'X-Tenant-ID: acme' \
  -d '{"text":"hello secure ai"}'
```

## 4. embedding-service API（:18080）

### 4.1 文本嵌入

`POST /embed`

请求体：`{"text": "..."}`；响应：

```json
{
  "tokens": [15339, 9966, 16796],
  "vectors": [[886579054, 41220833, 1088404245, 1208688725, 2696579055, 3957787595, 2415768237, 4168415434]]
}
```

`tokens` 为 cl100k_base 分词 ID（与 OpenAI token 数一致）；`vectors` 每个 token 对应 8 维向量（元素 < 2^32）。

### 4.2 指标

`GET /metrics` — Prometheus 文本格式，`otpmask_embed_requests_total` / `otpmask_embed_tokens_total`。

## 5. tee-infer-service API（:19090，内部/南向）

### 5.1 远程证明握手

`POST /attest` — MVP 返回 `{"status":"attested"}`（生产为 TDX Quote 双向验证）。

### 5.2 密钥签发

`POST /key/issue`

请求体：`{"model":"mock","request_id":"<唯一 ID>"}`，头需 `X-Attest-Token`；响应：

```json
{ "seed": "ed1bc089...", "nonce": "aeec2179...", "master_id": 1, "protocol_version": "1.0.0" }
```

`seed` 为请求密钥（OTP 掩码种子，仅经加密通道下发）；`nonce` 用于推理请求关联密钥；`master_id` 为主密钥版本（观测轮换）；`protocol_version` 为南向协议版本（5.2 版本一致性：插件与 TEE 不匹配时网关 fail-closed 拒绝）。

### 5.3 南向推理（二进制协议）

`POST /v1/infer`（别名 `/infer`）— 请求/响应为南向私有协议二进制（wire 格式见 8），`Content-Type: application/x-otpmask`。由网关插件构造，一般无需直接调用。

### 5.4 治理面

| 端点 | 说明 |
| --- | --- |
| `GET /usage` | 全部租户用量；`?tenant=acme` 过滤单租户 |
| `GET /audit` | 审计事件；`?tenant=acme` 过滤 |
| `GET /audit/verify` | 审计哈希链完整性，`{"ok":true,"events":N}` |
| `POST /audit/anchor` | 触发审计锚定（6.3）：链尾哈希追加写锚定文件，返回 `{"timestamp","events","chain_hash"}`；未启用锚定文件时 400 |
| `GET /metrics` | Prometheus 文本（请求/拒绝/密钥签发/审计链长度等 6 族指标） |

用量响应示例：

```json
{ "acme": { "tokens_in": 6, "tokens_out": 6, "requests": 2, "denies": 1 } }
```

审计事件字段（6.3 数据模型）：`event_id`、`timestamp`、`tenant_id`、`request_id`、`action`（key_issue/infer/deny）、`result`（ok 或拒绝原因，如 `guardrail_pii`）、`payload_hash`、`prev_hash`。

## 6. vllm-adapter API（:19190，TEE 内）

`POST /generate`：请求 `{"vectors":[[...]],"text":""}` → 响应 `{"tokens":[...]}`。明文推理接口，真实 vLLM 环境由 `vllm_adapter.py` 提供（`--mock` 与 `--model` 两种引擎，接口一致）。

`GET /health`：`{"status":"ok","engine":"mock|vllm"}`。

## 7. 状态码汇总

| 码 | 场景 |
| --- | --- |
| 200 | 成功（SSE 为流式 200） |
| 400 | 协议/请求错误：签名无效路径外的解码失败、重放、超窗时间戳、未知 nonce、畸形 body |
| 401 | 南向验签失败 / attestation 令牌无效 |
| 403 | 内容安全拦截（guardrail） |
| 413 | 请求体超过 16MB |
| 503 | TEE 不可用（fail-closed 拒绝） |

## 8. 南向协议 wire 格式（摘要）

固定顺序 Varint 编码（Protobuf 兼容，无字段号）：

```
InferenceRequest:
  string request_id | varint timestamp_ns | string model | varint max_new_tokens
  | bytes nonce | varint 向量数 m | m × CipherVector | bytes cipher_text | bytes signature

CipherVector: varint dim | n × varint（uint64 元素）

签名：HMAC-SHA256(K_sig, request_id || timestamp_ns || nonce || payload)
防重放：timestamp 30s 窗口 + request_id 去重
```

权威定义见 `protocol/proto/otpmask.proto`；Go/Python 双实现经交叉测试保持一致。

## 9. 集成示例（Python，走网关）

```python
import json, urllib.request

body = json.dumps({"text": "hello secure ai"}).encode
req = urllib.request.Request(
    "http://127.0.0.1:10000/infer", data=body,
    headers={"Content-Type": "application/json", "X-Tenant-ID": "acme"},
)
for line in urllib.request.urlopen(req, timeout=20):
    if line.startswith(b"data: [DONE]"):
        break
    print(line.decode.strip)
```
