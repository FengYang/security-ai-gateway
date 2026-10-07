# OTP-Mask 安全 AI 网关 API 参考

> **口径注（2026-09-18）**：本文中「TEE 内」等表述按 **S3 自建密态（`tee_gpu`，tee-infer/推理引擎位于 TEE 飞地内）** 语境撰写；**S2 对接第三方密态（`cmaas`）** 下 tee-infer 位于**客户可信域**、TEE 在厂商侧（**我方不需要 TEE**）；明文路径 `/provider/*` 不经 tee-infer、无 TEE 需求。场景与可信区域唯一事实源见《GA-产品场景与可信区域矩阵.md》。


## 1. 服务与端口

| 服务 | 地址 | 用途 | 认证 |
| --- | --- | --- | --- |
| 网关（Envoy + otpmask 插件） | `:10000` | 应用层推理入口（文本 → SSE） | `X-Tenant-ID` 租户头；`Authorization: Bearer <JWT>`（C-6 可选/强制） |
| auth-service | `:19200` | JWT 签发/校验（租户鉴权，C-6） | 无（内部网络） |
| embedding-service | `:18080` | 文本 → token/向量（内部可信域；路线 2 形态） | 无（内部网络） |
| tee-infer-service | `:19090` | 证明握手 / 密钥签发 / 南向推理 / 治理面 | `X-Session-ID`（quote 会话）/ `X-Attest-Token`（MVP） |
| vllm-adapter | `:19190` | 明文推理引擎接口（TEE 内；路线 2 保留） | 无（TEE 内网） |
| attest-verify（P3，D2） | `127.0.0.1:19191` | TDX quote 验证 sidecar（`/verify`、`/healthz`） | `X-Verify-Token`（可选，回环绑定） |

## 2. 通用约定

请求头：

| 头 | 作用域 | 说明 |
| --- | --- | --- |
| `Content-Type: application/json` | 网关 /embed 类 | JSON 请求体 |
| `X-Tenant-ID` | 网关 /infer | 租户标识；缺失时归入 `default` 租户（隔离独立，不与其他租户串用） |
| `Authorization: Bearer <token>` | 网关 /infer | 租户鉴权 JWT（HS256，C-6）：有效 token 以 `tenant` 声明覆盖 `X-Tenant-ID`（防伪造）；插件配置 `require_auth=true` 时无/无效 token 返回 401 |
| `X-Attest-Token` | tee-infer /key/issue | 远程证明令牌（MVP 共享令牌；生产为 TDX Quote 交换） |

错误码约定：`4xx` 为客户端可纠正错误（消息为中文描述）；`503` 为 TEE 链路不可用（fail-closed，不降级明文）；`413` 为请求体超限。**安全拦截的判定一律以 HTTP 状态码为准**（当前为 `403`）；响应体（若返回）仅作人类可读描述，**不保证存在与结构**。

## 3. 网关 API（:10000）

### 3.1 推理（SSE 流式）

`POST /infer`

请求体（`stream`/`engine_type` 为路线 1 可选扩展，P2/P5）：

```json
{ "text": "hello secure ai" }
{ "text": "你好", "engine_type": "tee_gpu", "stream": true }
{ "text": "你好", "engine_type": "cmaas" }
```

| 字段 | 说明 |
| --- | --- |
| `text` | 明文提示词（必填） |
| `engine_type` | `tee_gpu`（缺省，自建 GPU-TEE）/ `cmaas`（百炼机密 MaaS）/ `masked_vector`（路线 2 保留，缺省不指定时走既有向量链路） |
| `stream` | 流式 SSE（缺省 true）；`false` 时为单分片聚合（服务端统一 SSE 信封输出） |

> 注：指定 `engine_type: tee_gpu|cmaas` 时走南向 text 载荷（D1），**要求插件 `attest_mode: quote`**
> （text 载荷仅限证明会话；token 模式请求被 tee-infer fail-closed 拒绝）。

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
| 403 | 内容安全拦截（PII/SQL 注入/提示注入）。**判定以状态码为准**：客户端应依据 `403` 判定拦截；响应体**若返回**为中文描述，例：`内容安全拦截（<类别>）`，**不保证存在与结构**（部分路径实测为空体），不得依赖其解析 |
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

### 5.1 远程证明握手（挑战-响应，P1b）

`POST /attest` — 请求 `{"nonce":"<32B hex>"}`；响应 `{"session_id","server_pub","proof","protocol_version","session_ttl"}`。
`report_data = H(nonce ‖ server_pub)` 绑定握手公钥（防中间人替换）；证明链验证（nonce 回显 + report_data + app_hash + 签名）在插件侧完成（真机 TDX 下由 attest-verify sidecar 完成）。

`POST /attest/complete` — 请求 `{"session_id","client_pub"}`；ECDH + HKDF 派生会话密钥（K_sig/K_enc），返回 `{"status":"ok","session_id","session_ttl"}`。会话 TTL 5min，过期自动清理并零化密钥。

MVP 兼容：`POST /attest`（空 body）返回旧版握手确认（`{"status":"attested"}`）。

### 5.2 密钥签发

`POST /key/issue`

请求体：`{"model":"mock","request_id":"<唯一 ID>"}`；认证：quote 会话（`X-Session-ID` 头 + c2s 信封体）或 MVP `X-Attest-Token`。quote 会话下请求/响应整体入 K_enc 信封（AAD 绑定 `/key/issue`）；明文请求在有效会话下被 fail-closed 拒绝（`OTPMASK_SESSION_PLAINTEXT=dev` 仅调试放行）。响应（信封内 JSON）：

```json
{ "seed": "ed1bc089...", "nonce": "aeec2179...", "master_id": 1, "protocol_version": "1.0.0" }
```

`seed` 为请求密钥（OTP 掩码种子，仅经加密通道下发）；`nonce` 用于推理请求关联密钥；`master_id` 为主密钥版本（观测轮换）；`protocol_version` 为南向协议版本（5.2 版本一致性：插件与 TEE 不匹配时网关 fail-closed 拒绝）。

### 5.3 南向推理（二进制协议）

`POST /v1/infer`（别名 `/infer`）— 请求/响应为南向私有协议二进制（wire 格式见 8）。两种载荷：

| 载荷 | 说明 |
| --- | --- |
| text 载荷（路线 1，P2/P5） | 请求字段 `engine_type`/`attest_type`/`text_payload`（OpenAI 兼容 messages JSON）/`stream`；**仅限 quote 会话信封**（无会话 400 fail-closed）；响应为 SSE 信封流（`data: <hex(s2c 信封)>`，seq 严格递增，finish=stop 终止，防截断） |
| vectors 载荷（路线 2 保留） | 既有 `cipher_vectors`/`cipher_text` 掩码路径，`Content-Type: application/x-otpmask` |

由网关插件构造，一般无需直接调用。

### 5.4 治理面

| 端点 | 说明 |
| --- | --- |
| `GET /usage` | 全部租户用量（含配额视图 `quota`/`used_tokens`，P1）；`?tenant=acme` 过滤单租户 |
| `POST /usage/quota` | 设置租户 token 配额（P1）：`{"tenant":"acme","max_tokens":1000000}`，`max_tokens<=0` 解除；返回生效配额 |
| `GET /audit` | 审计事件；`?tenant=acme` 过滤 |
| `GET /audit/verify` | 审计哈希链完整性，`{"ok":true,"events":N}` |
| `POST /audit/anchor` | 触发审计锚定（6.3）：链尾哈希追加写锚定文件，返回 `{"timestamp","events","chain_hash"}`；未启用锚定文件时 400 |
| `GET /metrics` | Prometheus 文本（请求/拒绝/密钥签发/审计链长度等 6 族指标） |
| `GET /healthz`（`/healthz/live`） | readiness/liveness 探针；`-require-attest` 下无有效证明会话 → 503 |

> 审计事件 `action` 含 `key_issue`/`infer`/`deny`/`cmaas_attest`（P5：C-MaaS 证明/透明度引用，`payload_hash` 为引用哈希）。

用量响应示例（P1 起含配额视图）：

```json
{ "acme": { "tokens_in": 6, "tokens_out": 6, "requests": 2, "denies": 1, "quota": 1000000, "used_tokens": 12 } }
```

审计事件字段（6.3 数据模型）：`event_id`、`timestamp`、`tenant_id`、`request_id`、`action`（key_issue/infer/deny）、`result`（ok 或拒绝原因，如 `guardrail_pii`/`quota_exceeded`）、`payload_hash`、`prev_hash`；P2a 起 infer 事件附 `transformed_hash`（装饰/脱敏后引擎实收内容哈希，双 hash 审计）。

### 5.5 缓存管理 API（P0-2 语义缓存）

> 语义缓存为 tee-infer 内的模块（不新增独立服务），管理 API **同进程同端口**（`:19090`）。默认 `mode=off` 时缓存不产生任何行为变化。

**通用约定**：

- **鉴权**：`X-Admin-Token`（与 `/config`、`/metrics`、`/audit` 同一管理令牌）；缺失/错误 → `403 CACHE_FORBIDDEN`。（`cache-admin` 角色体系未落地，当前为等价鉴权。）
- **响应信封**：成功 `{"ok":true,"data":{…},"request_id":…}`；失败 `{"ok":false,"error":{"code","message"},"request_id":…}`；`request_id` 原样回显请求头 `X-Request-Id`。
- **门控**：`mode=off`（默认）或引擎未装配 → 运营端点一律 `409 CACHE_DISABLED`（`GET /config/cache` 仍可读）。
- **幂等**：所有 `DELETE` 与 `/cache/feedback`（按 `request_id`）均幂等。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/cache/stats` | 缓存总览：`mode`/`backend`/`entries{exact,negative,vector}`/`evictions`/`fast_check_blocks`/`semantic_false_positive`/`saved_tokens`/`lookups{kind:result}` |
| DELETE | `/cache/entry/{key_hash}` | 精确失效（按键）；返回 `{key_hash,deleted}` |
| DELETE | `/cache/tenant/{tenant_id}` | 失效（按租户，含向量）；返回 `{tenant_id,deleted}` |
| DELETE | `/cache/model/{model}` | 失效（按模型）；返回 `{model,deleted}` |
| DELETE | `/cache/all?confirm=yes` | 全量清空（**须 `confirm=yes`**）；返回 `{deleted}` |
| POST | `/cache/warmup` | 触发预热（体 `{"reset":bool}` 可空）；返回 `{task_id,total}` |
| GET | `/cache/warmup/{task_id}` | 预热任务进度（`WarmTask`） |
| POST | `/cache/feedback` | 误命中反馈上报；返回 `{request_id,verdict,duplicate}` |
| GET | `/cache/inspect/{key_hash}` | 条目检视（**仅元数据，不含文本**，I-6） |
| GET | `/config/cache` | 缓存配置只读快照 `{configured,config}`（`mode=off` 时仍可读） |

**错误码**：

| `error.code` | HTTP | 触发 |
| --- | --- | --- |
| `CACHE_DISABLED` | 409 | `mode=off`/引擎未装配时调用运营端点；或 `warmup.enabled=false` |
| `CACHE_INVALID_ARG` | 400 | 参数非法（缺 `confirm`、路径参数、体非法、预热文件不可读含 `warmup line N`）；方法不符为 **405** 同码 |
| `CACHE_NOT_FOUND` | 404 | `key_hash` 不存在；`task_id` 不存在或已过期 |
| `CACHE_FORBIDDEN` | 403 | 鉴权失败 |
| `CACHE_WARMUP_BUSY` | 409 | 已有活跃预热任务（单飞） |
| `CACHE_BACKEND_UNAVAILABLE` | 503 | 失效操作的后端（如 Redis）不可用 |

**要点**：

- **`/cache/inspect` 零文本**：`Entry.Text`/`Entry.Segments` 以 `json:"-"` 序列化隐藏，响应**天然不含缓存正文**；仅覆盖精确层（负向层无 `Entry` 元数据 → 404）。字段：`kind`/`id`/`tenant`/`engine`/`model`/`key_hash`/`prompt_hash`/`tin`/`tout`/`hits`/`lh_at`/`created_at`/`expire_at`/`pver`/`gver`/`cksum`。
- **`/cache/warmup` 单飞**：并发触发 → `409 CACHE_WARMUP_BUSY`；`GET` 返回 `WarmTask`：`id`/`status`(`idle|running|succeeded|failed`)/`total`/`succeeded`/`failed`/`skipped`/`truncated`/`started_at`/`finished_at`/`last_error`。**任务态不持久化**（进程重启即丢）。
- **`/cache/feedback`**：体 `{"request_id","verdict"∈good|bad|irrelevant,"note"?}`；`note` 截断 256 字节且**不落审计链/日志/库**；同 `request_id` 重复上报返回 `duplicate=true`（覆盖不重复计数）；未知 `request_id` 不报错。**归因（`request_id→scene`）归后续**。
- **策略/词库变更**：`policy_version`/`GuardVer` 变更后旧条目**自然失效**，无需清缓存。

**示例**：

```bash
BASE="http://127.0.0.1:19090"; TOKEN="<admin token>"
curl -s -H "X-Admin-Token: $TOKEN" "$BASE/cache/stats"
curl -s -X DELETE -H "X-Admin-Token: $TOKEN" "$BASE/cache/entry/<key_hash>"
curl -s -X DELETE -H "X-Admin-Token: $TOKEN" "$BASE/cache/all?confirm=yes"
curl -s -X POST -H "X-Admin-Token: $TOKEN" -d '{"reset":false}' "$BASE/cache/warmup"
curl -s -H "X-Admin-Token: $TOKEN" "$BASE/cache/inspect/<key_hash>"
```

## 6. vllm-adapter API（:19190，TEE 内）

`POST /generate`：请求 `{"vectors":[[...]],"text":""}` → 响应 `{"tokens":[...]}`。明文推理接口，真实 vLLM 环境由 `vllm_adapter.py` 提供（`--mock` 与 `--model` 两种引擎，接口一致）。

`GET /health`：`{"status":"ok","engine":"mock|vllm"}`。

## 7. 状态码汇总

| 码 | 场景 |
| --- | --- |
| 200 | 成功（SSE 为流式 200） |
| 400 | 协议/请求错误：签名无效路径外的解码失败、重放、超窗时间戳、未知 nonce、畸形 body |
| 401 | 南向验签失败 / attestation 令牌无效 |
| 403 | 内容安全拦截（guardrail）：**以状态码判定**，响应体不保证存在与结构；缓存管理 API 鉴权失败（`CACHE_FORBIDDEN`） |
| 404 | 缓存管理 API：资源不存在（`key_hash`/`task_id`，`CACHE_NOT_FOUND`） |
| 405 | 缓存管理 API：方法不符（同 `CACHE_INVALID_ARG`） |
| 409 | 缓存管理 API：门控/冲突（`CACHE_DISABLED`/`CACHE_WARMUP_BUSY`） |
| 413 | 请求体超过 16MB |
| 429 | 租户 token 配额超限（P1）或网关 QPS 限流（P0a，Envoy 层） |
| 503 | TEE 不可用（fail-closed 拒绝） |

## 8. 南向协议 wire 格式（摘要）

固定顺序 Varint 编码（Protobuf 兼容，无字段号）：

```
InferenceRequest:
  string request_id | varint timestamp_ns | string model | varint max_new_tokens
  | bytes nonce | varint 向量数 m | m × CipherVector | bytes cipher_text | bytes signature
  | [扩展段] string engine_type | string attest_type | bytes text_payload | varint stream

CipherVector: varint dim | n × varint（uint64 元素）

签名：HMAC-SHA256(K_sig, request_id || timestamp_ns || nonce || payload)
      payload 含 cipher_vectors || cipher_text || text_payload || stream（P2/P5 追加）
防重放：timestamp 30s 窗口 + request_id 去重
```

扩展段追加于 wire 末尾（向后兼容：旧格式请求/旧实现互可解码，P2 跨语言测试覆盖）；
`engine_type` 为空时不编码扩展段；`stream` 1 = 流式 SSE 信封响应。

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
