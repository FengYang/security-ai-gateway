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

## P2-1 流式重试（Envoy 层 V3 方案）

### 概述

流式重试是 Envoy 层的能力（非插件内实现，插件侧 Wasm SDK 不支持流式响应），用于在**响应头返回前**的失败场景下自动重试到备用 TEE 实例，降低用户感知的瞬时故障率。

> **限制（重要）**：
> - 仅响应头前失败才重试（connect-failure / 5xx / reset）
> - 流式中途断流不重试（HTTP 语义限制：已发出的数据不可撤回）
> - 单副本场景重试无效（重试也打同一个实例）
> - 多副本场景需配合 session affinity 保证信封会话兼容（K_enc 一致）

### 架构

```
客户端 → Envoy (cluster: tee-infer)
            │
            ├─ health_checks（已有，/healthz/live）
            ├─ outlier_detection（异常点摘除，与重试配合）
            ├─ retry_policy
            │   · num_retries: 0（默认关闭）
            │   · retry_on: connect-failure,502,503,504,reset
            │   · retry_budget（防重试风暴）
            │
            └─ 插件侧配合
                · stream_retry_enabled 开关
                · X-Otpmask-Retry-Attempt 头（计费归因，与非流式重试对齐）
                · X-Otpmask-Stream-Retry 头（开关标识）
```

### 配置

#### 1. 插件侧配置

| 配置项 | 类型 | 默认 | 说明 |
|--------|------|------|------|
| `stream_retry_enabled` | bool | `false` | 总开关。false 时不注入任何头，与 P0 行为一致 |
| `stream_retry_max_attempts` | int | `0` | 最大重试次数（仅头注入标记，实际以 Envoy 配置为准） |

#### 2. 裸 Envoy（deploy/k8s/envoy-gateway.yaml）

```yaml
route:
  cluster: tee-infer
  retry_policy:
    num_retries: 1                              # 改 0→1 开启
    retry_on: "connect-failure,refused-stream,502,503,504,reset"
    retry_budget:
      budget_percent: { value: 10.0 }           # 重试预算 10%（防风暴）
      min_retry_concurrency: 1

cluster:
  outlier_detection:
    consecutive_5xx: 5                           # 连续 5 次 5xx → 摘除
    base_ejection_time: 30s                      # 基础摘除时间
    max_ejection_percent: 50                     # 最多摘除 50% 端点
```

#### 3. Helm（deploy/helm/otpmask/）

```yaml
envoy:
  streamRetry:
    enabled: true
    numRetries: 1
    retryOn: "connect-failure,refused-stream,502,503,504,reset"
    budgetPercent: 10
  outlierDetection:
    enabled: true
    consecutive5xx: 5
    baseEjectionTime: 30s
    maxEjectionPercent: 50
```

#### 4. Higress（deploy/higress/）

```yaml
# ingress-infer.yaml annotation
nginx.ingress.kubernetes.io/proxy-next-upstream-tries: "1"
nginx.ingress.kubernetes.io/proxy-next-upstream: "error timeout http_500 http_502 http_503 http_504"
nginx.ingress.kubernetes.io/proxy-next-upstream-timeout: "60"

# otpmask-plugin.yaml config
stream_retry_enabled: "true"
stream_retry_max_attempts: "1"
```

### 启用步骤（推荐灰度放量）

| 阶段 | 配置 | 观察指标 | 通过标准 |
|------|------|----------|----------|
| Phase 0 | `num_retries=0`（仅配置） | 延迟/错误率基线 | 无变化 |
| Phase 1 | `num_retries=1`，灰度 10% | 重试成功率 / 重试率 / 首字节延迟 P99 | 重试成功率 > 60%，延迟增加 < 20% |
| Phase 2 | `num_retries=1`，全量 | 同上 | 同上 |
| Phase 3 | `num_retries=2`（可选） | 边际收益 | 第 2 次重试收益 > 5% |

**快速回滚**：将 `num_retries` 改回 `0` 或 `stream_retry_enabled=false`。

### 验证步骤

#### 配置正确性验证

```bash
# 1. Envoy 配置语法（裸 Envoy）
kubectl exec -n otpmask deploy/envoy-gateway -- \
  envoy --mode validate -c /etc/envoy/envoy.yaml
# 预期: configuration OK

# 2. Helm 模板渲染
helm template otpmask ./deploy/helm/otpmask -f stream-retry-values.yaml \
  | grep -A5 retry_policy
# 预期: num_retries: 1

# 3. Higress Ingress 注解
kubectl get ingress infer -n higress-system -o jsonpath='{.metadata.annotations}'
# 预期: 包含 3 个 retry 注解
```

#### 功能验证：connect-failure 场景

```bash
# 1. 记录基准重试计数
kubectl exec -n otpmask deploy/envoy-gateway -- \
  curl -s localhost:9901/stats | grep "tee-infer.upstream_rq_retry_total"

# 2. 模拟故障（缩容 TEE 到 0）
kubectl scale deploy/tee-infer-service --replicas=0 -n otpmask
sleep 5

# 3. 发送流式请求（预期 503，单副本故障场景）
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://<gateway>:30000/infer \
  -H "Content-Type: application/json" \
  -H "Accept: text/event-stream" \
  -d '{"text":"hello","stream":true,"engine_type":"tee_gpu"}'

# 4. 检查重试计数是否增加
kubectl exec -n otpmask deploy/envoy-gateway -- \
  curl -s localhost:9901/stats | grep "tee-infer.upstream_rq_retry_total"

# 5. 恢复
kubectl scale deploy/tee-infer-service --replicas=1 -n otpmask
```

#### 计费归因验证

1. 开启 `stream_retry_enabled=true`
2. 发送流式请求，在 TEE 侧检查请求头
   - 首次请求：`X-Otpmask-Retry-Attempt: 1`，`X-Otpmask-Stream-Retry: on`
   - 重试请求（Envoy 自动递增）：`X-Otpmask-Retry-Attempt: 2`
3. 验证计费系统中 attempt ≥ 2 的请求不计费

### 监控与告警

| 指标（Envoy 原生） | 说明 | 告警阈值 |
|------|------|----------|
| `envoy_cluster_upstream_rq_retry` | 总重试次数 | — |
| `envoy_cluster_upstream_rq_retry_success` | 重试成功次数 | — |
| `envoy_cluster_upstream_rq_retry_overflow` | 重试预算耗尽（防风暴触发） | > 0 → Critical |
| `envoy_cluster_outlier_detection_ejections_total` | 异常点摘除次数 | 5 分钟 > 5 次 → Warning |
| `envoy_cluster_upstream_cx_connect_fail` | 连接失败次数 | 突增 → Warning |

**重试率高告警**（> 10%）：
```
rate(envoy_cluster_upstream_rq_retry{cluster="tee-infer"}[5m])
/ rate(envoy_cluster_upstream_rq_total{cluster="tee-infer"}[5m])
> 0.1
```

### 注意事项

1. **信封会话兼容**：多副本场景下，跨实例重试可能导致 K_enc 不匹配 → 解密失败。需配合 session affinity（按信封会话 ID 一致性哈希）。当前单副本环境无此问题。
2. **重试风暴防护**：`retry_budget` 默认 10%，后端大面积故障时限制重试流量比例，避免放大压力。
3. **首字节延迟**：重试场景下用户感知为首字节延迟增加（正常，预期内）。监控 P99 首字节延迟，不超过基线 20% 可接受。
4. **HTTP 语义限制**：响应头发出后失败不重试（数据已发给客户端，不可撤回）。流式中途断流需客户端自行重发。
5. **Higress 差异**：Higress 使用 Nginx 兼容注解（`proxy-next-upstream-*`），语义与 Envoy 原生 `retry_policy` 略有差异，生产以实际测试为准。

### 文件清单

| 文件 | 说明 |
|------|------|
| `route.go` | `injectStreamRetryHeaders()` + `streamRetryEnabled` 运行态 + 头常量 |
| `main.go` | PluginConfig 新增 `StreamRetryEnabled` / `StreamRetryMaxAttempts` + parseConfig 解析 |
| `streamretry_test.go` | 4 个单测（默认值 / 头常量 / 头值计算 / 零行为） |
| `deploy/k8s/envoy-gateway.yaml` | 裸 Envoy retry_policy + outlier_detection |
| `deploy/helm/otpmask/values.yaml` | Helm streamRetry + outlierDetection 配置段 |
| `deploy/helm/otpmask/templates/envoy-gateway.yaml` | Helm 条件渲染 |
| `deploy/higress/ingress-infer.yaml` | Higress Ingress retry 注解 |
| `deploy/higress/otpmask-plugin.yaml` | Higress 插件 stream_retry 配置 |

## 生产迁移路径

- M4：Tokenizer + Embedding 独立服务接入（真实文本 → 向量）
- M6：TEE KeyService 替换 MemKeyStore（密钥生命周期 + 远程证明）
- 协议演进：mock JSON → 4.2 南向私有二进制协议（Protobuf + 签名）
