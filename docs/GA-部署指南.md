# GA 部署指南（OTP-Mask 安全 AI 网关）

> **生产环境为 Linux**：本指南脚本已跨平台（PowerShell 脚本经 pwsh 在 Linux 运行；另提供 `scripts/setup-env.sh` 一键脚本）。

## 1. 部署路径总览

| 路径 | 场景 | 前置 | 入口 |
| --- | --- | --- | --- |
| A. Docker Compose | 本地开发/演示 | Docker 19+（Windows/macOS/Linux） | `gateway/wasm/otpmask-plugin/docker-compose.yaml` |
| B. kind 单节点 | 生产清单真机验证 | Docker + kind + kubectl | `deploy/kind/kind-config.yaml` + `deploy/k8s` |
| C. Kubernetes | **生产（Linux）** | 集群 + metrics-server | `deploy/k8s` + `deploy/monitoring` |

## 1.0 路线 1 部署形态（text 载荷，D1）

路线 1（多引擎机密推理统一网关）下，南向统一 text 载荷（经 K_enc 加密通道），组件拓扑：

```
客户端 → Higress/Envoy 网关（otpmask wasm 插件）
           │ quote 会话（挑战-响应 + 证明验证）
           ▼
        tee-infer-service ──text 流式──> vLLM（OpenAI 兼容，tee_gpu）
           │                    └───> openai-proxy（C-MaaS 段②，cmaas）
           ▼
        attest-verify sidecar（127.0.0.1:19191，TDX quote 验证，D2）
```

关键差异（相对旧向量形态）：

| 项 | 说明 |
| --- | --- |
| 南向载荷 | text（明文 messages 经 K_enc 信封），不再走 embedding-service 向量化 |
| tee-infer 引擎 | `-engine-url http://vllm:8000`（vLLM OpenAI 兼容流式）；`-cmaas-url http://127.0.0.1:8080`（C-MaaS openai-proxy，`-cmaas-api-key`/`-cmaas-model` 可选） |
| tee-infer 治理（P1/P2a） | `-token-quota <n>`（每租户 token 配额，0=不限）；`-pii-mode mask`（PII 脱敏替换，默认 block 拦截）；`-system-prompt <text>`（提示词装饰）；配额经 `POST /usage/quota` 动态调整 |
| 网关底座（P0a，dev/回退形态） | Envoy 原生：CORS + IP 白名单（RBAC，默认 `0.0.0.0/0` 放行，生产收紧）+ QPS 限流（local_ratelimit，零外部依赖） |
| 网关底座（P0b，生产形态，D-0 修正为 B） | Higress 控制面：`deploy/higress/` 清单（otpmask WasmPlugin + key-auth/IP Restriction/Rate Limit/CORS，**failStrategy 一律 FAIL_CLOSED** + Ingress 路由），插件链序：认证/安全 → otpmask 段① 加密 → 路由；迁移见 `deploy/higress/README.md` |
| 证明验证 | `gateway/attest-verify` sidecar（localhost `/verify`，度量基线 allowlist）；真机 TDX 时插件经 localhost 调用 |
| 客户端请求 | `{"text":"...","engine_type":"tee_gpu|cmaas","stream":true}`；text 载荷仅限 quote 会话（token 模式拒绝） |
| 路由 | `deploy/` 内 `route-config.json` 声明模型→引擎映射（cmaas-* 仅 cmaas） |

> 路线 2（vectors 载荷）代码全保留（`masked_vector`），部署方式见 `docs/路线2研究跟踪.md`。

## 1.1 Linux 生产环境说明

| 项 | Linux 做法 |
| --- | --- |
| 一键搭建 | `bash scripts/setup-env.sh`（工具安装/构建/compose；`--skip-verify`、`--with-k8s`） |
| 验证套件 | 安装 pwsh（PowerShell Core）后 `pwsh -NoProfile -File scripts/verify-all.ps1`；未装 pwsh 时 setup-env.sh 提示替代验证 |
| 工具路径 | 脚本自动探测 PATH 中的 `go`/`helm`（`GO_BIN`/`HELM_BIN` 环境变量可覆盖） |
| 容器命名 | compose 项目名决定容器名（`otpmask-plugin-*`），pen_test.py 依赖此命名——Linux 下保持目录名一致即可 |
| GPU 引擎 | `python gateway/vllm-adapter/vllm_adapter.py --model ...`（或 pwsh 跑 vllm-up.ps1） |
| 服务化 | 生产建议 systemd 管理 tee-infer/embedding，或直接走路径 C（K8s） |

## 2. 路径 A：Docker Compose（开发）

```powershell
# 构建 wasm 插件（Go 1.24 原生 wasm，需要 GOOS/GOARCH）
$env:GOOS='wasip1'; $env:GOARCH='wasm'
go build -buildmode=c-shared -o gateway/wasm/otpmask-plugin/main.wasm ./gateway/wasm/otpmask-plugin

# 启动（envoy 网关 :10000 / embedding :18080 / tee-infer :19090 / mock :19000）
docker compose -f gateway/wasm/otpmask-plugin/docker-compose.yaml up -d --build

# 验证
powershell -NoProfile -File scripts/verify-all.ps1        # 10 项全量
python scripts/pen_test.py                                # 20 项渗透
```

端口：网关 `10000`（SSE 推理入口）；tee-infer 治理面 `19090`（/usage /audit /metrics）。

## 3. 路径 B：kind 单节点（清单验证）

```powershell
kind create cluster --config deploy/kind/kind-config.yaml
kubectl apply -k deploy/k8s
kubectl apply -k deploy/monitoring
# 预装 metrics-server（HPA 依赖）：
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
kubectl get pods -n otpmask   # 等待全部 Running
```

端口映射（与开发环境一致）：网关 `10000`（NodePort 30000）、Grafana `3000`（30001）、Prometheus `9090`（30090）。

验证 HPA/PDB：

```bash
kubectl get hpa,pdb -n otpmask
# NAME                         REFERENCE                MINPODS MAXPODS
# embedding-service-hpa        Deployment/embedding...  1       5
# NAME                       MIN AVAILABLE
# embedding-service-pdb      1
```

## 4. 路径 C：Kubernetes（生产）

### 4.1 镜像构建与推送

| 镜像 | 构建命令 | 说明 |
| --- | --- | --- |
| `otpmask/embedding-service:latest` | `docker build -f gateway/embedding-service/Dockerfile .` | 文本向量服务 |
| `otpmask/tee-infer-service:latest` | `docker build -f gateway/tee-infer-service/Dockerfile .` | TEE 密态推理 |
| `otpmask/envoy-gateway:latest` | `docker build -f gateway/wasm/otpmask-plugin/Dockerfile.k8s gateway/wasm/otpmask-plugin` | Envoy + wasm 插件（wasm 随镜像打包） |
| `security-ai-gateway/gateway-admin-service:latest` | `docker build -f gateway/gateway-admin-service/Dockerfile .` | 管理门户业务服务 + 内部凭据 broker（含 ca-certificates；`USER 65532` 与清单 `runAsNonRoot` 对齐） |
| `security-ai-gateway/gateway-core:latest` | `docker build -f gateway/gateway-core/Dockerfile .` | 控制面（处方/路由表/限流预算表签发 + 策略变更审计）；需 `otpmask-keys` 的 `core-sig-key`/`core-auth-token`，且 `core-sig-key` 必须与插件 `route_verify_key` 一致 |

> P0b-1 本地轻集群实测补齐：`gateway-admin-service` 此前**无 Dockerfile**（清单已引用该镜像但无法构建）；
> 同时 tee-infer / embedding 基础镜像补 `USER 65532`（清单置 `runAsNonRoot`，镜像默认 root 会被 kubelet 拒绝）。

> wasm 插件 7.1MB 超 ConfigMap 1MiB 限制，必须随镜像分发（`Dockerfile.k8s` 已内置）。

### 4.2 密钥注入（生产必读）

`deploy/k8s/secret.yaml` 中的 `sig-key`/`attest-token` 为**演示值**。生产要求：

1. 由 TEE 签发 K_sig 与远程证明凭证，经 Vault/KMS envelope 加密存储；
2. `kubectl apply -k deploy/k8s` 前以真实 Secret 覆盖（`kubectl create secret generic otpmask-keys --from-literal=...`）；
3. tee-infer 的 `args` 经 `secretKeyRef` 注入（清单已配置 `$(SIG_KEY)` 展开）。

### 4.3 部署与扩缩容

```bash
kubectl apply -k deploy/k8s
kubectl apply -k deploy/monitoring

# 扩缩容（HPA 自动；手动覆盖 minReplicas）
kubectl scale deployment tee-infer-service -n otpmask --replicas=3

# 滚动升级（PDB 保证至少 1 副本可用）
kubectl rollout restart deployment -n otpmask
```

HPA 参数（`deploy/k8s/hpa.yaml`）：embedding CPU 60%（min 1 / max 5）、tee-infer CPU 70%（min 1 / max 4，推理 CPU 敏感），scaleDown 稳定窗口 300s。

### 4.4 监控接入

- Prometheus 通过 pod 注解自动发现（`prometheus.io/scrape=true` + `/metrics`）；
- Grafana 预置面板"OTP-Mask 网关总览"（provisioning 自动加载）：
  - 推理请求速率（按租户/结果）、Token 累计、拒绝计数（按租户/原因）、审计哈希链长度；
- 生产补充：Alertmanager 告警（审计链断裂、denies 突增、HPA 失效、TEE 不可达）、TSDB PVC 持久化、Grafana 密码 Secret 化。

## 5. 运维手册

### 5.1 健康检查

| 端点 | 用途 |
| --- | --- |
| `GET /attest` | tee-infer 就绪/存活探针 |
| `GET /metrics` | embedding 探针 + Prometheus 抓取 |
| `GET /audit/verify` | 审计链完整性（建议定时巡检，告警阈值：ok=false） |
| `GET /usage` | 租户用量（对接计费） |

### 5.2 故障排查

| 现象 | 排查 |
| --- | --- |
| 网关 503 | TEE 不可用 → fail-closed（设计行为）。`docker logs otpmask-plugin-tee-infer-service-1` |
| 网关 400 协议错误 | 插件与 tee-infer 版本不一致（南向协议 wire 不兼容），确认两端 `protocol/` 同步 |
| text 请求 400"须在证明会话" | 插件 `attest_mode` 未配置 quote 或会话未建立（text 载荷仅限 quote 会话） |
| cmaas 请求 503"引擎未配置" | tee-infer 未加 `-cmaas-url` 参数（fail-closed，设计行为） |
| guardrail 403 | 内容安全拦截，`/audit` 中 `result=guardrail_<category>` 可查原因 |
| HPA 不扩缩 | 检查 metrics-server、Deployment 是否设置 resources.requests.cpu |
| 审计链断裂 | `verify` 返回 false → 事件被篡改或持久化损坏，进入事件响应流程 |

### 5.3 安全事件响应（摘要）

1. 审计链 verify 失败 / 告警 → 冻结变更，导出 `/audit` 全量；
2. 定位事件：`/usage` 异常租户 + `/audit` 按 tenant 过滤；
3. 轮换：重建 `otpmask-keys` Secret → `kubectl rollout restart`（主密钥 TTL 5min 自动轮换，K_sig 重启生效）；
4. 复盘并更新威胁模型（`otp-mask-threat-model/` 变更记录）。

## 6. 已知限制（MVP → 生产迁移清单）

| 项 | 现状 | 生产要求 |
| --- | --- | --- |
| TEE 形态 | 模拟飞地（进程隔离） | **按场景**：S1 明文路径无 TEE 需求；S2 对接第三方密态模型时 TEE 在厂商侧、我方无须 TEE（tee-infer 落客户可信域）；S3 自建密态推理需 TDX/SGX + 节点亲和。详见《GA-产品场景与可信区域矩阵.md》 |
| 认证 | `X-Tenant-ID` 客户端自声明 | 网关鉴权签发（JWT） |
| 密钥 | Secret 演示值 | Vault/KMS + TEE 签名注入 |
| 审计存储 | 内存哈希链 / WORM 文件（`-audit-file` + `-audit-anchor`，JSON Lines 只追加 + 链尾锚定，篡改检测 fail-closed） | 对象存储/WORM 归档 + 定期锚定公证 |
| Guardrail | 确定性规则 | 语义分类器（S3 时 TEE 内轻量模型；S2 时可部署于客户可信域同域） |
| 监控存储 | PVC（C-9：Prometheus 10Gi + Grafana 5Gi，kind 需 local-path provisioner） | 按留存周期扩容 + 归档 |

> **场景与 TEE 需求（2026-09-18 补）**：本表的生产要求列按**具体场景**裁剪，不存在「所有场景都要 TEE」的统一要求。场景 × 可信区域 × TEE 需求的唯一事实源见《GA-产品场景与可信区域矩阵.md》。
