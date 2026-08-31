# OTP-Mask 安全 AI 网关（security-ai-gateway）

密态 AI 网关：基于 **OTP-Mask 向量加密 + Higress Wasm 插件 + TEE 密态推理**，实现"网关链路不接触明文"的 AI 推理服务。客户端文本经加密后进入 TEE 飞地，解密、推理、采样、再加密全程在可信环境内完成。


## 1. 核心特性

| 特性 | 说明 |
| --- | --- |
| 密态推理（路径 A） | 明文仅存在于 TEE 飞地内；输出以 token 密文返回，网关侧解密为 SSE |
| OTP-Mask 向量加密 | 逐元素模 R 掩码 + HMAC-SHA256 PRG 流（拒绝采样，无偏），R=2^32 |
| 南向私有协议 | Varint 二进制 wire format，HMAC 签名 + 30s 防重放窗口 + request_id 去重 |
| 密钥生命周期 | 主密钥 TTL 5min 轮换 + 在途 30s 窗口（前向保密），请求密钥 = HMAC(master, reqID\|model\|ts) |
| 多租户隔离（M9） | 每租户独立 KeyManager；跨租户 nonce 拒绝 |
| 内容安全 Guardrail（M9/M11） | TEE 内明文检测 PII/SQL 注入/提示注入（Unicode 归一化 + 去空白混淆防御），命中 403 fail-closed |
| 审计哈希链（M9） | 6.3 数据模型，SHA-256 链式防篡改，`/audit/verify` 校验 |
| 可观测性（M10） | 应用 `/metrics`（Prometheus 文本）+ Grafana 预置面板 |
| 部署形态（M10） | Docker Compose（开发）/ K8s 清单 + HPA/PDB（生产）/ kind 单节点（验证） |

## 2. 架构与数据流

```
客户端 ──text──▶ Higress 网关 (otpmask Wasm 插件)
                     │ 1. /key/issue（OTP 密钥，经远程证明）
                     │ 2. /embed（明文分词向量，内部可信域）
                     │ 3. 向量 + 文本 OTP-Mask 加密 → 南向协议请求（签名）
                     ▼
               tee-infer-service（TEE 飞地）
                     │ 验签 → 防重放 → 租户密钥 → 解密（明文仅在此）
                     │ → Guardrail 检测 → 模型推理/采样 → 再加密 → 签名响应
                     ▼
              网关插件解密 token → SSE 流式返回客户端
```

组件：

| 组件 | 技术 | 端口 | 说明 |
| --- | --- | --- | --- |
| `gateway/wasm/otpmask-plugin` | Higress Wasm（Go 1.24 wasip1） | 10000 | 网关插件：密钥签发、加密、协议构造、SSE 组装、JWT 鉴权 |
| `gateway/auth-service` | Go | 19200 | JWT 签发/校验（HS256，租户鉴权，C-6） |
| `gateway/embedding-service` | Go + tiktoken（cl100k_base） | 18080 | 文本 → token → 向量（明文，内部可信域） |
| `gateway/tee-infer-service` | Go（模拟 TEE，MVP） | 19090 | 密态推理、密钥管理、guardrail、审计（内存/WORM）、指标 |
| `gateway/vllm-adapter` | Go / Python | 19190 | vLLM 明文推理对接（`-engine-url` 切换引擎） |
| `gateway/teecore` | Go 库 | - | KeyManager + 非线性算子（TEE 可信侧核心） |
| `protocol/` | Go / Python / proto | - | 南向协议三端实现（交叉一致性已验证） |
| `cipher/mask`、`secagg/` | Go | - | OTP-Mask 流、安全聚合（Paillier/Shamir） |

## 3. 快速开始（Docker Compose 开发环境）

前置：Windows + winget（自动安装缺件），或手动安装 Docker 19+、Go 1.24+、Python 3.10+。

```powershell
# Windows / macOS（PowerShell）：
powershell -NoProfile -File scripts/setup-env.ps1
# Linux（生产环境）：
bash scripts/setup-env.sh          # 工具安装/构建/compose；--skip-verify 跳过验证

# 或手动分步（等价）
# 1. 构建 wasm 插件（Go 1.24 原生 wasm）
$env:GOOS='wasip1'; $env:GOARCH='wasm'
go build -buildmode=c-shared -o gateway/wasm/otpmask-plugin/main.wasm ./gateway/wasm/otpmask-plugin

# 2. 启动环境（envoy + embedding + tee-infer + mock）
docker compose -f gateway/wasm/otpmask-plugin/docker-compose.yaml up -d --build

# 3. 网关推理（经插件加密链路，SSE 输出）
curl -X POST http://127.0.0.1:10000/infer -H 'Content-Type: application/json' -H 'X-Tenant-ID: acme' -d '{"text":"hello secure ai"}'

# 4. 治理面（用量/审计/指标）
curl http://127.0.0.1:19090/usage
curl http://127.0.0.1:19090/audit/verify
curl http://127.0.0.1:19090/metrics

# 5. 全套验证（11 项）
powershell -NoProfile -File scripts/verify-all.ps1
```

## 4. K8s 部署（生产路径）

```bash
# 清单校验（无集群）
powershell -NoProfile -File scripts/verify-k8s.ps1

# Helm 一键部署（推荐；deploy/helm/otpmask）
helm install otpmask deploy/helm/otpmask \
  --set secret.sigKey=<真实值> --set secret.attestToken=<真实值>

# kustomize 方式
kubectl apply -k deploy/k8s            # 应用 + HPA + PDB
kubectl apply -k deploy/monitoring     # Prometheus + Grafana

# 单节点真机验证（需 kind）
powershell -NoProfile -File scripts/verify-k8s.ps1 -Kind
```

详见 `docs/GA-部署指南.md`：端口映射（网关 10000 / Grafana 3000 / Prometheus 9090）、密钥注入、wasm 镜像打包、监控面板；接口文档见 `docs/API-参考.md`。

## 5. 安全模型摘要

- **信任边界**：明文仅出现在 TEE 飞地（`tee-infer-service`）与内部 embedding 服务；网关 Wasm 插件与网络链路只接触密文。
- **威胁缓解**：完整性（HMAC 签名）、防重放（30s 窗口 + 去重）、租户隔离（独立 KeyManager）、内容安全（Guardrail fail-closed）、审计（哈希链）、降级策略（TEE 不可用 → 503 拒绝，绝不降级明文）。
- **认证边界（MVP 已知项）**：`X-Tenant-ID` 与远程证明令牌为演示值；生产须由网关鉴权签发（JWT）并经 TEE 签名注入。
- 完整威胁模型：`otp-mask-threat-model/`；审计结论：`docs/Phase3-M11-安全审计与渗透测试.md`（20/20 渗透通过，1 项 P2 已修复）。

## 6. 目录结构

```
cipher/          OTP-Mask 掩码流、Paillier、KEX（密码学基座）
secagg/          安全聚合（Shamir/聚合器/mTLS/审计）
gateway/
  wasm/          Higress 插件（otpmask 主插件 + hello 示例）
  embedding-service/  文本向量服务
  tee-infer-service/  TEE 密态推理（含 guardrail/审计/指标）
  teecore/       KeyManager + 非线性算子
protocol/        南向协议（Go/Python/proto 三端一致）
deploy/          K8s 清单 + 监控 + kind 配置
scripts/         验证套件（verify-all / verify-k8s / pen_test）
docs/            里程碑文档（M1-M12）
```

## 7. 文档索引

| 文档 | 内容 |
| --- | --- |
| `higress-otpmask-vllm-技术方案与实施计划.md` | 总体方案与实施计划 |
| `docs/API-参考.md` | 全服务接口参考（网关/embedding/tee-infer/auth/vllm-adapter） |
| `docs/Phase3-M9-治理能力.md` | 多租户/用量/审计/Guardrail |
| `docs/Phase3-M10-部署与可观测性.md` | K8s 清单/HPA/PDB/监控 |
| `docs/Phase3-M11-安全审计与渗透测试.md` | 威胁复查/静态审计/渗透 |
| `docs/GA-部署指南.md` | 三路径部署指南 |
| `docs/GA-发布清单与验收报告.md` | 需求完成度与发布说明（v1.1.0） |
| `docs/GA-vLLM密态对接设计.md` | vLLM 对接层与 4.5 改造设计 |
| `docs/GA-灰度发布.md` | 金丝雀发布与回滚 |
| `docs/GA-插件配置热更新.md` | 插件配置热加载路径 |
| `docs/GA-TDX移植设计.md` | TEE 硬件前置：飞地边界/远程证明/移植路线 |
| `docs/GA-计费接口设计.md` | 计费对接（用量数据/拉取推送/幂等） |
| `docs/GA-第三方审计材料包.md` | 第三方安全审计评审材料清单 |
| `docs/GA-实现总结与研发指引.md` | 实现总结 + 生成物索引 + 研发入口 |
| `otp-mask-threat-model/` | 威胁模型（TH-01~13 + GW-01~10） |

## 8. 状态

Phase 1（M1-M3 网关接入）✅ → Phase 2（M4-M8 密态推理路径 A）✅ → Phase 3（M9 治理 / M10 部署 / M11 安全 / M12 发布）✅ —— 全部里程碑完成，进入 GA 候选。
