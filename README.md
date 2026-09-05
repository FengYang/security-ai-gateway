# OTP-Mask 安全 AI 网关（security-ai-gateway）

**多引擎机密推理统一网关**：以**机密推理为核心定位**——基于 **OTP-Mask 向量加密 + Higress Wasm 插件 + TEE 密态推理**，实现"网关链路不接触明文"的 AI 推理服务（客户端文本经加密进入 TEE 飞地，解密、推理、采样、再加密全程在可信环境内，全链路 fail-closed）。**Higress 插件生态是核心功能支撑**——AI 网关的完整功能面（认证 key-auth/OAuth/OIDC、安全 WAF/IP/Bot、限流/灰度/热更新、多模型代理/MCP 等）全部由 Higress 插件体系承载。**只有安全（加密隧道）不构成 AI 网关**——安全与插件功能面共同构成完整的 AI 网关。


## 1. 核心特性

| 特性 | 说明 |
| --- | --- |
| **Higress 插件生态（核心功能支撑）** | 生产形态为 Higress 控制面（`deploy/higress/`），全量复用插件市场：key-auth/OAuth/OIDC（认证）、WAF/Bot/IP Restriction（安全）、限流/灰度/WasmPlugin 热更新（流量）、MCP/多模型代理（AI 原生）；插件链序保证在段① 加密前端执行，不破坏密文 |
| 密态推理（路径 A） | 明文仅存在于 TEE 飞地内；输出以 token 密文返回，网关侧解密为 SSE |
| 南向统一 text 载荷（路线 1，D1） | 网关 → tee-infer 全程 K_enc 加密（AES-256-GCM 信封，双向子密钥 + 反重放）；vLLM OpenAI 兼容流式 / C-MaaS SDK 通道 |
| 多引擎统一治理（路线 1） | `tee_gpu`（自建 GPU-TEE）/ `cmaas`（百炼机密 MaaS）/ `external_tee`（预留）；鉴权/Guardrail/审计/多租户与引擎无关 |
| OTP-Mask 向量加密（路线 2 保留） | 逐元素模 R 掩码 + HMAC-SHA256 PRG 流（拒绝采样，无偏），R=2^32；vectors 载荷路径全保留供后续推进 |
| 南向私有协议 | Varint 二进制 wire format，HMAC 签名 + 30s 防重放窗口 + request_id 去重；text 载荷/流式字段追加（向后兼容） |
| 密钥生命周期 | 主密钥 TTL 5min 轮换 + 在途 30s 窗口（前向保密），请求密钥 = HMAC(master, reqID\|model\|ts) |
| 多租户隔离（M9） | 每租户独立 KeyManager；跨租户 nonce 拒绝 |
| 内容安全 Guardrail（M9/M11） | TEE 内明文检测 PII/SQL 注入/提示注入（Unicode 归一化 + 去空白混淆防御），命中 403 fail-closed；**补齐 C-MaaS 无内容安全空位** |
| 审计哈希链（M9） | 6.3 数据模型，SHA-256 链式防篡改，`/audit/verify` 校验；C-MaaS 证明引用落审计（`cmaas_attest`） |
| 可观测性（M10） | 应用 `/metrics`（Prometheus 文本）+ Grafana 预置面板 |
| 部署形态（M10） | Docker Compose（开发）/ **Higress 控制面（生产，`deploy/higress/`，D-0=B）** / K8s 清单 + HPA/PDB / kind 单节点（验证） |

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
| `gateway/tee-infer-service` | Go（模拟 TEE，MVP） | 19090 | 密态推理、密钥管理、guardrail、审计（内存/WORM）、指标；text 载荷 SSE 信封流 |
| `gateway/vllm-adapter` | Go / Python | 19190 | vLLM 明文推理对接（路线 2 保留；路线 1 由 tee-infer 直连 vLLM OpenAI 兼容接口） |
| `gateway/attest-verify` | Go | 19191 | 证明验证 sidecar（D2）：quote 解析 + 度量基线比对，localhost `/verify` |
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

## 7. 文档索引（当前有效；历史文档见 `docs/archive/`）

**新开发/集成方入口（按序读）**：`README.md` → `docs/GA-项目总览与路线图.md`（全景进度，先看"走到哪了"）→ `docs/GA-网关功能面研发计划.md`（**当前开发依据**）→ `docs/GA-路线1发布规划.md`；角色选读见各文档"读者"标注。

| 文档 | 内容 |
| --- | --- |
| `confidential-ai-gateway-whitepaper/` | **对外推广技术方案白皮书**（HTML v3.0，宏观+微观，多受众） |
| `docs/GA-项目总览与路线图.md` | **单一事实源**：已完成/待办/前置条件/决策记录/文档地图（每次推进后更新） |
| `docs/GA-网关功能面研发计划.md` | **当前主线研发计划（开发依据 + 待评审）**：网关功能面 GF.1-GF.5 |
| `docs/GA-路线1发布规划.md` | 路线 1 总纲（P1-P5，已验收，历史主线） |
| `docs/GA-路线1研发落地验收报告.md` | 路线 1 验收证据（M1-M3 冻结）与遗留项（M4） |
| `docs/GA-AI网关能力补齐方案.md` | 网关功能面方案（v4，实施中） |
| `ai-gateway-roadmap/ai-gateway-roadmap.html` | **战略路线图（管理层视图）**：三阶段策略/时间轴/验收/资源；进度单一事实源见 `docs/GA-项目总览与路线图.md` |
| `docs/GA-CMAAS对接设计.md` | C-MaaS 引擎对接设计 |
| `docs/总体技术方案-v2.md` | 架构基线 v3.0（含 §2.4/§3.10 网关功能面） |
| `docs/API-参考.md` | 全服务接口契约（text 载荷/SSE 信封/配额端点） |
| `docs/GA-部署指南.md` | 部署路径（含 Higress 控制面形态）+ 运维/事件响应 |
| `docs/GA-计费接口设计.md` | 外部计费对接（token 计量/对账） |
| `docs/GA-TDX移植设计.md`、`docs/GA-第三方审计材料包.md` | M4 真机前置 / 外部审计材料准备 |
| `docs/路线2研究跟踪.md` | 路线 2 长期研究跟踪清单 |
| `docs/archive/` | **历史文档归档（32 份，审计线索，非当前依据）**，索引见 `docs/archive/README.md` |
| `otp-mask-threat-model/` | 威胁模型（TH-01~13 + GW-01~10） |

## 8. 状态

Phase 1-3（M1-M12）全部完成 ✅ → **路线 1（多引擎机密推理统一网关）M1-M3 达成、代码冻结**；网关功能面核心集（配额/脱敏/装饰/双 hash + Envoy 底座）完成；D-0 修正为 Higress 控制面形态，`deploy/higress/` 清单就绪待集群部署。**下一步按 `docs/GA-网关功能面研发计划.md` 推进 GF.1（Higress 控制面落地）**；剩余工作为外部依赖阻塞（M4 真机：TDX 硬件/C-MaaS 账号）或按研发计划排期。全景进度见 `docs/GA-项目总览与路线图.md`。
