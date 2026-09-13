# Higress 控制面形态部署（P0b：D-0 修正为形态 B）

> 目的：生产网关从裸 Envoy（`deploy/k8s/envoy-gateway.yaml`）迁移到 Higress 控制面形态，
> 在保证段① 加密链与 fail-closed 安全语义的前提下，启用 Higress 插件生态能力
> （key-auth / IP Restriction / Rate Limit / CORS，后续可加 WAF / Bot / OAuth）。
> 前置决策：D-0 = B（2026-09-01 修正）。

## 0. 集群基线（评审 P1-1，GF.1 启动前填写）

> 研发计划 GF.1 要求：GF.1 启动前记录集群基线并归档至本文件，作为 GF.5 性能对照的起点，
> 变更需记录（新增/变更行加日期）。当前集群未就绪，下表为字段模板，GF.1 部署时填写。

| 基线项 | 值 | 记录日期 |
| --- | --- | --- |
| K8s 版本 | （待填，如 v1.29.x） | — |
| 节点规格 | （CPU/内存/数量，含 higress-system 与 otpmask 命名空间调度） | — |
| Higress 版本 | Gateway v2.1.5（对齐镜像） | — |
| 网络策略 | 内网隔离 CIDR：10.0.0.0/8、172.16.0.0/12、192.168.0.0/16 | — |
| Pod 限额与资源预留 | （网关/tee-infer 的 requests/limits 实测值） | — |
| 变更记录 | （基线变更时追加行，含变更内容与日期） | — |

## 1. 迁移原理

- 现有 `gateway/wasm/otpmask-plugin/Dockerfile.k8s` 基镜像**就是 Higress Gateway v2.1.5**，
  只是被 `-c /etc/envoy/envoy.yaml` 覆盖为裸 Envoy 模式。迁移 = 恢复 Higress 原生启动模式 + 部署控制面。
- **otpmask 插件代码零改动**（Proxy-Wasm ABI），挂载方式从 `envoy.yaml` 裸挂改为 WasmPlugin CRD。
- 插件链序（Higress phase 保证）：`cors（预检豁免）→ key-auth(AUTHN) → ip-restriction(AUTHZ) → rate-limit(RATE_LIMIT) → otpmask(DEFAULT，段① 加密) → 路由`，
  认证/安全插件在加密前端执行，不接触密文 body，段① 加密链不破坏。
  **CORS 预检豁免为 GF.1 必验项**：浏览器 OPTIONS 预检请求（无 x-api-key）不得被 key-auth 拦截；
  若实测预检被 key-auth 拦截，需给 cors 显式设置早于 AUTHN 的 phase（或给 key-auth 增加 OPTIONS 豁免），
  见 §7 验证矩阵。
- **强制项**（v3 评审 P0）：所有启用插件 `failStrategy: FAIL_CLOSED`。

## 2. 安装步骤

```bash
# 1. 安装 Higress 控制面 + 数据面（官方 Helm；版本对齐镜像 v2.1.5）
helm repo add higress.io https://higress.io/helm-charts
helm install higress -n higress-system --create-namespace higress.io/higress \
  --set global.local=true

# 2. 部署密钥 Secret（先注入真实 sig-key/attest-token，替换占位符；见 §6）
kubectl apply -f deploy/higress/otpmask-secret.yaml

# 3. 部署 otpmask 插件（先构建并推送 OCI artifact，替换 url；先注入 sig_key/attest_token 占位符）
kubectl apply -f deploy/higress/otpmask-plugin.yaml

# 4. 启用安全插件（先改占位 key/网段/配额）
kubectl apply -f deploy/higress/security-plugins.yaml

# 5. 推理与管理路由
kubectl apply -f deploy/higress/ingress-infer.yaml

# 6. 验证插件链
kubectl get wasmplugins -n higress-system
# 预期：otpmask / key-auth / ip-restriction / local-rate-limit / cors 全部 Ready，failStrategy=FAIL_CLOSED

# 7.（GF.2）生态扩展插件 + 网关 HPA（在 GF.1 验证通过后启用）
kubectl apply -f deploy/higress/security-plugins-extended.yaml   # WAF(影子模式)/Bot/OAuth(骨架)
kubectl apply -f deploy/higress/gateway-hpa.yaml                 # 网关 HPA（依赖 metrics-server）
```

## 3. 灰度切换（生产）

```bash
# 保持旧 envoy-gateway 运行，先验证新链：
#   key-auth 未配 key → 401（FAIL_CLOSED 生效）
#   配 key + 合法请求 → 200 SSE
#   IP 名单外 → 403
# 验证通过后，将外部流量切至 higress-gateway Service（DNS/LB 权重），
# 观察 verify-all.ps1 第 17-19 项 + 渗透回归，再下线 envoy-gateway。
```

## 4. 与既有清单的关系

| 清单 | 处置 |
| --- | --- |
| `deploy/k8s/envoy-gateway.yaml` | 保留为 dev/回退形态（P0a Envoy filter 仍有效）；生产流量切换后归档 |
| `higress-standalone/` | Higress 控制面运行时生成清单快照（勿手改），作为现状参考 |
| `deploy/higress/` | **新生产形态的声明式清单（本目录）** |

## 5. 安全语义核对（迁移后必须验证）

1. 段① 加密：`otpmask` 插件在 key-auth/ip-restriction 之后执行，密文 body 不被安全插件读取；
2. FAIL_CLOSED：任一插件故障 → 请求拒绝（不降级明文）；
3. 租户鉴权分层：key-auth（调用方 API Key）→ otpmask 内 JWT（租户 claim），claim 覆盖规则不变；
4. WAF 边界：推理路径 body 内容检测不适用（密文），WAF 做元数据级防护；内容安全由 tee-infer Guardrail 承担。

## 6. 密钥注入（sig_key / attest_token 生产化，评审 P0）

- `otpmask-plugin.yaml` 的 `sig_key`/`attest_token` 仅在 **token 模式**（`attest_mode: token`）下使用，
  且必须与 tee-infer 侧 `otpmask-keys` Secret（`deploy/k8s/secret.yaml` / `deploy/higress/otpmask-secret.yaml`）一致，
  否则签名验签/证明校验 fail-closed 拒绝。
- 当前生产推荐 `attest_mode: quote`（挑战-响应会话 K_sig 派生，二者不参与），但仍严禁硬编码演示值。
- 注入方式（WasmPlugin config 为静态 JSON，不支持 secretKeyRef，须由流水线替换）：
  1. **Kustomize**：`secretGenerator` 生成 `otpmask-keys`，`replacements` 将 Secret 值写入 WasmPlugin config 占位符；
  2. **Helm**：values 注入 `sigKeyHex`/`attestTokenHex` 模板变量；
  3. **CI 变量替换**：`sed`/`envsubst` 替换 `__SIG_KEY_HEX__`/`__ATTEST_TOKEN_HEX__`（严禁把真实值提交进仓库）。
- 真实密钥由 KMS/Vault/TEE 签发后写入集群 Secret；轮换需 tee-infer 与插件两侧同步（避免窗口期签名不匹配）。

### 6.1 段① 凭据运行时拉取（推荐；Phase 1 门禁 #8 落地）

上述"流水线替换"模式下 CR 内**仍是明文**（wasm config 不支持 secretKeyRef）。改为**运行时拉取**可让 CR 彻底不含真实密钥：

1. 管理面凭据文件（0600，**不入库**，默认 `deploy/secrets/otpmask-keys.env`）：

   ```
   sig_key=<64 位 hex>
   attest_token=<与 tee-infer 侧一致>
   ```

2. gateway-admin-service 启用只读端点：`ADMIN_CREDENTIAL_TOKEN=<受限读取令牌>`
   （可选 `ADMIN_CREDENTIAL_FILE` 指定文件路径）。**未配置令牌 = 端点不注册**（fail-closed，不裸奔投递）。
   端点契约：`GET /v1/adminext/credentials/otpmask-keys`，请求头 `X-Credential-Token`（常量时间比较），
   响应 `{"name","sig_key","attest_token"}`；非 GET → 405；名称不支持 → 404；文件缺失/损坏/权限过宽 → 503。
3. 插件侧在 `otpmask-plugin.yaml` 打开：`credential_enabled: "true"` + `credential_service/port/name/interval`
   + `credential_token`（建议经 Secret 注入）；此模式下 `sig_key`/`attest_token` 两键**可整体删除**。
4. 轮换：改写凭据文件 → 插件在 `credential_interval`（缺省 300s）内热生效，**无需重启网关/插件**；
   编排脚本 `scripts/rotate-otpmask-keys.ps1`（写新密钥 → 触发/等待拉取 → 校验生效）。

**语义与边界（如实）**：

- 失败策略＝**保留旧值**（不像路由表那样拒绝入缓存）：密钥被清空会导致全量请求 401，可用性优先；
  连续失败以 `otpmask_cred_fetch_reject_total` 与日志暴露，不静默。
- 通道为**内网 + 受限读取令牌（明文）**，属评审选定口径；CR 内仍保留该读取令牌（非厂商密钥、非段① 真实密钥）。
- token 模式下 sig_key/attest_token 与 tee-infer 的一致性仍须人工保证（不一致 → fail-closed 拒绝）。
- 观测三计数：`otpmask_cred_fetch_cb_total`（回调是否执行，恒 0 = 回调被丢弃）/`_ok_total`/`_reject_total`。

## 7. GF.1 验证矩阵（切换前必须全绿）

| # | 验证项 | 预期 |
| --- | --- | --- |
| 1 | key-auth 未配 key | 401（FAIL_CLOSED） |
| 2 | 配 key + 合法请求 | 200 SSE 流 |
| 3 | IP 名单外 | 403 |
| 4 | 超限流 | 429 |
| 5 | 任一插件故障 | 请求拒绝（fail-closed） |
| 6 | CORS OPTIONS 预检（无 x-api-key） | 不被 key-auth 拦截，返回 CORS 头 |
| 7 | 管理端点 /usage /audit | 内网 CIDR 外一律 403（ip-restriction） |
| 8 | 插件链序 | cors → key-auth(AUTHN) → ip(AUTHZ) → rate-limit → otpmask(DEFAULT)，otpmask 之前插件不改写 body |
| 9 | 明文不落网关侧 | 网关日志/追踪无明文 body |
| 10 | verify-all 19 项 + 渗透回归 | 全 PASS |

## 8. GF.2 生态扩展清单（本目录）

| 文件 | 用途 | 阶段 |
| --- | --- | --- |
| `security-plugins-extended.yaml` | WAF（Coraza，影子模式）、Bot Detect、OAuth/OIDC 接入骨架 | GF.2.1 / GF.2.2 |
| `gateway-hpa.yaml` | 网关 HPA（`higress-gateway`，CPU 阈值 65%，min=2） | GF.2.6 |

- WAF 先 `sec_rule_engine: DetectionOnly` 影子观察，无误杀再切 `On`；推理路径 body 为段① 密文，
  WAF/Bot 仅做元数据级防护，内容安全由 tee-infer Guardrail 承担（方案 §3.10.4）。
- OAuth/OIDC 为接入骨架，client_secret/cookie_secret 走 KMS/Vault（GF.2.5），字段按企业 IdP 填充并核验（GF.1.7）。

## 9. AI Provider 统一接入（GF.3.2，10+ Provider）

复用 Higress 内建 **ai-proxy** 插件（零自研代码，v2.0.1），入站统一 OpenAI messages 契约
（对齐1）、出站标准 OpenAI SSE（对齐2）；插件按 provider type 自动做协议/鉴权/Host 改写与响应回转。

> **Key 激活主路径 = Higress 控制台（界面配置，见 §9.2）**。仓库三件套为**无 key 基线**：
> 只声明固定契约（`/provider/<name>` + provider type），不含任何厂商 API Key（真实 key 严禁入库）。

### 9.1 三件套清单（无 key 基线）

| 文件 | 内容 | 说明 |
| --- | --- | --- |
| `mcp-bridge-registries.yaml` | McpBridge `default`：17 家厂商 dns registry（上游域名/443/HTTPS） | 上游 DNS 来源 |
| `ingress-ai-providers.yaml` | 17 条 Ingress：`/provider/<name>/` 前缀路由 | 入口路径（每厂商独立） |
| `ai-proxy-providers.yaml` | WasmPlugin `ai-proxy`：17 条 matchRules（provider type / 协议特例，**无 apiTokens**） | 厂商转换配置（key 由控制台持有） |

厂商清单（17 家）：
- 国际 7：openai / claude / gemini / groq / openrouter / mistral / yi*
- 国产 10：qwen / deepseek / moonshot / minimax / doubao / hunyuan / ernie（type=`baidu`）/ spark / stepfun / coze*
- *yi 归国产（零一万物）；coze 为 `protocol: original` 透传 + `subPath` 剥离前缀特例。

### 9.2 激活流程（控制台界面，推荐）

1. 访问控制台 `http://<网关>:8001`（首次初始化管理员），进入 **AI 服务 → AI 服务提供者（LLM Provider）**；
2. 点击创建，选择厂商类型（openai / claude / qwen / deepseek / spark 等内置适配），
   填写 **API Key**（spark 按复合格式 `APIKey:APISecret`）、Endpoint/自定义 BaseURL，保存即激活
   （配置落控制台托管的 ai-proxy 插件，热更新，无需改代码/重启网关；控制台对 key 有加密落盘与令牌降级策略）；
3. 在 **AI 路由管理** 创建路由绑定该 Provider（按路径/模型匹配），即可经网关统一入口调用。
   - 调用契约（对齐1）：`POST /provider/<name>/v1/chat/completions`（OpenAI messages 体）等固定路径由
     `ingress-ai-providers.yaml` 基线声明；若控制台创建了自己的 AI 路由，以控制台路由为准。

> 自动化/gitops 场景（无控制台或需版本化管理）：`kubectl apply` 三件套（无 key）后，
> 由受控流水线/Secrets 注入 key 到**控制台托管插件或专用配置源**；**请勿**把真实 key 写回仓库清单。
> 注意：若已由控制台启用同名 `ai-proxy` 插件，勿与本清单的 ai-proxy 重复 apply（二选一，避免双配置冲突）。

### 9.3 明文/密态双轨边界（T1 §4.3）

- `/provider/*` = **明文直连**：ai-proxy 注入厂商 key 后直连上游，body 不过 otpmask 段① 加密；
- `/infer` = **密态链路**（不变）：otpmask 段① → tee-infer；
- otpmask 作用域为白名单（仅 `infer` 路由，`otpmask-plugin.yaml` 有完整机制说明），ai-*/tee-admin 路由自动豁免。
  勿改回 `config:{} + configDisable:true` 黑名单式豁免——wasm-go 对空配置按全局启用处理，会误拦截明文 body。

### 9.4 本地端到端验证（higress-standalone，已完成）

本地以 mock 上游（mock_infer.py：OpenAI/Claude 兼容端点 + 密文 homomorphic mock）验证：
- ai-claude JSON/SSE、ai-openai JSON/SSE：4 组全部 200（协议改写、x-api-key/Bearer 注入、SSE 透传、响应回转 OpenAI 格式）；
- `/infer` 密态回归（向量闭环保质）：输入 `[1..8]` → 掩码加密 → mock 密文域 `+7` → 解密回 `[8..15]`，200。
- 本地 mock 对 claude 鉴权校验用 `x-api-key`（ai-proxy standard 模式注入并删除 Authorization），openai 用 Bearer。
- 注：本地 E2E 用的是 `higress-standalone/wasmplugins/ai-proxy.yaml`（**含 mock token** 的独立副本）；
  生产 `deploy/higress/ai-proxy-providers.yaml` 为无 key 基线，二者互不影响。

### 9.5 本地（fake-apiserver / higress-standalone）已知限制（生产不受影响）

1. **Ingress backend 须用 McpBridge resource 方式**（`kind: McpBridge, name: default`）+ `higress.io/destination` 注解；
   `service` backend 会把 name 展开成 `<name>.<ns>.svc.cluster.local` FQDN，路由不到 registry 物化的 `<name>.<type>` 簇
   → 503 cluster_not_found（本地 E2E 实证 resource=200 / service=503；生产同为该 controller 转换逻辑，已统一为 resource）。
2. **registry domain 有强校验**：static 须 `IP:Port`；dns 须合法 FQDN（domainRegex 含点）。非法时仅 controller
   error 日志，ServiceEntry 静默不生成（本地曾用单标签 `mock-infer-higress` 踩坑）。生产域名均合法，dns 照常。
3. **fake-apiserver 会丢弃 WasmPlugin `spec.configuration`**（defaultConfig 不进 ECDS），配置必须走 matchRules。
4. **wasm-go 空配置 = 全局启用**（按默认值跑）——这是 configDisable 豁免无效的根因，白名单制是正解。
5. 生产 dns registry 443 端口必须显式 `protocol: HTTPS`（漏配 = 明文打 443，TLS 握手失败）。

### 9.6 自定义厂家接入（OpenAI 兼容，界面零开发）

内置 17 家之外的第三方/自建模型，走**「OpenAI 兼容」类型 + 自定义 BaseURL**，无需改代码：

1. **AI网关管理 → AI服务提供者管理 → 创建AI服务提供者**：大模型供应商选 `OpenAI/OpenAI 兼容`
   （界面标签已注明"自定义厂家选此项"）；**服务名称自填**（如 `my-vendor`，即决定调用前缀 `/provider/my-vendor/`）；
2. **「OpenAI 服务类型」选「自定义服务」**（默认是「OpenAI 官方服务」，不选则不出 BaseURL 字段），
   再填「自定义 OpenAI 服务 BaseURL」（如 `https://llm.internal.example.com/v1`；同协议多地址可一次填多个）；
3. 「凭证」填该厂商 **API Key**，保存即激活（key 落控制台托管插件，不入仓库，见 §9.2）；
4. 调用：`POST /provider/<自填名称>/v1/chat/completions`（OpenAI messages 体，出站标准 SSE）。

**限制（如实）**：当前仅支持 **OpenAI 兼容协议**。非 OpenAI 协议的自定义厂家（自定义 header /
鉴权签名 / 请求体转换）**不支持**——需在 ai-proxy 之外新增适配层，属独立工作包（待排期），不在本轮范围。
