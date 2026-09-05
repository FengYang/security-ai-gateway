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
