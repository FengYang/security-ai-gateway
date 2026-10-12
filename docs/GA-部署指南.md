# GA 部署指南（OTP-Mask 安全 AI 网关）

> **生产环境为 Linux**：本指南脚本已跨平台（PowerShell 脚本经 pwsh 在 Linux 运行；另提供 `scripts/setup-env.sh` 一键脚本）。

## 1. 部署路径总览

| 路径 | 场景 | 前置 | 入口 |
| --- | --- | --- | --- |
| A. Docker Compose | 本地开发/演示 | Docker 19+（Windows/macOS/Linux） | `gateway/wasm/otpmask-plugin/docker-compose.yaml` |
| B. kind 单节点 | 生产清单真机验证 | Docker + kind + kubectl | `deploy/kind/kind-config.yaml` + `deploy/k8s` |
| C. Kubernetes | **生产（Linux）** | 集群 + metrics-server | `deploy/k8s` + `deploy/monitoring` |

> **⚠️ 完成环境搭建 ≠ 可以对外提供服务**：除软硬件环境外，还有一批**法定/合规必办步骤**（含**具名复核与签署**，如词库具名复核）——见 **§7 上线前的法定与合规必办步骤**。未完成 §7 清单，系统只能内网试运行，**不得对外提供服务、不得提交备案**。

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
| tee-infer 治理 | `-token-quota <n>`（每租户 token 配额，0=不限）；`-pii-mode mask`（PII 脱敏替换，默认 block 拦截）；`-system-prompt <text>`（提示词装饰）；配额经 `POST /usage/quota` 动态调整 |
| 网关底座（开发 / 回退形态） | Envoy 原生：CORS + IP 白名单（RBAC，默认 `0.0.0.0/0` 放行，生产收紧）+ QPS 限流（local_ratelimit，零外部依赖） |
| 网关底座（生产形态） | Higress 控制面：`deploy/higress/` 清单（otpmask WasmPlugin + key-auth/IP Restriction/Rate Limit/CORS，**failStrategy 一律 FAIL_CLOSED** + Ingress 路由），插件链序：认证/安全 → otpmask 段① 加密 → 路由；迁移见 `deploy/higress/README.md` |
| 证明验证 | `gateway/attest-verify` sidecar（localhost `/verify`，度量基线 allowlist）；真机 TDX 时插件经 localhost 调用 |
| 客户端请求 | `{"text":"...","engine_type":"tee_gpu|cmaas","stream":true}`；text 载荷仅限 quote 会话（token 模式拒绝） |
| 路由 | `deploy/` 内 `route-config.json` 声明模型→引擎映射（cmaas-* 仅 cmaas） |

> 路线 2（vectors 载荷）代码全保留（`masked_vector`），部署方式见 §1 路线说明。

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

> 本地轻集群实测补齐：`gateway-admin-service` 此前**无 Dockerfile**（清单已引用该镜像但无法构建）；
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
- 生产补充：Alertmanager 告警（审计链断裂、denies 突增、HPA 失效、TEE 不可达）、TSDB PVC 持久化、Grafana 密码 Secret 化；
- **截断率告警的现场接线与演练为部署单位事项（S13）**，查询/阈值/分级见《[GA-截断率监控与处置Runbook.md](output-guard/GA-截断率监控与处置Runbook.md)》。
- **输出侧审查告警工程化（S2-6）**：
  - 指标 `otpmask_output_guard_restart_detected`（gauge 0/1）由 tee-infer 对账器自动置位，无需额外 sidecar；
  - 告警规则见 `docs/output-guard/GA-输出侧-告警规则-PrometheusRule.yaml`（CRD 形态），含 **7 条告警 ＋ 2 条记录规则**：截断率升高（warning ＞10%/10m、critical ＞25% 双窗口）、Pod 反复重启（kube-state-metrics 为主 ＋ `restart_detected` 后备）、句级降级率升高、槽位占满终止；**「503 激增」为已删除的幽灵规则**（过载实际表现为句级丢句＋HTTP 200，并非 503）；
  - 演练验收单见 `docs/output-guard/GA-输出侧-告警演练验收单.md`，覆盖重启风暴与同 Pod 重启叠加两场景；
  - **采集侧车问题**：若 Prometheus 通过 sidecar exporter 间接采集，需保证该 sidecar 与 tee-infer 共生命周期（sidecar 崩溃不影响 tee-infer 业务）；推荐直接 Pod 注解 + `/metrics` 直采，避免侧车单点失效导致告警盲区。

## 5. 运维手册

### 5.1 健康检查

| 端点 | 用途 |
| --- | --- |
| `GET /attest` | tee-infer 就绪/存活探针 |
| `GET /metrics` | embedding 探针 + Prometheus 抓取 |
| `GET /audit/verify` | 审计链完整性（建议定时巡检，告警阈值：ok=false） |
| `GET /usage` | 租户用量（对接计费） |
| `GET /healthz`（**readiness**） | 证明状态 ＋ **输入侧审核侧车健康**：侧车不健康 → **503 摘流**；状态由 `otpmask_guard_sidecar_healthy`（0/1）暴露 |
| `GET /healthz/live`（**liveness**） | **仅进程存活**，刻意**不联动**审核侧车；**清单 livenessProbe 必须指向此路径**（指 `/healthz` 会因侧车故障重启容器 → 重启风暴 + `-seal-file` 为空时证明会话失效） |

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
| **输入侧审核侧车不可用**（403 增多、body 含 `classifier_unavailable`） | runbook：① 看 `otpmask_guard_sidecar_healthy` 是否 0；② 按归因定位 `increase(otpmask_guard_failclosed_total{backend="http-sidecar"}[5m]) by (reason)`（`unreachable`／`timeout`／`http_status`／`bad_response`）；③ 日志 `[guardrail] 侧车健康探活失败／恢复`；④ **先恢复侧车**（探活恢复后自动回挂、无需人工），再抽样核验 `/healthz` 与一次请求 200。⚠️ 摘流生效前的窗口内，请求返回 **403**（非 503），排查时需结合 body 类目与上述指标区分 |

### 5.3 安全事件响应（摘要）

1. 审计链 verify 失败 / 告警 → 冻结变更，导出 `/audit` 全量；
2. 定位事件：`/usage` 异常租户 + `/audit` 按 tenant 过滤；
3. 轮换：重建 `otpmask-keys` Secret → `kubectl rollout restart`（主密钥 TTL 5min 自动轮换，K_sig 重启生效）；
4. 复盘并更新威胁模型（`otp-mask-threat-model/` 变更记录）。

### 5.4 策略/词库版本发布与回滚（S1-4 / G21）

**版本库位置**：`<policy-dir>/versions/`（与 policy 根目录同处**一个只读分发单元**）。容器为
`readOnlyRootFilesystem`，故**发布是离线步骤，运行时不写盘**；tee-infer 只做只读发现 / 显式引用 / 回滚。

| 步骤 | 命令 / 端点 | 说明 |
| --- | --- | --- |
| 发布（离线） | `./scripts/policy-publish.ps1 -Version pv… -FromDir <草稿目录> -BenchJson <评测记录.json>` | 复算 manifest 逐个 sha256（不符即中止）；**无评测记录只能归档为 `draft`**（不可被引用）；首次发布加 `-InitBaseline` 自举门禁基线 |
| 发布物校验 | `go test -mod=mod ./gateway/tee-infer-service/ -run TestPolicyVersionArtifactsVerify -v` | 逐版本复算哈希 ＋ bench 硬门禁（脚本与 CI 共用） |
| 发现 | `GET /config/policy/versions` | 列可用版本、状态、bench 摘要与当前引用（管理令牌） |
| 显式引用 | `POST /config/policy/activate {"version":"pv…"}` | 须过 bench 硬门禁；失败 **409** 且**保留旧版继续服务**（不回内部错误全文，只回原因枚举） |
| 回滚 | `POST /config/policy/rollback`（缺省＝上一 active；`{"version":"pv…"}`＝回任意历史版本） | 上一 active 可能是"**未引用态（根目录）**"，此时回滚 = 回到镜像默认策略 |
| 启动即引用 | `-output-guard-policy-version pv…` | 启动时解析；版本库不可用 / 版本非法 / 未过门禁 → **拒绝启动**（fail-closed） |
| 持久化 | `-output-guard-config <file>` | 引用状态跨重启保持（与 mode 覆盖**同文件、读改写合并**，互不覆盖）；未配置则仅进程内生效 |

**bench 硬门禁口径**：`rule_detect`／`semantic_detect` **不低于**已登记基线、`fp` **不高于**基线，且语料指纹须与基线一致
（语料不同即不可比 → 拒绝）。基线由首次发布自举，**不预置**（未登记基线时任何发布都会被拒绝，属预期）。

**指标**：`otpmask_output_guard_policy_version{version}`（当前生效版本）、
`otpmask_output_guard_policy_activate_total{action,result,reason}`（引用/回滚结果）、
`otpmask_output_guard_policy_rollback_total{reason}`（未生效即保留旧版的回退计数）。

**应急**：任一回滚失败都不会改变当前生效版本；彻底回到镜像默认策略 = `POST /config/policy/rollback`（缺省）。
**未配置版本库**（无 `versions/index.json`）时上述能力全部不启用，行为与改造前**逐字节一致**。

### 5.5 功能 / 子系统专项运维文档索引

> 项目级运维入口为本章；各功能/子系统的**专项运维细则**（Runbook/SOP/演练）保留在各自子域，**须以本章为索引**（不得成为影子标准文档）。统一规范见《[GA-文档体系规范.md](GA-文档体系规范.md)》。

| 功能/子系统 | 专项运维文档 | 说明 |
|---|---|---|
| 多模型智能路由（P0-1） | 本文件 **§10** | 已内联 |
| 语义缓存（P0-2） | 本文件 **§11** | 已内联 |
| 策略/词库版本发布与回滚 | 本文件 **§5.4** | 已内联 |
| 输出侧内容审查 | [截断率监控与处置 Runbook](output-guard/GA-截断率监控与处置Runbook.md)；[OG20 模式热切换与回滚演练 SOP](output-guard/GA-输出侧-OG20模式热切换与回滚演练SOP.md)；[告警演练验收单](output-guard/GA-输出侧-告警演练验收单.md) | 子域 `docs/output-guard/`；口径以其本体为准 |
| 管理门户（Higress 控制台） | [升级操作手册](管理门户-升级操作手册.md) | 子系统操作细则（**非**项目级标准文档） |

> **索引维护**：新增功能级 Runbook/SOP 时，须同步登记本表。

## 6. 已知限制（MVP → 生产迁移清单）

| 项 | 现状 | 生产要求 |
| --- | --- | --- |
| TEE 形态 | 模拟飞地（进程隔离） | **按场景**：S1 明文路径无 TEE 需求；S2 对接第三方密态模型时 TEE 在厂商侧、我方无须 TEE（tee-infer 落客户可信域）；S3 自建密态推理需 TDX/SGX + 节点亲和 |
| 认证 | `X-Tenant-ID` 客户端自声明 | 网关鉴权签发（JWT） |
| 密钥 | Secret 演示值 | Vault/KMS + TEE 签名注入 |
| 审计存储 | 内存哈希链 / WORM 文件（`-audit-file` + `-audit-anchor`，JSON Lines 只追加 + 链尾锚定，篡改检测 fail-closed） | 对象存储/WORM 归档 + 定期锚定公证；**留存期以 `-audit-retention-days` 声明**（缺省 **365** 天、法定硬底 **180** 天、`0`=不声明；非法值拒绝启动），声明值见启动日志 / `GET /config` 的 `audit_retention_days` / 指标 `otpmask_audit_retention_days`——**删除由存储层生命周期策略按声明值执行**（服务不删除审计数据，以保哈希链可从创世复算） |
| Guardrail | 确定性规则 | 语义分类器（S3 时 TEE 内轻量模型；S2 时可部署于客户可信域同域） |
| 输出侧 L2 与明文侧审核服务**实例分离** | 未强制 | **两实例必须不同主机 / 不同 Service**；`-output-guard-l2-url` **不得**等于明文侧审核服务地址（地址白名单只能校验"落在可信域"，校验不了"是否同一实例"，须部署层兜住）；部署清单逐项打勾 |
| **副本下限（接入审核侧车时）** | 现清单 `replicas: 1`、HPA `minReplicas: 1`（单节点现场形态，见清单注释） | 接入审核侧车后建议 `spec.replicas` 与 HPA `minReplicas` **≥2** 并叠加滚动冗余：**单副本场景下侧车不可用即该实例不可服务** |
| **输入侧审核侧车接线** | 清单**尚未声明** `-guard-classifier-url`，亦无侧车容器/资源声明 | 侧车落地时须一并：显式 `-guard-classifier-timeout`（**CPU 形态 ≥30–60s**，勿沿用 2s 默认）、侧车 `GET /healthz`（免鉴权且覆盖"后端就绪"）、requests/limits（**以 spike 实测为准**，勿沿用 tee-infer 现有规格）、以 **`startupProbe` ＋侧车 `readinessProbe`** 保证"侧车先行"（**不得**把常驻侧车放入 `initContainer`——`initContainer` 须运行至完成，仅可作"就绪门"或采用 K8s 原生 sidecar），并显式声明 `maxSurge`/`maxUnavailable`/`progressDeadlineSeconds` |
| **审核后端形态（D-LLM-7 已裁定，2026-09-26）** | 现清单未接线；形态**技术侧已签** ＝ **同机密 VM 内独立进程侧车**（K8s 形态＝**同 Pod 多容器**）；Q2／Q3／Q4／Q11 待安全/证明补签 | 接线须覆盖**全部 6 处发布产物**（`deploy/k8s`／`deploy/helm`／`deploy/tee`（base＋`overlays/nvidia-cc`、`gn8v-tee`）／`deploy/k8s/canary`／`scripts/deploy-tee-infer-linux.sh`（systemd 单机）／`higress-standalone` 接入层），其中 **canary 须与稳定版同构**（现 canary 无 `-output-guard*` 且探针指 `/attest`）；**每 Pod 独立侧车**（**禁止**为侧车建独立 Deployment/Service/Endpoints，反面范式见 `deploy/tee/base/vllm-adapter.yaml`）；补**侧车 egress 约束**（A2 只管 tee-infer→侧车方向）；镜像 `tag@sha256`；**同 Pod 第二容器指标采集路径**（现单 `prometheus.io/port` 注解采不到）。**依据**：本体 §17 与《[D-LLM-7 决策材料](GA-大模型内容合规规划-D-LLM-7决策材料-审核后端形态与飞地边界.md)》 |
| **侧车摘流耗时与容量** | 未实测 | 以 K3S `sidecar kill` 实测"侧车故障→实例摘流"耗时并回填本节；按 N−1 规则（`(N−1)×C ≥ λ_peak`）给出副本下限与容量预算 |
| 监控存储 | PVC（Prometheus 10Gi + Grafana 5Gi，kind 需 local-path provisioner） | 按留存周期扩容 + 归档 |

> **场景与 TEE 需求（2026-09-18 补）**：本表的生产要求列按**具体场景**裁剪，不存在「所有场景都要 TEE」的统一要求。

## 7. 上线前的法定与合规必办步骤（环境搭建之外）

> **本章定位（2026-09-27 增）**：§2–§4 只解决「**系统能跑**」；本章解决「**能合法对外**」。
> **本章即为此事的唯一事实源（本体）**：原独立文档《GA-部署单位具名与签署事项清单》已于 2026-09-27 **并入本章**（本指南在白名单内、随仓库交付；独立清单属 `.gitignore` 本地资产，合并后既保持单一出处、又能随代码交付到部署单位）。
> **判定**：未完成本章清单 ≠ 部署失败，而是**不得对外**——系统可内网试运行，但**不得对外提供服务、不得提交备案**。
> **为什么禁止、怎样才能解禁**：见 §7.1.1（不得对外的原因）、§7.1.2（不得报备的原因）、§7.1.3（达标条件与放行流程）。

### 7.0 责任边界与事项性质

#### 7.0.1 责任边界（开发单位 / 部署单位）

| 角色 | 职责 | **不承担** |
|---|---|---|
| **开发单位**（本方） | 开发、测试、内部审查（含多角色/多 agent 评审）、交付可复现证据与工具、机制与门禁建设、如实标注未闭项 | 不代部署单位具名；不代替其判断"内容是否拦对"；**不承担其法定合规责任** |
| **部署单位**（正式部署并运营该系统的公司/团队） | **具名复核**、签署、对外申报、运行责任、风险接受 | — |

**原则**：开发单位可以把具名复核的成本压到最低（提供机器可读缺陷清单、分层交付、一键切换机制），但**不能替部署单位签字**，也不能替其承担法定责任。本清单即为二者的分界。

#### 7.0.2 三类性质（**12 项不都是法律要求的签字**）

| 类 | 性质 | 是否属"法定签字要求" | 具体项 |
|---|---|---|---|
| **甲** | 合规/监管义务的**举证与承诺**（对外产生责任） | **是**（**具体法条与适用性由部署单位合规团队认定**，开发单位不作法律结论）；对外材料通常需**具名/盖章** | S1、S2、S3、S4、S10、S11 |
| **乙** | **经营/风险决策授权** | 否。但**未授权则策略无法定稿**，后果由决策主体承担 | S5、S6、S9、S12、**S14** |
| **丙** | **内部运维责任移交**（管理动作） | 否。属交付/运维交接，非法律要求 | S7、S8、S13 |

三类**都不应由开发单位代做**：甲类不能代签（法律责任主体不符）、乙类不能代定（商业取舍）、丙类不能代担（运行责任）。区分意义在于：甲类是**对外申报的前置**；乙/丙类只影响**内部能否定稿与上线**。

#### 7.0.3 分工现状（谁已完成、谁待办）

**开发单位已完成（可复现证据随交付物）**

- 词库/题库生成器与规模档：关键词 **10068** 条（A.1 每类 ≥200 ✓、A.2 每类 ≥100 ✓、占位 0）；题集 正 2000／负 500／拒答 500
- **复核留痕机制与门禁**：`review-ledger.json` 一类目一批、条数须与词条一致、加载期 fail-closed；`review_level` 决定报备形态能否生成
- 版本库与发布门禁：`policy/versions/`（逐版本快照哈希 ＋ bench 硬门禁 ＋ **输出侧不可回退门禁**）
- **分层交付**：`blocklist.csv`（含 `source`/`review_status`）＋ `blocklist-seed-only.csv`（基词层 140 条，逐条可解释）＋ 扩量层（机器生成候选池）
- 内部质量活动：六角色 agent 评审（判删 ≈4150 条），并按"方案 (c)"结构性重建搭配关系（见 §7.8.1）
- 工具链：`scripts/policy-publish.ps1`、`scripts/export-blocklist.ps1`（零依赖）

**待部署单位完成**：§7.2 的 **S1–S14**（其中 **S1 是唯一被工具硬门控**的一项）。

### 7.1 与环境搭建的关系（一句话）

| 阶段 | 目标 | 完成判据 |
|---|---|---|
| §2–§4 环境搭建 | 系统能启动、链路能通 | 健康检查通过（§5.1）＋ 冒烟通过 |
| **本章 §7** | **能合法对外** | **§7.4 勾选清单全绿 ＋ §7.6 证据归档** |

**两个阶段相互不可替代**：环境搭不起来则无系统可谈；本章不完成则**系统越"能跑"风险越大**（已具备对外服务能力但无合规依据）。

#### 7.1.1 为什么此时"不得对外提供服务"

本产品是**生成式人工智能服务的网关组件**；法定的服务提供者义务（内容安全、安全评估、备案、标识、留存等）**随"对外提供服务"这一行为落到部署单位**，不随软件交付转移。环境能跑只证明"有能力"，不产生"合法依据"。在 §7 清单未完成时对外，具体风险是：

1. **无备案/安评即对外**：面向公众提供生成式 AI 服务，依规应在提供前完成安全评估并履行算法备案/登记等手续（**是否适用、走何种程序，由部署单位合规团队按其形态认定**）。未完成即对外，等于无证运营，责任直接归于服务提供者。
2. **内容拦截"是否拦对"无人背书（S1 缺）**：词库仍是"机器生成＋开发单位角色级复核"，**无具名责任人确认**。此时对外，31 类违法内容可能漏出，部署单位将直接承担"未履行内容安全保障义务、生成/传播违法内容"的责任。
3. **enforcing 未获授权（S6 缺）**：误杀线与准入闸门未定线，系统只能停在 shadow/off；若为保业务而不拦截，等于在无内容保障下对外。
4. **运行义务未落地**：标识形态（S3）、日志留存（S4）、fail-closed 例外（S5）、运行责任人（S7）、密钥归属（S8）、审计只读承诺（S11）任一缺失，都会在监管核查或事故发生时出现"义务未履行/责任无人认领"。
5. **出境风险（S10 缺）**：供应链与数据出境未登记判定，一旦流量走境外 provider，可能构成未履行出境程序。

> 一句话：**"系统能跑"不能替代上述任何法定/责任前提**；开发单位也不能用工程交付替部署单位消除这些前提。故限定为**内网试运行**（不触发面向公众的服务义务），不禁止内部联调、测试与演练。纯内部形态的具体适用义务，依 S0-⑥ 主体判定与法务结论为准。

#### 7.1.2 为什么此时"不得提交备案"

备案/登记是**具名、可追责的正式申报**，材料须真实、完整、口径一致。未完成清单时提交，问题不是"早交晚交"，而是**材料在主体、措施佐证、栏目口径上不齐**：

| 缺口 | 导致的材料问题 |
|---|---|
| **S2 申报主体未定** | 无申请人主体信息（名称/信用代码/负责人），材料**无法被受理** |
| **S1 未具名复核** | "内容安全保障措施"栏无责任主体确认；工具**硬门控**使报备形态附件（`blocklist-keywords-only.csv`、`filing_ready=true` 摘要）**根本不生成**——附件不齐 |
| **S3/S4/S11 未定** | 生成标识、日志留存范围期限、审计只读与留存承诺等栏目**无定稿口径** |
| **S3-1 / S0-① 口径未对齐** | 建设规模题库、抽检合格率（≥90%）、拒答率（≥95%）等**评估证据不完整或不可比**，无法支撑安全评估/备案结论 |
| **S10 未判定** | 第三方组件与数据出境相关栏目**缺登记结论** |

在上述状态下强行报送，轻则**不予受理/退回补正**、拉长周期，重则材料失据被认定为**不实申报**。因此在"材料齐、措施有背书、口径一致"前设门，不提交。

#### 7.1.3 怎样才能"对外提供服务、提交备案"（达标门与放行流程）

解禁不是一句话，而是**两道门、一次具名放行**；每道门都以可验证证据为准（明细见 §7.2，勾选见 §7.4，操作见 §7.5，证据要求见 §7.6）。

**门 A · 报备门（满足后才能提交备案）**

- [ ] **S1** 词库/导出内容**具名复核**：`review_level=named`、`reviewer` 为具名责任人、`filing_ready=true` 并产出报备 CSV
- [ ] **S2** 申报主体信息齐备（主体/信用代码/服务名/负责人/联系方式）
- [ ] **S3** 生成标识落地形态定稿并已实现
- [ ] **S4** 日志/内容留存范围、期限、存证方式定稿
- [ ] **S11** 审计只读账号与留存期对外承诺签署（与 S4 一致）
- [ ] **S10** 供应链与出境登记签署、出境情形已判定
- [ ] **评估证据**：§9.3/§9.4 在锁定版本上的合格率、拒答率（**双口径分列**，口径B**剔除默认 `pass` 类目且剔除 A5 族**，A5 单列为"事实性问题"独立指标）等结果达标且题库口径已对齐（S3-1/S0-①）
- [ ] **S14** §9.4 拒答率**判据口径确认**（[D-LLM-10 §10.1／§10.2](GA-大模型内容合规规划-D-LLM-10决策材料-分类体系与题库口径裁决.md) 的 Q13–Q15：口径B 定义〔仅"产生处置动作"＝排除默认 `pass` 类目〕／A5 族是否纳入「应拒答」判据／双口径均未达下的对外写法；**§10.2 已出四路评审与建议措辞，签署栏见 §10.2.7**）
- [ ] **材料一致性复核**：申报材料 ↔ 系统配置 ↔ 评测结果三者一致

→ 由**部署单位**经属地系统提交，留存**提交回执**（S2 证据）；开发单位不代申报。

**门 B · 上线门（取得备案/安评结果后，才能对外服务）**

- [ ] 备案/安全评估**通过或取得受理回执并满足属地放行要求**（以合规团队认定为准）
- [ ] 门 A 全部保持有效
- [ ] **S5** fail-closed 取值与例外登记一致；**S6** 误杀线定线签署 → enforcing 获授权（或法务书面替代方案）
- [ ] **S7** 运行责任人、**S8** 密钥/Secret 归属与轮换、**S9** 计费单价（如启用计费）、**S12** 残余风险接受决策
- [ ] **S13** 截断率告警现场接线实测、enforcing/回滚与两重启场景演练完成
- [ ] 配置快照与健康检查全绿

→ 由**部署单位具名签放行单**（开发单位不签），再经授权端点**转 enforcing**，并按截断率 runbook 进入上线观察（恢复/稳定判据见该 runbook §6）。

**放行流程（顺序）**：① 逐项执行 §7.2/§7.5 → ② 对照 §7.4 打勾、按 §7.6 归档四要素证据 → ③ 材料/配置/评测一致性复核 → ④ 部署单位具名批准 → ⑤ 提交备案并取回执 → ⑥ 授权转 enforcing 上线观察。**先门 A 后门 B**：未取得报备/安评结果前不得对外；前期准备可并行。

**六步放行操作细则**（每步含 执行人／操作／产出验证／不通过处置；命令中 PowerShell 设环境变量用 `$env:NAME="1"`，bash 用 `NAME=1`；管理端点统一带头 `X-Admin-Token`，变更类操作另带 `X-Admin-Actor` 操作人、`X-Request-ID` 以便审计）：

> 勾选与签署的**统一载体**：《[GA-报备与上线放行单模板](GA-报备与上线放行单模板.md)》（每租户一份，含两门勾选、证据、具名签署与上线观察记录）。

**第 1 步｜执行必办作业（对应门 A/B 条件）**
- *执行人*：部署单位（主体），开发单位提供工具与可复现证据、现场支持。
- *操作*：
  - S1 词库/导出内容具名复核，严格按 §7.5：① 指定与提交人不同的具名复核人 → ② `review-ledger.json` 改 `review_level=named`、各批 `reviewer` 填具名 → ③ `POLICY_GEN=1 go test -mod=mod ./gateway/tee-infer-service/ -run TestGeneratePolicyAssets` → ④ `pwsh ./scripts/policy-publish.ps1 -Version pv… -FromDir <草稿目录> -BenchJson <评测记录.json>`，随后 `go test -mod=mod ./gateway/tee-infer-service/ -run TestPolicyVersionArtifactsVerify` → ⑤ `pwsh ./scripts/export-blocklist.ps1`。
  - S2/S3/S4/S11/S10：申报主体、标识形态、留存声明、审计只读承诺、供应链出境判定逐项定稿（表见 §7.2）。
  - S5/S6/S7/S8/S9/S12/S14：fail-closed 例外、误杀线签署、责任人、密钥归属、单价表、残余风险决策、§9.4 判据口径确认（D-LLM-10 **§10.1／§10.2** 的 Q13–Q15，见 §7.2 S14；§10.2 已含四路评审与建议措辞）。
  - S13：截断率告警在 Alertmanager 接到值班并实测触发；enforcing/回滚与两重启场景现场演练（离线测试基线：`go test -mod=mod ./gateway/tee-infer-service/ -run TestS22EnforcingDrillAndRollback`）。
- *产出/验证*：S1 导出摘要 `filing_ready=true` 并产出 `blocklist-keywords-only.csv`；各项有定稿载体。
- *不通过*：S1 未具名则报备 CSV **不生成**（设计硬门控），不得进入后续；其余任一定稿缺失，对应门内条件保持未满足。

**第 2 步｜逐项打勾并归档证据**
- *执行人*：部署单位（复核人/合规）。
- *操作*：对照 §7.4 逐项打勾；按 §7.6 归档四要素（完成判据＋载体快照＋时间戳＋具名责任人）；独立复算数据面审计链：
  `go build -mod=mod -o audit-verify.exe ./gateway/audit-verify/cmd/audit-verify` 后 `./audit-verify.exe -file <tee链文件> -schema tee [-anchor <锚点>]`；或 `GET /audit/verify`（自证，独立验证以 audit-verify 为准）。
- *产出/验证*：§7.4 全勾；audit-verify 退出码 0（链完整、锚点一致）。
- *不通过*：退出码 1（链断）/2（锚点不符或截断）→ 暂停放行，按 §5.2/§5.3 排查并重做证据。

**第 3 步｜材料 / 配置 / 评测 一致性复核**
- *执行人*：部署单位合规＋技术，开发单位协助。
- *操作*：
  - 跑评估并写报告：`OG_EVAL93_WRITE=1 go test -mod=mod ./gateway/tee-infer-service/ -run TestOutputGuard93GenerationEval`；`OG_EVAL94_WRITE=1 go test -mod=mod ./gateway/tee-infer-service/ -run TestOutputGuard94CategoryReport`。
  - 三方比对：备案/安评材料 ↔ `GET /config` 配置快照（mode、policy_version、标识、留存、类目）↔ §9.3/§9.4 报告（生成合格率 ≥90%；应拒答拒答率**双口径分列**——口径A〔严格：仅 `block`〕与口径B〔已处置：含 `flag`/`mask`，**不含默认 `pass` 类目且剔除 A5 族**；**Q14 已由产品 2026-09-29 签批**，剔除后口径B ≈ 100%，**但不得宣称达标**，仅分类目披露；A5 单列为"事实性问题"独立指标〕，判据 ≥95% 为**目标值，当前口径A 未达**；非拒答误拒率 ≤5%；弱类目单列）。
  - 对账：`POST /reconcile/run`（或查 `GET /reconcile`）确认 `ok=true`、`billing_blocked=false`；版本以 `GET /config/policy/versions` 与材料一致。
- *产出/验证*：一份"一致性核对结论"（无差异项或差异已闭环）。
- *不通过*：指标不达标或口径不一致 → 回到第 1 步整改并复跑；弱类目须在材料中如实书面列明，不得用总均值掩盖。
- ⚠️ *口径注*：拒答率口径A/B 属**判据口径**（GB/T 45654-2025 §9.4 未直述"标记/脱敏是否计入拒答"），口径B 定义与 A5 族剔除已于 **2026-09-29 由产品（张三）按 D-LLM-10 §10.2.8 签批**；法务侧 Q13/Q14 仍待具名确认。**对外统一写法**：双口径分列、口径A 如实标注未达、口径B 分类目披露且**不得宣称"已达标"或"100% 拒答"**；A5 族单列为"事实性问题"独立指标。

**第 4 步｜部署单位具名批准（关键门，开发单位不签）**
- *执行人*：部署单位有权批准人。
- *操作*：基于第 2、3 步证据，签**放行单**（批准人具名、日期、批准范围＝租户/服务/版本、残余风险接受、后续观察要求）。
- *产出/验证*：具名放行单归档（四要素齐全）；后续所有变更类调用以批准人为 `X-Admin-Actor`。
- *不通过*：无具名批准 → **流程在此停止**，不得提交备案、不得对外；可继续内网整改。

**第 5 步｜提交备案并取得回执**
- *执行人*：部署单位（开发单位不代申报）。
- *操作*：经属地备案/登记系统提交 S2 主体信息与各栏目；附 S1 报备形态 CSV、`export-summary.json`、版本/SHA 及评估证据。
- *产出/验证*：取得**提交回执/受理编号**并归档（截图＋时间）。
- *不通过*：不予受理/退回补正 → 按退回项回第 1–3 步修正后重报；发现材料失据风险不得强行报送。

**第 6 步｜授权转 enforcing 并进入上线观察**
- *执行人*：部署单位运维（凭第 4 步批准），开发单位现场支持。
- *操作*：
  - **enforcing 只能经启动参数开启（运行时不可升）**：重启时加 `-output-guard enforcing`，并按需带 `-output-guard-policy-version pv…`；⚠️ 若配置了 `-output-guard-config <file>` 持久化文件，须先确认其中无 `shadow/off` 覆盖记录（否则启动按该覆盖值生效）。按 PDB 滚动重启（`kubectl rollout restart`，保证至少 1 副本可用）。
  - 验证：启动日志显示 mode=enforcing；`GET /config` 的 `mode=enforcing`、`policy_version` 为批准版本；一次真实请求链路正常。
  - 观察：按《[截断率监控与处置Runbook](output-guard/GA-截断率监控与处置Runbook.md)》§6 值守，截断率回落并稳定 ≥30m、无残留 503/崩溃循环、`/reconcile` 正常。
  - 回滚（异常时）：运行时允许降级，`POST /config/output-guard` body `{"mode":"shadow"}`（带批准人 actor）；策略版本回退 `POST /config/policy/rollback`。
- *产出/验证*：enforcing 上线观察记录与稳定判据满足。
- *不通过*：观察期截断率/可用性越线 → 按 runbook 降级回滚并复盘，回到对应步骤。

> 任一步未达标都在该步闭环，不跳步、不"先上线后补手续"。
**变更/年检**：词库大版本（S1）、供应链（S10）、留存期（S4）等变更按同一流程复核更新。

### 7.2 必办事项明细（S1–S14）

| # | 性质 | 事项 | 为什么必须部署单位具名/拍板 | 载体（在哪里签） | 时机 | 项目内依据 | 未签的后果 |
|---|---|---|---|---|---|---|---|
| **S1** | 甲 | 内容拦截**词库具名复核** | "是否拦对了"是事实断言，须由承担内容安全主体责任的一方认定 | `gateway/tee-infer-service/policy/review-ledger.json`：`review_level: role → named` ＋ `reviewer` 写**具名责任人** | 首次上线前；每次词库大版本变更前 | B2 本体 §5 前置条件④；[D-LLM-4 §11](GA-大模型内容合规规划-D-LLM-4决策材料-词库与题库来源.md)；**乙类 S5-5 导出内容（关键词/正则/类目/版本/SHA 清单）的具名复核即本项，同一硬门控** | 工具**已强制**：报备形态 `blocklist-keywords-only.csv` 不生成、不得对外申报 |
| **S2** | 甲 | 备案**申报主体**信息（主体名称/统一社会信用代码/服务名称/负责人/联系方式） | 申报主体即部署单位 | 属地备案申报系统 ＋ 备案材料首页 | 备案提交前 | B2 本体 §5／B2-7 | 材料缺主体，无法提交 |
| **S3** | 甲 | 生成内容**标识**条款的落地形态（显式/隐式标识） | 标识义务主体为服务提供者 | 接口/前端配置 ＋ 备案材料 §4 | 上线前 | 输出侧 OG-⑬（标识条款）；B2 本体 | 标识不合规风险 |
| **S4** | 甲 | **日志与内容留存**声明（留存范围/期限/存证方式） | 留存期限由部署单位按其合规要求确定 | 审计保留期配置 ＋ 备案材料 | 上线前；年检 | 审计链设计；B2 本体 | 核查时无法举证 |
| **S5** | 乙 | **fail-closed 策略**的例外与放行口径 | "后端不可用即拒绝"影响业务连续性，须业务方承担后果 | `-fail-closed` 启动参数 ＋ 例外登记表 | 上线前 | [D-LLM-3（审核后端不可用处置口径）](GA-大模型内容合规规划-D-LLM-3决策材料-审核后端不可用处置口径.md) | 事故责任不清 |
| **S6** | 乙 | **误杀线与准入闸门定线**（含 A2 歧视类动作、输出侧 fp 绝对上限） | 属"可接受误伤"的商业/合规取舍 | [D-LLM-8 材料](GA-大模型内容合规规划-D-LLM-8决策材料-误杀线与准入闸门定线.md) 签署页 ＋ 策略配置 | 定线评审时 | D-LLM-8 材料 | 策略无法定稿（当前 `block`/`flag` 依赖此项） |
| **S7** | 丙 | **运行责任人**（Guardrail／推理引擎／网关的日常责任人） | 运行责任主体 | 运维交接单（本指南 §5） | 交付/上线 | 本指南 §5 | 事故无人认领 |
| **S8** | 丙 | **密钥与 Secret 托管**（KMS/Secret 归属、轮换责任人） | 密钥属部署单位资产 | K8s Secret／KMS 配置 ＋ 交接单 | 上线前；轮换时 | 管理门户 apiTokens Secret 化方案（M1/M2） | 密钥失控 |
| **S9** | 乙 | **计费单价表**（成本核算口径） | 项目内仅**计量无单价**，单价属商业决定 | 外部单价表导入配置 | 计费上线前 | 《GA-计费接口设计》（billing 仅计量） | 无法出账 |
| **S10** | 甲 | **供应链与出境登记**（第三方组件、数据出境） | 登记主体为实际运营方；**是否构成法定登记/出境情形由部署单位判定** | [docs/supply-chain/](supply-chain/) 登记表签署 | 上线前；组件变更时 | 供应链与出境域（本体登记表） | 出境未登记风险 |
| **S11** | 甲 | **审计只读账号与留存期**的对外承诺 | 承诺对外，须主体签署 | 门户 auditor 配置 ＋ 备案材料 | 上线前 | 《[管理门户-细化方案](管理门户-细化方案.md)》 | 承诺无效（工具侧已强制只读，但承诺主体仍是部署单位） |
| **S12** | 乙 | 词库**扩量层残余缺陷**的"接受/继续修复"决策 | 影响拦截质量与量级口径，属风险自留决策 | 本章 §7.4 勾选 ＋ D-LLM-8 | 本轮交付时 | 本章 §7.8（残余项登记） | 风险归属不明 |
| **S13** | 丙 | **监控告警现场接线与合规演练**：截断率告警接线（Alertmanager 路由＋值班升级链）、enforcing 演练与回滚（S2-2）、TEE 会话重启风暴/同 Pod 重启叠加预案演练（S2-6 两场景） | 接线与演练只能在现场环境完成，运行责任由部署单位承担；开发单位交付查询/阈值/预案，不代替其接线与演练 | Alertmanager/监控配置 ＋ 演练记录（含时间、参演人、结果、问题闭环） | 上线前；每次转 enforcing 前；年检 | 《[截断率监控与处置Runbook.md](output-guard/GA-截断率监控与处置Runbook.md)》、S2-2 演练测试、本指南 §5 | 现场"告警不响/无人会处置"，误伤风暴或重启抖动不能被及时兜住 |
| **S14** | 乙 | **§9.4 拒答率判据口径确认**（①口径B 定义＝仅"产生处置动作"〔排除默认 `pass` 类目〕；②**A5 族是否纳入「应拒答」判据**；③口径A／口径B **双口径均未达 95%** 下的**对外写法**） | 判据口径与对外承诺属合规/商业取舍，且**直接决定备案材料"效果结论"栏怎么填**——未确认则该栏无法定稿 | [D-LLM-10 §10.1／§10.2](GA-大模型内容合规规划-D-LLM-10决策材料-分类体系与题库口径裁决.md) 的 **Q13–Q15 批注/签署页**（§10.2 已含四路评审汇总与**签署栏 §10.2.7**：法务＋产品＋算法＋安全；原件按 §7.6 归档） | 报备前（门 A 材料初稿之前）；判据口径变更时 | D-LLM-10 §10／**§10.1**；《[GA-输出侧-§9.4分类目评测报告](output-guard/GA-输出侧-§9.4分类目评测报告.md)》（口径A 21.60%／口径B 93.20%／弱类目 A5-01·A5-02） | 口径未确认：材料"效果结论"栏无定稿口径；**口径B 数值不得单独对外引用**，且不得宣称"已达标/100% 拒答" |

> **依据列说明**：仅列**项目内可查证**的条款/文档；涉及法定或监管要求的具体法条与适用性，**由部署单位合规团队认定**，开发单位不作法律结论。本表是**责任边界建议（开发单位视角）**，不是法律意见。

### 7.3 时间线（相对上线日 T）

| 时点 | 必办项 | 责任方 |
|---|---|---|
| T-30 | **S14** §9.4 判据口径确认（法务＋产品）、**S2** 申报主体信息、**S3** 标识形态、**S4** 留存声明 → 备案材料初稿 | 部署单位（合规/法务＋产品） |
| T-14 | **S1 词库具名复核**（操作见 §7.5）→ 产出台账签名与报备形态 | 部署单位（内容责任人） |
| T-7 | **S5** fail-closed 例外口径、**S6** 误杀线定线、**S9** 计费单价表 | 部署单位（业务/合规） |
| T-1 | **S7** 运行责任人、**S8** 密钥与 Secret 托管交接、**S13** 告警现场接线核对与合规演练 | 部署单位（运维） |
| T（上线日） | §7.4 勾选清单全绿后放行；**S11** 审计只读与留存期承诺随备案材料提交 | 部署单位 |
| 年检 / 变更 | **S4** 留存期复核、**S10** 供应链与出境登记更新、**S1** 词库大版本复核 | 部署单位 |

### 7.4 上线勾选与证据（逐项打勾；定义见 §7.2）

| 勾选 | # | 性质 | 事项 | 完成判据（可验证） | 证据留存 | 本指南相关章节 |
|---|---|---|---|---|---|---|
| ☐ | S1 | 甲 | 词库**具名复核** | `review-ledger.json` 的 `review_level=named` 且 `reviewer` 为具名责任人；导出摘要 `filing_ready=true` | 台账 + 报备形态 CSV + `export-summary.json` + 版本号 | §5.4、§7.5 |
| ☐ | S2 | 甲 | 备案**申报主体**信息 | 属地系统提交回执 / 材料首页主体信息齐备 | 提交回执截图 + 材料定稿 | — |
| ☐ | S3 | 甲 | 生成内容**标识**条款 | 接口/前端已按定稿形态实现并有验证记录 | 配置快照 + 验证记录 | §1.0 |
| ☐ | S4 | 甲 | **日志与留存声明** | `-audit-retention-days` 已按声明值设置（见 §6 行：缺省 365、法定硬底 180） | 启动日志 / `GET /config` / 指标 `otpmask_audit_retention_days` | §6 |
| ☐ | S5 | 乙 | **fail-closed 例外口径** | `-fail-closed` 取值与例外登记表一致 | 启动参数快照 + 例外登记 | §5.3 |
| ☐ | S6 | 乙 | **误杀线与准入闸门定线** | D-LLM-8 材料签署页完成；策略动作（`block`/`flag`）与定线一致 | 签署页 + 策略配置快照 | §5.4 |
| ☐ | S7 | 丙 | **运行责任人** | 交接单含 Guardrail/引擎/网关责任人 | 运维交接单 | §5 |
| ☐ | S8 | 丙 | **密钥与 Secret 托管** | 归属与轮换责任人明确；无演示值残留 | 交接单 + Secret/KMS 配置核对 | §4.2 |
| ☐ | S9 | 乙 | **计费单价表** | 外部单价表已导入（billing 仅计量，无内置单价） | 单价表版本 + 导入记录 | — |
| ☐ | S10 | 甲 | **供应链与出境登记** | 登记表签署；出境情形已判定 | 登记表 + 判定结论 | — |
| ☐ | S11 | 甲 | **审计只读与留存期承诺** | auditor 只读（服务端强制）＋ 承诺期与 S4 一致 | 配置快照 + 备案材料 | §5.1 |
| ☐ | S12 | 乙 | 词库**残余缺陷接受/继续修复**决策 | 本章 §7.8.1 残余项登记已给出结论 | 决策记录 | §5.4 |
| ☐ | S13 | 丙 | **告警接线与合规演练** | 截断率告警路由到值班并实测触发；enforcing/回滚演练与两重启场景演练各完成并有记录 | Alertmanager 配置快照 + 演练记录 | §4.4 |
| ☐ | S14 | 乙 | **§9.4 拒答率判据口径确认** | [D-LLM-10 §10.1／§10.2](GA-大模型内容合规规划-D-LLM-10决策材料-分类体系与题库口径裁决.md) 的 Q13–Q15 已批注（**签署栏见 §10.2.7**：法务＋产品＋算法＋安全）：口径B 定义、A5 族判据、对外写法三项均有结论 | 批注/签署页（按 §7.6 归档） | §7.1.3、§7.2 |

### 7.5 S1 词库具名复核 —— 操作步骤（唯一被工具**硬门控**的一项）

> 这是最容易被漏掉、也最容易验证的一项：**未具名 ⇒ 报备形态不生成**（工具层强制，非人工提醒）。

1. 部署单位指定**具名复核人**（须与其 `submitter` 不同人）；
2. 修改 `<policy-dir>/review-ledger.json`：`review_level` 由 `role` 改为 `named`；各批 `reviewer` 由角色名（如 `security-team`）改为**具名责任人**；
3. 离线重生成词库：`POLICY_GEN=1 go test ./gateway/tee-infer-service/ -run TestGeneratePolicyAssets`；
4. 发布新版本（须过哈希 + bench 门禁）：`pwsh ./scripts/policy-publish.ps1 -Version pv… -FromDir <草稿目录> -BenchJson <评测记录.json>`，随后 `go test ./gateway/tee-infer-service/ -run TestPolicyVersionArtifactsVerify`；
5. 生成报备物：`pwsh ./scripts/export-blocklist.ps1` → 摘要 `filing_ready=true`，并产出 `blocklist-keywords-only.csv`（**未具名时该文件不生成**——这是设计意图，不是故障）；
6. 归档：报备物 + `export-summary.json` + 版本号/快照 SHA-256。

### 7.6 证据归档要求

- 每项完成后归档四要素：**完成判据 ＋ 载体快照 ＋ 时间戳 ＋ 具名责任人**；
- 词库类：`policy/versions/<version>/`（逐文件 sha256）＋ `export-summary.json`；
- 归档位置与留存期按 **S4/S11 已声明的口径**执行（本指南不另立口径）；
- **开发单位不留存签署原件**（签署件由部署单位按其留存要求归档）。

### 7.7 易混淆项：哪些是"工程步骤"、哪些才是"法定必办"

下表列出常被误当作"合规动作"的工程步骤，避免清单被稀释：

| 工程步骤 | 是否属法定必办 | 说明 |
|---|---|---|
| TEE/TDX 部署与真机验证 | **否** | 按场景需求裁剪（§6），不是签字项 |
| 密钥注入／Secret 创建 | **否** | 属技术动作；**S8 签的是"归属与轮换责任人"** |
| 审计链启用与锚定 | **否** | 属技术能力；**S4/S11 签的是"留存声明与对外承诺"** |
| 词库/策略版本发布与回滚 | **否** | 属工程动作；**S1 签的是"词条内容已复核"这一事实** |
| 监控/告警接入 | **否** | 运维就绪性，非合规签字项 |
| 备案材料编制 | **否**（材料本身） | 编制是作业；**S2/S3/S4/S11 签的是其中对外承担责任的口径** |

### 7.7.1 运营/部署单位待办清单（研发结项不阻塞项）

> **2026-09-29 研发结项口径**：下表 18 项为**部署/运营单位责任**，研发侧已完成全部编码、测试、工程交付与内部评审（R 类已归零）。这些事项**转入部署/运营侧跟踪，不再作为研发结项阻塞项**。研发按 §7.6 四要素提供技术协助（配置快照、日志、口径说明、评测脚本）。

| 编号 | 事项 | 性质 | 责任方 | 研发已提供 | 备注 |
|---|---|---|---|---|---|
| S0-⑤ | spike 四象限＋GPU 现实性 | 自加 | 部署单位（提供 T4/TDX 环境） | 测脚本与取数方法 | 需真机环境 |
| S0-⑥ | 二维主体判定表 D-LLM-1 | 法定 | 产品＋法务 | 判定表骨架与字段 | 主体定性 |
| S0-⑦ | provider 出境＋境内核查 | 法定 | 法务＋商务 | 数据流图与 18 家登记清单 | 含 Phala 主体核实 |
| S0-⑧ | 模型许可与可复现登记（D1 回填） | 混合 | 部署单位（提供 HF 可达环境） | `g4-download-model.py` 脚本与回填位 | 取 commit SHA |
| S1-5 | 配置刚性分级（形态判定） | 法定 | 产品（公众/内部形态） | 刚性开关与审计链 | `-public-facing` 已实现 |
| S2-1 | 浸泡达标 | 标准·备案 | 运营（真实流量窗口） | 指标与浸泡观察手册 | 真实流量才能取数 |
| S2-2 | 四闸门授权与切 enforcing | 标准·备案 | 四道闸门（SRE/安全/产品/法务） | 切换能力与回滚方案 | 升级禁、降级允 |
| S2-4 | 误杀线定线（D-LLM-8） | 混合 | 产品＋SRE | 实测数据（6/40＝15%，拦截类 1/40）与推荐值 | 产品已签推荐，待法务/安全 |
| S2-5 | 误杀基线达标验收 | 标准·备案 | 产品＋SRE | 基线数据与复跑脚本 | 待 S2-4 定线后验收 |
| S2-6 | 告警接线与演练 | 自加 | SRE（Alertmanager 路由＋值班） | 告警规则（7＋2 记录＋低流量兜底）与 Runbook | 工程化已完成 |
| S3-1 | 类目动作表与分类体系对应 | 标准·备案 | 法务＋产品 | 31 类动作对照表 | 口径一致性 |
| S3-2 | 策略切换与类目启停 tee 运行时 | 混合 | 安全团队（D8 复核） | 端点与审计留痕 | C 策略三前置待解 |
| S3-4 | 语义后端选型 PoC | 混合 | 算法＋算力预算审批 | PoC 方案与对比脚本 | 已签"延后" |
| S3-5 | 拒答率达标对齐 | 标准·备案 | 算法＋产品 | 评测框架与基线（口径A 21.60%/口径B 剔除后≈100%） | 产品已签 Q14 |
| S3-6 | 真实模型合格率演练 | 标准·备案 | 运营（真实模型窗口） | 评测脚本与 SLO 基线 | 需真实推理后端 |
| S4-4 | SaaS 租户处置（客户决策） | 混合 | 产品（SaaS 决策） | 状态机与隔离机制 | 工程已完成 |
| S5-8 | 销售话术与对外承诺定稿 | 自加 | 法务 | 事实数据与口径说明 | 不得宣称达标 |
| X-2 | T6 跨系统联调 | 跨系统 | T6 团队 | API 与对接文档 | 工程侧已就绪 |

> **交付边界**：研发侧交付物＝代码仓库＋本部署指南＋备案材料骨架＋同源证据链＋评测与告警脚本。运营/部署单位交付物＝具名签署＋现场操作记录＋外部资质回执。双方按 §7.6 四要素留痕归档。

### 7.8 残余风险登记与本章修订记录

#### 7.8.1 词库残余项登记（S12 的决策对象）

- **评审口径**：六角色 agent 评审 = 开发单位**内部质量活动**，**不构成具名人工复核**，不得替代 S1。
- **评审结论**：2026-09-27 判删 ≈4150/10312（40%），缺陷为 D1 不成词／D2 极性错误／D4 近义冗余。
- **已处置**：按"方案 (c)"**结构性重建**——轴级排除（`exclude_left/right`）＋ 动宾搭配白名单（`left_objects`）＋ 反向白名单（`right_lefts`，权利类客体）＋ 法定术语逐条显式（`terms`）＋ 及物动词反序（`verb_right`）＋ 有效客体扩量。重建后 **10068 条**（≥10000 ✅、A.1 每类 ≥200 ✅、A.2 每类 ≥100 ✅、占位 0）；A3-04 因盲目组合判删率达 90%，**取消自由组合**改为"少量白名单组合＋法定术语"。
- **残余（须部署单位决策）**：重建仅消除**可判定的**搭配/极性/冗余缺陷，**仍属机器生成＋开发单位角色级复核**，**不等同人工逐条审定**；A3-04 等**窄域类目**的词面数受领域实际词汇量约束，无法再靠组合补量。
- **可选结论**：①接受现状并在备案材料中如实标注"审核状态"；②继续逐条人工精修后再发版。

#### 7.8.2 本章修订记录

| 日期 | 内容 |
|---|---|
| 2026-09-29 | **新增 §7.7.1 运营/部署单位待办清单（研发结项口径）**：把遗留清单 18 项未闭项按"R/O 责任主体"分类，**确认 18 项全部为 O 类（部署/运营单位责任）**，R 类（研发责任）已全部归零；18 项转入本节跟踪，**不再作为研发结项阻塞项**。研发侧已完成举证：代码入仓、OSS 与 `-tags saas` 全量测试绿、3 个 P0 缺陷全闭、告警与可观测性就绪、备案材料骨架与同源证据链齐。研发按 §7.6 四要素继续提供技术协助，不承担阻塞责任。同步在《[遗留工作清单](GA-大模型内容合规规划-遗留工作清单.md)》§1.1.1 加责任主体映射表、§1.1 总览加注研发结项口径。 |
| 2026-09-28 | **新增 S14（乙类）：§9.4 拒答率判据口径确认**——口径B 定义（仅"产生处置动作"＝**排除默认 `pass` 类目**）、A5 族是否纳入「应拒答」判据、口径A/B 双口径均未达 95% 下的对外写法；载体＝[D-LLM-10 §10.1](GA-大模型内容合规规划-D-LLM-10决策材料-分类体系与题库口径裁决.md) 的 **Q13–Q15 批注/签署页**（法务＋产品具名）。同步更新 §7.0 三类性质（乙类）、§7.1 待部署单位完成项（→**S1–S14**）、§7.1.3 门 A 清单、§7.2 明细表＋标题、§7.3 时间线（T-30）、§7.4 勾选；《[GA-报备与上线放行单模板](GA-报备与上线放行单模板.md)》门 A 同步加 S14。**背景**：第二轮评审 P0-2 订正口径B（原 100.00%→**93.20%**，弱类目由「无」变为 **A5-01/A5-02**），"采用口径B 即达标"前提不再成立并新生三问，须外部具名确认后备案材料"效果结论"栏方可定稿。开发单位只备料与如实登记，不代签。 |
| 2026-09-28 | **新增《[GA-报备与上线放行单模板](GA-报备与上线放行单模板.md)》并在 §7.1.3 加指针**：两门勾选（门 A 报备 8 项／门 B 上线 10 项）＋证据载体＋具名签署＋备案回执＋上线执行观察记录，每租户一份；模板已加入 `.gitignore` 白名单随仓库交付。模板条件与 §7.1.3/§7.2 一致，未新增机制。 |
| 2026-09-27 | **§7.1.3 扩写"六步放行操作细则"**：六步逐一补 执行人/具体操作（真实命令与 HTTP 端点）/产出验证/不通过处置——S1 具名五步命令、audit-verify 独立复算、§9.3/§9.4 评估写盘与三方一致性比对、具名批准门、属地报备取回执、以启动参数 `-output-guard enforcing` 滚动重启上线观察及回滚；注明鉴权头（X-Admin-Token/Actor/Request-ID）与持久化覆盖注意事项。均引用仓库内既有脚本/端点/测试，未新增机制。 |
| 2026-09-27 | **§7.1 深化：补"为什么禁止 / 怎样解禁"**。新增 §7.1.1（不得对外的原因：法定义务随对外行为归于部署单位，无备案/安评、S1 无背书、enforcing 未授权、运行义务未落地、出境未判定）、§7.1.2（不得报备的原因：主体/措施背书/栏目口径/评估证据/出境结论不齐，强报面临不予受理或不实申报）、§7.1.3（达标路径：**门 A 报备门 → 门 B 上线门 → 部署单位具名放行**，含逐项条件、证据与六步放行流程）；顶部判定语加指引。编号不变，明细/勾选/证据仍指向 §7.2/§7.4/§7.5/§7.6，避免重复。 |
| 2026-09-27 | **新增 S13（丙类）：监控告警现场接线与合规演练**——截断率告警接线、enforcing/回滚演练、TEE 会话重启风暴与同 Pod 重启叠加两场景演练，载体为监控配置＋演练记录；同步更新 §4.4 指针、§7.0.2 丙类、§7.0.3、§7.2（含 S1 交叉引用乙类 S5-5 内容部分）、§7.3、§7.4。**背景**：乙类草稿外部依赖收口——具名复核与现场接线演练按既有责任划分归部署单位并集中登记于本章，开发单位不代签、不代演练；这些外部/现场事项**不阻断开发进度完成**（未完成只影响"合法对外"放行，见 §7 判定）。 |
| 2026-09-27 | **并入原独立文档《GA-部署单位具名与签署事项清单》**（该文件已删除，不再作为独立文件维护）：本章现为本主题的**唯一事实源**。新增 §7.0（责任边界／三类性质／分工现状）、§7.2（S1–S12 明细）、§7.8（残余风险登记与修订记录）；原 §7.0–§7.5 顺延为 §7.1、§7.3–§7.7。**动机**：本指南在白名单内随仓库交付，独立清单属 `.gitignore` 本地资产——合并后单一出处且能随代码交付到部署单位。 |
| 2026-09-27 | 建档：新增本章「上线前的法定与合规必办步骤（环境搭建之外）」，并在 §1 部署路径总览顶部加放行指针。 |

## 8. 生产部署分步操作指南（技术 · Kubernetes）

> 本章为**技术部署**的 step-by-step 操作清单，解决「系统能跑起来、链路能跑通」的问题。
> 合规与放行流程见 §7；本章是 §7 的**技术前置条件**。
>
> 适用场景：路径 C（Kubernetes 生产）。kind / Docker Compose 见 §2/§3。

### 8.0 前置检查

| # | 项 | 命令 / 验证方式 | 预期 |
|---|---|---|---|
| 1 | K8s 集群可达 | `kubectl cluster-info` | 返回集群地址 + CoreDNS running |
| 2 | metrics-server 可用 | `kubectl top nodes` | 返回节点 CPU/内存 |
| 3 | 命名空间存在 | `kubectl get ns otpmask` | 存在；不存在则执行 §8.1.1 |
| 4 | 镜像仓库可达 | 手动 `docker pull <镜像>` | 能拉取 |
| 5 | 默认 StorageClass | `kubectl get sc` | 至少 1 个 default SC（监控 PVC 用） |

### 8.1 第一步：基础资源（Namespace + Secret）

#### 8.1.1 创建命名空间

```bash
kubectl apply -f deploy/k8s/namespace.yaml
# 确认
kubectl get ns otpmask
```

#### 8.1.2 创建密钥（生产必读）

`deploy/k8s/secret.yaml` 中的密钥为**演示值**，生产必须替换：

```bash
# 生成随机签名密钥（32 字节 hex）
SIG_KEY=$(openssl rand -hex 32)

# 创建 Secret（覆盖演示值）
kubectl create secret generic otpmask-keys -n otpmask \
  --from-literal=sig-key=$SIG_KEY \
  --from-literal=core-sig-key=$SIG_KEY \
  --from-literal=core-auth-token=$(openssl rand -hex 16) \
  --from-literal=attest-token=$(openssl rand -hex 32) \
  --dry-run=client -o yaml | kubectl apply -f -

# 验证
kubectl get secret otpmask-keys -n otpmask
kubectl describe secret otpmask-keys -n otpmask | grep "sig-key\|core-sig-key"
```

> **重要**：`core-sig-key` 必须与插件侧 `route_verify_key` 完全一致，否则路由表验签失败 → 插件降级。
>
> 密钥管理建议：Vault / KMS envelope 加密，不要明文提交到 Git。

### 8.2 第二步：部署核心服务

按依赖顺序部署：Redis → 控制面 → 推理服务 → 网关插件。

#### 8.2.1 Redis（限流 + 速率限制缓存）

```bash
kubectl apply -k deploy/k8s
# 仅部署 Redis（如果用 kustomize 是一次性全量，可用 label 过滤）
kubectl get pods -n otpmask -l app=redis -w
# 等 STATUS 变 Running
```

#### 8.2.2 控制面（gateway-core + gateway-admin-service）

```bash
# 确认镜像已推送
# 部署
kubectl apply -f deploy/k8s/gateway-core.yaml
kubectl apply -f deploy/k8s/gateway-admin-service.yaml

# 验证 Pod
kubectl get pods -n otpmask -l app=gateway-core -w
kubectl get pods -n otpmask -l app=gateway-admin-service -w

# 验证控制面 API
kubectl port-forward svc/gateway-core -n otpmask 8085:8085 &
curl -s http://localhost:8085/healthz
# 预期：返回 ok
```

> 如果 Pod 状态是 `CreateContainerConfigError`，检查 Secret 是否存在（`kubectl describe pod <pod> -n otpmask | tail -20`）。

#### 8.2.3 推理服务（tee-infer-service）

```bash
kubectl apply -f deploy/k8s/tee-infer-service.yaml
kubectl get pods -n otpmask -l app=tee-infer-service -w

# 健康检查
kubectl port-forward svc/tee-infer-service -n otpmask 19090:19090 &
curl -s http://localhost:19090/attest
# 预期：返回 quote 或 mock 证明
```

### 8.3 第三步：部署 Higress 网关 + Wasm 插件

#### 8.3.1 安装 Higress（如果尚未安装）

```bash
# 使用 Helm 安装（首次）
helm repo add higress.io https://higress.io/helm-charts
helm repo update
helm install higress higress.io/higress -n higress-system --create-namespace \
  --set global.enableStatus=false
```

#### 8.3.2 部署 otpmask Wasm 插件

```bash
# 部署插件配置
kubectl apply -f deploy/higress/otpmask-plugin.yaml

# 部署路由（infer ingress）
kubectl apply -f deploy/higress/ingress-infer.yaml

# 验证插件加载
kubectl get wasmplugin otpmask -n higress-system
# 查看 Higress 网关日志确认插件加载成功
kubectl logs -n higress-system deploy/higress-gateway | grep -i "otpmask\|wasm" | tail -20
```

#### 8.3.3 部署其他安全插件（可选）

```bash
# Key Auth / IP Restriction / Rate Limit / CORS
kubectl apply -f deploy/higress/security-plugins.yaml
# 扩展插件
kubectl apply -f deploy/higress/security-plugins-extended.yaml
```

#### 8.3.4 启用 Higress MCP Server（P1；**需 Higress ≥ 2.2.4**）

> 依据《GA-Higress-MCP接入与打通-技术实现方案》v1.5 §4 / §8。能力本体见《P1--MCP协议网关》。
> **前置**：Higress 需具备 Redis —— 默认**复用** `otpmask/redis-ratelimit`（方案 §4.3 R1）；
> 亦可用官方安装参数 `--set global.enableRedis=true` 生成 `redis-stack-server`（R2）。

```bash
# 1) 预览将写入的 mcpServer 段（不改任何配置）
python3 scripts/higress-mcp.py --profile native --dry-run

# 2) 启用（合并写入 higress-config 的 mcpServer 键 + 滚动重启网关 + 冒烟）
python3 scripts/higress-mcp.py --profile native

# 3) 回滚（删除 mcpServer 键 + 重启，等价"一键关闭"）
python3 scripts/higress-mcp.py --rollback
```

| 项 | 说明 |
|---|---|
| 写入语义 | 脚本**只合并/删除 `data.higress.mcpServer` 键**，保留 `tracing` 等既有键（防整份覆盖丢失） |
| 情况①（native） | 即本条；Higress 原生 MCP Server 提供完整协议面 |
| 情况②（secure） | 分轨：`public-tools`（Higress）/ `secure-tools`（段① → TEE）。路由见 `deploy/higress/ingress-mcp.yaml`；**`--profile secure` 尚未实现**（依赖段① 不透明载荷 + TEE 内 MCP 协议层，属 P2） |
| 完整握手 | 需先**注册 MCP 服务**（`mcpServer.servers[]` 或控制台 MCP 管理界面），见方案 §4.5 |
| 客户端接入 | `http://<gateway>/mcp-servers/<name>/sse`（官方契约） |

#### 8.3.5 已知前置缺口（**部署密态轨前必须闭环**）

| 缺口 | 现象（P0 实测） | 处置 |
|---|---|---|
| **`cryptop` 服务未部署** | 网关 Pod 仅 `higress-gateway` 1 容器；全集群无 `cryptop*`；未监听 19097 → **段① 加密链路前置不满足** | 按 `deploy/higress/cryptopsvc-sidecar-patch.yaml` 注入；**属既有密态链路缺口，非 MCP 方案引入**（方案 RK-9） |

### 8.4 第四步：监控部署

```bash
# Prometheus + Grafana
kubectl apply -k deploy/monitoring

# 验证
kubectl get pods -n monitoring -w
kubectl get svc -n monitoring

# 访问 Grafana（默认 admin/admin）
# NodePort: 30001
```

### 8.5 第五步：冒烟测试

```bash
# 获取网关地址（NodePort 方式）
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[0].address}')
HTTP_PORT=$(kubectl get svc higress-gateway -n higress-system -o jsonpath='{.spec.ports[0].nodePort}')

# 冒烟请求（text 推理）
curl -s -X POST "http://$NODE_IP:$HTTP_PORT/v1/infer" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: test-tenant" \
  -d '{"text":"hello","engine_type":"tee_gpu","stream":false}' | head -c 500

# 预期：返回 200 + 推理结果（或证明相关错误，但不是 503/连接错误）
```

### 8.6 第六步：功能验证 Checklist

逐项验证核心功能：

| # | 功能 | 验证方法 | 通过标准 |
|---|---|---|---|
| 1 | 正常请求 | 发一次推理请求 | 200 OK + 返回结果 |
| 2 | 路由表热更新 | 控制面更新路由 → 插件生效 | 请求路由到新端点 |
| 3 | 签名验签 | 篡改签名 → 被拒绝 | 返回降级/错误，不生效 |
| 4 | 版本回退防护 | 推送低版本配置 → 被忽略 | 高版本配置仍生效 |
| 5 | 熔断 | 某端点 50% 失败 → 熔断 | 流量切走，失败端点无流量 |
| 6 | 重试 | 临时故障 → 自动重试成功 | 业务无感，请求成功 |
| 7 | 降级 | 全部端点故障 → L2/L3 降级 | 返回降级响应，不崩溃 |
| 8 | 灰度切流 | 开启灰度 → 白名单走灰度 | 白名单租户命中灰度端点 |
| 9 | 灰度回滚 | 灰度失败率超阈值 → 自动回滚 | 流量回到稳定版 |
| 10 | 限流 | 超过 QPS 限制 → 被限流 | 返回 429 |

### 8.7 回滚操作

```bash
# 插件版本回滚
# 修改 WasmPlugin 的 url 指向上一版本，重新 apply
kubectl apply -f deploy/higress/otpmask-plugin.yaml

# 服务回滚
kubectl rollout undo deployment/tee-infer-service -n otpmask
kubectl rollout undo deployment/gateway-core -n otpmask

# 查看回滚历史
kubectl rollout history deployment/tee-infer-service -n otpmask
```

## 9. 上线技术验收 Checklist

> **本章定位**：纯技术验收清单，用于确认「系统达到可上线的技术状态」。
> 合规与放行见 §7；本章是 §7 门 B 的**技术前置条件**。
>
> 验收通过 = 所有 P0 项 ✅；P1 项允许上线后补齐，但须有明确计划。

### 9.1 功能验收（P0）

| 优先级 | # | 项 | 验证方法 | 结果 |
|---|---|---|---|---|
| P0 | F-01 | 正常推理请求 200 | curl 发送 text 请求 | ☐ |
| P0 | F-02 | 流式推理正常 | curl -N 验证 SSE 格式 | ☐ |
| P0 | F-03 | 多端点路由生效 | 配置多端点，验证流量分配 | ☐ |
| P0 | F-04 | 失败率感知路由 | 注入失败，验证流量倾斜 | ☐ |
| P0 | F-05 | 熔断机制 | 连续失败 → 熔断 → 流量切走 | ☐ |
| P0 | F-06 | 熔断恢复 | 冷却期后 → 半开探测 → 恢复 | ☐ |
| P0 | F-07 | 自动重试 | 临时故障 → 重试成功 | ☐ |
| P0 | F-08 | 重试预算 | 高失败率下重试不放大 | ☐ |
| P0 | F-09 | L2/L3 降级 | 全部端点故障 → 兜底不崩溃 | ☐ |
| P0 | F-10 | 灰度切流 | 白名单 → treatment/control 分组 | ☐ |
| P0 | F-11 | 灰度自动回滚 | 灰度失败率超阈值 → 自动回滚 | ☐ |
| P1 | F-12 | 配置热更新（零停机） | 更新路由表，请求不中断 | ☐ |
| P1 | F-13 | 限流生效 | 超 QPS 返回 429 | ☐ |

### 9.2 性能验收（P0）

| 优先级 | # | 项 | 目标值 | 验证方法 | 结果 |
|---|---|---|---|---|---|
| P0 | P-01 | 路由层延迟 p95 | < 5ms | 压测工具（wrk/hey） | ☐ |
| P0 | P-02 | 单节点 QPS | > 5,000 | 稳态压测 5min | ☐ |
| P0 | P-03 | 熔断判断耗时 | < 1ms | benchmark + 真实流量 | ☐ |
| P0 | P-04 | 高并发稳定性 | 内存增长 < 10MB / 小时 | 满负载 1h | ☐ |
| P0 | P-05 | 大流不雪崩 | 10x 流量自动降级不崩溃 | 突发压测 | ☐ |
| P1 | P-06 | 配置更新延迟 | < 10ms / 次 | 高频更新测试 | ☐ |
| P1 | P-07 | Wasm 内存占用 | < 50MB | runtime 观测 | ☐ |
| P1 | P-08 | onTick 性能 | < 1ms（10 端点） | 日志埋点 | ☐ |

### 9.3 安全验收（P0）

| 优先级 | # | 项 | 验证方法 | 结果 |
|---|---|---|---|---|
| P0 | S-01 | HMAC 签名验证有效 | 正确签名接受 / 错误签名拒绝 | ☐ |
| P0 | S-02 | 配置篡改防护 | 修改内容不重签 → 被拒绝 | ☐ |
| P0 | S-03 | 版本回退防护 | 低版本配置被忽略 | ☐ |
| P0 | S-04 | 密钥不在日志中出现 | grep 日志确认 | ☐ |
| P0 | S-05 | API Key 脱敏 | 错误信息中不暴露完整 key | ☐ |
| P0 | S-06 | Wasm 沙箱隔离 | 插件无法访问宿主文件系统 | 架构评审 + 验证 | ☐ |
| P1 | S-07 | 请求体大小限制 | 超大请求返回 413 | ☐ |
| P1 | S-08 | 审计日志完整 | 操作可追溯，哈希链连续 | audit-verify 工具 | ☐ |
| P1 | S-09 | TLS 配置 | 入口启用 TLS，弱密码套件禁用 | SSL Labs / openssl s_client | ☐ |
| P1 | S-10 | RBAC 有效 | 管理接口需鉴权，越权被拒 | 渗透测试 | ☐ |

### 9.4 可观测性验收（P0）

| 优先级 | # | 项 | 验证方法 | 结果 |
|---|---|---|---|---|
| P0 | O-01 | 核心指标上报 | Prometheus 能查到 otpmask_* 指标 | ☐ |
| P0 | O-02 | 路由请求量 | `rate(otpmask_route_requests_total[5m])` 有数据 | ☐ |
| P0 | O-03 | 延迟分位数 | histogram_quantile 能算 p95 | ☐ |
| P0 | O-04 | 端点健康状态 | 每个端点 health_status gauge 有值 | ☐ |
| P0 | O-05 | 熔断状态 | circuit_breaker_state gauge 正确 | ☐ |
| P0 | O-06 | 降级级别 | degrade_level gauge 正确反映状态 | ☐ |
| P0 | O-07 | 日志格式规范 | JSON 结构化，含 request_id | ☐ |
| P0 | O-08 | 关键告警配置 | 熔断 / 高失败率 / 错误率告警 | ☐ |
| P1 | O-09 | Grafana 仪表盘 | 总览面板数据完整 | ☐ |
| P1 | O-10 | 日志检索 | Loki / ELK 能按 request_id 查链路 | ☐ |

### 9.5 运维验收（P1）

| 优先级 | # | 项 | 验证方法 | 结果 |
|---|---|---|---|---|
| P1 | OPS-01 | HPA 自动扩缩 | 加压后副本数增加 | ☐ |
| P1 | OPS-02 | PDB 生效 | 节点维护时不中断服务 | ☐ |
| P1 | OPS-03 | 滚动升级零停机 | rollout restart 不丢请求 | ☐ |
| P1 | OPS-04 | 回滚能力 | rollout undo 可回到上一版本 | ☐ |
| P1 | OPS-05 | 故障演练 | 单 Pod 崩溃 → 自动恢复 | ☐ |
| P1 | OPS-06 | 备份与恢复 | 配置 / 密钥备份 + 恢复演练 | ☐ |
| P1 | OPS-07 | 运行手册 | 常见故障有排查步骤 | 对照 §5.2 |

### 9.6 验收签字

| 角色 | 姓名 | 日期 | 签字 |
|---|---|---|---|
| 开发负责人 | | | |
| 测试负责人 | | | |
| 运维负责人 | | | |
| 安全负责人 | | | |

> **验收通过标准**：所有 P0 项 ✅，P1 项有明确的补齐计划和责任人。
>
> 验收通过后，方可进入 §7 的合规放行流程（门 A → 门 B → 具名放行）。

### 9.7 真机验收与准备件索引（跨功能）

> 项目级验收主体为本章 §9.1–§9.6；**真机（TDX / GPU-CC）验收操作单与准备件**保留为**过程留证/模板**，索引如下（不计入标准文档）。

| 件 | 文档 | 用途 |
|---|---|---|
| GF3.2 真机 TDX 密态 SSE 端到端验收 | [GA-GF3.2-真机TDX验收操作单.md](GA-GF3.2-真机TDX验收操作单.md) | 对齐改造成果的真机验收步骤 |
| GF5 真机验收（R1-A/B/C） | [GF5-真机验收模板.md](GF5-真机验收模板.md) | 性能决策门 / C-MaaS 验证 / 规格 |
| TEE 虚拟机验证准备包 | [GA-TEE虚拟机验证准备包.md](GA-TEE虚拟机验证准备包.md) | 租用 TEE 云主机后的验证清单与判据 |
| P0-2 语义缓存性能基准（BM-1..BM-8） | [GA-AI网关能力补齐-性能基准报告.md](GA-AI网关能力补齐-性能基准报告.md) | 基准方法与实测（本地实测 + 待真机分账） |
| GA-Higress-MCP 任务验收留证（T-1…T-9 / V-1…V-9） | [GA-Higress-MCP-任务验收留证.md](verify/mcp/GA-Higress-MCP-任务验收留证.md) | MCP 接入与打通整体验收证据：进程内测试 + 真机 V-1/V-2/V-3/V-7/V-9、红线 V-4/V-5 采样与**验收方 2026-10-12 签字记录（§17，已通过）**；本地留存（不随仓库开源） |
| GA-Higress-MCP T-9 测试与渗透留证 | [GA-Higress-MCP-T-9-测试与渗透-验收留证.md](verify/mcp/GA-Higress-MCP-T-9-测试与渗透-验收留证.md) | T-9 单元级断言与渗透用例（进程内端到端，含红线 §10.1 判据③）；本地留存（不随仓库开源） |

---

## 10. 路由模块（多模型智能路由）运维手册

> **本章定位**：路由模块（P0-1）专项运维指南，覆盖配置、操作、故障排查、观测与回滚。
> 通用部署与运维见 §1–§6；全局上线验收见 §9；本章为路由专项补充。

### 10.1 组件与部署拓扑

路由模块由以下组件构成，以 Higress WasmPlugin 形态接入数据面：

```
客户端 → Higress 网关（Envoy + otpmask WasmPlugin）
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
   gateway-core     tee-infer        cmaas / vllm
   （控制面：        （TEE 推理      （各引擎端点
    路由表签发）      引擎端点）       由路由表配置）
```

| 组件 | 部署形态 | 关键配置 | 说明 |
|---|---|---|---|
| **otpmask WasmPlugin** | Higress `extensions.higress.io/WasmPlugin` CR | `url` / `matchRules[0].config` | 数据面路由决策，与 otpmask 加密插件共用同一 wasm |
| **gateway-core** | K8s Deployment + Service + Secret | `core-sig-key` / `core-auth-token` | 控制面：路由表/限流表签发，签名使用 `core-sig-key` |
| **otpmask-keys Secret** | K8s Secret（`otpmask` 命名空间） | `sig-key` / `attest-token` 等 | 数据面密钥，WasmPlugin 经 `secret_name` 引用 |
| **wasm-files 服务** | K8s Deployment + Service（可选） | — | wasm 制品 HTTP 分发；wasm 超 ConfigMap 1MiB 限制时使用 |

**依赖关系**：
- 路由决策启用 = `gateway_core_enabled=true` **且** `route_verify_key` 有效（≥32 字节 hex）
- 路由表拉取 = 需 gateway-core 可达 + `gateway_core_token`（Bearer 鉴权）
- 验签密钥 = 插件侧 `route_verify_key` 必须与 gateway-core 的 `core-sig_key` **完全一致**

### 10.2 配置参数速查表

以下为路由模块相关的 WasmPlugin 配置项（`matchRules[0].config` 内）：

| 参数 | JSON key | 类型 | 默认值 | 取值范围 | 风险等级 | 说明 |
|---|---|---|---|---|---|---|
| **路由总开关** | `gateway_core_enabled` | bool | `false` | true/false | ⚠️ 中 | 关闭 = 行为与接线前完全一致，不介入任何请求 |
| **控制面服务名** | `gateway_core_service` | string | `""` | 服务名 / FQDN | 低 | Higress 服务发现名；推荐用 `<name>.dns` 短名（与 `outbound\|port\|\|<name>.dns` cluster 一致） |
| **控制面端口** | `gateway_core_port` | int/string | `0` | 1–65535 | 低 | gateway-core 的 HTTP 端口 |
| **控制面令牌** | `gateway_core_token` | string | `""` | — | 🔴 高 | Bearer 鉴权令牌；生产经 Secret 注入，勿明文落 CR |
| **验签密钥** | `route_verify_key` | string | `""` | 64 字符 hex（32 字节） | 🔴 高 | 路由表/限流表 HMAC 验签密钥；必须与 gateway-core `core-sig-key` 一致 |
| **缓存过期** | `max_stale_seconds` | int | `300` | -1=永不过期；0=始终过期；>0=秒 | ⚠️ 中 | 超过此时长未刷新的路由表视为 stale；stale 且无有效处方 → fail-closed |
| **拉取周期** | `poll_interval` | int | `60` | ≥1（秒） | 低 | 路由表周期拉取间隔；最小粒度 100ms |
| **非流式重试** | `route_dispatch_enabled` | bool | `false` | true/false | ⚠️ 中 | 启用后插件自持出站派发，失败时换端点重发；默认关闭 = Envoy 直发 |
| **限流开关** | `ratelimit_enabled` | bool | `false` | true/false | ⚠️ 中 | 启用后周期拉取 `/ratelimits` 并本地执行限流 |
| **凭据拉取开关** | `credential_enabled` | bool | `false` | true/false | 低 | 启用后从管理面周期拉取 sig_key/attest_token，CR 内不落明文 |

> **生产关键参数**：`route_verify_key`、`gateway_core_token` 为敏感配置，必须经 Secret / Vault 注入，不得直接写入 WasmPlugin CR 并提交 Git。

### 10.3 日常运维操作

#### 10.3.1 路由表变更

路由表由 gateway-core 管理，数据面插件被动拉取。变更流程：

```bash
# 1. 在 gateway-core 更新路由表（具体 API 见 gateway-core 文档）
#    路由表版本号必须递增（防回滚）

# 2. 验证数据面是否已拉取到新版本（按 VM 逐个验证）
kubectl exec -n higress-system <gw-pod> -- \
  curl -s http://127.0.0.1:15090/stats/prometheus | \
  grep 'otpmask_route_fetch_ok_total'

# 3. 发测试请求验证路由决策
curl -H "X-Tenant-ID: <tenant>" -H "X-Otp-Model: <model>" \
  http://<gateway>/infer
```

**生效延迟**：≈ `poll_interval` 秒（各 VM 独立拉取，存在轻微时间差）。
如需立即生效，可触发 WasmPlugin 热更新（改 URL query 参数），代价是所有 VM 重启、缓存清空。

#### 10.3.2 配置热更新（WasmPlugin）

通过 ECDS 热更新 WasmPlugin 配置，**无需重启网关 Pod**：

```bash
# 示例：调整 max_stale 为 600 秒
kubectl patch wasmplugin otpmask -n higress-system --type=merge \
  -p '{"spec":{"matchRules":[{"config":{"max_stale_seconds":600}}]}}'

# 示例：切换 wasm 版本（改 URL query 触发重新加载）
kubectl patch wasmplugin otpmask -n higress-system --type=merge \
  -p '{"spec":{"url":"http://wasm-files.otpmask.svc.cluster.local/otpmask-v5.wasm?v=20261001"}}'
```

> **⚠️ 已知约束**：频繁开关 `gateway_core_enabled` 可能导致部分 worker VM 的周期拉取 tick 丢失（ECDS 热更新 + sync.Once 交互问题）。
> 若发现路由表停止刷新（`otpmask_route_fetch_ok_total` 不再增长），重启网关 Pod 即可恢复。

#### 10.3.3 wasm 版本升级

```bash
# 1. 构建新版 wasm（在 Linux/Go 环境）
GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared \
  -o otpmask-v6.wasm ./gateway/wasm/otpmask-plugin

# 2. 上传到 wasm-files 服务（或替换镜像内 wasm）
kubectl cp otpmask-v6.wasm otpmask/<wasm-files-pod>:/usr/share/nginx/html/

# 3. 滚动更新（改 URL 触发 ECDS 热加载，零停机）
kubectl patch wasmplugin otpmask -n higress-system --type=merge \
  -p '{"spec":{"url":"http://wasm-files.otpmask.svc.cluster.local/otpmask-v6.wasm"}}'

# 4. 验证：请求正常 + 指标正常
kubectl exec -n higress-system <gw-pod> -- \
  curl -s -o /dev/null -w '%{http_code}' \
  -H "X-Tenant-ID: tenant-a" -H "X-Otp-Model: qwen-plus" \
  http://127.0.0.1:30000/infer
```

#### 10.3.4 回滚 SOP

| 回滚场景 | 操作 | 预期 |
|---|---|---|
| **路由表回滚** | 在 gateway-core 发布更高版本号的旧内容路由表（版本号必须递增，防回滚机制禁止版本号递减） | 下一个 poll 周期生效 |
| **配置回滚** | `kubectl patch` 恢复旧配置；或 `kubectl rollout undo`（若用 Deployment 管理） | ECDS 秒级生效 |
| **wasm 版本回滚** | `kubectl patch wasmplugin` 改回旧版 URL | ECDS 热加载，各 VM 逐批生效；期间部分请求可能走旧 VM 部分走新 VM |
| **紧急降级（关闭路由）** | `gateway_core_enabled: false` → 行为与接线前完全一致，不再 fail-closed | ECDS 秒级生效；注意：关闭后路由决策完全退出，请求直通后端 |

> **紧急降级优先级**：关路由（直通）→ 回滚 wasm → 回滚配置 → 重启 Pod。
> 优先关路由，最快速、影响最小。

### 10.4 故障排查手册

| 现象 | 可能原因 | 排查步骤 | 处置 |
|---|---|---|---|
| **请求全部 503 fail-closed** | 路由表为空 / 过期 / 拉取失败 | 1. 查 `otpmask_route_fetch_ok_total` 是否在增长<br>2. 查 `otpmask_fail_closed_total` 增长速度<br>3. 查 gateway-core `/routes` 是否正常返回<br>4. 查 Envoy `outbound\|8085\|\|gateway-core.dns` cluster 是否健康 | 紧急：关路由（`gateway_core_enabled=false`）<br>长期：修复拉取链路 |
| **路由表拉取指标不增长** | tick 丢失（ECDS 热更新 + sync.Once） / gateway-core 不可达 / 鉴权失败 | 1. 看日志是否有"拉取 /routes 返回 401"等 warn<br>2. `otpmask_route_fetch_cb_total` 是否增长<br>3. 都不增长 = tick 丢失 | 重启网关 Pod（最快恢复） |
| **部分请求 503 部分正常** | 部分 worker VM 缓存为空 / 路由表不一致 | 1. 连续发 20+ 请求看状态码分布<br>2. 若比例约 1/N（N=worker 数）= 某 VM 缓存空 | 等一个 poll 周期；或重启 Pod |
| **路由表验签失败** | `route_verify_key` 与 gateway-core 不一致 / 路由表被篡改 | 1. 日志中找"拉取 /routes 返回 200"但无"验签通过"<br>2. 对比两端密钥 hex | 修正密钥配置；若密钥被轮换，同步更新 |
| **路由决策不生效（请求直通）** | `gateway_core_enabled=false` 或 `route_verify_key` 无效 | 1. 确认配置为 boolean `true`（不是字符串 `"true"`）<br>2. 确认 `route_verify_key` 是 64 字符有效 hex<br>3. 查日志是否有"路由决策已启用" | 修正配置；WasmPlugin config 为 Object 类型，bool 字段须为 JSON boolean |
| **401 Unauthorized** | `gateway_core_token` 错误 / 缺失 | 日志中有"拉取 /routes 返回 401" | 补全/修正令牌 |
| **性能下降明显** | 路由决策开销异常 / 拉取过于频繁 / EWMA 计算量大 | 1. 对比开/关路由的 QPS 和延迟<br>2. 看 `otpmask_route_latency_seconds` histogram | 正常开销：QPS -1~3%，延迟 +0.2~0.5ms；若超阈值排查 |
| **熔断后不恢复** | 熔断冷却期配置过长 / 半开探测全部失败 | 1. 查 `otpmask_route_circuit_breaker_state` gauge<br>2. 查后端端点是否真的恢复了 | 修复后端；或临时调整熔断参数 |
| **灰度流量比例不对** | 哈希分布不均 / 配置未生效 | 1. 查 `otpmask_route_canary_*` 指标<br>2. 确认灰度配置已生效 | 灰度基于 tenant ID 哈希，样本量小时可能不均匀；大流量下趋近目标比例 |

#### 常用排查命令

```bash
# 查路由拉取指标
kubectl exec -n higress-system <pod> -- \
  curl -s http://127.0.0.1:15090/stats/prometheus | grep otpmask_route

# 查 gateway-core cluster 健康
kubectl exec -n higress-system <pod> -- \
  curl -s 'http://127.0.0.1:15000/clusters?filter=gateway-core'

# 查 otpmask 插件日志（最近 5 分钟，过滤关键字）
kubectl logs -n higress-system <pod> --since=5m | grep 'otpmask-plugin' | grep -i 'route\|拉取\|fail-closed'

# 手动验证路由表 API
kubectl exec -n higress-system <pod> -- \
  curl -s -H "Authorization: Bearer <token>" http://gateway-core.dns:8085/routes
```

### 10.5 观测指标速查

路由模块所有指标前缀为 `otpmask_route_`，按类型分类：

#### Counter（计数器）

| 指标 | 说明 | 告警建议 |
|---|---|---|
| `otpmask_route_requests_total` | 经端点选择的路由请求数 | — |
| `otpmask_route_degraded_total` | 降级到 L2 缓存（处方缺失/失效）次数 | 突增 → 处方签发异常 |
| `otpmask_fail_closed_total` | fail-closed 拒绝次数 | 短时间激增 → 路由表全空/过期，P1 告警 |
| `otpmask_route_fetch_ok_total` | 路由表拉取并验签通过次数 | 持续不增长 → 拉取停滞，P2 告警 |
| `otpmask_route_fetch_reject_total` | 路由表拉取被拒绝次数（HTTP 非 200 / 验签失败 / 版本回滚） | 持续增长 → 控制面异常或密钥错配，P1 告警 |
| `otpmask_route_fetch_cb_total` | 拉取回调执行总次数 | 与 ok+reject 对账 |
| `otpmask_route_config_reload_total` | 路由配置平滑热更新次数 | — |
| `otpmask_route_degrade_events_total` | 三级降级级别变更次数 | 频繁变更 → 后端不稳定 |
| `otpmask_route_canary_whitelist_total` | 灰度白名单命中次数 | — |
| `otpmask_route_canary_treatment_total` | 灰度实验组请求数 | — |
| `otpmask_route_canary_control_total` | 灰度对照组请求数 | — |

#### Gauge（仪表盘）

| 指标 | 说明 | 告警建议 |
|---|---|---|
| `otpmask_route_circuit_breaker_state{endpoint}` | 端点熔断状态（0=正常 / 1=半开 / 2=熔断） | 状态=2 且持续 >5min → 端点故障，P2 告警 |
| `otpmask_route_degrade_level` | 当前降级级别（0=正常 / 1=L1 / 2=L2 / 3=L3） | 级别≥2 → 后端大面积故障，P1 告警 |

#### Histogram（直方图）

| 指标 | 说明 | 告警建议 |
|---|---|---|
| `otpmask_route_latency_seconds` | 端到端路由请求延迟 | p95 持续 > 预期值的 2 倍 → 性能退化，P2 告警 |

### 10.6 上线前检查清单（路由模块专项）

> 本清单为 §9 全局上线验收的**路由模块专项补充**。全局验收通过 §9 执行；
> 本清单在路由模块首次上线或大版本变更时使用，作为 §9 的路由维度细化。

#### 功能验收

| # | 项 | 验证方法 | 结果 |
|---|---|---|---|
| R-F01 | 单路由命中（已知 tenant+model 返回预期引擎） | curl 指定租户和模型，验证 `X-Otp-Engine` 响应头 | ☐ |
| R-F02 | 未知租户 fail-closed（503） | 用不存在的租户发请求，验证返回 503 | ☐ |
| R-F03 | 处方验签生效（有效处方走 L1） | 带有效 X-Otp-Route 头，验证使用 preferred_engine | ☐ |
| R-F04 | 伪造处方降级 L2（不 fail-closed） | 带伪造签名的 X-Otp-Route，验证请求仍被路由（降级），不 503 | ☐ |
| R-F05 | 主备切换（主端点故障 → 切备） | 注入主端点 50% 失败，验证流量切到备端点 | ☐ |
| R-F06 | 权重路由（按比例分配） | 配置 70/30 权重，验证大流量下比例趋近 7:3 | ☐ |
| R-F07 | 熔断机制（连续失败 → 熔断 → 半开 → 恢复） | 连续失败注入，验证状态变化 | ☐ |
| R-F08 | 非流式重试（临时故障自动重试成功） | 端点偶发失败，验证重试后成功 | ☐ |
| R-F09 | 三级降级（全端点故障 → 逐级降级） | 所有端点故障，验证降级级别逐步提升 | ☐ |
| R-F10 | 灰度切流（白名单 / treatment / control） | 配置灰度策略，验证分组正确 | ☐ |
| R-F11 | 配置热更新（路由表变更零停机） | 更新路由表，验证流量平滑切换、无 5xx 尖峰 | ☐ |

#### 性能验收

| # | 项 | 目标值 | 验证方法 | 结果 |
|---|---|---|---|---|
| R-P01 | 路由决策 QPS 开销 | ≤ 5% | 开/关路由对比压测 | ☐ |
| R-P02 | 路由决策延迟增量 | ≤ 1ms（p95） | 开/关路由对比延迟 | ☐ |
| R-P03 | 长稳内存增长 | ≤ 10 MB / 小时 | 满负载 1h，观察内存 | ☐ |
| R-P04 | 大流不雪崩 | 10x 流量下自动降级、不崩溃 | 突发压测 | ☐ |

#### 安全验收

| # | 项 | 验证方法 | 结果 |
|---|---|---|---|
| R-S01 | 路由表 HMAC 验签有效 | 正确签名接受 / 错误签名拒绝 | ☐ |
| R-S02 | 版本回退防护 | 低版本号路由表被忽略 | ☐ |
| R-S03 | 篡改防护 | 修改路由表内容不重签 → 被拒绝 | ☐ |
| R-S04 | fail-closed 密态语义 | 无可用路由时拒绝（503），不静默直通 | ☐ |
| R-S05 | 注入防护 | 特殊字符 tenant/model 不 crash、正常处理 | ☐ |
| R-S06 | 密钥不在日志中出现 | grep 日志确认无 `route_verify_key` / `gateway_core_token` 明文 | ☐ |

#### 运维验收

| # | 项 | 验证方法 | 结果 |
|---|---|---|---|
| R-OPS01 | 路由表热更新生效 | 更新路由表，一个 poll 周期内生效 | ☐ |
| R-OPS02 | WasmPlugin 配置热更新 | patch 配置，请求不中断 | ☐ |
| R-OPS03 | wasm 版本升级回滚 | 升级 → 验证 → 回滚，全程零停机 | ☐ |
| R-OPS04 | 紧急降级（关路由） | `gateway_core_enabled=false`，秒级生效，请求直通 | ☐ |
| R-OPS05 | 监控指标完整 | Prometheus 能查到所有 `otpmask_route_*` 指标 | ☐ |
| R-OPS06 | 关键告警配置 | fail-closed 激增 / 拉取停滞 / 熔断 三类告警可用 | ☐ |
| R-OPS07 | 日志可追溯 | 每条路由决策有日志，含 request_id / endpoint / strategy | ☐ |

#### 上线前 Go/No-Go 检查

- [ ] 所有 P0 功能项 ✅
- [ ] 性能指标在目标范围内 ✅
- [ ] 安全验收全部通过 ✅
- [ ] 监控告警接入完成 ✅
- [ ] 回滚方案验证通过 ✅
- [ ] 运维团队培训完成 ✅
- [ ] 已知问题与规避措施文档化 ✅

---

## 11. 语义缓存模块（P0-2）运维手册

> **本章定位**：语义缓存模块（P0-2）专项部署与运维指南，覆盖组件拓扑、配置、日常操作、故障排查、观测与回滚。
> 通用部署与运维见 §1–§6；全局上线验收见 §9；本章为语义缓存专项补充（**结构对齐 §10 路由模块**）。
> **对应实现**：E1–E4B + G3（`8552be1`）+ G1 基准（`1c9396b`）+ **HNSW 向量索引（`16d9fba`，v1.11，默认后端 `hnsw`）**；**默认 `mode=off`**，行为与现网逐字节一致。

### 11.0 红线（务必保持）

| # | 红线 | 说明 | 违反后果 |
|---|---|---|---|
| R1 | **`mode=off`（默认）逐字节一致** | 不组装语义存储、不追加 `/metrics` 缓存指标、不写 L1 | 现网行为漂移 |
| R2 | **缓存故障绝不拖垮推理主链** | 一切异常 fail-open 到 miss（§6.9） | 缓存问题放大为可用性事故 |
| R3 | **明文不出飞地** | 内存明文随进程消亡；Redis 只存 AEAD 密文（§5.3） | 合规事故 |
| R4 | **管理 API 凭证不下发租户侧** | `X-Admin-Token` 属平台运维凭证 | 越权操作缓存 |

### 11.1 组件与部署拓扑

语义缓存是 **tee-infer-service 内的模块**（不新增独立服务，§3.5）：

```
客户端 → Higress 网关 → tee-infer-service（TEE 内）
                              │  cacheengine 模块
                              ├── L0 精确缓存（进程内）
                              ├── 负向缓存（进程内）
                              ├── 语义缓存（embedding + 向量索引）
                              └── 管理 API（/cache/* 同进程同端口）
                                     │
                     ┌───────────────┼────────────────┐
                     ▼               ▼                ▼
                  Redis         embedding sidecar   预热清单文件
                （密文共享，       （向量化，        （只读挂载，
                  形态 B/C）        形态 C）         /etc/og/warmup.jsonl）
```

| 组件 | 部署形态 | 关键配置 | 说明 |
|---|---|---|---|
| **cacheengine 模块** | tee-infer 进程内 | `CACHE_CONFIG_PATH` / `CACHE_MODE` | 缓存主逻辑；默认 `off` 不激活 |
| **Redis** | K8s Deployment/Service（或托管） | `redis.*` | 形态 B/C；**只存 AEAD 密文** |
| **embedding sidecar** | 同 Pod sidecar 或内网服务 | `semantic.embedder.*` | 形态 C；向量化（维度须一致） |
| **预热清单文件** | 只读卷（`0444`） | `warmup.file` | JSONL；由控制面/运营投递 |
| **管理 API** | tee-infer 同端口 `:19090` | `-admin-token` / `-listen` | `/cache/*` 十一端点（含 `POST /config/cache/reload`；见 API 参考 §5.5） |

**部署形态与选择**：

| 形态 | 说明 | 前置依赖 | 适用 |
|---|---|---|---|
| **A · 进程内精确** | 仅精确键缓存，无外部依赖 | 无 | 起步/单实例；`mode=exact` |
| **B · Redis 共享精确** | 精确层落 Redis（多副本共享） | Redis ≥6.2 | 多副本、跨重启保留 |
| **C · 语义（+向量）** | 精确 + 语义（sidecar + 向量） | Redis + embedding sidecar（+VSS 可选） | 语义命中收益场景 |

**选择建议**：先以**形态 A**（`mode=exact`）验证零回归与精确命中，再按需演进 B/C。

**依赖关系**：
- 缓存激活 = `mode ≠ off`（默认 `off`）。
- 语义启用 = `semantic.enabled=true` **且** 启动期维度探针通过（否则**自动降级 `mode=exact`**）。
- **向量后端（`semantic.vector.backend`）默认 `hnsw`**（v1.11；进程内图索引，无外部依赖）；`flat` 为显式可选（小容量/需零召回损失）；`redis-vss` 需**双条件**——三者**无自动切换**，未知值**启动拒绝**（规则 27）。
- `redis-vss` 向量后端 = **双条件**（Redis 向量能力探测通过 **且** `redis.addr` 落在 `trusted_cidr` 内），缺一**启动拒绝**。
- Redis 不可达 = 形态 B/C 降级形态 A（fail-open），不阻断推理。

### 11.2 配置参数速查表

**加载顺序**（启动期）：

```
DefaultConfig()（mode=off）
  → CACHE_CONFIG_PATH 指定文件（LoadConfig）
  → ApplyEnv()（CACHE_* 覆盖）
  → Validate()（失败：告警 + 回退默认 off）
  → 语义探针 / BuildSemanticStoreFromConfig（失败：降级 exact 或关闭语义）
```

> 任一环节失败均 **fail-safe 回退 off/精确**，不阻断 tee-infer 启动；但缓存会静默不可用，须查日志 `[tee] 缓存配置加载失败…` / `[tee] 语义缓存探针失败…`。

**环境变量（部署期切换，无需改配置文件；仅覆盖"总开关与连接参数"）**：

| 变量 | 取值 | 风险 | 说明 |
|---|---|---|---|
| `CACHE_CONFIG_PATH` | 文件路径 | 低 | JSON 配置路径（缺省用默认 `mode=off`） |
| `CACHE_MODE` | `off`/`exact`/`semantic`/`full` | ⚠️ 中 | 缓存总开关 |
| `CACHE_REDIS_ENABLED` | `1/0/true/false/yes/no` | ⚠️ 中 | Redis L1（形态 B/C）开关 |
| `CACHE_REDIS_ADDR` | `host:port` | 低 | Redis 地址 |
| `CACHE_SEMANTIC_ENABLED` | 同上 | ⚠️ 中 | 语义层开关 |
| `CACHE_EMBEDDER_ENDPOINT` | URL | 低 | sidecar 端点（默认 `http://127.0.0.1:18081/embed`） |
| `CACHE_EMBEDDER_MODEL` | 模型名 | 低 | 默认 `bge-small-zh-v1.5` |
| `CACHE_EMBEDDER_DIM` | 正整数 | ⚠️ 中 | 默认 `512`；**须与 sidecar 一致**，否则探针失败降级 |
| `CACHE_VECTOR_BACKEND` | `flat`/`hnsw`/`redis-vss` | ⚠️ 中 | **默认 `hnsw`**（v1.11）；`redis-vss` 需**双条件**；**未知值启动拒绝**（不再静默回退 flat） |

> **安全阈值（`threshold.*` 等）只能走配置文件评审**（`ApplyEnv` 不覆盖）。

**配置文件高频项**（完整字段以 `cacheengine/config.go` 为准；JSON，时长 `"5s"`、容量 `"256MB"`）：

| 路径 | 类型 | 风险 | 说明 |
|---|---|---|---|
| `mode` | enum | ⚠️ 中 | `off/exact/semantic/full`（**默认 off**，红线 R1） |
| `scope` | enum | ⚠️ 中 | `per_tenant`（默认）/`global` |
| `policy_version` | string | 低 | 变更 → 旧条目**自然失效**（无需清缓存） |
| `cache_memory_budget` | size | ⚠️ 中 | 超 `watermark_high` → 只读态；回落 `watermark_low` → 恢复写 |
| `exact.*` | — | 低 | `enabled`/`ttl`/`max_entries`/`max_entry_bytes` |
| `negative.*` | — | 低 | 负向缓存（`only_for` 限定快失败类） |
| `semantic.embedder.dim` | int | ⚠️ 中 | **须与 sidecar 一致** |
| `semantic.vector.backend` | enum | ⚠️ 中 | `flat/hnsw/redis-vss`（**默认 `hnsw`**；后者双条件；未知值启动拒绝——规则 27） |
| `semantic.vector.hnsw.*` | — | ⚠️ 中 | HNSW 参数：`m`(16)/`ef_construction`(200)/`ef_search`(64)/`max_entries`(50000)；**`ef_search ≥ top_k`**（规则 27）；`ef_search`↑召回↑延迟↑，`m`↑内存↑ |
| `semantic.threshold.*` | float | 🔴 高 | 场景化阈值（事实/通用/代码/数学） |
| `redis.password_ref` | string | 🔴 高 | 引用外部机密（`env:VAR`/密钥管理），**不落明文** |
| `guard.read_fast_check` / `write_requires_out_guard` | bool | ⚠️ 中 | 读时快审 / 写前门禁（安全，慎改） |
| `write_limit.*` | — | 低 | 写入限流：上限 = `min(入向QPS × inbound_headroom, max_qps)`（§7.4.2） |
| `gray.stage` | enum | ⚠️ 中 | `G-0..G-5`（§12.2；驱动 `#36`） |
| `warmup.file` / `warmup.qps` | string/int | 低 | 预热清单路径 / 节流（0=不限） |

**配置示例**：

```json
// 形态 A（推荐起步）
{ "mode": "exact", "scope": "per_tenant", "policy_version": "p1",
  "cache_memory_budget": "256MB", "exact": { "enabled": true, "ttl": "10m" },
  "semantic": { "enabled": false }, "redis": { "enabled": false },
  "gray": { "enabled": false, "stage": "G-0" },
  "write_limit": { "enabled": true, "max_qps": 200, "inbound_headroom": 1.2, "window": "1s" } }
```

```json
// 形态 B（Redis 共享精确）
{ "mode": "exact",
  "redis": { "enabled": true, "addr": "redis.og.svc:6379", "db": 0,
             "password_ref": "env:REDIS_PASSWORD", "trusted_cidr": ["10.0.0.0/8"],
             "key_prefix": "og:cache:", "ttl_slack": "5s", "pool_size": 64, "max_retries": 2 } }
```

```json
// 形态 C（语义）
{ "mode": "semantic",
  "semantic": { "enabled": true,
    "embedder": { "kind": "sidecar", "endpoint": "http://127.0.0.1:18081/embed",
                  "model_id": "bge-small-zh-v1.5", "dim": 512, "timeout": "200ms", "fail_open": true },
    "vector": { "backend": "hnsw", "top_k": 5,
                "hnsw": { "m": 16, "ef_construction": 200, "ef_search": 64, "max_entries": 50000 } },
    "threshold": { "factual": 0.92, "general": 0.88, "code": 0.95, "math": 0.97 } },
  "gray": { "enabled": true, "stage": "G-4", "canary_tenants": ["t1"], "traffic_percent": 5 } }
```

> 示例阈值/水印为**示意值**；实际取值以本体 §4.2/§6.5 与评审结论为准。

**依赖部署要点**：

- **Redis**：≥6.2（RESP）；`redis-vss` 需 **Redis 8.0+ / Redis Stack**；凭证经 `password_ref` 引用；仅内网可达、`trusted_cidr` 收紧。
- **embedding sidecar**：端点 + `health_endpoint`（留空按 endpoint 推导）；输出维度**必须**等于 `dim`；`fail_open=true` 时不可用 → 语义 miss（不阻塞主链）。
- **预热清单挂载**：`warmup.file`（建议 `/etc/og/warmup.jsonl`）以**只读卷** `0444` 挂载；格式 JSONL `{"tenant","engine","model","prompt","max_new_tokens"}`（**不含 text**）；更新为**全量替换**，导入 `sha256` 记入审计。

### 11.3 日常运维操作

#### 11.3.1 开关与回滚

| 操作 | 命令/方式 | 生效 |
|---|---|---|
| 启用精确缓存 | `CACHE_MODE=exact` + 滚动重启 | 重启后 |
| 启用语义 | `CACHE_SEMANTIC_ENABLED=true`（+ sidecar 就绪） | 重启后 |
| **一键止血** | `CACHE_MODE=off` + 滚动重启 | **无需清缓存** |
| 降级精确 | `CACHE_SEMANTIC_ENABLED=false` | 重启后 |
| Redis 降级 | `CACHE_REDIS_ENABLED=false`（形态 B/C → A） | 重启后 |

> **配置热更新（§6.10，v1.12 起支持）**：`POST /config/cache/reload`（`X-Admin-Token` 鉴权）重读 `CACHE_CONFIG_PATH`（+ 环境覆盖）并**热更**——`mode`/`threshold`/`ttl_policy`/`gray`/`write_limit`/`jitter`/`guard`/`tenant_policy` 等**即时生效、既有条目保留**；**结构性维度**（embedder、`vector.backend`、`max_entries`、`redis.*`、`key_format`、`scope`）**拒绝热更**，返回 **409 `restart_required`**，需**滚动重启**。
> **⚠️ 注意**：`mode=off` 时该端点返回 409 `CACHE_DISABLED`（与其它运营端点一致）；热更不影响 `/metrics` 计数与既有条目（便于快速回滚）。

#### 11.3.2 缓存失效

| 场景 | 操作 |
|---|---|
| 单条错误条目 | `DELETE /cache/entry/{key_hash}` |
| 租户隔离/清退 | `DELETE /cache/tenant/{tenant_id}`（含向量） |
| 模型升级/下线 | `DELETE /cache/model/{model}` |
| 事故期全清 | `DELETE /cache/all?confirm=yes`（**须 confirm**，留痕，建议限频+变更单） |
| 策略/词库更新 | **无需清缓存**：`policy_version`/`GuardVer` 变更后旧条目自然失效 |

#### 11.3.3 预热

```bash
# 触发（reset=true 先全量失效；返回 task_id）
curl -s -X POST -H "X-Admin-Token: $TOKEN" -d '{"reset":false}' "$BASE/cache/warmup"
# 查询进度
curl -s -H "X-Admin-Token: $TOKEN" "$BASE/cache/warmup/<task_id>"
```

- **单飞**：并发触发返回 `409 CACHE_WARMUP_BUSY`。
- **节流**：`warmup.qps` 防打爆上游。
- **失败处置**：文件/行非法 → `400 CACHE_INVALID_ARG`（`message` 含 `warmup line N`）；单条失败 → 记 `failed` 继续；全失败 → 任务 `failed`（不写条目）；被写前审查拦截 → 记 `skipped`（**不算失败**）。
- **任务态不持久化**：进程重启后任务丢失（P0 接受）。

#### 11.3.4 灰度放量与门禁

```bash
# 阶段门禁校验（需 /metrics）
CACHE_METRICS_URL=http://127.0.0.1:19090/metrics bash scripts/cache-canary.sh --stage G-2
# 回滚动作指引
bash scripts/cache-canary.sh --rollback --to G-1
```

| 阶段 | 门禁（脚本可算项） |
|---|---|
| G-0 影子（`write_only`） | 写入成功率/无误命中 → **MANUAL**（无 stores 计数器/需告警系统） |
| G-1 白名单 5% | M1 精确命中率 > 10% |
| G-2 白名单 50% | M1 > 15% 且 精确查表 p95 < 1ms |
| G-3 全量精确 | 无 P1 告警 → **MANUAL** |
| G-4 语义 | M5 误命中率 < 1% |
| G-5 语义全场景 | 无 P1 告警 → **MANUAL** |

- **退出码**：`0` 通过（MANUAL 不判失败）/ `1` 未过 / `2` 参数或环境错误；证据 JSON 落 `CACHE_CANARY_OUT`。
- **回滚判据**（§12.2）：误命中率 >1% / 命中延迟 p95 超预算 / 数据串租（I-8）/ 任一安全告警（AL-1、AL-5）。
- **⚠️ 回滚方式**：§12.3 依赖 `gray` 配置下发热更新（§6.10 未接线），脚本**只产出指引 + 证据**；实际回滚按 11.3.1 执行（写回 `gray.stage` + 滚动重启）。

### 11.4 故障排查手册

| 症状 | 判断 | 处置 |
|---|---|---|
| 缓存全不命中（精确也 miss） | `lookups_total{kind="exact",result="disabled"}` 增长 / 日志回退 | 查配置加载与 `mode`；确认 sidecar/Redis 探针 |
| 语义命中恒 miss | `otpmask_cache_embedder_errors_total` / `embed_timeout_total` 增长 | 查 embedding sidecar；不可用时语义**自动 fail-open 为 miss**，必要时 `CACHE_MODE=exact` |
| Redis 报错（`redis_errors_total` 增长） | AL-4 | 查 Redis 连通/容量；必要时 `CACHE_REDIS_ENABLED=false` 降级形态 A |
| 只读态（`readonly=1`） | AL-8 内存水位 | 查泄漏（`estimated_bytes`）；或上调 `cache_memory_budget` 并重启；回落低水位**自动恢复写** |
| `panic_total` 增长 | AL-1 | 查 error 日志栈；缓存 panic 已 recover 转 miss（不拖垮主链）；必要时 `mode=off` |
| `write_throttled_total` 增长 | AL-6 | 疑似批量灌入；按 `tenant` 定位；核对 `write_limit` |
| `audit_fail_total` 增长 | AL-10 | 查审计后端（旁路信号，不阻塞缓存写入） |
| 命中回放异常 | `replay_total{result="error"}` | 查条目完整性（`entry_corrupt_total`）与分片；必要时删除该条目 |
| 预热后仍 miss | — | 预热条目键由"与真实请求同一链路"的 `transformed_hash` 决定；核对清单 prompt 与线上请求口径 |
| `/metrics` 无 `otpmask_cache_*` | — | `CACHE_MODE=off`（默认）时不追加缓存指标（红线 R1） |

> **通用止血顺序**：① 定位；② 降级（`semantic→exact`）；③ 禁用（`mode=off`）；④ 回滚变更。全程**不清缓存**亦可恢复（版本自然失效）。

### 11.5 观测指标速查

| 指标 | 用途 |
|---|---|
| `otpmask_cache_lookups_total{kind,result}` | 命中率（M1/M2） |
| `otpmask_cache_lookup_duration_seconds{kind}` | 查表延迟（M3） |
| `otpmask_ttft_seconds{mode,cache}` | TTFT 命中改善（M4） |
| `otpmask_cache_semantic_false_positive_total` | 误命中（M5） |
| `otpmask_cache_redis_errors_total` | Redis 错误 |
| `otpmask_cache_write_throttled_total{tenant}` | 写入限流 |
| `otpmask_cache_canary_total{stage,result}` | 灰度放量 |
| `otpmask_cache_warmup_items_total{result}` | 预热条目 |
| `otpmask_cache_estimated_bytes` / `readonly` | 内存水位/只读态 |
| `otpmask_cache_panic_total` | panic 计数 |
| `otpmask_cache_read_fast_check_block_total` | 读时快审拦下 |

**告警（§9.3）**：

| # | 告警 | 级别 | 处置 |
|---|---|---|---|
| AL-1 | `rate(otpmask_cache_panic_total[5m]) > 0` | P1 | 有 panic 即查；必要时 `mode=off` 止血 |
| AL-2 | 语义误命中率 > 1%（且命中样本 > 100/h） | P1 | 收紧场景阈值 / 关闭该场景 |
| AL-3 | 命中延迟 p95 > 15ms | P2 | 查 sidecar 与向量索引 |
| AL-4 | `rate(otpmask_cache_redis_errors_total[5m]) > 1` | P2 | 查 Redis；必要时降级形态 A |
| AL-5 | 读时快审拦下激增 | P1 | 疑似投毒或词库更新；查审计链 |
| AL-6 | 写入限流触发 | P2 | 疑似批量灌入；查 `tenant` |
| AL-7 | 向量容量 > `hnsw.max_entries×0.9`（默认后端）/ `flat_max_entries×0.9`（flat） | P2 | 扩容或清理；**不自动切换后端** |
| AL-8 | `estimated_bytes > cache_memory_budget×0.9` | P1 | 查泄漏/上调预算 |
| AL-9 | `rate(embed_invalid_total[5m]) > 5` | P2 | 查 sidecar；语义自动降级为精确 |
| AL-10 | `rate(audit_fail_total[5m]) > 0` | P2 | 查审计后端 |
| AL-11 | 流式分片降级占比 > 20% | P2 | 查 `stream.max_segments` 与响应长度 |

**门禁**：`scripts/metrics-required.txt`（缓存指标均 `conditional`，触发条件 `CACHE_MODE != off`）；`pwsh scripts/check-metrics-green.ps1`。

### 11.6 上线前检查清单（语义缓存专项）

> 本清单为 §9 全局上线验收的**语义缓存专项补充**，结构与 §10.6 一致。

#### 功能验收

| # | 项 | 验证方法 | 结果 |
|---|---|---|---|
| C-F01 | `mode=off` 零回归 | 开关前后同一请求逐字节对比响应 | ☐ |
| C-F02 | 精确命中生效 | 同口径请求二次调用，审计 `cache_hit=true` | ☐ |
| C-F03 | 租户隔离 | 跨租户同 prompt 不互相命中 | ☐ |
| C-F04 | 语义命中（形态 C） | 相似问题命中；不相似不命中 | ☐ |
| C-F05 | 写前门禁 | 未过输出审查的结果不写缓存 | ☐ |
| C-F06 | 读时快审 | 命中回放前审查生效（`read_fast_check_block_total`） | ☐ |
| C-F07 | 失效（按键/租户/模型/全量） | 四类 DELETE 幂等且生效 | ☐ |
| C-F08 | 预热 | 触发→进度至 `succeeded`；`not_writable` 记 skipped | ☐ |
| C-F09 | 写入限流 | 超限写入被丢弃并记 `write_throttled_total` | ☐ |
| C-F10 | 灰度放量 | G-0 影子只写不读；阶段门禁脚本可用 | ☐ |

#### 性能验收（详见 §8.3 BM-1..8）

| # | 项 | 目标值 | 验证方法 | 结果 |
|---|---|---|---|---|
| C-P01 | 精确查表延迟 | p95 < 1ms | BM-1 | ☐ |
| C-P02 | 语义查表延迟 | p95 < 15ms | BM-2（真机） | ☐ |
| C-P03 | 命中 TTFT 改善 | 首帧显著下降 | BM-3（真机） | ☐ |
| C-P04 | 内存占用 | ≤ `cache_memory_budget` | BM-5 | ☐ |
| C-P05 | 侧信道抖动 | KS p>0.05 | BM-4 | ☐ |

#### 安全验收

| # | 项 | 验证方法 | 结果 |
|---|---|---|---|
| C-S01 | 明文不出飞地 | Redis 取值非明文；`/cache/inspect` 响应无正文 | ☐ |
| C-S02 | 管理 API 鉴权 | 无/错 `X-Admin-Token` → 403 | ☐ |
| C-S03 | `mode=off` 门控 | 运营端点 → 409 `CACHE_DISABLED` | ☐ |
| C-S04 | 管理凭证不落明文 | 配置文件无 token 明文；grep 日志无泄漏 | ☐ |
| C-S05 | `redis-vss` 双条件 | 能力探测 + `trusted_cidr` 缺失时启动拒绝 | ☐ |
| C-S06 | 预热无直灌文本 | 清单不含 text；正文仅由推理产出 | ☐ |

#### 运维验收

| # | 项 | 验证方法 | 结果 |
|---|---|---|---|
| C-OPS01 | 一键回滚 | `CACHE_MODE=off` + 重启，请求恢复正常 | ☐ |
| C-OPS02 | 指标完整 | Prometheus 可查全部 `otpmask_cache_*` | ☐ |
| C-OPS03 | 告警可用 | AL-1/AL-2/AL-5/AL-8 四类配置并验证 | ☐ |
| C-OPS04 | 灰度门禁脚本 | `cache-canary.sh` 各退出码可复现 | ☐ |
| C-OPS05 | 降级可用 | sidecar/Redis 停服后正常推理（fail-open） | ☐ |
| C-OPS06 | 启动自检 | `/config/cache` 与 `/cache/stats` 与形态一致 | ☐ |

#### 上线前 Go/No-Go 检查

- [ ] 所有 P0 功能项 ✅
- [ ] 性能指标在目标范围内 ✅
- [ ] 安全验收全部通过 ✅
- [ ] 监控告警接入完成 ✅
- [ ] 回滚方案验证通过 ✅
- [ ] 运维团队培训完成 ✅
- [ ] 已知问题与规避措施文档化 ✅
