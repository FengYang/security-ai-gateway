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
- [ ] **评估证据**：§9.3/§9.4 在锁定版本上的合格率、拒答率（**双口径分列**）等结果达标且题库口径已对齐（S3-1/S0-①）
- [ ] **S14** §9.4 拒答率**判据口径确认**（D-LLM-10 §10.1 的 Q13–Q15：口径B 定义〔仅"产生处置动作"＝排除默认 `pass` 类目〕／A5 族是否纳入「应拒答」判据／双口径均未达下的对外写法）
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
  - S5/S6/S7/S8/S9/S12/S14：fail-closed 例外、误杀线签署、责任人、密钥归属、单价表、残余风险决策、§9.4 判据口径确认（D-LLM-10 §10.1 的 Q13–Q15，见 §7.2 S14）。
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
  - 三方比对：备案/安评材料 ↔ `GET /config` 配置快照（mode、policy_version、标识、留存、类目）↔ §9.3/§9.4 报告（生成合格率 ≥90%；应拒答拒答率**双口径分列**——口径A〔严格：仅 `block`〕与口径B〔已处置：含 `flag`/`mask`，**不含默认 `pass` 类目**〕，判据 ≥95% 为**目标值，当前实测未达**；非拒答误拒率 ≤5%；弱类目单列）。
  - 对账：`POST /reconcile/run`（或查 `GET /reconcile`）确认 `ok=true`、`billing_blocked=false`；版本以 `GET /config/policy/versions` 与材料一致。
- *产出/验证*：一份"一致性核对结论"（无差异项或差异已闭环）。
- *不通过*：指标不达标或口径不一致 → 回到第 1 步整改并复跑；弱类目须在材料中如实书面列明，不得用总均值掩盖。
- ⚠️ *口径注*：拒答率口径A/B 属**判据口径**（GB/T 45654-2025 §9.4 未直述"标记/脱敏是否计入拒答"），口径B 为变更项，**须经法务/产品按 D-LLM-10 确认后方可对外引用**；确认前对外材料只列口径A 并如实标注未达标，**不得宣称"已达标"或"100% 拒答"**。

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
| **S14** | 乙 | **§9.4 拒答率判据口径确认**（①口径B 定义＝仅"产生处置动作"〔排除默认 `pass` 类目〕；②**A5 族是否纳入「应拒答」判据**；③口径A／口径B **双口径均未达 95%** 下的**对外写法**） | 判据口径与对外承诺属合规/商业取舍，且**直接决定备案材料"效果结论"栏怎么填**——未确认则该栏无法定稿 | [D-LLM-10 §10.1](GA-大模型内容合规规划-D-LLM-10决策材料-分类体系与题库口径裁决.md) 的 **Q13–Q15 批注/签署页**（法务＋产品具名；原件按 §7.6 归档） | 报备前（门 A 材料初稿之前）；判据口径变更时 | D-LLM-10 §10／**§10.1**；《[GA-输出侧-§9.4分类目评测报告](output-guard/GA-输出侧-§9.4分类目评测报告.md)》（口径A 21.60%／口径B 93.20%／弱类目 A5-01·A5-02） | 口径未确认：材料"效果结论"栏无定稿口径；**口径B 数值不得单独对外引用**，且不得宣称"已达标/100% 拒答" |

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
| ☐ | S14 | 乙 | **§9.4 拒答率判据口径确认** | [D-LLM-10 §10.1](GA-大模型内容合规规划-D-LLM-10决策材料-分类体系与题库口径裁决.md) 的 Q13–Q15 已批注（法务＋产品具名）：口径B 定义、A5 族判据、对外写法三项均有结论 | 批注/签署页（按 §7.6 归档） | §7.1.3、§7.2 |

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
| 2026-09-28 | **新增 S14（乙类）：§9.4 拒答率判据口径确认**——口径B 定义（仅"产生处置动作"＝**排除默认 `pass` 类目**）、A5 族是否纳入「应拒答」判据、口径A/B 双口径均未达 95% 下的对外写法；载体＝[D-LLM-10 §10.1](GA-大模型内容合规规划-D-LLM-10决策材料-分类体系与题库口径裁决.md) 的 **Q13–Q15 批注/签署页**（法务＋产品具名）。同步更新 §7.0 三类性质（乙类）、§7.1 待部署单位完成项（→**S1–S14**）、§7.1.3 门 A 清单、§7.2 明细表＋标题、§7.3 时间线（T-30）、§7.4 勾选；《[GA-报备与上线放行单模板](GA-报备与上线放行单模板.md)》门 A 同步加 S14。**背景**：第二轮评审 P0-2 订正口径B（原 100.00%→**93.20%**，弱类目由「无」变为 **A5-01/A5-02**），"采用口径B 即达标"前提不再成立并新生三问，须外部具名确认后备案材料"效果结论"栏方可定稿。开发单位只备料与如实登记，不代签。 |
| 2026-09-28 | **新增《[GA-报备与上线放行单模板](GA-报备与上线放行单模板.md)》并在 §7.1.3 加指针**：两门勾选（门 A 报备 8 项／门 B 上线 10 项）＋证据载体＋具名签署＋备案回执＋上线执行观察记录，每租户一份；模板已加入 `.gitignore` 白名单随仓库交付。模板条件与 §7.1.3/§7.2 一致，未新增机制。 |
| 2026-09-27 | **§7.1.3 扩写"六步放行操作细则"**：六步逐一补 执行人/具体操作（真实命令与 HTTP 端点）/产出验证/不通过处置——S1 具名五步命令、audit-verify 独立复算、§9.3/§9.4 评估写盘与三方一致性比对、具名批准门、属地报备取回执、以启动参数 `-output-guard enforcing` 滚动重启上线观察及回滚；注明鉴权头（X-Admin-Token/Actor/Request-ID）与持久化覆盖注意事项。均引用仓库内既有脚本/端点/测试，未新增机制。 |
| 2026-09-27 | **§7.1 深化：补"为什么禁止 / 怎样解禁"**。新增 §7.1.1（不得对外的原因：法定义务随对外行为归于部署单位，无备案/安评、S1 无背书、enforcing 未授权、运行义务未落地、出境未判定）、§7.1.2（不得报备的原因：主体/措施背书/栏目口径/评估证据/出境结论不齐，强报面临不予受理或不实申报）、§7.1.3（达标路径：**门 A 报备门 → 门 B 上线门 → 部署单位具名放行**，含逐项条件、证据与六步放行流程）；顶部判定语加指引。编号不变，明细/勾选/证据仍指向 §7.2/§7.4/§7.5/§7.6，避免重复。 |
| 2026-09-27 | **新增 S13（丙类）：监控告警现场接线与合规演练**——截断率告警接线、enforcing/回滚演练、TEE 会话重启风暴与同 Pod 重启叠加两场景演练，载体为监控配置＋演练记录；同步更新 §4.4 指针、§7.0.2 丙类、§7.0.3、§7.2（含 S1 交叉引用乙类 S5-5 内容部分）、§7.3、§7.4。**背景**：乙类草稿外部依赖收口——具名复核与现场接线演练按既有责任划分归部署单位并集中登记于本章，开发单位不代签、不代演练；这些外部/现场事项**不阻断开发进度完成**（未完成只影响"合法对外"放行，见 §7 判定）。 |
| 2026-09-27 | **并入原独立文档《GA-部署单位具名与签署事项清单》**（该文件已删除，不再作为独立文件维护）：本章现为本主题的**唯一事实源**。新增 §7.0（责任边界／三类性质／分工现状）、§7.2（S1–S12 明细）、§7.8（残余风险登记与修订记录）；原 §7.0–§7.5 顺延为 §7.1、§7.3–§7.7。**动机**：本指南在白名单内随仓库交付，独立清单属 `.gitignore` 本地资产——合并后单一出处且能随代码交付到部署单位。 |
| 2026-09-27 | 建档：新增本章「上线前的法定与合规必办步骤（环境搭建之外）」，并在 §1 部署路径总览顶部加放行指针。 |
