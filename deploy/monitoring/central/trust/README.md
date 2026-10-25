# P2-4 T-4.3：中央侧通道信任资产（**中央集群**）

> 与 `deploy/monitoring/central/`（中央聚合栈）配套。本目录提供**跨集群通道**的信任资产，
> 不含中央聚合栈本身的清单（那些在上一级目录）。

## 1. 中央侧落地形态：由客户环境决定（**二选一**）

本项目**不自建**中央接收端（GSLB/自研采集均不采用）。中央侧只有两种落地形态：

| | 形态 A：客户既有 Prometheus | 形态 B：我方交付的中央栈 |
|---|---|---|
| 组件 | 客户环境已有的 Prometheus / 监控平台（自带 remote-write receiver） | `deploy/monitoring/central/`（中央 Prometheus + Alertmanager + 看板） |
| 部署动作 | **不部署我方 central 资产**；只需把我方中央资产中的看板/告警配置对接过去 | `kubectl apply -k deploy/monitoring/central` + Grafana 挂载数据源 + 导入看板 |
| remote_write 目标地址 | `https://<客户接收端>/api/v1/write` | `http(s)://prometheus-central.<中央命名空间>.svc.cluster.local:9090/api/v1/write` |
| 证书签发 | 由**客户 CA** 签发（我方发送侧持有其 CA） | 由我方/客户约定的 CA 签发，双方共用同一 CA |
| mTLS 终止位置 | 由客户接收端自身或其前置网关承担 | **Prometheus 原生不校验客户端证书 → 必须前置 mTLS 终止代理**（见 §2） |
| cluster 标签 | 仍由各集群 `external_labels.cluster` 附加（客户接收端需保留该标签） | 同左（中央 Prometheus 不重写标签） |
| 告警去重 | 需在客户 Alertmanager 侧按本文档 §4 口径配置 | 我方 central 的 alertmanager-central.yaml 已按该口径实现 |
| 启用步骤差异 | ① 客户侧开启 receiver 并提供 CA/端点 → ② 我方各集群填 URL + 证书 → ③ 客户侧配置看板/去重 | ① 部署 central 资产 → ② 配 mTLS 代理与 CA → ③ 各集群填 URL + 证书 → ④ 导入看板 |

> 无论哪种形态，**remote_write 的目标地址都必须按环境填写**（占位符
> `REPLACE_WITH_CENTRAL_WRITE_ENDPOINT`），我方资产中**不写死任何内网地址**。

## 2. 接收侧 mTLS：Prometheus 原生不校验客户端证书

`--web.enable-remote-write-receiver` 暴露的是**无鉴权**写入端点。因此形态 B 的生产部署必须：

1. 在中央 Prometheus 前置一个**做 mTLS 终止与客户端证书校验**的代理（网关/Envoy/Nginx 均可），
   只放行持有受信 CA 签发客户端证书的发送方；
2. Prometheus 仅监听集群内网，被代理以本地回环/内网地址访问；
3. 代理与 Prometheus 之间为明文内网（可接受，前提是同信任域、同节点/同网络域）。

**证书 Secret 引用示例**（发送侧与接收侧共用同一 CA）：

| 侧 | Secret | 键 | 消费方 |
|----|--------|-----|--------|
| 发送（各集群） | `otpmask-remote-write-mtls` | `ca.crt` / `tls.crt` / `tls.key` | `deploy/monitoring-overlays/remote-write-mtls`（Prometheus 挂载到 `/etc/prometheus/mtls`） |
| 接收（中央） | 由 mTLS 代理消费（`otpmask-remote-write-mtls-ca` 或等价） | `ca.crt` | 代理的客户端证书校验配置 |

模板：`deploy/monitoring-overlays/remote-write-mtls/secret-remote-write-mtls.example.yaml`
（**不在 resources 内，勿 apply**；真实证书由 KMS/cert-manager 签发注入，凭据禁止入库）。

## 3. 中央采集器的出站边界（默认拒绝 + 白名单放行）

`networkpolicy-central-collector-egress.yaml`：对带标签 `otpmask.io/role=central-collector`
的 Pod 施加**默认拒绝出站**，仅放行：

- DNS（kube-system 53）；
- 各集群的**导出端点端口**（gateway-core 8085 / tee-infer 19090），来源网段按集群逐条列出。

这是**跨集群审计采集**的网络边界（新增信任面收敛在中央侧，不触碰数据面既有策略）。
默认拒绝口径：未列入白名单的目标一律拒绝出站；白名单网段为空 → 该集群采集不可达。

> 说明：中央审计采集器（`otpmask.io/role=central-collector`）是**客户环境组件**，
> 我方不交付该组件本体；本策略按标签契约对其施加边界，标签不存在时策略自然空转。

## 4. 告警去重与 cluster 口径（与 central 栈一致）

见 `../README.md` 第 2、3 节（`cluster` 标签口径 + 三层去重）。形态 A 下，
客户侧 Alertmanager 需采用同一口径，否则会出现 N 集群重复轰炸。

## 5. 待环境就绪（本目录资产无法本机验证）

- ❌ 未做集群验证（本机无 K8s）：mTLS 代理选型与配置未实测；证书签发/注入未实测。
- ❌ 未验证 `REPLACE_WITH_CENTRAL_WRITE_ENDPOINT` 的连通性与证书 SAN 匹配。
- ❌ 未验证 NetworkPolicy 在客户实际 CNI 上的生效（部分 CNI 需额外开启）。
- ⚠️ 中央采集器本体（`otpmask.io/role=central-collector`）由客户环境提供，其身份与
  出站网段需与 §3 白名单核对。
