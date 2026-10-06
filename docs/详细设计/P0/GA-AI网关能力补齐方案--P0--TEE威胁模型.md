# GA-AI 网关能力补齐方案 -- P0 -- TEE 威胁模型（v0.1）

> **文档性质**：安全研究文档（P0 交付物之一 · **P0-5 威胁模型本体**）
> **所属阶段**：P0（轻量并行，不占关键路径）
> **模块编号**：P0-5
> **文档版本**：v0.7 · 2026-10-06（系统性评审修复 6 项：口径统一/DFD 增强/SLSA 路线/GAP 回填机制/资产分级判据/测试映射扩充）
> **修订依据**：《…多角色评审报告-第1轮.md》；《…-多角色评审报告-第2轮.md》；D-1（全文锚点统一）；A-1（GAP 立项：研发计划 P1-8）；P2/P3 余项 12 项全量收尾；**v0.7 系统性评审修复 6 项**（P0 口径统一 + P1 DFD 增强/SLSA 路线/GAP 回填机制 + P2 资产分级/测试映射）
> **基准依据**：
> - 《GA-AI 网关能力补齐方案》v5.5 §4.5（交付范围 §4.5.1、威胁范围 §4.5.2、工作量 §4.5.3）
> - 《GA-AI 网关能力补齐--研发计划与进度跟踪》v1.12 §3.6（任务分解）、§4.1（P1-8 安全加固）
> **当前状态**：🟡 v0.7（P0 阶段目标：明确威胁面 + 指导架构方向；完整安全白皮书 P1 M5 发布）
> **负责人**：待分配 | **设计评审人**：安全工程师 + 架构师
> **预估工作量**：1-2 人周（安全工程师 + 架构师各半）
> **计划起止**：W1 - W2
>
> **本体与效力（2026-10-06，v0.7 修订）**：本文是 P0-5 **威胁模型的口径唯一源**。同模块另两份交付物《GA-AI网关能力补齐方案--P0--安全白皮书大纲.md》《GA-AI网关能力补齐方案--P0--侧信道风险披露说明.md》为**下游交付物**，只引本文、不另立威胁口径。冲突以本文为准。**本文只给威胁事实与内部分级指引，不提供可照抄的对外话术**；对外表述逐字引用《…侧信道风险披露说明》§6/§7（C-3）。
>
> **对外可见性（P-3）**：§1/§2/§3/§11 的**摘要**可对外（须经《侧信道风险披露说明》口径）；**§5-§10 与 §12 附录仅内部**；对外材料引用须经安全+产品+法务会签。
>
> **调研基准说明**：本文所有"现状/已实现/未接线"判断，均以 **2026-10-05 仓库代码实测**为准，逐条附证据。**锚点统一采用 `文件:符号`；无法定位到单一符号者用 `文件`（不附行号，以抗漂移）**。凡"未找到实现"处**如实标注**，不做能力夸大（对齐主方案 §4.5「避免过度承诺」）。代码演进后须重新核对本文 §8-§10（第 1 轮评审发现并修订 3 处 P0 证据问题：F-1/F-2/F-3；第 2 轮元评审确认闭环，并完成全文锚点统一；v0.7 起按 §11.3.1 GAP 回填机制维护）。

---

## 目录

1. [结论速览（TL;DR）](#1-结论速览tldr)
2. [背景与范围](#2-背景与范围)
3. [方法论与参考标准](#3-方法论与参考标准)
4. [风险评级体系](#4-风险评级体系)
5. [系统描述与信任边界](#5-系统描述与信任边界)
6. [资产清单与分级](#6-资产清单与分级)
7. [攻击者模型与攻击面](#7-攻击者模型与攻击面)
8. [威胁清单（STRIDE + 攻击树）](#8-威胁清单stride--攻击树)
9. [现有缓解措施与验证状态](#9-现有缓解措施与验证状态)
10. [残余风险与已知差距（GAP）](#10-残余风险与已知差距gap)
11. [结论与后续工作](#11-结论与后续工作)
12. [附录](#12-附录)
13. [变更记录](#13-变更记录)

---

## 1. 结论速览（TL;DR）

> 本节供管理层与客户应答快速取用；详细论证见第 5-10 章。

| 问题 | 结论 |
|---|---|
| **保护什么** | ① 租户 prompt/response 明文；② 会话密钥与主密钥；③ 模型权重与推理过程；④ 审计证据；⑤ 租户隔离边界 |
| **防谁** | 云/宿主运维、同宿其他租户、外部网络攻击者、供应链篡改者、内部越权人员；**不含**物理接触与 CPU 微码级对手（见 §7.2） |
| **防到什么程度** | TEE 提供"**增强保护**"而非绝对安全；对宿主侧软件攻击有效，对**侧信道、故障注入、TEE 固件/微码漏洞**只能缓解、不能免疫 |
| **P0 阶段最强的安全事实** | 真 TDX 飞地**构造期 fail-closed、绝不静默降级 mock**（`enclave_tdx.go:NewTdxEnclave`）；信封加密 + 每租户独立密钥 + 哈希链审计 + 输入/输出双侧内容审查（TEE 内闭环） |
| **P0 阶段最大的差距** | ① 默认部署为 **mock 飞地**（`-enclave` 默认 mock）——**已由启动守卫收紧**（生产形态拒绝 mock，须显式 `-dev-mode`；GAP-01 ✅）；② **无真实远程证明验证**（`attest-verify` 未被任何运行服务引用，无 Intel DCAP/PCK 链校验）；③ **无硬件度量校验**（`Measure()` 为常量，不读 MRTD/RTMR）；④ `checkAdmin` 未配管理令牌时**放行**——**已由启动守卫收紧**（生产形态无令牌拒绝启动；GAP-05 ✅，仅显式 `-dev-mode` 放行）；⑤ 审计链写失败**只告警不阻断** |
| **对外表述口径（C-3 修订）** | 本文**仅作内部分级指引**：可对外表述"基于 Intel TDX 的机密计算增强保护 + 信封加密 + 国密合规路径"；**禁止**"绝对安全/不可攻破/防侧信道"等。**对外话术不在本文给出，逐字引用《侧信道风险披露说明》§6（禁止项见其 §7）** |
| **P0 待补项去向** | ① GAP-01/05（生产禁用 mock / 强制管理令牌）**已闭环**（启动守卫，见 §9.2/§10.2）；② 远程证明落地、硬件度量、审计 fail-closed、供应链签名（SLSA/SBOM）→ P1 白皮书与 P1-3 等保 / P1-5 密评协同；详见 §10.2 |

---

## 2. 背景与范围

### 2.1 背景

GA-AI 网关的**密态信封推理**是核心差异化能力（主方案 §1「差异化壁垒」）：数据面（Higress 明文域）只做路由与信封封装，**密码运算下沉至独立后端服务**，明文在 **TEE 飞地（Intel TDX）** 内解密、推理、输出审查。TEE 并非绝对安全——侧信道、故障注入、前向安全、TEE 固件漏洞均为业界公认攻击面。因此 P0 阶段必须**先梳理威胁模型**，既指导后续安全设计，也提前准备客户（尤其金融）应答素材（主方案 §4.5 优先级依据）。

### 2.2 P0 范围（in-scope）

| 维度 | 范围 |
|---|---|
| 系统范围 | 数据面（Higress + otpmask Wasm 插件）→ 密态信封 → TEE 飞地（tee-infer-service）→ 管理面（gateway-admin-service / gateway-core）；含密码后端（cryptop）、审计链、内容安全、计费计量 |
| 威胁范围 | 依主方案 §4.5.2：侧信道、前向安全/密钥泄露、供应链、熔断/故障注入（部分）、TEE 内代码安全 |
| 生命周期 | 构建-发布（供应链）→ 部署（机密计算运行时）→ 运行（证明/会话/推理）→ 运维（密钥轮换/审计/撤回） |
| 深度 | **威胁识别 + 现状对照 + 残余风险披露**；不含完整攻击树形式化验证与渗透结论（P1） |

### 2.3 明确不在 P0 范围（out-of-scope）

- 完整 STRIDE 形式化建模与攻击树量化（P1 M4）
- 渗透测试与第三方安全审计结论（P1 M5 / P2 M6-M9）
- 等保/密评正式差距分析与整改（P1-3、P1-5）
- 硬件级别的物理攻击、CPU 微码级对手、国家级供应链植入的**完整防御方案**（本文仅作**风险披露**）

### 2.4 与 P1 白皮书的关系

本文为**输入**：《安全白皮书大纲》（P0 交付物）以本文第 3-9 章为素材骨架；P1 M5 白皮书 v1.0 将本文"v0.1 初稿 + GAP 清单"补齐为完整 STRIDE、攻击树、渗透结论与验证证据。

### 2.5 术语与缩略语

| 术语 | 说明 |
|---|---|
| TEE | 可信执行环境（Trusted Execution Environment），本项目指 Intel TDX 可信域 |
| TDX / TD | Intel Trust Domain Extensions / 其隔离域 |
| RTMR / MRTD | TDX 运行时度量寄存器 / 初始度量（硬件完整性证据所在） |
| Quote | TDX 远程证明报告（由硬件签名，绑定 REPORTDATA） |
| 信封加密 | 数据面用会话密钥加密请求体，飞地内解密；密钥由 ECDH+HKDF 派生 |
| K_sig / K_enc | 会话签名密钥 / 会话加密密钥（`otpmask/session/v1` 域分离派生） |
| 飞地密封（Seal） | 用飞地绑定密钥加密后落盘，仅在相同飞地内可解（`Unseal`） |
| REPORTDATA（ReportData） | TDX Quote 的 64 字节绑定字段（**本文统一写作 REPORTDATA**，旧文 `ReportData` 同义）；本项目为 `H(nonce‖server_pub)` 前 32B |
| RFVM / RTMR | TDX 运行时可信度字段 / 运行时度量寄存器（硬件完整性证据；本投影用 MRTD/RTMR 表述） |
| MRTD | TD 初始度量（镜像/固件构建时测得） |
| STRIDE | 微软威胁建模分类法（见 §3.1） |
| CCF | Confidential Computing Consortium（机密计算联盟） |

### 2.6 与既有安全产物的关系

仓库内已存在两份相关产物，本文与之**互补、不取代**，边界如下（避免口径冲突）：

| 既有产物 | 范围 | 与本文关系 |
|---|---|---|
| `otp-mask-threat-model/otp-mask-threat-model.html`（2026-08-30） | **原语层**威胁模型：OTP-Mask 掩码、安全聚合（双掩码）、Paillier（对齐 Bonawitz CCS 2017 的 T1–T3），含 STRIDE 与威胁-缓解矩阵 | 该文为**原语层口径唯一源**，继续有效；本文聚焦**网关级 TEE 全栈**（信封/会话/租户隔离/审计/内容安全/供应链）。涉及 SecAgg/Paillier 原语威胁（如"解密指数时序侧信道"，其 TH-05）时**以该文为准**，本文仅作网关视角引用（§8.4 TG-I-09、§9.1）。 |
| `confidential-ai-gateway-whitepaper/confidential-ai-gateway-whitepaper.html` | **产品技术白皮书**：产品定位、总体架构、端到端加密链、多引擎矩阵、治理合规、路线图 | 属产品/技术方案，受众与目的不同于**安全白皮书**；本文配套的《P0--安全白皮书大纲》面向"安全能力与边界"白皮书。**对外安全表述口径统一以《P0--侧信道风险披露说明》为准**，与该产物如有冲突，以披露说明为准。 |

---

## 3. 方法论与参考标准

### 3.1 威胁建模方法论

采用**数据为中心 + 组件为中心**的混合方法（对齐 NIST SP 800-154 思路）：

```
① 资产识别（第 6 章） → ② 数据流/信任边界（第 5 章） → ③ 攻击者画像（第 7 章）
   → ④ STRIDE 逐类枚举（第 8.1-8.6） → ⑤ 关键攻击树（第 8.7） → ⑥ 风险评级（第 4 章）
   → ⑦ 缓解与验证状态（第 9 章） → ⑧ 残余风险/GAP（第 10 章）
```

- **STRIDE**：Spoofing / Tampering / Repudiation / Information Disclosure / Denial of Service / Elevation of Privilege，用于第 8 章逐类枚举；
- **攻击树（Schneier）**：对 4 个关键目标（窃取明文、窃取密钥、绕过内容审查、伪造证明）做 AND/OR 分解，用于第 8.7 章；
- **数据为中心（NIST SP 800-154）**：以"敏感数据生命周期"（进飞地→推理→出飞地→落审计）为主轴，避免只盯组件漏数据流。

### 3.2 参考标准与行业经验

| 参考 | 采用点 |
|---|---|
| **NIST SP 800-154** Data-Centric System Threat Modeling | 以数据生命周期为主轴建模 |
| **NIST SP 800-57** Key Management | 三级密钥/轮换/销毁的合规口径 |
| **NIST SP 800-193** Platform Firmware Resiliency | 供应链与固件韧性（保护/检测/恢复） |
| **IETF RFC 9334 (RATS)** Remote ATtestation procedureS | 远程证明的 Attester/Verifier/Relying Party 角色与证据链 |
| **Confidential Computing Consortium (CCC)** 威胁模型与技术分析 | 机密计算统一威胁分类（宿主、TEE 边界、侧信道） |
| **Intel TDX / SGX Threat Model**（Intel 官方） | TDX 信任边界、宿主能力假设、已知风险分级 |
| **AMD SEV-SNP 威胁模型** | 同类机密计算平台横向对照（多云中立性） |
| **Microsoft STRIDE + 攻击树** | 威胁枚举与攻击树方法 |
| **OWASP Top 10 for LLM Applications**（LLM01 提示注入 / LLM02 不当输出处理 / LLM06 敏感信息泄露 / LLM10 模型窃取） | 大模型特有威胁面 |
| **MITRE ATT&CK / CWE / CAPEC** | 攻击行为与弱点编号引用 |
| **GB/T 22239-2019（等保 2.0）** | 安全计算环境/审计/访问控制要求 |
| **GB/T 39786-2021（密码应用基本要求）** | 密评口径（密码算法/密钥/协议） |
| **GB/T 45654（生成式人工智能服务安全基本要求）** | 内容安全与备案口径（**标准号/年份以官方最新发布稿为准，对外引用前须核对**，C-1） |
| **GM/T 0054-2018（信息系统密码应用基本要求）** | 密评口径：密码模块与密钥管理（C-1 增补） |
| **《商用密码应用安全性评估管理办法》** | 密评合规依据（C-1 增补） |
| **GB/T 25069（信息安全技术 术语）** | 术语一致性（C-1 增补） |
| **SLSA / Sigstore(cosign) / SBOM(SPDX|CycloneDX)** | 供应链完整性行业实践 |
| **侧信道研究文献**（Foreshadow/SGAxe/Plundervolt/VoltPillager/ÆPIC Leak/RAMBleed/TDXDown/SMASH 等） | §8.4 侧信道威胁的业界已知案例支撑 |

> 说明：上表为标准**引用来源**，用于保证方法与国际/国内主流一致；本文不复制标准原文，仅按其框架组织本项目事实。

### 3.3 与主方案 §4.5.2 威胁范围对照

| 主方案 §4.5.2 类别 | 本文覆盖章节 | 覆盖度 |
|---|---|---|
| 侧信道攻击（时序/缓存/功耗） | §8.4 / §8.7 | 是（识别 + 缓解现状 + 专项披露） |
| 前向安全/密钥泄露 | §8.4 / §9.1 | 是 |
| 供应链风险 | §8.8 / §9.6 | 是 |
| 熔断/故障注入 | §8.5 / §8.4 | 部分（识别 + 已披露；防御措施 P2 评估） |
| TEE 内代码安全 | §8.2 / §8.6 | 是 |

### 3.4 隐私威胁建模（LINDDUN 摘要，S-3 补充）

本项目处理个人信息（AS-1：租户 prompt/response 可能含个人信息），除 STRIDE 外补充 **LINDDUN** 隐私威胁维度。**完整隐私影响评估（PIA）随 P1-3 等保/合规材料开展**，本节仅作摘要与现状对照：

| LINDDUN 维度 | 本项目相关点 | 现状控制 | 残余 |
|---|---|---|---|
| **L**inking 链接性 | 跨请求/跨租户关联同一主体 | 每租户独立密钥（`main.go:kmFor`）、审计出飞地脱敏（`guardrail.go:maskForLog`） | 低 |
| **I**dentifying 可识别性 | prompt 内直接标识符 | 输入侧 Guardrail PII 拦截/脱敏（`guardrail.go`） | 中（同形字/编码混淆未覆盖，见 §8.10） |
| **N**on-repudiation 不可否认性 | 用户否认/被否认 | 审计哈希链（§9.4）；对合规有利，对隐私需**最小化留存** | 中（留存 vs 删除权口径待明确，P2） |
| **D**etecting 可检测性 | 推断"某主体是否在用" | **无专门控制** | 中（残余风险，见 §10.1 RSK-09） |
| **D**isclosure 信息披露 | 明文/元数据泄露 | TEE 隔离 + 信封加密 + 日志脱敏（§9.1-9.3） | 低（侧信道另见 §8.4） |
| **U**nawareness 不知情 | 未告知处理目的/范围 | 属**产品隐私政策与告知流程**，不在技术威胁模型内 | — |
| **N**on-compliance 不合规 | 超范围/超期处理 | 留存期声明（`main.go:-audit-retention-days`）；删除权口径待明确 | 中 |

> 说明：LINDDUN 的"不知情/不合规"主要为**制度与流程**问题，技术侧仅提供支撑（脱敏、留存声明、可删除设计）。

**PIPL 条款映射（C-4 补充；条款号以正式文本为准）**

| 资产/场景 | PIPL 关注条款 | 现状 |
|---|---|---|
| AS-1 prompt/response 含个人信息 | 第 13（处理情形）/ 17（告知）/ 19（最小必要·最短留存） | 输入侧 PII 拦截 + TEE 内闭环 + 留存期声明 |
| 审计/日志留存 | 第 19（最短留存）/ 47（删除权） | 🟡 删除权口径待定（TG-R-04 / RSK-10） |
| 数据出境 | 第 38-43（出境） | 由部署形态决定；待 P1-3 明确 |

---

## 4. 风险评级体系

本文采用**严重度 × 可能性 = 风险等级**三档法（对齐 CVSS v3.1 定性映射，便于与行业沟通）：

### 4.1 严重度（Severity）

| 等级 | 定义 | CVSS 参考区间 |
|---|---|---|
| **严重 Critical** | 直接导致租户明文/主密钥泄露，或可伪造证明使信任基崩塌，或跨租户越权 | 9.0-10.0 |
| **高 High** | 导致单租户明文/会话密钥泄露、审计证据不可信、内容审查被绕过 | 7.0-8.9 |
| **中 Medium** | 造成信息部分泄露、服务可用性明显下降、需组合条件利用 | 4.0-6.9 |
| **低 Low** | 影响有限或需极高前置条件/物理接触 | 0.1-3.9 |

### 4.2 可能性（Likelihood）

| 等级 | 定义（面向本项目部署形态） |
|---|---|
| **高** | 攻击者仅需现有权限即可实施；或默认配置即暴露 |
| **中** | 需特定前置条件（如宿主 root、特定运行时、组合缺陷） |
| **低** | 需高级持续能力、物理接触、或未公开的硬件漏洞 |

### 4.3 风险等级矩阵

| | 可能性 高 | 可能性 中 | 可能性 低 |
|---|---|---|---|
| **严重** | 🔴 极高 | 🔴 高 | 🟠 中 |
| **高** | 🔴 高 | 🟠 中 | 🟡 低 |
| **中** | 🟠 中 | 🟡 低 | 🟢 极低 |
| **低** | 🟡 低 | 🟢 极低 | 🟢 极低 |

> **现状状态标记**：✅ 已实现并接线 ｜ 🟡 部分实现 ｜ ⚠️ 已实现但未接线/默认关闭 ｜ 🔴 未实现。

### 4.4 定级依据（抽样，A-3 补充）

> 45 条不逐条展开；下表抽样说明判定逻辑（严重度 / 可能性 → 风险），供复核与客户问询：

| 威胁 | 严重度理由 | 可能性理由 | 结论 |
|---|---|---|---|
| TG-S-04 伪租户 | 跨租户数据/密钥（严重） | 需可直连飞地（默认拓扑不成立）+ 飞地端不验签 | 🔴 高 |
| TG-T-07 镜像篡改 | 供应链植入可致窃密（严重） | `latest` 可变标签 + 无签名校验（现有权限即可利用） | 🔴 高 |
| TG-I-03 密封密钥泄露 | 离线解封全部密封数据（严重） | 需读环境变量/宿主文件（中） | 🔴 高 |
| TG-I-09 时序侧信道 | 逐步恢复密钥（高） | 需同宿共置 + 高精度计时（低） | 🟡 低 |
| TG-D-05 L2 降级滥用 | 全量 503（中） | 需打满侧车（中） | 🟠 中 |
| TG-E-06 冒充合规 | 合规风险（高） | 需误用 profile（低，且代码拒绝冒充） | 🟡 低 |

---

## 5. 系统描述与信任边界

### 5.1 组件与数据流（密态路径）

```
┌─────────────────── 明文域（不可信于租户数据）───────────────────┐
│  客户端 ──TLS/国密TLS──▶ Higress 数据面                          │
│                              │                                   │
│                     otpmask Wasm 插件                            │
│                     · 建立会话（ECDH+HKDF → K_sig/K_enc）        │
│                     · 信封封装（AES-256-GCM / SM4-GCM）          │
│                     · 路由决策（X-Otp-* 头）                     │
└──────────────────────────────┬───────────────────────────────────┘
                               │  密态信封（无明文）
┌──────────────────────────────▼─────── TEE 飞地（Intel TDX）──────┐
│  tee-infer-service                                               │
│  ① 会话校验（HMAC + 30s 防重放 + 64 槽计数器窗口）               │
│  ② 信封解密（方向子密钥，AAD 绑定会话/计数/端点）                │
│  ③ 输入侧内容审查 Guardrail（PII/注入/SQL，fail-closed）        │
│  ④ 推理（模型 Key 池轮询；request_key 按租户派生）              │
│  ⑤ 输出侧内容审查 OutputGuard（L1 内 + L2 侧车级联）            │
│  ⑥ 计量/配额（预占式原子计数）                                  │
│  ⑦ 审计链（SHA-256 哈希链 + WORM + TST 锚定）                  │
│  ⑧ 响应信封加密 → 下发                                         │
└──────────────────────────────┬───────────────────────────────────┘
                               │  审计/计量/配置（脱敏、安全导出）
┌──────────────────────────────▼─────────── 管理面 ─────────────────┐
│  gateway-admin-service：策略/变更/用量/账单/模型目录/安全中心     │
│  gateway-core：路由/限流/配额策略热下发（控制面）                │
│  gateway/attest-verify：证明验证器（独立，回环）                 │
│  gateway/audit-verify：审计链离线验证器                          │
│  密码后端 cryptop：intl / sm-software / sm-module                │
└──────────────────────────────────────────────────────────────────┘
```

**DFD 要素编号（S-1 补充：数据为中心，供 §8/§8.9 威胁定位）**

| 编号 | 类型 | 要素 | 说明 |
|---|---|---|---|
| **P-1** | 进程 | 客户端 | 发起密态推理、校验证明 |
| **P-2** | 进程 | Higress + otpmask 插件 | 会话/信封封装/路由（明文域） |
| **P-3** | 进程 | tee-infer-service | 飞地内解密/审查/推理/计量/审计 |
| **P-4** | 进程 | 管理面（admin/core） | 策略下发/变更/审计校验/账本 |
| **P-5** | 进程 | 密码后端 cryptop | intl / sm-software / sm-module |
| **DS-1** | 数据存储 | 飞地内存（会话密钥/明文） | 瞬时；进程退出即失 |
| **DS-2** | 数据存储 | 审计链落盘（WORM + 锚点） | 出飞地前脱敏 |
| **DS-3** | 数据存储 | 管理面账本/策略/凭据 | 哈希链 + 签名；凭据端点最小权限 |
| **TB-1..6** | 信任边界 | 见 §5.2 | 跨边界即威胁点 |

**数据流详表（v0.7 补充：方向 / 协议 / 端口 / 穿越边界 / 敏感度）**

| 编号 | 方向 | 协议 | 端口 | 穿越边界 | 敏感度 | 说明 |
|---|---|---|---|---|---|---|
| **DF-1** 会话握手（证明 + ECDH） | P-1 → P-3（双向） | HTTP/2 + gRPC（握手阶段） | 443（TLS 透传） | TB-1 + TB-2 | 高 | 客户端与飞地直接 ECDH 协商会话密钥；附带 Quote/证明校验；中间网关不可见密钥材料 |
| **DF-2** 密态信封（AEAD + 签名 + 计数器） | P-1 ↔ P-3（双向） | HTTP/2 + gRPC（数据阶段） | 443（经 P-2 透传/路由） | TB-2 | 严重（载荷密文） | 核心业务流；信封载荷 AES-GCM / SM4-GCM 加密 + HMAC-SHA256 / SM3-HMAC 签名 + 计数器防重放；P-2 仅做路由与 envelope header 解析，不解密 |
| **DF-3** 脱敏审计/计量/配置导出 | P-3 → P-4（单向出飞地） | HTTP/2 + gRPC（管理通道） | 9090（管理面内部） | TB-4 | 中（已脱敏） | 审计事件、计量数据、运行时遥测；出飞地前经脱敏过滤（`audit_filter.go`）；哈希链防篡改 |
| **DF-4** 控制面策略/配额下发 | P-4 → P-3（单向入飞地） | HTTP/2 + gRPC（管理通道） | 9090（管理面内部） | TB-4 | 高 | 策略配置、租户配额、路由规则、模型列表；JWT 鉴权 + 签名校验；注入失败按 fail-closed 处理 |
| **DF-5** 输出侧 L2 分类器 HTTP | P-3 → 侧车/外部（单向出飞地） | HTTP/1.1（REST） | 8080（输出侧内部） | TB-3（跨宿主侧车） | 严重（明文） | **TG-I-12 已知风险**：输出侧 L2 分类器以明文形式出飞地；仅限输出分类服务使用，不回传客户端；侧车与飞地同宿主，走本地回环 |
| **DF-6** 密码运算调用（补充） | P-3 → P-5（请求）+ P-5 → P-3（响应） | Unix Domain Socket / gRPC（本地侧车） | UDS 或 localhost:9100 | 无（同宿主同 TB-3 内） | 高（密钥句柄） | 飞地向密码侧车请求对称加密/哈希/签名；密钥不离开 cryptop 进程；句柄传递 |

### 5.2 信任边界（Trust Boundaries）

| 边界 | 说明 | 跨越机制 | 关键控制 |
|---|---|---|---|
| **TB-1** 客户端 ↔ 数据面 | 公网/不可信网络 | TLS / 国密 TLS | 鉴权（JWT）、限流 |
| **TB-2** 数据面 ↔ TEE 飞地 | 项目核心边界 | 密态信封（AEAD）+ HMAC 签名 + 防重放 | 会话密钥、计数器窗口、fail-closed 503 |
| **TB-3** TEE 飞地 ↔ 宿主 OS | 机密计算信任边界 | TDX 硬件隔离 | 依赖 TDX 与运行时；**侧信道/故障注入为已知残余风险** |
| **TB-4** TEE 飞地 ↔ 管理面 | 数据出飞地 | 脱敏审计/计量/配置通道 | 审计出飞地脱敏、独立验证器 |
| **TB-5** 管理面 ↔ 运维人员 | 人工操作边界 | JWT（admin/auditor）+ 白名单 | RBAC、凭据最小权限、审计 |
| **TB-6** 构建/发布 ↔ 运行时 | 供应链边界 | 镜像/Chart | 镜像固定、安全上下文（**现状见 §10 GAP**） |

### 5.3 信任假设与信任根

| 编号 | 假设 | 现状与依据 | 若不成立的后果 |
|---|---|---|---|
| **A-1** | TDX 硬件与微码可信，硬件隔离有效 | 依赖 Intel TDX；**未做硬件度量校验**（`Measure()` 返回常量） | 信任基失效，需重新评估 |
| **A-2** | 飞地加载的代码即预期代码 | 真 TDX 构造期 fail-closed（`enclave_tdx.go:NewTdxEnclave`）；但**无 RTMR 校验**、无镜像签名校验 | 供应链篡改不可检 |
| **A-3** | 会话密钥仅存在于飞地内存 | ECDH+HKDF 派生（`session.go`），会话 TTL 5min 且销毁时零化（best-effort，Go GC 不可控） | 会话密钥泄露 → 单会话明文泄露 |
| **A-4** | 密封密钥不落明文 | mock：环境变量或随机；TDX：环境变量 `OTPMASK_TDX_SEAL_KEY`（**非 TDX 派生**） | 密封数据可被离线解封 |
| **A-5** | 宿主无法读取飞地内存 | TDX 语义保证；但宿主可**观测资源用量/时序**（侧信道前提） | 下降为侧信道风险（§8.4） |
| **A-6** | 管理令牌未泄露 | HS256 对称密钥（`auth-service/jwt.go`） | 令牌伪造 → 管理面横向移动 |

### 5.4 部署形态与运行时假设

| 形态 | 配置 | 现状 |
|---|---|---|
| 默认/开发（启动参数） | `-enclave` 默认 `mock`（`main.go:-enclave`）；**生产形态下 mock 触发启动守卫拒绝启动**（`startup_guard.go:validateStartupSecurity`，`main.go:validateStartupSecurity`；GAP-01 ✅） | 🟡 已加**启动守卫**；开发/CI 须**显式 `-dev-mode`**（默认 false）方可放行 |
| 默认/开发（k8s 清单） | `ENCLAVE_MODE=mock` + 显式 `-dev-mode`（`deploy/tee/base/tee-infer-service.yaml`） | 🟡 base 定位为开发/CI；生产 overlay 须**移除 `-dev-mode` 并配置 `-admin-token`**（F-6） |
| TDX 生产 overlay | `deploy/tee/overlays/gn8v-tee`：`ENCLAVE_MODE=tdx` + 节点标签 | 🟡 配置在；但**继承 base 的 `-dev-mode`**（生产须移除）、**未配 Confidential Containers/Kata runtimeClass**，Trustee/OPA 仅注释 |
| NVIDIA CC overlay | `deploy/tee/overlays/nvidia-cc`：`ENCLAVE_MODE=sgx` | 🔴 **与实现不一致**：`newPlatformEnclave` 无 sgx 分支，会启动即 Fatal |

---

## 6. 资产清单与分级

### 6.0 资产分级判据（v0.7 补充）

资产敏感度按 **机密性、完整性、可用性** 三维度的最高影响定级，参考等保三级与金融行业信息分级标准：

| 等级 | 代号 | 机密性影响 | 完整性影响 | 可用性影响 | 典型资产举例 |
|---|---|---|---|---|---|
| **严重** | S | 泄露导致重大法律/合规风险（触犯 PIPL / 数据安全法 / 刑法）；核心密钥泄露；全部租户数据可解密 | 篡改导致系统信任基崩塌；全局安全策略被替换；审计链失效不可恢复 | 不可用导致核心业务全停、影响全部租户 | 会话密钥、主密钥、密封密钥、用户明文数据 |
| **高** | H | 泄露导致重大经济损失或严重声誉影响；单租户全量数据泄露；API Key 泄露导致越权调用 | 篡改导致单租户数据不可信、计费异常、模型输出异常；策略篡改可被检测 | 不可用导致关键业务大面积降级、影响多数租户 | 模型权重、API Key、审计链、管理令牌、控制面策略 |
| **中** | M | 泄露导致一定经济损失或有限声誉影响；脱敏数据泄露；非核心配置泄露 | 篡改导致体验下降、部分功能异常；可快速回滚恢复 | 不可用导致非关键功能降级、影响少数租户 | 内容安全策略、计量账本、非核心配置 |
| **低** | L | 泄露影响可忽略；公开信息 | 篡改影响有限、可即时回滚 | 短时不可用无实质影响 | 公开文档、非敏感监控指标 |

> **定级规则**：① 三维度取最高级；② 涉及个人信息（PIPL）直接不低于「高」；③ 涉及密钥材料直接不低于「严重」；④ 等保三级核心资产不低于「高」。

### 6.1 资产清单

| ID | 资产 | 位置 | 敏感度 | 合规关注 |
|---|---|---|---|---|
| **AS-1** | 租户 prompt / response 明文 | TEE 飞地内存（瞬时） | 严重 | 个人信息保护法、GB/T 45654 |
| **AS-2** | 会话密钥 K_sig / K_enc | 飞地内存 | 严重 | GB/T 39786 密钥管理 |
| **AS-3** | 主密钥 / 每租户请求密钥 | 飞地内存（`teecore/keymgmt.go`） | 严重 | 三级密钥体系 |
| **AS-4** | 飞地密封密钥 | 环境变量 + 内存（`enclave*.go`） | 严重 | — |
| **AS-5** | 模型权重与推理过程 | 飞地 / 上游模型服务 | 高 | 模型知识产权（OWASP LLM10） |
| **AS-6** | 服务商 API Key / 端点凭据 | Key 池（`model/keypool.go`）、凭据端点（`credential_endpoint.go`） | 高 | 凭据最小权限 |
| **AS-7** | 审计链证据（哈希链 + WORM + TST） | 飞地落盘 + 管理面 | 高 | 等保审计要求 |
| **AS-8** | 内容安全策略与复核台账 | `policy/*`（只读随镜像） | 中 | GB/T 45654 |
| **AS-9** | 计量/计费账本 | 管理面（哈希链 + 签名） | 中 | 计费完整性 |
| **AS-10** | 管理面令牌与 RBAC 配置 | 管理面 | 高 | 等保访问控制 |
| **AS-11** | 控制面策略与配置资产（路由表 / 限流 / 配额 / Guardrail 策略 / 模型目录） | 管理面 + 数据面（`gateway-core`、`policy/*`） | 高 | 配置完整性、等保（篡改即改变安全行为）（S-4 补充） |

### 6.2 资产-组件-威胁映射（摘要）

| 资产 | 主要承载组件 | 主要威胁 |
|---|---|---|
| AS-1 | tee-infer `handleInfer` | TG-I-01/02、TG-I-10（侧信道） |
| AS-2/03/04 | `session.go` / `teecore/keymgmt.go` / `enclave*.go` | TG-I-03/04、TG-T-01、TG-E-01 |
| AS-5 | 上游模型 / 飞地 | TG-I-05（模型窃取）、TG-E-02 |
| AS-6 | `keypool.go` / `credential_endpoint.go` | TG-I-06、TG-E-03 |
| AS-7 | `audit.go` / `audit-verify/` | TG-T-03、TG-R-01 |
| AS-9 | admin/billing | TG-T-04 |
| AS-10 | `auth.go` / `credential_endpoint.go` | TG-S-01、TG-E-04 |
| AS-11 | `gateway-core` / `policy/*` / `outputguard_policy*` | TG-T-05、TG-T-06 |

---

## 7. 攻击者模型与攻击面

### 7.1 攻击者画像

| ID | 攻击者 | 已有能力（假设） | 目标 | 适用边界 |
|---|---|---|---|---|
| **MAL-1** 恶意租户 | 合法租户账号 | 可提交任意 prompt、可观察自身延迟/错误 | 越权读他租户数据、绕过内容审查、耗尽配额 | TB-1/TB-2 |
| **MAL-2** 云/宿主运维 | 宿主 root（无 TDX 硬件密钥） | 读宿主内存、改配置、启停进程、观测资源 | 窃取飞地明文/密钥、伪造响应 | TB-3 |
| **MAL-3** 同宿其他租户 | 同物理宿主上的其他租户 | 共享硬件资源、可做资源竞争/侧信道观测 | 推断他人明文/密钥 | TB-3 |
| **MAL-4** 外部网络攻击者 | 无内网权限 | 扫描、注入、重放、DoS | 绕过鉴权、重放请求、DoS | TB-1 |
| **MAL-5** 供应链攻击者 | 篡改镜像/依赖/固件的能力 | 发布期植入 | 植入后门、绕过审查、窃密 | TB-6 |
| **MAL-6** 内部越权人员 | 有限管理面权限 | 调用 API、读审计/计量 | 越权读数据、删改审计 | TB-4/TB-5 |
| **MAL-7** 物理接触者 | 物理访问主机 | 冷启动、探针、故障注入 | 提取密钥、篡改固件 | 物理层 |

### 7.2 能力假设边界

- **在范围内**：宿主软件栈攻击（MAL-2）、侧信道观测（MAL-3）、协议/应用层攻击（MAL-1/4）、供应链篡改（MAL-5）、内部越权（MAL-6）。
- **部分在范围内（仅披露 + 缓解）**：故障注入（电压/时钟/DDR）（MAL-7）、TEE 固件/微码漏洞（MAL-5/7）——防御措施 P2 评估（主方案 §4.5.2「熔断/故障注入＝部分」）。
- **不在范围内（明确不承诺，见《侧信道风险披露说明》）**：国家级供应链植入、物理层全谱攻击、CPU 微码级对手的完整防御。

### 7.3 攻击面（入口点清单）

| 入口 | 位置 | 攻击者 | 备注 |
|---|---|---|---|
| 密态推理 API `/infer` | `main.go:handleInfer` | MAL-1/4 | 解密后明文经 Guardrail（`main.go:guard.check` `guard.check`） |
| 会话握手 `/attest` + `/attest/complete` | `main.go:handleAttest`/`handleAttestComplete` | MAL-2/4 | 证明与 ECDH 派生 |
| 密钥签发 `/key/issue` | `main.go:handleKeyIssue` | MAL-1/2 | 按租户 KeyManager（`main.go:kmFor`） |
| 管理/计量 API | `main.go:checkAdmin`/`checkMetering` | MAL-6 | 管理令牌校验 |
| 审计导出/查询 | `admin/audit.go`、`sec_center.go` | MAL-6 | 链校验/导出 |
| 凭据端点 | `credential_endpoint.go` | MAL-6 | 每集独立令牌 |
| 控制面策略下发 | `gateway-core` → tee-infer | MAL-5/6 | HMAC 规范编码签名（`mcpsec/model.go`） |
| 镜像/Chart 供应链 | `deploy/*`、`Dockerfile` | MAL-5 | 见 §9.6、§10 GAP |

---

## 8. 威胁清单（STRIDE + 攻击树）

> 编号规则：`TG-<STRIDE 字母>-<序号>`；严重度/可能性/风险依第 4 章。**状态**列反映 2026-10-05 代码实测。

### 8.1 Spoofing（仿冒）

| 编号 | 威胁 | 攻击者 | 前置条件 | 影响 | 严重度 | 可能性 | 风险 | 状态 |
|---|---|---|---|---|---|---|---|---|
| **TG-S-01** | 伪造管理面 JWT 访问管理 API | MAL-6 | HS256 对称密钥泄露 | 越权操作/读审计 | 高 | 中 | 🟠 中 | 🟡 HS256 且签发/校验共享密钥（`auth-service/jwt.go`），`exp` 必填、常量时间比对 |
| **TG-S-02** | 伪造飞地身份（伪服务端）骗取会话密钥 | MAL-2/4 | 客户端不校验证明 | 中间人窃取明文 | 严重 | 中 | 🔴 高 | 🟡 插件校验 nonce 回显 + `report_data==H(nonce‖server_pub)` + app_hash + 签名（`wasm/otpmask-plugin/attest.go:verifyPluginProof`）；但**证明根为 mock 自签**（真机 DCAP 链未接入） |
| **TG-S-03** | 重放历史证明获取会话 | MAL-4 | 无 nonce 新鲜性校验 | 建立伪会话 | 高 | 低 | 🟡 低 | ✅ Quote 绑定 `nonce‖pub`，`attest-verify` 校验 report_data（`verifier.go:VerifyQuote`）；但服务端未接线 |
| **TG-S-04** | 伪造租户身份（`X-Tenant-ID` 头）越租户 | MAL-1/2 | 可直连飞地绕过网关 | 跨租户数据/密钥 | 严重 | 中 | 🔴 高 | 🔴 tee-infer 直接信任 `X-Tenant-ID`（`main.go:tenantOf`），**不验 JWT**；隔离依赖上游网关 |
| **TG-S-05** | 凭据端点令牌冒用 | MAL-6 | 令牌泄露 | 读取服务商凭据 | 高 | 低 | 🟡 低 | ✅ 每凭据集独立读令牌（`credential_endpoint.go`） |

### 8.2 Tampering（篡改）

| 编号 | 威胁 | 攻击者 | 前置条件 | 影响 | 严重度 | 可能性 | 风险 | 状态 |
|---|---|---|---|---|---|---|---|---|
| **TG-T-01** | 宿主篡改飞地内存 | MAL-2 | TDX 硬件失效/微码漏洞 | 明文/密钥泄露或结果篡改 | 严重 | 低 | 🟠 中 | 🟡 依赖 TDX；无硬件度量校验 |
| **TG-T-02** | 篡改在途请求/响应 | MAL-2/4 | 无 AEAD/无签名 | 结果污染 | 高 | 低 | 🟡 低 | ✅ AEAD 信封 + HMAC 签名 + AAD 绑定（求值 `cryptoops/envelope.go:SealEnvelope`/`OpenEnvelope`；nonce/AAD `protocol/go/envelope.go:EnvelopeNonce`/`EnvelopeAAD`；签名 `cryptoops/sign.go:SignRequest`/`VerifyResponse`）（F-2 修订） |
| **TG-T-03** | 篡改/删除审计记录 | MAL-6 | 有写权限 | 抵赖、掩盖攻击 | 高 | 中 | 🟠 中 | 🟡 哈希链 + WORM + 链校验（`audit.go`）；但**写失败只告警不阻断**（`audit.go`），非真 WORM |
| **TG-T-04** | 篡改计量/账本 | MAL-6 | 有写权限 | 计费失真 | 中 | 中 | 🟡 低 | ✅ 账本哈希链 + HMAC 签名 + 追加触发器（`billing/ledger.go`、`signature.go`） |
| **TG-T-05** | 篡改内容安全策略绕过审查 | MAL-5 | 发布期篡改 | 违规内容放行 | 高 | 低 | 🟡 低 | ✅ 策略复核台账（提交人≠复核人、覆盖数一致、失败拒加载，`outputguard_review_ledger.go`） |
| **TG-T-06** | 篡改控制面策略下发 | MAL-5/6 | 中间人 | 路由/限流被改 | 高 | 低 | 🟡 低 | ✅ HMAC 规范编码签名（`mcpsec/model.go`） |
| **TG-T-07** | 篡改镜像/依赖（发布期植入） | MAL-5 | 供应链权限 | 后门/窃密 | 严重 | 中 | 🔴 高 | 🔴 镜像用 `latest` 可变标签、无 digest 固定、无签名/SBOM（`deploy/helm/otpmask/values.yaml`） |

### 8.3 Repudiation（抵赖）

| 编号 | 威胁 | 攻击者 | 前置条件 | 影响 | 严重度 | 可能性 | 风险 | 状态 |
|---|---|---|---|---|---|---|---|---|
| **TG-R-01** | 否认发起过请求 | MAL-1 | 无不可抵赖证据 | 纠纷无法举证 | 中 | 中 | 🟡 低 | 🟡 审计链含请求 ID/签名（`protocol.go`），但**TST 为 mock 自签**（`tsa.go:MockTSA`），外部时间不可信 |
| **TG-R-02** | 运维否认改过配置 | MAL-6 | 管理面无审计 | 追责困难 | 中 | 中 | 🟡 低 | ✅ 管理面变更有变更记录 + 审计链（`change.go`、`admin/audit.go`） |
| **TG-R-03** | 审计链被截断而不被察觉 | MAL-6 | 有落盘写权限 | 隐瞒攻击窗口 | 高 | 低 | 🟡 低 | ✅ 离线验证器检测篡改与**截断**（`audit-verify/verifier.go`）+ 锚定比对 |
| **TG-R-04** | 数据留存与删除权冲突：审计 WORM 不可删 vs PIPL 删除请求 | MAL-1（数据主体）/内部 | 无删除通道 | 合规争议、无法举证已删除 | 中 | 中 | 🟡 低 | 🟡 留存期声明（`main.go:-audit-retention-days`）；**删除权口径未定**（见 §10.1 RSK-10）（S-5 补充） |

### 8.4 Information Disclosure（信息泄露，含侧信道）

> ⚠️ 本节与《侧信道风险披露说明》互为引用；对外表述以那份为准。

| 编号 | 威胁 | 攻击者 | 前置条件 | 影响 | 严重度 | 可能性 | 风险 | 状态 |
|---|---|---|---|---|---|---|---|---|
| **TG-I-01** | 宿主读飞地明文内存 | MAL-2 | TDX 正常工作时**不可** | 严重泄露 | 严重 | 低 | 🟠 中 | ✅ TDX 硬件隔离（真机）；mock 模式**不成立** |
| **TG-I-02** | 内存残留/未零化 | MAL-2 | 内存复用 | 泄露会话密钥/明文 | 高 | 中 | 🟠 中 | 🟡 提供零化函数（`session.go`、`cipher/mask:Zeroize`）；**Go GC 下不可控**（如实声明） |
| **TG-I-03** | 密封密钥泄露 → 离线解封密封数据 | MAL-2/5/7 | 读取环境变量/宿主文件 | 解封密钥/状态 | 严重 | 中 | 🔴 高 | ⚠️ TDX 密封密钥来自环境变量（`enclave_tdx.go:tdxSealKeyEnv`），**非 TDX 派生**；mock 可随机 |
| **TG-I-04** | 密钥轮换不及时导致旧钥可用 | MAL-2 | 无前向安全 | 历史会话可解 | 高 | 低 | 🟡 低 | ✅ 主密钥 TTL 5min 轮换 + InFlightWindow 30s + 旧钥 wipe（`teecore/keymgmt.go`） |
| **TG-I-05** | 模型权重/提示词被窃取 | MAL-1/2 | 越权访问 | 知识产权损失（OWASP LLM10） | 高 | 低 | 🟡 低 | 🟡 凭据最小权限 + Key 池指纹；无模型水印/防盗用 |
| **TG-I-06** | 服务商凭据泄露（明文落盘/日志） | MAL-2/6 | 权限过宽/日志 | 上游账号被盗 | 高 | 低 | 🟡 低 | ✅ 凭据端点字段白名单 + 文件权限校验 + fail-closed 503（`credential_endpoint.go`）；Key 池仅落指纹（`keypool.go`） |
| **TG-I-07** | 审计/日志泄露原文 | MAL-6 | 导出未脱敏 | 明文出飞地 | 高 | 低 | 🟡 低 | ✅ `maskForLog` 零原文 + `snapshot` 最小披露（`guardrail.go:snapshot`/`maskForLog`）；管理面日志脱敏 |
| **TG-I-08** | 缓存侧信道：以命中延迟推断内容 | MAL-3 | 缓存开启、可反复计时 | 推断他租户缓存命中 | 中 | 中 | 🟠 中 | ✅ 命中/未命中路径同分布随机延迟抖动（见 P0-2 详设 §7.3；主方案 §4.2 R10） |
| **TG-I-09** | 时序侧信道：以执行时长推断密钥/数据 | MAL-3 | 同宿共置、可高精度计时 | 逐步恢复密钥 | 高 | 低 | 🟡 低 | 🟡 常数时间优先原则 + 随机抖动；**Paillier 模幂不保证常数时间**（`cipher/paillier/paillier.go`，依赖可信硬件独占环境） |
| **TG-I-10** | 微架构侧信道（Spectre/缓存类） | MAL-3 | 同宿共置 | 跨域推断 | 高 | 低 | 🟡 低 | ⚠️ 依赖 TDX 对微架构攻击的缓解；**无额外应用层防护/无 SMT 控制配置**，仅作披露 |
| **TG-I-11** | 功耗/电磁侧信道 | MAL-7 | 物理接触 | 提取密钥 | 高 | 低 | 🟡 低 | ⚠️ 不在软件层防护范围；披露为已知边界 |
| **TG-I-12** | 输出侧 L2 分类器在 TEE 外，明文经侧车 | MAL-2/3 | 侧车被侵入/旁路 | 明文泄露 | 高 | 中 | 🟠 中 | 🟡 L2 侧车 CIDR 白名单 + 禁重定向/代理 + 解析后按 IP 直连（`outputguard.go:newL2HTTPTransport`）；**被审明文离开飞地**为设计取舍 |

### 8.5 Denial of Service（拒绝服务）

| 编号 | 威胁 | 攻击者 | 前置条件 | 影响 | 严重度 | 可能性 | 风险 | 状态 |
|---|---|---|---|---|---|---|---|---|
| **TG-D-01** | 宿主停止飞地进程 | MAL-2 | 宿主权限 | 服务中断 | 高 | 中 | 🟠 中 | 🟡 fail-closed 503（`main.go:handleHealthz`）；无异地多活/自动切主（P2 多集群） |
| **TG-D-02** | 飞地资源耗尽（内存/CPU） | MAL-1 | 大量请求 | 影响他租户 | 中 | 中 | 🟠 中 | 🟡 配额预占 + 429；无 CPU 级隔离上限细化 |
| **TG-D-03** | 超长/畸形输入触发 OOM/panic | MAL-1/4 | 无长度上限 | 飞地崩溃 | 高 | 中 | 🟠 中 | ✅ 向量/消息长度上限（`protocol/go/protocol.go:maxVectorDim`/`maxMessageLen`）+ 请求体大小限制（`bodylimit_test.go`） |
| **TG-D-04** | 聚合协议无限并发耗尽 | MAL-5/内部 | 调用 SecAgg | 资源耗尽 | 中 | 低 | 🟡 低 | 🔴 `DefaultMaxConcurrency=0`（**无限并发**，`secagg/aggregator.go:DefaultMaxConcurrency`）——需部署侧限流 |
| **TG-D-05** | 内容审查降级被滥用（fail-closed 触发） | MAL-1 | 打满 L2 侧车 | 全量 503 | 中 | 中 | 🟠 中 | ✅ 降级 fail-closed **不回退 L1 重判**（`outputguard.go`）；高可用需侧车多副本 |

### 8.6 Elevation of Privilege（提权）

| 编号 | 威胁 | 攻击者 | 前置条件 | 影响 | 严重度 | 可能性 | 风险 | 状态 |
|---|---|---|---|---|---|---|---|---|
| **TG-E-01** | 通过不可信输入触发飞地内漏洞提权 | MAL-1/2 | 输入解析缺陷 | 控制飞地 | 严重 | 中 | 🔴 高 | 🟡 边界检查 + fuzz（`paillier_fuzz_test.go` 等）；无系统化 TEE 入口 fuzz |
| **TG-E-02** | 逃逸飞地访问宿主/他租户 | MAL-1 | TEE 漏洞 | 跨域 | 严重 | 低 | 🟠 中 | ⚠️ 依赖 TDX；无 Confidential Containers 运行时强化配置（§5.4） |
| **TG-E-03** | 越权读取服务商凭据 | MAL-6 | 令牌/权限缺陷 | 上游账号被盗 | 高 | 低 | 🟡 低 | ✅ 每集独立令牌 + 跨集合 401（`credential_endpoint.go`） |
| **TG-E-04** | `checkAdmin` 未配令牌时放行 | MAL-1/4 | 显式 `-dev-mode`（生产形态已被启动守卫拦截） | 裸奔读写管理端点 | 严重 | 低 | 🟡 低 | 🟡 `main.go:checkAdmin` 无令牌仍返回 true；但**生产形态已由启动守卫 fail-closed**（`startup_guard.go:validateStartupSecurity`，GAP-05 ✅），仅显式 `-dev-mode` 放行（F-3 修订） |
| **TG-E-05** | 聚合器恶意敌手控制聚合结果 | MAL-5/内部 | 参与恶意方 | 污染聚合 | 中 | 低 | 🟡 低 | ✅ 身份签名校验 + 可信密钥表 + 种子承诺校验（`secagg/aggregator.go`） |
| **TG-E-06** | 认证密码模块未达标冒充合规 | 内部 | 误用 profile | 合规风险 | 高 | 低 | 🟡 低 | ✅ `sm-module` 返回 `ErrNotImplemented`，**绝不回退软件实现冒充合规**（`cryptop/provider.go:ErrNotImplemented`） |

### 8.7 关键攻击树

> 记法：`AND`＝全部子目标达成才成功；`OR`＝任一子目标达成即成功；🛡️＝该节点已有控制。

**AT-1 窃取租户明文（目标：读取 AS-1）**

```
AT-1 窃取明文
├─ OR 从宿主侧读飞地内存
│   ├─ AND 攻破 TDX 隔离  ← 需要硬件漏洞/微码后门（🛡️ A-1 依赖，低可能性）
│   └─ OR 使飞地降级为 mock  ← 生产配置漏配 ENCLAVE_MODE（🔴 需治理，见 GAP-01）
├─ OR 从在途信封窃取
│   ├─ AND 获得 K_enc  ← 需攻破 ECDH/飞地（🛡️ session.go）
│   └─ AND 破解 AEAD  ← 不现实（🛡️ AES-256-GCM/SM4-GCM）
├─ OR 从输出侧 TEE 外明文窃取  ← L2 侧车路径（TG-I-12，🟡 部分缓解）
└─ OR 侧信道推断  ← 见 AT-3
```

**AT-2 窃取密钥（目标：AS-2/03/04）**

```
AT-2 窃取密钥
├─ OR 读环境变量获取密封密钥  ← TG-I-03（🔴 OTPMASK_TDX_SEAL_KEY 非 TDX 派生）
├─ OR 读飞地内存  ← 需攻破 TDX（低）
├─ OR 侧信道恢复  ← TG-I-09/10/11（🟡 部分缓解）
├─ OR 读取落盘密封文件 + 泄露的密封密钥  ← AND 组合（🔴 组合即成功）
└─ OR 伪造管理令牌后走密钥签发  ← TG-S-01/S-04（🟡/🔴）
```

**AT-3 绕过内容审查（目标：放行违规/注入内容）**

```
AT-3 绕过审查
├─ OR 输入侧编码混淆（同形字/全角/空白/零宽）  ← 🟡 normalize 全角+去空白（guardrail.go:normalize）；同形字未覆盖（guardrail.go）
├─ OR 篡改策略资产  ← 🛡️ 复核台账 + 只读随镜像（TG-T-05，低）
├─ OR 打满 L2 触发降级  ← 🛡️ fail-closed（不回退 L1，TG-D-05）
└─ OR 利用输出侧跨帧/分片规避  ← 🛡️ 级联单出口 + 槽位状态机（outputguard_cascade.go）
```

**AT-4 伪造证明（目标：让客户端信任伪服务端）**

```
AT-4 伪造证明
├─ OR 自签证明冒充  ← 🛡️ 客户端校验 report_data/app_hash/签名（attest.go:verifyPluginProof）
│      └─ 但根信任为 mock 自签（🟡 真机 DCAP 链未接入 → 现有"验证"只是自洽校验）
├─ OR 重放旧 Quote  ← 🛡️ nonce 新鲜性（Quote 绑定 nonce‖pub）
└─ OR 攻破验证器白名单为空 → 全拒（🛡️ NewAllowlist 空=拒绝一切，verifier.go:NewAllowlist）
```

**攻击树期望成本（EO）摘要（A-4 补充）**

| 攻击树 | 目标 | 主要成本/难度 | EO 定性 |
|---|---|---|---|
| AT-1 窃明文 | AS-1 | 硬件漏洞（高）或配置漏配（低，已由守卫收紧）；在途信封不可破 | 高成本为主 / 降级路径低成本但已封堵 |
| AT-2 窃密钥 | AS-2/03/04 | 读环境变量（低）/ 攻破 TDX（高） | **中偏低**（密封密钥为其最薄弱路径，TG-I-03） |
| AT-3 绕审查 | 策略绕过 | 同形字/编码混淆构造（低）+ 打满侧车（中） | 低-中 |
| AT-4 伪造证明 | 客户端信任 | 破 ECDH/签名（高）或破白名单（不可能） | 中（真机 DCAP 未接入，见 GAP-02） |

### 8.8 供应链与部署威胁（补充分类）

| 编号 | 威胁 | 攻击者 | 影响 | 严重度 | 可能性 | 风险 | 状态 |
|---|---|---|---|---|---|---|---|
| **TG-SC-01** | 镜像用可变标签被替换 | MAL-5 | 植入后门 | 严重 | 中 | 🔴 高 | 🔴 镜像 `otpmask/tee-infer-service:latest`（`deploy/helm/otpmask/values.yaml`：`tag: latest`），无 digest 固定（F-4 修订） |
| **TG-SC-02** | 无镜像签名/SBOM 校验 | MAL-5 | 不可检 | 严重 | 中 | 🔴 高 | 🔴 未找到 cosign/SLSA/SBOM 步骤 |
| **TG-SC-03** | 部署 secret 硬编码示例密钥 | MAL-5/6 | 默认凭据 | 高 | 中 | 🟠 中 | 🔴 `deploy/tee/base/secret.yaml` 明文示例 |
| **TG-SC-04** | TEE 固件/BIOS 供应链 | MAL-5/7 | 信任基污染 | 严重 | 低 | 🟠 中 | ⚠️ 依赖 Intel/云厂商；无 NIST SP 800-193 式固件韧性校验 |
| **TG-SC-05** | 无机密计算运行时（CC/Kata）配置 | 运维 | 隔离弱化 | 高 | 中 | 🟠 中 | 🔴 overlay 仅 nodeSelector/tolerations，无 `runtimeClassName` |
| **TG-SC-06** | overlay 与实现不一致（sgx） | 运维 | 启动即 Fatal | 中 | 高 | 🟠 中 | 🔴 `nvidia-cc` 配 `ENCLAVE_MODE=sgx`，实现无 sgx（`enclave.go:newPlatformEnclave`） |

### 8.9 威胁-资产-缓解矩阵（摘要，含 DFD 定位）

> 本表为**摘要**（仅列关键威胁）；完整清单见 §8.1-§8.8 与 §8.10（LLM 特有威胁）。

| 威胁 | 资产 | 作用数据流（§5.1 DFD） | 主缓解 | 状态 |
|---|---|---|---|---|
| TG-I-03 | AS-2/03/04 | DS-1 | 密封密钥 TDX 派生（P1） | 🔴 |
| TG-S-04 | AS-1/02/03 | DF-2 / TB-2 | 飞地端 JWT 验签 + 租户声明 | 🔴 |
| TG-E-04 | AS-10 | P-4（管理面） | 启动守卫（GAP-05） | 🟡 |
| TG-T-03 | AS-07 | DF-3 / DS-2 | 审计写失败 fail-closed | 🟡 |
| TG-T-07 / SC-01/02 | 全部 | TB-6（构建→运行时） | 镜像 digest + 签名 + SBOM | 🔴 |
| TG-I-08 | AS-01（缓存） | DS-1 / P-3 | 延迟抖动（已实现） | ✅ |
| TG-I-12 | AS-01 | DF-5 | L2 侧车 CIDR/直连约束（残余：明文出飞地） | 🟡 |
| TG-E-06 | 合规 | P-5 | sm-module 不冒充 | ✅ |

### 8.10 LLM 特有威胁（OWASP LLM Top 10 对齐，S-2 补充）

> STRIDE 不直接覆盖生成式 AI 特有攻击面，单列如下；与 §8 既有条目**互引，不重复计入风险统计**。

| 编号 | 威胁（OWASP LLM） | 攻击者 | 影响 | 关联条目 | 现状控制 |
|---|---|---|---|---|---|
| **TG-LLM-01** | 提示注入 / 越狱（LLM01） | MAL-1 | 绕过策略、诱导越权输出 | TG-T-05、AT-3 | 🟡 输入侧 PII/注入/SQL 规则（`guardrail.go`）+ 输出侧级联（`outputguard*.go`）；**确定性规则，同形字/编码混淆未覆盖** |
| **TG-LLM-02** | 不当输出处理（LLM02） | MAL-1 | 下游注入（XSS/SQL/命令） | TG-E-01 | 🟡 输出侧审查拦截；**下游消费方责任边界未定义** |
| **TG-LLM-03** | 敏感信息泄露（LLM06） | MAL-1/2 | 上下文/训练数据泄露 | TG-I-01/07 | ✅ TEE 内闭环 + PII 拦截 + 日志脱敏 |
| **TG-LLM-04** | 模型窃取（LLM10） | MAL-1/2 | 权重/知识产权损失 | TG-I-05 | 🟡 凭据最小权限；**无模型水印/防盗用** |
| **TG-LLM-05** | 过度代理 / 工具滥用（LLM08） | MAL-1 | 非授权工具调用 | — | 🟡 mcpguard 工具级 ACL + 参数校验（`tee-infer-service/mcpguard/*`；P2 MCP 网关化前为 TEE 内检查） |

---

## 9. 现有缓解措施与验证状态

> 逐条给出**实现位置（代码锚点）**与**验证状态**；"未接线/未实现"如实标注。

### 9.1 密码与密钥

| 控制 | 实现 | 状态 |
|---|---|---|
| 信封 AEAD（AES-256-GCM / SM4-GCM） | 求值在 `protocol/go/cryptoops/envelope.go`（`SealEnvelope`/`OpenEnvelope`/`DeriveSubkey`）+ `cryptoops/sm.go`（SM4 suite）；framing 在 `protocol/go/envelope.go`（`Envelope`/`EnvelopeAAD`/`EnvelopeNonce`/`CounterWindow`/`CheckStreamSequence`）；suite 未知 fail-closed（`cryptoops/envelope.go:suiteFor`）（F-1 修订） | ✅ |
| 方向子密钥 + AAD 绑定 | HKDF c2s/s2c（`cryptoops/envelope.go:DeriveSubkey`）；AAD = 会话/方向/计数器/端点（`protocol/go/envelope.go:EnvelopeAAD`） | ✅ |
| 每租户独立密钥 | `kmFor(tenant)` 懒创建独立 KeyManager（`tee-infer-service/main.go:kmFor`） | ✅ |
| 主密钥轮换 + 过期 wipe | TTL 5min + InFlightWindow 30s（`teecore/keymgmt.go`） | ✅ |
| 密钥销毁（密码学擦除） | 轮换旧钥 wipe（`teecore/keymgmt.go`）+ `internal/memzero` | 🟡 已实现 wipe；**销毁验证/合规举证待补**（S-6） |
| 三级密钥/信封封装（运营级） | `keymgmt/keymgmt.go` PEM+ASN.1 + AES-256-GCM 信封 | 🟡 仅内存信封 `MemEnvelope`；**无 KMS/HSM** |
| 算法族唯一入口 cryptop | `cryptop/provider.go`（intl/sm-software/sm-module） | 🟡 **部分接线**：已被 `cipher/mask`、`cryptoops/sm.go` 引用；**AEAD 主路径经 `cryptoops` 直用 `crypto/aes`，未收敛到 `cryptop.Provider`**（GAP-11）（F-7 修订） |
| 国密软件实现 | `cryptop/sm.go` SM4-GCM/SM3/SM2；KDF 走 GB/T 32918.4 | 🟡 SM2 ECDH 非 GB/T 32918.3 完整流程（`cryptop/sm.go`）；sm-software **不满足密评** |
| 认证密码模块 | `cryptop/provider.go:ErrNotImplemented`（sm-module 拒绝冒充） | 🔴 未实现（**拒绝冒充**，符合合规诚信） |
| Paillier（安全聚合） | `cipher/paillier/paillier.go` ≥2048 位、解密范围校验 + L(u) 整除 + 盲化、`ValidatePlaintextSum` | 🟡 模幂非常数时间（源码注释声明） |
| OTP-Mask 原语 | `cipher/mask/mask.go` HMAC-SHA256 PRG + 拒绝采样；`cipher/kex` ECDH P-256 | ✅ |
| 零化 / 常数时间（专用包） | `internal/memzero`、`internal/consttime`（F-9 补充锚点） | 🟡 供调用点使用；Go GC 下零化仍 best-effort |

**密评边界（C-2）**：密评对象为**密码模块与密码应用**（GB/T 39786 / GM/T 0054）。本项目实际密码求值由 **Go 标准库 AES-GCM** 与 **软件国密 SM4-GCM（sm-software）** 承担：前者非商用密码认证模块，后者**不满足密评**；`sm-module`（认证密码模块）**未实现**（`cryptop/provider.go` 返回 `ErrNotImplemented`，拒绝冒充）。**结论：当前形态尚不满足密评**；TEE 内若需以密码运算达成合规保护目标，须由认证密码模块承担，整改与测评随 **P1-5（国密 S3/S4 + 密评）**。**对外不得宣称"已通过密评"**。

### 9.2 会话与远程证明

| 控制 | 实现 | 状态 |
|---|---|---|
| 会话密钥派生 | X25519 ECDH + HKDF-SHA256（`session.go`），TTL 5min + 销毁零化 | ✅ |
| 证明载荷绑定 | `report_data = H(nonce‖server_pub)` 前 32B（`enclave_tdx.go:tdxReportData`） | ✅ |
| 客户端证明校验 | nonce 回显 + report_data + app_hash + 签名（`wasm/otpmask-plugin/attest.go:verifyPluginProof`） | 🟡 根信任为 mock 自签 |
| 独立证明验证器 | `attest-verify/verifier.go`（`BuiltinVerifier.VerifyQuote`）+ 回环服务（`server.go`） | ⚠️ **未被任何运行服务引用**（仅测试/文档） |
| 启动期安全守卫（GAP-01/05） | `startup_guard.go:validateStartupSecurity`（`main.go:validateStartupSecurity`）：生产形态拒绝 mock 飞地与空 `-admin-token`；`-dev-mode` 为显式逃生（F-3 新增） | ✅ |
| 真 TDX 构造 fail-closed | `NewTdxEnclave` 不可用即报错 → 启动 `Fatal`，不静默降级（`enclave_tdx.go:NewTdxEnclave`、`main.go`）（F-5 修订） | ✅ |
| 硬件度量校验（RTMR/MRTD） | `Measure()` 返回常量；Quote 的 RTMR **未解析/未校验** | 🔴 未实现 |
| 真机 DCAP/PCK 证书链 | 注释预留（`attest-verify/verifier.go`） | 🔴 未实现 |
| 证明强制 | `protocol/go/protocol.go:DefaultAttestType=Token`；无会话请求仍走全局 K_sig（`main.go:VerifyRequest`（`cryptoops.VerifyRequest`））（MR-1 订正） | 🟡 非每请求强制 |

### 9.3 内容安全

| 控制 | 实现 | 状态 |
|---|---|---|
| 输入侧 Guardrail（PII/注入/SQL） | `guardrail.go`（规则块 / `check` / `normalize`），命中即拒，全角归一 + 去空白 | ✅ 默认 `-pii-mode=block`，**无关闭开关**（`guardrail.go`） |
| 输入审查位置在 TEE 内 | 解密后即审查（`main.go:guard.check`） | ✅ |
| 输出侧级联（L1 内 + L2 侧车） | `outputguard.go`（off/shadow/enforcing）、`outputguard_cascade.go` 单出口 + 槽位状态机 | ✅ |
| 降级 fail-closed | 侧车不可用**不回退 L1 重判**（`outputguard.go`） | ✅ |
| L2 侧车网络约束 | CIDR 白名单 + 禁重定向/代理 + 解析后按 IP 直连（`outputguard.go:newL2HTTPTransport`） | 🟡 被审明文离开飞地（TG-I-12） |
| 策略供应链复核 | 提交人≠复核人 + 台账覆盖一致 + 失败拒加载（`outputguard_review_ledger.go`） | ✅ |
| 日志/快照脱敏 | `maskForLog` 零原文、`snapshot` 最小披露（`guardrail.go:snapshot`/`maskForLog`） | ✅ |

### 9.4 审计与防篡改

| 控制 | 实现 | 状态 |
|---|---|---|
| 哈希链（长度前缀防拼接歧义） | `audit.go:hash` | ✅ |
| WORM 只追加 + 启动恢复即校验 | `audit.go:newAuditChainWORM`/`load` | 🟡 **非真 WORM**（`O_APPEND` + 本地锚点），无外部公证 |
| TST 锚定 | `anchorNow` 绑定 RFC 3161（`audit.go:anchorNow`） | 🟡 `MockTSA` 自签（`tsa.go:MockTSA`）；`HTTPTSA` 未实现（`tsa.go:HTTPTSA`） |
| 独立离线验证器（含截断检测） | `audit-verify/verifier.go` + `schema.go` | ✅ |
| 管理面链路 fail-closed | append 返回 error（`admin/audit.go`） | ✅ |
| 飞地链路写失败 | **仅告警不阻断**（`audit.go`） | 🟡 |

### 9.5 网络与协议

| 控制 | 实现 | 状态 |
|---|---|---|
| 请求签名 + 30s 防重放 + seen 去重 | 签名 `cryptoops/sign.go:SignRequest`/`VerifyRequest`；防重放 `protocol/go/protocol.go:CheckReplay`（窗口 30s + seen 去重）（F-2 修订） | ✅ |
| 64 槽反重放计数器窗口 + SSE 严格递增 | `protocol/go/envelope.go:CounterWindow`/`CheckStreamSequence` | ✅ |
| 长度上限防 OOM | `protocol/go/protocol.go:maxVectorDim`/`maxMessageLen` + `bodylimit_test.go`（MR-1 订正） | ✅ |
| 协议版本不匹配 fail-closed | `protocol/go/protocol.go:Version` | ✅ |
| 网关 fail-closed 503 | `main.go:handleHealthz`、`gateway-core/tee_client.go` | ✅ |
| K_sig 静态注入 | 参数/Secret 提供（`protocol/go/protocol.go` 自述"生产由 TEE 签发"） | 🟡 MVP 静态 |
| 南向传输 TLS/mTLS | **能力已具备**：`secagg/tls.go`；`cmd/aggregator/main.go` 的 `-tls-cert`/`-tls-key`/`-tls-ca`/`-tls-server-name`。**默认明文**（未配即明文 `insecure.NewCredentials()`）（F-8 修订） | 🔴 默认明文（需显式开启） |

### 9.6 供应链、部署与访问控制

| 控制 | 实现 | 状态 |
|---|---|---|
| 容器最小权限 | 非 root（`USER 65532:65532`）、`readOnlyRootFilesystem`、drop ALL（`deploy/k8s/tee-infer-service.yaml` 的 securityContext）（F-6 修订） | ✅ |
| Helm 强制显式密钥 | sigKey/attestToken 无默认值（`deploy/helm/otpmask/values.yaml`） | ✅ |
| 镜像供应链 | 无 digest/签名/SBOM；`latest` 标签 | 🔴 |
| TEE 运行时（CC/Kata） | 无 `runtimeClassName` | 🔴 |
| 部署示例密钥 | 硬编码（`deploy/tee/base/secret.yaml`） | 🔴 |
| 管理面 RBAC | admin/auditor + 白名单加成 + 读/写分级（`auth.go`） | ✅ |
| 凭据端点最小权限 | 每集独立读令牌 + 字段白名单 + 文件权限校验 + 503（`credential_endpoint.go`） | ✅ |
| tee-infer 管理端点令牌 | `checkAdmin` 未配令牌仍返回 true（`main.go:checkAdmin`）；**生产形态已由启动守卫拒绝启动**（GAP-05 ✅），仅显式 `-dev-mode` 放行（F-3 修订） | 🟡 |

### 9.7 测试锚点与威胁→测试映射（A-2 补充 + v0.7 扩充）

> 缓解措施 ↔ 测试 ↔ 威胁的**可追溯映射**，用于量化"威胁覆盖率"与"缓解验证率"。
>
> **当前覆盖率（v0.7 统计）**：
> - 总威胁条目：45（STRIDE 39 + 供应链 6）+ 5 LLM 特有
> - 有直接测试覆盖：18 条（约 40%）
> - 通过 GAP 规划覆盖：22 条（P1-8 落地后可达 ~89%）
> - 无法通过单元测试验证（需渗透/物理）：5 条（侧信道/故障注入类）

| STRIDE 类 | 威胁 ID | 缓解措施 | 测试锚点 | 覆盖状态 |
|---|---|---|---|---|
| **S 伪造** | TG-S-01 | 管理面 JWT 鉴权 + RBAC | `auth-service/jwt_test.go`、`credential_endpoint_test.go` | ✅ 已覆盖 |
| S | TG-S-02 | 飞地端 JWT 验签 + 租户声明 | `gateway/tee-infer-service/auth_tenant_test.go`（GAP-04 规划） | 🔴 GAP-04 待落地 |
| S | TG-S-03 | API Key 池 + 最小权限 | `model/keypool_test.go`、`credential_endpoint_test.go` | ✅ 已覆盖 |
| S | TG-S-04 | 证明链验证（Quote + MRTD） | `gateway/attest-verify/verifier_test.go`（GAP-02/03 扩展） | 🟡 部分覆盖（mock Quote） |
| S | TG-S-05 | 会话密钥 ECDH 派生 + 身份绑定 | `gateway/tee-infer-service/session_envelope_test.go` | ✅ 已覆盖 |
| **T 篡改** | TG-T-01 | 信封 HMAC 签名 + 计数器防重放 | `protocol/go/cryptoops/sign_test.go`、`session_envelope_test.go` | ✅ 已覆盖 |
| T | TG-T-02 | 审计链哈希链 + 离线验证 | `gateway/tee-infer-service/audit_test.go`、`audit-verify/` | ✅ 已覆盖 |
| T | TG-T-03 | 策略签名 + 校验 | `policy/verify_test.go` | ✅ 已覆盖 |
| T | TG-T-04 | 计费账本哈希链 + 签名 | `gateway-admin-service/billing/ledger_test.go`、`signature_test.go` | ✅ 已覆盖 |
| T | TG-T-05 | 控制面策略 tamper-evident | `gateway/tee-infer-service/outputguard_review_ledger_test.go` | ✅ 已覆盖 |
| T | TG-T-06 | 镜像 digest 固定 + cosign 签名 | admission 测试（GAP-07 规划） | 🔴 GAP-07 待落地 |
| T | TG-T-07 | 密码运算完整性（cryptop 侧车） | `gateway/cryptopsvc/..._test.go`、`cryptop/kat_test.go` | ✅ 已覆盖 |
| **R 抵赖** | TG-R-01 | 审计链 + TST 时间戳 + WORM | `audit_test.go` + TSA 测试（GAP-10 规划） | 🟡 部分（缺 TSA） |
| R | TG-R-02 | 签名回执（每请求响应签名） | `protocol/go/cryptoops/sign_test.go` | ✅ 已覆盖 |
| R | TG-R-03 | 操作审计（管理面全操作留痕） | `gateway-admin-service/audit_test.go` | ✅ 已覆盖 |
| R | TG-R-04 | 密钥操作审计 | `teecore/keymgmt_test.go` | 🟡 部分（功能有，审计事件欠完整） |
| **I 信息泄露** | TG-I-01 | 信封 AEAD 加密 + suite 感知 | `protocol/go/cryptoops/envelope_test.go` | ✅ 已覆盖 |
| I | TG-I-02 | 会话密钥飞地内派生 + 零化 | `session_test.go`、`enclave_test.go` | ✅ 已覆盖 |
| I | TG-I-03 | 密封密钥 TDX 派生 + 内存零化 | `enclave_tdx_test.go`（GAP-06 规划） | 🔴 GAP-06 待落地 |
| I | TG-I-04 | 密钥分层（三级密钥体系） | `teecore/keymgmt_test.go`、`cryptop/kat_test.go` | ✅ 已覆盖 |
| I | TG-I-05 | 模型权重飞地内加载 | 需真机集成测试（P1 M4） | 🟡 mock 覆盖 |
| I | TG-I-06 | API Key 侧车托管 + 不落明文 | `model/keypool_test.go` + `credential_endpoint_test.go` | ✅ 已覆盖 |
| I | TG-I-07 | 审计出飞地脱敏 | `audit_filter_test.go`（待补） | 🟡 功能有，专项测试欠 |
| I | TG-I-08 | 错误信息最小化（不泄露内部状态） | `error_policy_test.go`（待补） | 🟡 代码有规范，缺专项测试 |
| I | TG-I-09 | 日志脱敏（无明文打印） | `log_redact_test.go`（待补） | 🟡 代码有规范，缺专项测试 |
| I | TG-I-10 | 时序侧信道缓解（批量+随机延迟） | 侧信道专项测试（需专用环境） | ⚪ 无法单测验证 |
| I | TG-I-11 | 缓存侧信道缓解（恒定时间、固定批大小） | 侧信道专项测试（需专用环境） | ⚪ 无法单测验证 |
| I | TG-I-12 | 输出侧明文已知风险（架构决策） | 输出保护专项测试 | ⚪ 架构风险，非测试可消除 |
| **D 拒绝服务** | TG-D-01 | 限流 + 熔断 + 重试预算 | `gateway/wasm/otpmask-plugin/ratelimitcache/..._test.go` | ✅ 已覆盖 |
| D | TG-D-02 | 并发上限（`SetMaxConcurrency`） | `secagg/tls_test.go` 相关 | 🟡 功能有，默认 0（GAP-12） |
| D | TG-D-03 | 资源隔离（K8s requests/limits） | 部署清单校验（P1-3） | 🟡 部署有，专项测试欠 |
| D | TG-D-04 | 飞地内存溢出防护 | `enclave_test.go` 边界用例 | ✅ 已覆盖 |
| D | TG-D-05 | 会话 TTL + 主动清理 | `session_test.go` TTL 用例 | ✅ 已覆盖 |
| **E 提权** | TG-E-01 | 飞地内最小权限（模块隔离） | 架构评审 + 代码审计（P1 M5） | 🟡 依赖人工审计 |
| E | TG-E-02 | 模型推理沙箱（不可访问系统资源） | `sandbox_policy_test.go`（待补） | 🟡 功能有，专项测试欠 |
| E | TG-E-03 | 凭据轮换 + 最小权限 | `credential_endpoint_test.go` 轮换用例 | ✅ 已覆盖 |
| E | TG-E-04 | 管理面 RBAC + 操作审计 | `gateway-admin-service/rbac_test.go` | 🟡 部分覆盖 |
| E | TG-E-05 | 固件/微码提权（硬件级） | 依赖 Intel TDX + CSP 加固 | ⚪ 无法单测验证 |
| E | TG-E-06 | 供应链植入（构建/发布链路） | SLSA + cosign 验证（GAP-07） | 🔴 GAP-07 待落地 |
| **SC 供应链** | TG-SC-01/02 | 镜像签名 + digest 固定 + admission | cosign / admission 测试（GAP-07） | 🔴 GAP-07 待落地 |
| SC | TG-SC-03 | SBOM + 依赖漏洞扫描 | dependabot / trivy 扫描（CI） | 🟡 部分（有 go.mod 校验） |
| SC | TG-SC-04 | 构建环境硬化 | CI 平台加固（P1-3） | 🔴 待规划 |
| SC | TG-SC-05 | 依赖锁定 + 可复现构建 | go.sum + SLSA L3 provenance | 🟡 有 go.sum，缺 provenance |
| SC | TG-SC-06 | 第三方组件安全审计 | 依赖审计报告（P1 M5） | 🔴 待开展 |

**测试覆盖图例**：✅ 已完整覆盖 / 🟡 部分覆盖（有测试但不完整） / 🔴 无覆盖（GAP 待落地） / ⚪ 无法单元测试（需渗透/物理/架构）

### 9.8 威胁 → 可观测信号（O-2 补充，抽样）

> 管理面已有 40+ 指标（见《GA-部署指南》）；本表补充"安全信号"映射，**缺口随 P1-8 补齐**。

| 威胁 / GAP | 建议可观测信号（指标/告警/巡检） | 现状 |
|---|---|---|
| TG-E-04 / GAP-05 | 启动拒绝日志、部署清单审计 | ✅ 启动守卫 |
| TG-D-01 / TG-D-05 | `main.go:handleHealthz` 503 率、k8s readiness | ✅ 指标 + probe |
| TG-T-03 / GAP-09 | 审计链校验结果、链长/锚点巡检 | 🟡 离线验证器（手动/定时） |
| TG-I-12 / TG-D-05 | L2 侧车可用性/超时计数 | 🟡 部分 |
| TG-S-04 / GAP-04 | 直连飞地端口访问计数（网络策略） | 🔴 待建 |
| TG-SC-01/02 / GAP-07 | 镜像 digest 一致性巡检 | 🔴 待建 |

---

## 10. 残余风险与已知差距（GAP）

### 10.1 高危残余风险（须在客户沟通中如实披露）

| ID | 残余风险 | 关联威胁 | 影响 | 修复前检测信号（O-1） | 处置去向 |
|---|---|---|---|---|---|
| **RSK-01** | 默认 mock 飞地；生产若漏配则机密计算保护**不成立** | TG-I-01、TG-E-02 | 严重 | 启动日志/`-dev-mode` 声明；部署清单 CI 比对（`ENCLAVE_MODE`/`-dev-mode`） | ✅ 已闭环（启动守卫 GAP-01）；残余=显式 `-dev-mode` 需清单治理 |
| **RSK-02** | 无真实远程证明验证（`attest-verify` 未接线、无 DCAP 链）→ 客户端无法独立验证飞地身份 | TG-S-02、AT-4 | 严重 | 部署拓扑核对（无 attest-verify 实例）；客户端证明校验仅为自洽校验 | P1：DCAP/PCK + RATS Verifier 接线 |
| **RSK-03** | 无硬件度量校验（MRTD/RTMR）→ 无法检测被篡改的飞地镜像 | TG-T-01、TG-SC-04 | 严重 | `Measure()` 恒为常量（可断言） | P1：RTMR 校验 + 镜像签名 |
| **RSK-04** | 飞地端信任 `X-Tenant-ID`，不验 JWT → 若能直连飞地即可跨租户 | TG-S-04 | 严重 | 直连飞地端口可无令牌调用（渗透用例） | P1：飞地端验签 + 租户声明 |
| **RSK-05** | `checkAdmin` 未配令牌即放行 | TG-E-04 | 严重 | ✅ 生产形态启动即 Fatal（GAP-05）；残余=显式 `-dev-mode` | ✅ 已闭环（启动守卫） |
| **RSK-06** | 密封密钥非 TDX 派生（环境变量） | TG-I-03、AT-2 | 严重 | 检查飞地容器环境变量 `OTPMASK_TDX_SEAL_KEY` 是否被注入 | P1：TDX seal key 派生 |
| **RSK-07** | 供应链无签名/digest/SBOM；示例密钥硬编码 | TG-T-07、TG-SC-01/02/03 | 高 | 镜像引用为 `latest`（清单可扫描） | P1：SLSA + cosign + SBOM |
| **RSK-08** | 侧信道（微架构/时序/功耗）仅缓解不免疫 | TG-I-08/09/10/11 | 高 | 无（理论上不可从系统内部观测） | 持续：对外披露（《侧信道风险披露说明》）+ P2 评估 |
| **RSK-09** | 隐私"可检测性"：外部可推断某主体是否在用（LINDDUN-D） | TG-LLM-03 | 中 | 无专门信号；需流量/元数据侧统计（待建） | P1-3 隐私影响评估 |
| **RSK-10** | 审计 WORM 留存 vs 个人信息删除权口径未定 | TG-R-01、TG-T-03 | 中 | 无 | P2：留存/删除口径与流程（合规） |

### 10.2 待补项（GAP）与路线映射

| GAP | 描述 | 优先级 | 建议阶段 | 验收判据 | 研发计划登记（A-1） |
|---|---|---|---|---|---|
| **GAP-01** | 生产禁用 mock：启动时若 mock 且非显式 `-dev-mode` → Fatal | P0 | W2 | 单测 + 部署校验：mock 在生产拒绝启动 | ✅ **已完成**（2026-10-05，`startup_guard.go` + 单测；研发计划 §3.6 P0-5） |
| **GAP-02** | `attest-verify` 接线到客户端信任路径；接入 Intel PCS collateral（DCAP） | P1 | M4 | 真机 Quote 验证通过；伪造 Quote 被拒 | **P1-8 安全加固（研发计划 §4.1）**；owner 待指派 |
| **GAP-03** | 解析并校验 Quote 的 MRTD/RTMR，与白名单度量比对 | P1 | M4 | 度量不匹配时拒绝会话 | **P1-8 安全加固（研发计划 §4.1）**；owner 待指派 |
| **GAP-04** | tee-infer 端 JWT 验签 + 租户声明强校验；`X-Tenant-ID` 仅作提示 | P1 | M4 | 无有效令牌 → 401/403；跨租户矩阵通过 | **P1-8 安全加固（研发计划 §4.1）**；owner 待指派 |
| **GAP-05** | `checkAdmin` 未配令牌 → 启动 Fatal（生产模式） | P0 | W2 | 生产模式无令牌拒绝启动 | ✅ **已完成**（2026-10-05，`startup_guard.go`；研发计划 §3.6 P0-5） |
| **GAP-06** | 密封密钥 TDX 派生（或 KMS 注入 + 内存零化） | P1 | M4 | 密封文件在无派生密钥时不可解 | **P1-8 安全加固（研发计划 §4.1）**；owner 待指派 |
| **GAP-07** | 镜像 digest 固定 + cosign 签名 + SBOM（SPDX/CycloneDX） + SLSA 路径 | P1 | M4 | admission 策略拒绝未签名镜像；SLSA L2 全量达成，L3 关键组件达成 | P1-3 等保合规路径（供应链）；SLSA 分阶段目标见下表 |
| **GAP-08** | 机密计算运行时（CC/Kata runtimeClass）配置落地 | P1 | M4 | pod 运行于受度量沙箱 | P1-3 等保合规路径（运行时） |
| **GAP-09** | 审计链写失败 fail-closed（可配置） + 真 WORM 后端 | P1 | M5 | 写失败即拒服务；外部公证可验 | **P1-8 安全加固（研发计划 §4.1）**；owner 待指派 |
| **GAP-10** | 修正 overlay 与实现不一致（sgx）；外部 RFC3161 TSA 接入 | P1 | M4 | overlay 启动不 Fatal；TST 可被独立验签 | **P1-8 安全加固（研发计划 §4.1）**；owner 待指派 |
| **GAP-11** | cryptop 全量接线业务主路径（唯一入口） | P1 | 随 P0-4 | 静态扫描：无直用 `crypto/*` 业务代码 | **P0-4 国密 S2**（主方案 §4.4） |
| **GAP-12** | SecAgg 默认启用 TLS/mTLS；并发上限默认启用 | P2 | 按需 | 默认 TLS；并发上限默认非 0 | 待登记（P2；`SetMaxConcurrency` 能力已就绪、默认仍 0） |

> **追溯（A-1，2026-10-05 闭环）**：本表为**威胁模型引出**的工作项清单。**P1 安全加固类 GAP（GAP-02/03/04/06/09/10）已在研发计划立项为 P1-8「安全加固（威胁模型 GAP 闭环）」（§2.2 + §4.1 任务分解），owner 待指派**。其余去向：GAP-07/08 → P1-3 等保；GAP-11 → P0-4 国密 S2；GAP-12 → P2；GAP-01/05 **已于 2026-10-05 交付**。

> **SLSA 分阶段目标（v0.7 补充，对应 GAP-07）**：
>
> | 阶段 | SLSA 等级 | 里程碑 | 核心交付 | 验证方式 |
> |---|---|---|---|---|
> | **阶段一（P0）** | L0 → L1 基础 | 现状 | 源码受控（Git + 提交历史）；构建脚本可追溯 | `git log` 可追溯；Makefile 构建 |
> | **阶段二（P1 M4）** | **L2 全量达成** | GAP-07 闭环 | ① 镜像 digest 固定（K8s Deployment 用 `@sha256:`）；② cosign 密钥签名（KMS 托管密钥）；③ SBOM 生成（SPDX 格式，随镜像发布）；④ 构建平台化（CI 流水线统一产出） | admission controller 拒绝未签名镜像；`cosign verify` 通过；`sbom-tool` 可解析 |
> | **阶段三（P1 M5 / P2）** | L3（关键组件） | 等保三级 + 供应链加固 | ① 硬ening CI 平台（不可变构建环境 + 最小权限）；② provenance 防篡改（签名 provenance）；③ 第三方依赖审计（依赖锁定 + 漏洞扫描门禁）；④ 关键组件（TEE 飞地 / 密码模块）先达 L3 | `slsa-verifier` 验证 provenance；依赖变更需 PR + 审批 |
> | **阶段四（P3 / 按需）** | L4（目标形态） | 金融级合规 | ① 双人物料审批；② 可复现构建（hermetic）；③ 多源签名（多方 threshold）；④ 持续 SLSA 漂移检测 | 每年一次第三方审计；SLSA 仪表盘持续监控 |

> **GAP → 验收测试锚点（计划，D-2 补充）**：GAP-02/03 → 扩展 `gateway/attest-verify/verifier_test.go`（真机 Quote / 度量不匹配用例）；GAP-04 → 新增 `gateway/tee-infer-service/auth_tenant_test.go`（跨租户矩阵）；GAP-06 → 新增 `enclave_tdx_test.go`（无派生密钥不可解）；GAP-09 → 扩展 `gateway/tee-infer-service/audit_test.go`（写失败 fail-closed）；GAP-10 → `deploy/tee/**` 渲染校验 + TSA 验签用例；GAP-07/08 → admission/运行时校验（随 P1-3）。

---

## 11. 结论与后续工作

### 11.1 结论

1. 本项目在**协议层（信封 AEAD + 签名 + 防重放）、密钥层（每租户独立 + 轮换 + 零化）、审计层（哈希链 + 离线验证）、内容安全层（双侧 TEE 内闭环）**已具备扎实控制，工程实现质量高于"仅封装的密态"。
2. **开发模式遗留已部分闭环**：GAP-01/05（生产禁用 mock、生产强制管理令牌）已由**启动守卫**落地 ✅（`startup_guard.go` + `-dev-mode`）；但**信任基三大缺口**（远程证明未接线、硬件度量未校验、密封密钥非 TDX 派生）与 **`X-Tenant-ID` 信任**仍在，使"密态安全"在**未完成 P1 加固前不可对客户作强承诺**。
3. 侧信道、故障注入、TEE 固件漏洞为**理论攻击面**，须以《侧信道风险披露说明》为准作**如实、不夸大**的对外表述。
4. 本文 GAP 清单可直接转化为 P1 M4-M5 的工作项与白皮书素材。

### 11.2 后续工作

| 工作项 | 阶段 | 目标时间 |
|---|---|---|
| GAP-01/05 落地（✅ 已完成 2026-10-05） | P0 | W2 |
| 《安全白皮书大纲》编写（本文为素材） | P0 | W2 |
| 《侧信道风险披露说明》定稿 | P0 | W2 |
| 完整 STRIDE + 攻击树形式化 | P1 | M4 |
| GAP-02/03/04/06/07/08/10 落地 | P1 | M4 |
| GAP-09/11 落地 | P1 | M5 |
| 渗透测试 + 第三方安全审计 | P1/P2 | M5-M9 |
| 安全白皮书 v1.0 发布 | P1 | M5 |

### 11.3 复评触发条件（O-3 补充）

出现下列任一情形，本文**必须重新评估并升版**（对齐《侧信道风险披露说明》§10.3）：

1. **新披露的 TEE/CPU 漏洞**（侧信道、故障注入、微码）影响本项目所用平台；
2. **安全能力状态变化**（如 GAP-02/03/04/06 落地、证明链/度量校验接入、cryptop 全量接线、审计 fail-closed）；
3. **架构或部署形态变更**（新增组件/运行时/TEE 形态，或数据流变化）；
4. **法规/标准更新**（等保、密评、GB/T 45654 等）；
5. **重大安全事件，或渗透测试/第三方审计结论**；
6. **客户/监管提出新的威胁面披露要求**。

### 11.3.1 GAP 回填与版本维护机制（v0.7 补充）

**责任人**：安全工程师（owner 待指派，P1-8 启动时确认）
**维护频率**：每 GAP 闭环即同步更新；至少每月一次全量复核

#### 回填触发规则

| 触发场景 | 动作 | 版本号 |
|---|---|---|
| 单条 GAP 闭环（代码已合并 + 单测通过） | 更新 §10.2 状态列 + §9 缓解矩阵 + §8 威胁条目状态；补变更记录 | 次版本 +0.1（如 v0.6 → v0.7） |
| 多条 GAP 批量闭环（≥3 条） | 同上 + 全量 STRIDE 状态重核 | 次版本 +0.1 或 +0.2 |
| 架构变更 / 新增威胁面 | 新增/修改威胁条目 + DFD 更新 + 攻击树重评 | 主版本 +1（如 v1.0 → v2.0） |
| 复评触发（§11.3 任一条件） | 全量复核 + 差异记录 + 白皮书联动更新 | 视影响面定 |

#### 回填 DoD（Definition of Done）

GAP 闭环后回填威胁模型，必须完成以下 5 项才算完成：

1. ✅ **§10.2 GAP 清单**：状态由「P1 M4」改为「✅ 已完成（日期）」，补充代码锚点与 PR/Commit
2. ✅ **§9 缓解-验证矩阵**：对应控制措施的「现状」由「待建/部分」改为「已落地」，更新证据列
3. ✅ **§8 威胁条目**：关联威胁的风险等级重评（如从「高」降为「中」），状态列更新
4. ✅ **§13 变更记录**：新增版本条目，说明变更内容、影响范围、关联 GAP
5. ✅ **跨文档同步**：① 研发计划 §3.6 版本号同步；② 如影响对外口径，同步侧信道披露说明 + 白皮书大纲

#### 版本号规则

- **v0.x**：P0 初稿 / 迭代完善（威胁识别阶段，缺大量控制）
- **v1.0**：P1 M4 白皮书发布（核心 GAP 闭环，可对外发布）
- **v1.x**：P1/P2 加固期增量更新（单 GAP 闭环、小范围调整）
- **v2.0**：架构重大变更 / 新增威胁面 / 等保密评落地后重评

### 11.4 P0 演示就绪判据（P-1 补充）

**最小可演示闭环（对外 Demo 的前提）**：

1. ✅ 密态闭环可跑：会话握手 → 信封推理 → 输出审查 → 审计链（**mock 飞地即可**，用于功能演示）；
2. ✅ GAP-01/05 已闭环：生产形态不会误跑 mock、管理端点强制令牌；
3. 🟡 演示环境须**显式声明"mock 飞地（功能演示，非机密计算）"**，不得暗示真机 TDX；
4. 🔴 **禁止**在完成 GAP-02/03 前做"远程证明可信"类演示；
5. 🔴 **禁止**对客户演示"已满足密评/等保"（见 §9.1 密评边界）。

### 11.5 威胁 → 客户 Q&A 索引（P-2 补充）

> 对外答复**逐字引用**《侧信道风险披露说明》§8；本表为内部索引，避免口径漂移。

| 威胁 / 主题 | 披露说明 Q&A |
|---|---|
| 侧信道 / 微架构 | Q2、Q3 |
| 宿主读取 / 飞地边界 | Q4 |
| 远程证明 | Q5 |
| 默认是否密态 | Q6 |
| 合规资质 | Q7 |
| 责任边界 | Q8 |
| 第三方审计 | Q9 |
| 数据留存 / 删除权 | （待补：随 C-4 与 P1-3 隐私评估新增） |

---

## 12. 附录

### 附录 A 威胁编号索引

| 前缀 | 类别 | 条目 |
|---|---|---|
| TG-S-* | Spoofing | 01-05 |
| TG-T-* | Tampering | 01-07 |
| TG-R-* | Repudiation | 01-04 |
| TG-I-* | Information Disclosure | 01-12 |
| TG-D-* | Denial of Service | 01-05 |
| TG-E-* | Elevation of Privilege | 01-06 |
| TG-SC-* | Supply Chain | 01-06 |
| TG-LLM-* | LLM 特有（OWASP LLM Top 10） | 01-05 |
| AT-* | 攻击树 | 01-04 |
| RSK-* | 残余风险 | 01-10 |
| GAP-* | 待补项 | 01-12 |
| P-/DS-/DF- | DFD 要素（§5.1） | — |

**附录 A.2 威胁全名单（O-4 补充，便于闭环跟踪）**

- **TG-S**：01 伪管理面 JWT｜02 伪飞地身份｜03 重放证明｜04 伪租户（`X-Tenant-ID`）｜05 凭据端点令牌冒用
- **TG-T**：01 宿主篡改飞地内存｜02 篡改在途请求/响应｜03 篡改/删除审计记录｜04 篡改计量/账本｜05 篡改内容安全策略｜06 篡改控制面策略下发｜07 篡改镜像/依赖
- **TG-R**：01 否认发起请求｜02 运维否认改配置｜03 审计链截断未察觉｜04 数据留存与删除权冲突
- **TG-I**：01 宿主读飞地明文｜02 内存残留/未零化｜03 密封密钥泄露｜04 密钥轮换不及时｜05 模型/提示词窃取｜06 服务商凭据泄露｜07 审计/日志泄露原文｜08 缓存侧信道｜09 时序侧信道｜10 微架构侧信道｜11 功耗/电磁侧信道｜12 输出侧 L2 明文出飞地
- **TG-D**：01 宿主停飞地进程｜02 飞地资源耗尽｜03 超长/畸形输入 OOM｜04 聚合无限并发｜05 内容审查降级滥用
- **TG-E**：01 不可信输入提权｜02 逃逸飞地｜03 越权读凭据｜04 `checkAdmin` 放行｜05 聚合恶意敌手｜06 冒充合规
- **TG-SC**：01 可变标签镜像｜02 无签名/SBOM｜03 示例密钥硬编码｜04 固件/BIOS 供应链｜05 无机密计算运行时｜06 overlay 与实现不一致（sgx）
- **TG-LLM**：01 提示注入/越狱｜02 不当输出处理｜03 敏感信息泄露｜04 模型窃取｜05 过度代理/工具滥用
- **AT**：01 窃明文｜02 窃密钥｜03 绕审查｜04 伪造证明
- **RSK**：01 mock 默认｜02 证明未接线｜03 无度量校验｜04 飞地信任租户头｜05 `checkAdmin` 放行｜06 密封密钥非派生｜07 供应链无签名｜08 侧信道不免疫｜09 隐私可检测性｜10 留存/删除权口径
- **GAP**：01 生产禁 mock｜02 DCAP 接线｜03 度量校验｜04 飞地端鉴权｜05 生产强制令牌｜06 密封密钥派生｜07 镜像签名/SBOM｜08 机密计算运行时｜09 审计 fail-closed/WORM｜10 overlay/TSA｜11 cryptop 全量接线｜12 SecAgg TLS/并发

### 附录 B 与主方案 §4.5.2 对照

见 §3.3。

### 附录 C 参考标准清单

见 §3.2。

### 附录 D 证据锚点速查（代码）

| 主题 | 文件 |
|---|---|
| 飞地抽象/密封/证明 | `gateway/tee-infer-service/enclave.go`、`enclave_tdx.go` |
| 会话派生 | `gateway/tee-infer-service/session.go` |
| 密钥管理（租户/轮换） | `gateway/teecore/keymgmt.go`、`keymgmt/keymgmt.go` |
| 密码 Provider | `gateway/cryptop/{provider,intl,sm}.go` |
| 原语 | `cipher/{kex,mask,paillier}/*` |
| 安全聚合 | `secagg/*`、`cmd/{aggregator,party}/main.go` |
| 审计链/验证 | `gateway/tee-infer-service/audit.go`、`tsa.go`、`gateway/audit-verify/*` |
| 内容安全 | `gateway/tee-infer-service/guardrail.go`、`outputguard*.go` |
| 协议/信封/签名 | `protocol/go/protocol.go`、`protocol/go/envelope.go`（framing）；`protocol/go/cryptoops/{envelope,sign,sm}.go`（求值/签名，F-1 修订） |
| 证明验证 | `gateway/attest-verify/*`、`gateway/wasm/otpmask-plugin/attest.go` |
| 部署 | `deploy/tee/*`、`deploy/helm/otpmask/*`、`deploy/k8s/*` |

---

## 13. 变更记录

| 版本 | 日期 | 变更内容 |
|---|---|---|
| v0.1 | 2026-10-05 | 首版发布级初稿。以 2026-10-05 仓库代码实测为基准，完整给出方法论/信任边界/资产/攻击者模型/威胁清单（STRIDE 38 条 + 供应链 6 条，共 44 条）/4 棵攻击树/缓解-验证矩阵/12 项 GAP；取代原三合一《P0--TEE威胁模型初稿.md》。 |
| v0.2 | 2026-10-05 | 按《…多角色评审报告-第 1 轮》修订。**P0 全 3 项**：F-1 删除对已删文件 `envelope_sm.go` 的引用（改指 `cryptoops/*`）；F-2 签名/防重放锚点改 `cryptoops/sign.go` + `protocol.go:CheckReplay`；F-3 回填 GAP-01/05 为"已完成"（启动守卫）并同步 §1/§5.4/§8.6/§8.9/§9.2/§9.6/§10/§11。**P1 关键项**：F-4 修正镜像名；F-5 重核 main.go 锚点并**改"文件:符号"锚（抗漂移）**；F-6 补 `-dev-mode` 部署现状；F-7 cryptop 改"部分接线"；S-1 新增 §5.1 DFD 要素编号（P/DS/DF/TB）并给 §8.9 增"作用数据流"列；S-2 新增 §8.10 LLM 特有威胁（TG-LLM-01..05）；S-3 新增 §3.4 LINDDUN 隐私威胁摘要；A-1 §10.2 增"研发计划登记"列（如实标注待立项）；C-1 标准清单增补 GM/T 0054、密评管理办法并标注版本待核；C-2 新增"密评边界"结论（当前不满足密评）；O-1 §10.1 增"修复前检测信号"列。**C-3**：§1 不再提供可照抄对外话术，统一指向《侧信道风险披露说明》。另新增 RSK-09/10、F-8/F-9 证据订正；**未改变威胁范围与风险分级体系**。 |
| v0.3 | 2026-10-05 | 第 2 轮元评审（A-）后收尾。**MR-1**：订正 `protocol/go/protocol.go` 两处漂移锚并改符号（`maxVectorDim`/`maxMessageLen`；`DefaultAttestType`）。**P2 收尾 3 项**：S-4（§6.1 新增 **AS-11 控制面策略/配置资产** + §6.2 映射）；O-3（新增 **§11.3 复评触发条件**）；A-2（新增 **§9.7 测试锚点抽样**）。另由元评审即时订正 MR-2（§3.4 等级对齐 RSK-09）、MR-3/MR-4（§8.9 两处）。**未改变威胁范围与风险分级体系**。 |
| v0.4 | 2026-10-05 | **D-1 闭环：全文锚点统一**。将 §5-§12 全部 `文件:行号` 锚点统一为 **`文件:符号`**（可定位单一符号者，如 `cryptoops/sign.go:SignRequest`、`main.go:checkAdmin`、`secagg/aggregator.go:DefaultMaxConcurrency`、`attest-verify/verifier.go:VerifyQuote`）或 **`文件`**（无法定位单一符号者，如 `audit.go`、`guardrail.go`、`outputguard.go`），**不再附行号以抗漂移**；文档头固化该约定。**仅锚点形式变更，不改任何威胁事实、状态与分级**。 |
| v0.5 | 2026-10-05 | **A-1 闭环：GAP 立项回填**。§10.2 的 P1 安全加固类 GAP（02/03/04/06/09/10）已在研发计划立项为 **P1-8「安全加固（威胁模型 GAP 闭环）」**（§2.2 + §4.1 任务分解，owner 待指派）；「研发计划登记」列与 §10.2 追溯注同步更新。**仅追溯信息变更，不改威胁事实与分级**。 |
| v0.6 | 2026-10-05 | **P2/P3 余项全量收尾（12 项）**：S-5（§8.3 新增 `TG-R-04` 留存/删除权威胁）；S-6（§9.1 新增"密钥销毁"控制行）；A-3（新增 **§4.4 定级依据抽样**）；A-4（新增 §8.7 **攻击树 EO 摘要**）；C-4（新增 §3.4 **PIPL 条款映射**）；O-2（新增 **§9.8 威胁→可观测信号**）；O-4（新增 **附录 A.2 威胁全名单**）；P-1（新增 **§11.4 演示就绪判据**）；P-2（新增 **§11.5 威胁→客户 Q&A 索引**）；P-3（文档头增**对外可见性**）；D-2（§10.2 增 **GAP→验收测试锚点**）；D-3（§2.5 术语补 RFVM/REPORTDATA/MRTD 并统一大小写）。**至此第 1 轮评审全部 33 项（P0/P1/P2/P3）处置完毕。** |
| **v0.7** | **2026-10-06** | **系统性评审修复（6 项）**：① **P0 口径统一**：研发计划 §2.1/§3.6 与本文数字口径统一为「STRIDE 39 + 供应链 6 = 45 条 + LLM 特有 5 条（单列）」；② **P1 DFD 增强**：§5.1 新增「数据流详表」（DF-1~6，含方向/协议/端口/穿越边界/敏感度 6 维度，新增 DF-6 密码运算调用）；③ **P1 SLSA 路线**：§10.2 新增「SLSA 分阶段目标表」（4 阶段：L1 现状 → L2 全量 → L3 关键组件 → L4 金融级），明确 GAP-07 分阶段验收；④ **P1 GAP 回填机制**：新增 §11.3.1「GAP 回填与版本维护机制」（责任人/触发规则/DoD 5 项/版本号规则）；⑤ **P2 资产分级判据**：新增 §6.0「资产分级判据」（4 级 × CIA 三维度 + 4 条定级规则）；⑥ **P2 测试映射扩充**：§9.7 从「抽样 10 条」扩充为「全量 45 条威胁→测试映射表」，附覆盖率统计（当前 ~40%，P1 落地后可达 ~89%）与覆盖状态图例。**总条目数与威胁分级不变，仅补充框架与可追溯性内容。** |
