// Package main — N6 · Higress 插件组合编排（§4.3.6，V-S1/V-S9）。
//
// 职责：按场景（S1/S2/S3-a/S3-b/S4）维护插件组合模板，支持渲染（供 N1 向导写入
// 表 ⑧ plugin_set）、租户级差异对比、冲突预检与复用率口径。
//
// 模板资产化（v1.7）：基线以 YAML 落 deploy/tenant-plugins/*.yaml（随部署版本管理、
// CI 校验 schema），本文件以 Go 常量内置同一份内容；tenant_plugin_test.go 断言
// 磁盘资产 == 内置常量，防止两者漂移。不引外部文件依赖，避免声明口径与二进制不同步。
//
// 链序（§4.3.6，v1.5 修正）：密态轨须段①先解密——otpmask 必须排在 ai-proxy
// 协议转换/出口之前；S1 明文轨无 otpmask。
//   - S1     ：cors → key-auth → ip-restriction → local-rate-limit → ai-proxy → 路由
//   - S2/S3/S4：… → local-rate-limit → otpmask → ai-proxy → 路由
//
// 复用率（V-S9，v1.7 明确）：复用插件覆盖的治理面能力数 / §5.3.2 治理面能力总数，
// 验收线 ≥ 70%；段①/Guardrail/语义缓存（密态轨）/审计链/远程证明/国密为结构不可复用项，
// 不计入分母。
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// pluginTemplateVersion N6 插件组合模板版本（记入表 ⑧ template_version）。
const pluginTemplateVersion = "n6-v1"

// scenarioS1..S4 场景常量（S3 拆 a/b 两态，S5 暂缓不可选）。
const (
	scenarioS1  = "s1"
	scenarioS2  = "s2"
	scenarioS3a = "s3a"
	scenarioS3b = "s3b"
	scenarioS4  = "s4"
)

// segment2Mode* 段② 形态（对齐 §3.5 表 ⑧ CHECK 约束）。
const (
	segment2None             = "none"
	segment2VendorSDK        = "vendor_sdk"
	segment2EnclavePlaintext = "enclave_plaintext"
	segment2CrossNodeMTLS    = "cross_node_mtls"
	segment2CiphertextDomain = "ciphertext_domain"
)

// accessModeASegmented v1.6 锁定：恒 A 型（网关侧治理、分段密态）；B 型/端到端禁选。
const accessModeASegmented = "a_segmented"

// pluginEntry 插件组合中的单个插件（名 + 执行序 + 参数）。
type pluginEntry struct {
	Name   string            `yaml:"name" json:"name"`
	Order  int               `yaml:"order" json:"order"`
	Params map[string]string `yaml:"params,omitempty" json:"params,omitempty"`
}

// pluginTemplate N6 插件组合基线模板（一份 YAML ↔ 一个场景）。
type pluginTemplate struct {
	TemplateVersion string        `yaml:"template_version"`
	Scenario        string        `yaml:"scenario"`
	Segment1        bool          `yaml:"segment1"`
	Segment2Mode    string        `yaml:"segment2_mode,omitempty"`
	Note            string        `yaml:"note,omitempty"`
	Chain           []pluginEntry `yaml:"chain"`
}

// scenarioSpec 场景 → 开通字段推导（N1 向导接入形态"场景推导只读"，§4.3.1）。
// access_mode 恒 a_segmented（S1=明文域治理，S2=强制分段密态，S3/S4=同族）。
type scenarioSpec struct {
	Segment1     bool
	Segment2Mode string
	AccessMode   string
}

// scenarioSpecs 场景矩阵（§3.6.2 矩阵口径；S5 暂缓不在此表）。
var scenarioSpecs = map[string]scenarioSpec{
	scenarioS1:  {Segment1: false, Segment2Mode: segment2None, AccessMode: accessModeASegmented},
	scenarioS2:  {Segment1: true, Segment2Mode: segment2VendorSDK, AccessMode: accessModeASegmented},
	scenarioS3a: {Segment1: true, Segment2Mode: segment2EnclavePlaintext, AccessMode: accessModeASegmented},
	scenarioS3b: {Segment1: true, Segment2Mode: segment2CrossNodeMTLS, AccessMode: accessModeASegmented},
	scenarioS4:  {Segment1: true, Segment2Mode: segment2CiphertextDomain, AccessMode: accessModeASegmented},
}

// lookupScenario 返回场景推导（ok=false = 未知/暂缓场景，拒绝提交 S5）。
func lookupScenario(scenario string) (scenarioSpec, bool) {
	spec, ok := scenarioSpecs[strings.ToLower(strings.TrimSpace(scenario))]
	return spec, ok
}

// knownScenarios 返回可开通场景（排序，供枚举/测试）。
func knownScenarios() []string {
	out := make([]string, 0, len(scenarioSpecs))
	for s := range scenarioSpecs {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ---------- 基线资产（内置常量，与 deploy/tenant-plugins/*.yaml 逐字节同步）----------

const s1PluginYAML = `# GA-AI 网关 · 租户插件组合基线（N6，§4.3.6 / §3.6.2）
# 场景：S1 通用模型（明文轨）——无段① otpmask；ai-proxy 直连 17 家 Provider。
# 链序（§4.3.6，v1.5 修正）：cors → key-auth → ip-restriction → local-rate-limit → ai-proxy → 路由
# 治理面插件集对齐 §3.6.2 S1 行：key-auth / ai-proxy / ai-statistics / ai-token-ratelimit /
# ai-quota / request-validation / ip-restriction / replay-protection。
template_version: n6-v1
scenario: s1
segment1: false
segment2_mode: none
note: "S1 明文轨：无 otpmask 段①，明文在客户可信域内受治理。"
chain:
- name: cors
  order: 10
- name: key-auth
  order: 20
  params:
    global_auth: "false"
- name: ip-restriction
  order: 30
- name: replay-protection
  order: 35
- name: local-rate-limit
  order: 40
- name: request-validation
  order: 50
- name: ai-quota
  order: 60
- name: ai-token-ratelimit
  order: 70
- name: ai-statistics
  order: 80
- name: ai-proxy
  order: 90
`

const s2PluginYAML = `# GA-AI 网关 · 租户插件组合基线（N6，§4.3.6 / §3.6.2）
# 场景：S2 第三方密态（A 型治理 + 厂商段②，强制分段密态）。
# 链序（§4.3.6，v1.5 修正）：cors → key-auth → ip-restriction → local-rate-limit →
# otpmask → ai-proxy → 路由（段① inbound 解密须先于 ai-proxy 出口）。
# 关键：otpmask 必须先于 ai-proxy（后者需读明文 prompt 做协议转换）。
template_version: n6-v1
scenario: s2
segment1: true
segment2_mode: vendor_sdk
note: "S2：段② = 厂商 SDK 加密通道；本地仅作 A 型治理，不得宣称端到端密态。"
chain:
- name: cors
  order: 10
- name: key-auth
  order: 20
  params:
    global_auth: "false"
- name: ip-restriction
  order: 30
- name: replay-protection
  order: 35
- name: local-rate-limit
  order: 40
- name: otpmask
  order: 50
  params:
    direction: inbound
- name: request-validation
  order: 60
- name: ai-quota
  order: 70
- name: ai-token-ratelimit
  order: 80
- name: ai-statistics
  order: 90
- name: ai-proxy
  order: 100
`

const s3aPluginYAML = `# GA-AI 网关 · 租户插件组合基线（N6，§4.3.6 / §3.6.2）
# 场景：S3-a 自建密态（轴 B = 我方自建飞地；段② = 飞地内明文域）。
# 提示：-enclave tdx（TDX 机密 VM）+ GPU-CC（显存机密）为 S3-a 主张"明文不出飞地"的前提。
# 链序同 S2：otpmask 必须先于 ai-proxy。
template_version: n6-v1
scenario: s3a
segment1: true
segment2_mode: enclave_plaintext
note: "S3-a：飞地内明文域；可主张'明文不出飞地'（含显存须 GPU-CC）；-enclave tdx。"
chain:
- name: cors
  order: 10
- name: key-auth
  order: 20
  params:
    global_auth: "false"
- name: ip-restriction
  order: 30
- name: replay-protection
  order: 35
- name: local-rate-limit
  order: 40
- name: otpmask
  order: 50
  params:
    direction: inbound
- name: request-validation
  order: 60
- name: ai-quota
  order: 70
- name: ai-token-ratelimit
  order: 80
- name: ai-statistics
  order: 90
- name: ai-proxy
  order: 100
`

const s3bPluginYAML = `# GA-AI 网关 · 租户插件组合基线（N6，§4.3.6 / §3.6.2）
# 场景：S3-b 自建密态（段② = 跨节点 mTLS；多机多卡密态互联为业界空白 Q-9）。
# 约束：不能主张"整链在 TEE 内"；调度层（llm-d 等）接触明文须显式声明。
# 链序同 S2：otpmask 必须先于 ai-proxy。
template_version: n6-v1
scenario: s3b
segment1: true
segment2_mode: cross_node_mtls
note: "S3-b：跨节点 mTLS；明文不出扩展信任域，不能主张整链 TEE；调度层接触明文（Q-9）。"
chain:
- name: cors
  order: 10
- name: key-auth
  order: 20
  params:
    global_auth: "false"
- name: ip-restriction
  order: 30
- name: replay-protection
  order: 35
- name: local-rate-limit
  order: 40
- name: otpmask
  order: 50
  params:
    direction: inbound
- name: request-validation
  order: 60
- name: ai-quota
  order: 70
- name: ai-token-ratelimit
  order: 80
- name: ai-statistics
  order: 90
- name: ai-proxy
  order: 100
`

const s4PluginYAML = `# GA-AI 网关 · 租户插件组合基线（N6，§4.3.6 / §3.6.2）
# 场景：S4 路线2 密态向量（后端 = masked_vector；段② = 密文域）。
# 链序同 S2：otpmask 必须先于 ai-proxy。
template_version: n6-v1
scenario: s4
segment1: true
segment2_mode: ciphertext_domain
note: "S4：掩码向量后端（masked_vector）；段② = 密文域，同 S3 承诺边界。"
chain:
- name: cors
  order: 10
- name: key-auth
  order: 20
  params:
    global_auth: "false"
- name: ip-restriction
  order: 30
- name: replay-protection
  order: 35
- name: local-rate-limit
  order: 40
- name: otpmask
  order: 50
  params:
    direction: inbound
- name: request-validation
  order: 60
- name: ai-quota
  order: 70
- name: ai-token-ratelimit
  order: 80
- name: ai-statistics
  order: 90
- name: ai-proxy
  order: 100
`

// embeddedPluginTemplates 场景 → 基线 YAML（内置常量，与磁盘资产同步见测试）。
var embeddedPluginTemplates = map[string]string{
	scenarioS1:  s1PluginYAML,
	scenarioS2:  s2PluginYAML,
	scenarioS3a: s3aPluginYAML,
	scenarioS3b: s3bPluginYAML,
	scenarioS4:  s4PluginYAML,
}

// parsePluginTemplate 解析一段插件模板 YAML。
func parsePluginTemplate(raw string) (*pluginTemplate, error) {
	var t pluginTemplate
	dec := yaml.NewDecoder(strings.NewReader(raw))
	dec.KnownFields(false) // 容忍新增可选字段（前向兼容）
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("tenant: 解析插件模板 YAML: %w", err)
	}
	return &t, nil
}

// loadPluginTemplate 加载指定场景的内置基线模板（未知/暂缓场景 → 错误）。
func loadPluginTemplate(scenario string) (*pluginTemplate, error) {
	key := strings.ToLower(strings.TrimSpace(scenario))
	raw, ok := embeddedPluginTemplates[key]
	if !ok {
		return nil, fmt.Errorf("tenant: 未知场景 %q（S5 暂缓，不可开通）", scenario)
	}
	t, err := parsePluginTemplate(raw)
	if err != nil {
		return nil, err
	}
	if t.Scenario != key {
		return nil, fmt.Errorf("tenant: 模板场景错配（期望 %s，实得 %s）", key, t.Scenario)
	}
	return t, nil
}

// renderPluginSet 渲染场景插件组合（N1 向导 → 表 ⑧ plugin_set）。
// 返回：插件链、模板版本；预检不通过 → 拒绝（带回原因）。
func renderPluginSet(scenario string) ([]pluginEntry, string, error) {
	t, err := loadPluginTemplate(scenario)
	if err != nil {
		return nil, "", err
	}
	if err := precheckPluginSet(t); err != nil {
		return nil, "", err
	}
	return t.Chain, t.TemplateVersion, nil
}

// marshalPluginSet 序列化插件链为 JSON（表 ⑧ plugin_set 落库用）。
func marshalPluginSet(chain []pluginEntry) (string, error) {
	b, err := json.Marshal(chain)
	if err != nil {
		return "", fmt.Errorf("tenant: 序列化 plugin_set: %w", err)
	}
	return string(b), nil
}

// unmarshalPluginSet 反序列化表 ⑧ plugin_set。
func unmarshalPluginSet(raw string) ([]pluginEntry, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var chain []pluginEntry
	if err := json.Unmarshal([]byte(raw), &chain); err != nil {
		return nil, fmt.Errorf("tenant: 解析 plugin_set: %w", err)
	}
	return chain, nil
}

// ---------- 冲突预检（§4.3.6：同链两个限流类插件 / 缺失必需插件 → 拒绝并回带原因）----------

// pluginRequiredCore 治理面必需插件（§3.6.2 矩阵：S1 行 8 项 + cors 入口）。
var pluginRequiredCore = []string{
	"cors", "key-auth", "ip-restriction", "replay-protection",
	"request-validation", "ai-quota", "ai-token-ratelimit", "ai-statistics", "ai-proxy",
}

// pluginExclusiveClass 互斥类别：同类插件在同一链中最多 1 个（防"同链两个限流"等冲突）。
var pluginExclusiveClass = map[string]string{
	"local-rate-limit":       "rate-limit",
	"key-rate-limit":         "rate-limit",
	"cluster-key-rate-limit": "rate-limit",
	"ai-token-ratelimit":     "token-rate-limit",
	"ai-quota":               "quota",
	"opa":                    "policy-engine",
	"ai-security-guard":      "content-guard",
	"request-block":          "content-guard",
	"waf":                    "waf",
	"otpmask":                "segment1",
}

// precheckPluginSet 冲突/完整性预检（N6，交 N5 下发前的门禁）。
// 覆盖：① 缺失必需插件；② 同类互斥插件重复；③ 段① 开关与 otpmask 一致；
// ④ otpmask 必须先于 ai-proxy；⑤ 执行序唯一且升序。
func precheckPluginSet(t *pluginTemplate) error {
	if t == nil {
		return errors.New("tenant: 插件模板为空")
	}
	if len(t.Chain) == 0 {
		return errors.New("tenant: 插件链为空")
	}

	present := make(map[string]int, len(t.Chain)) // name → 出现次数
	classSeen := make(map[string]string)          // class → 首个插件名
	var reasons []string
	prevOrder := -1
	orderSeen := make(map[int]string)

	for _, p := range t.Chain {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			reasons = append(reasons, "存在空插件名")
			continue
		}
		// ⑤ 执行序唯一且升序
		if other, dup := orderSeen[p.Order]; dup {
			reasons = append(reasons, fmt.Sprintf("执行序 %d 重复（%s 与 %s）", p.Order, other, name))
		} else {
			orderSeen[p.Order] = name
		}
		if p.Order < prevOrder {
			reasons = append(reasons, fmt.Sprintf("执行序非升序：%s(order=%d)", name, p.Order))
		}
		prevOrder = p.Order
		// ② 同类互斥
		present[name]++
		if class, ok := pluginExclusiveClass[name]; ok {
			if first, dup := classSeen[class]; dup {
				reasons = append(reasons, fmt.Sprintf("同类插件冲突：%s 与 %s 同属 %s 类", first, name, class))
			} else {
				classSeen[class] = name
			}
		}
	}

	// ① 缺失必需插件
	for _, req := range pluginRequiredCore {
		if present[req] == 0 {
			reasons = append(reasons, fmt.Sprintf("缺失必需插件：%s", req))
		}
	}

	// ③ 段① 开关与 otpmask 一致
	hasOtp := present["otpmask"] > 0
	if t.Segment1 && !hasOtp {
		reasons = append(reasons, "segment1=true 但缺少 otpmask（段①）")
	}
	if !t.Segment1 && hasOtp {
		reasons = append(reasons, "segment1=false 却包含 otpmask（S1 明文轨无段①）")
	}

	// ④ otpmask 必须先于 ai-proxy（段①解密先于协议转换/出口）
	if hasOtp {
		var otpOrder, proxyOrder int
		for _, p := range t.Chain {
			switch p.Name {
			case "otpmask":
				otpOrder = p.Order
			case "ai-proxy":
				proxyOrder = p.Order
			}
		}
		if otpOrder >= proxyOrder {
			reasons = append(reasons, fmt.Sprintf("otpmask(order=%d) 必须早于 ai-proxy(order=%d)", otpOrder, proxyOrder))
		}
	}

	if len(reasons) > 0 {
		return fmt.Errorf("tenant: 插件组合预检失败：%s", strings.Join(reasons, "；"))
	}
	return nil
}

// diffPluginSet 计算期望链与租户当前 chain 的差异（N6 差异对比；租户覆盖全局默认）。
// 返回 added/removed/changed（按插件名）。
func diffPluginSet(desired, current []pluginEntry) pluginSetDiff {
	cur := make(map[string]pluginEntry, len(current))
	for _, p := range current {
		cur[p.Name] = p
	}
	des := make(map[string]pluginEntry, len(desired))
	for _, p := range desired {
		des[p.Name] = p
	}
	var d pluginSetDiff
	for _, p := range desired {
		old, ok := cur[p.Name]
		if !ok {
			d.Added = append(d.Added, p.Name)
			continue
		}
		if old.Order != p.Order {
			d.Changed = append(d.Changed, p.Name)
		}
	}
	for _, p := range current {
		if _, ok := des[p.Name]; !ok {
			d.Removed = append(d.Removed, p.Name)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	sort.Strings(d.Changed)
	d.InSync = len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
	return d
}

// pluginSetDiff 插件组合差异（N6）。
type pluginSetDiff struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	Changed []string `json:"changed"`
	InSync  bool     `json:"in_sync"`
}

// ---------- 复用率口径（V-S9）----------

// governanceCapability §5.3.2 治理面能力 → Higress 插件映射。
// Reused：本方案复用（含"复用现有/复用底座"）；Structural：§5.3.3 结构不可复用项，
// 不计入分母。
type governanceCapability struct {
	Name       string // 能力
	Plugin     string // Higress 插件/复用点
	Reused     bool
	Structural bool
}

// governanceCapabilities §5.3.2 全 16 项能力（顺序对齐原表行号）。
var governanceCapabilities = []governanceCapability{
	{"租户身份入口认证", "key-auth", true, false},         // 1
	{"租户 JWT（tenant claim）", "auth-service HS256", true, false}, // 2 复用现有
	{"SSO / OIDC", "oidc", false, false},                  // 3 Phase 3 增强候选
	{"外部 IdP / IAM", "external-auth", false, false},     // 4 增强候选
	{"Token 限流 / 并发", "ai-token-ratelimit", true, false}, // 5
	{"配额（日/月/模型/Tier）", "ai-quota", true, false},     // 6 复用底座
	{"用量统计", "ai-statistics", true, false},             // 7 复用底座
	{"模型代理 / 协议转换", "ai-proxy", true, false},         // 8
	{"请求参数校验", "request-validation", true, false},      // 9
	{"IP 黑白名单", "ip-restriction", true, false},           // 10
	{"防重放", "replay-protection", true, false},             // 11
	{"内容安全（Guardrail）", "ai-security-guard/qwen3guard", false, true}, // 12 结构不可复用
	{"敏感数据脱敏（Guardrail）", "ai-data-masking", false, true},          // 13 结构不可复用
	{"复杂策略外置", "opa", false, false},                    // 14 增强候选
	{"数据出境地域策略", "geo-ip", true, false},               // 15 复用候选
	{"WAF / 防爬", "waf/bot-detect/request-block", false, false}, // 16 按需
}

// higressReuseRate 计算治理面插件复用率（V-S9：≥ 70%）。
// 返回 rate、复用能力数、计入分母的能力总数。
func higressReuseRate() (float64, int, int) {
	reused, denom := 0, 0
	for _, c := range governanceCapabilities {
		if c.Structural {
			continue
		}
		denom++
		if c.Reused {
			reused++
		}
	}
	if denom == 0 {
		return 0, 0, 0
	}
	return float64(reused) / float64(denom), reused, denom
}

// pluginReusePassing 复用率是否达验收线（≥ 70%）。
func pluginReusePassing() bool {
	rate, _, _ := higressReuseRate()
	return rate >= 0.70
}
