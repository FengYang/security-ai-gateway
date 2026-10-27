// Package main — 模型目录只读端点（M2 A-1'）。
//
// 设计：docs/管理门户-M2剩余项重排计划.md §3 A-1'。
//
// 数据源（均为控制面实时运行态，higress-standalone/ bind-mount 只读）：
//   - ai-proxy CR：spec.defaultConfig.providers[]（id/type/protocol/openaiCustomUrl/
//     有无 apiTokens）——与漂移检测同源（ADMIN_BROKER_CR_FILE）；
//   - ai-route ConfigMap 目录：data.data 单行 JSON（路径/模型谓词、上游与权重、模型映射）。
//
// 解析策略（零外部依赖，go.mod 不引入 YAML 库）：CR 用行扫描 + 正则（与
// broker_secret.go detectOrphans 同风格）；ai-route 的 data.data 为单行 JSON，
// 直接走 encoding/json（未知字段忽略，向前兼容）。
//
// 完成定义对齐（重排计划 §3 A-1'）：
//   - 只读，任意已认证会话可读（requireReadAccess，auditor 亦可）；
//   - 无 CR / 目录缺失 / 单文件损坏 → 200 空列表或跳过（日志告警，不报错）。
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// modelsAPIBase 模型目录端点（经控制台 AdminExtProxyController 通用转发暴露）。
const modelsAPIBase = "/v1/adminext/models"

// defaultAIRoutesDir ai-route ConfigMap 目录缺省值（控制面实时运行态，随仓库根运行）。
const defaultAIRoutesDir = "higress-standalone/configmaps"

// ---------- 配置 ----------

// modelCatalogSettings 模型目录数据源配置。
type modelCatalogSettings struct {
	crFile    string // ai-proxy CR 文件（与漂移检测同源：ADMIN_BROKER_CR_FILE）
	routesDir string // ai-route ConfigMap 目录（ADMIN_SVC_AI_ROUTES_DIR）
}

// loadModelCatalogSettings 加载模型目录配置（env 注入，带缺省）。
func loadModelCatalogSettings() *modelCatalogSettings {
	s := &modelCatalogSettings{
		crFile:    os.Getenv("ADMIN_BROKER_CR_FILE"),
		routesDir: os.Getenv("ADMIN_SVC_AI_ROUTES_DIR"),
	}
	if s.routesDir == "" {
		s.routesDir = defaultAIRoutesDir
	}
	return s
}

// ---------- ai-proxy CR 解析（行扫描）----------

// aiProxyProvidersKeyRe 定位 spec.defaultConfig.providers 键行。
//
// managedFields 中的 "f:providers: {}" 不以 providers: 起始，不会误匹配；
// matchRules[].config.provider（gitops 基线形态，单数）亦不匹配。
var aiProxyProvidersKeyRe = regexp.MustCompile(`^(\s*)providers:\s*(\S.*)?$`)

// crProviderEntry ai-proxy CR 中单个 provider 条目（仅目录所需字段，**不存 token 值**）。
type crProviderEntry struct {
	ID              string
	Type            string
	Protocol        string
	OpenaiCustomURL string
	HasTokens       bool // apiTokens 列表非空 = CR 仍存明文 Key（迁移前形态）
}

// parseAIProxyProviders 行扫描解析 ai-proxy CR 的 spec.defaultConfig.providers。
//
// 目标形态（控制台受管，Kubernetes Java Client 生成，缩进稳定）：
//
//	providers:
//	- apiTokens:
//	  - sk-xxx
//	  id: phala
//	  openaiCustomUrl: https://...
//	- id: phala-broker
//	  openaiCustomUrl: http://.../llm-broker/phala/...
//
// 列表条目与 providers: 同缩进（条目首属性位于 "- " 之后），属性/嵌套列表项
// 再缩进一级。条目缺 id 不入结果；token 行仅判非空，值不进入任何结构。
func parseAIProxyProviders(raw string) map[string]*crProviderEntry {
	out := make(map[string]*crProviderEntry)
	lines := strings.Split(raw, "\n")
	start := -1
	for i, ln := range lines {
		m := aiProxyProvidersKeyRe.FindStringSubmatch(strings.TrimRight(ln, "\r"))
		if m == nil {
			continue
		}
		if strings.TrimSpace(m[2]) != "" {
			return out // 行内空列表（providers: []）= 无条目
		}
		start = i
		break
	}
	if start < 0 {
		return out
	}

	var cur *crProviderEntry
	itemIndent := -1
	inTokens := false
	flush := func() {
		if cur != nil && cur.ID != "" {
			out[cur.ID] = cur
		}
		cur = nil
	}
	for _, ln := range lines[start+1:] {
		ln = strings.TrimRight(ln, "\r")
		trimmed := strings.TrimSpace(ln)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(ln) - len(strings.TrimLeft(ln, " "))

		if itemIndent < 0 {
			// 尚未见条目：非 "- " 起始 = 列表为空或紧随同级键，列表结束
			if !strings.HasPrefix(trimmed, "-") {
				break
			}
			itemIndent = indent
		} else if indent < itemIndent {
			break // 回到更浅层级 = providers 列表结束
		}

		if indent == itemIndent {
			if !strings.HasPrefix(trimmed, "-") {
				break // 同缩进非列表项 = 列表结束（防御形态）
			}
			flush()
			cur = &crProviderEntry{}
			inTokens = false
			if rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "-")); rest != "" {
				cur.applyProperty(rest, &inTokens)
			}
			continue
		}

		// 更深缩进：条目属性或 apiTokens 块列表项
		if cur == nil {
			continue
		}
		if inTokens && strings.HasPrefix(trimmed, "-") {
			if v := strings.TrimSpace(strings.TrimPrefix(trimmed, "-")); v != "" {
				cur.HasTokens = true
			}
			continue
		}
		cur.applyProperty(trimmed, &inTokens)
	}
	flush()
	return out
}

// applyProperty 应用单条 "key: value" 属性（条目首属性可位于 "- " 之后）。
// 任何显式属性行都会终结 apiTokens 块上下文。
func (p *crProviderEntry) applyProperty(prop string, inTokens *bool) {
	*inTokens = false
	k, v, ok := strings.Cut(prop, ":")
	if !ok {
		return
	}
	k = strings.TrimSpace(k)
	v = strings.Trim(strings.TrimSpace(v), `"'`)
	switch k {
	case "id":
		p.ID = v
	case "type":
		p.Type = v
	case "protocol":
		p.Protocol = v
	case "openaiCustomUrl":
		p.OpenaiCustomURL = v
	case "apiTokens":
		switch {
		case v == "":
			*inTokens = true // 块列表形态，条目在后续行
		case v != "[]" && v != "null" && v != "~":
			p.HasTokens = true // 行内非空列表（防御形态）
		}
	}
}

// ---------- ai-route ConfigMap 解析 ----------

// aiRoutePredicate / aiRouteUpstream / aiRouteData 与控制台前端
// interfaces/ai-route.ts 的模型对齐（camelCase）。
type aiRoutePredicate struct {
	MatchType  string `json:"matchType"`
	MatchValue string `json:"matchValue"`
}

type aiRouteUpstream struct {
	Provider     string            `json:"provider"`
	Weight       int               `json:"weight"`
	ModelMapping map[string]string `json:"modelMapping"`
}

type aiRouteData struct {
	Name            string             `json:"name"`
	PathPredicate   *aiRoutePredicate  `json:"pathPredicate"`
	ModelPredicates []aiRoutePredicate `json:"modelPredicates"`
	Upstreams       []aiRouteUpstream  `json:"upstreams"`
}

// aiRouteLabelRe 判定 ConfigMap 是否为控制台受管 ai-route（label 行缩进任意）。
var aiRouteLabelRe = regexp.MustCompile(`(?m)^\s+higress\.io/config-map-type:\s*ai-route\s*$`)

// aiRouteDataRe 提取 data.data 单行 JSON（控制台以单引号标量写入；顶层 data: 无缩进不匹配）。
var aiRouteDataRe = regexp.MustCompile(`(?m)^\s+data:\s*'(.*)'\s*$`)

// loadAIRoutes 扫描目录装载全部 ai-route（文件名序，输出确定）。
//
// 目录不存在 → 空列表；非 ai-route 的 yaml（无 label）忽略；
// 单文件损坏（读失败/缺 data.data/JSON 非法）→ 日志告警跳过，不整体失败。
func loadAIRoutes(dir string) []aiRouteData {
	out := make([]aiRouteData, 0)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[models] ai-route 目录读取失败（按空目录呈现）：%v", err)
		}
		return out
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !(strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			log.Printf("[models] ai-route 文件读取失败 %s（跳过）：%v", name, err)
			continue
		}
		if !aiRouteLabelRe.Match(raw) {
			continue
		}
		m := aiRouteDataRe.FindSubmatch(raw)
		if m == nil {
			log.Printf("[models] ai-route 文件缺少 data.data 单行 JSON %s（跳过）", name)
			continue
		}
		var route aiRouteData
		if err := json.Unmarshal(m[1], &route); err != nil {
			log.Printf("[models] ai-route JSON 解析失败 %s（跳过）：%v", name, err)
			continue
		}
		out = append(out, route)
	}
	return out
}

// ---------- HTTP handler ----------

// modelCatalogHandler 模型目录只读端点。
type modelCatalogHandler struct {
	settings *modelCatalogSettings
}

// newModelCatalogHandler 装配模型目录 handler。
func newModelCatalogHandler(s *modelCatalogSettings) *modelCatalogHandler {
	return &modelCatalogHandler{settings: s}
}

// modelRouteEntry 模型目录行：一条 ai-route 上游（route × provider 绑定）。
type modelRouteEntry struct {
	Route             string            `json:"route"`             // ai-route 名称
	Path              string            `json:"path"`              // 路径前缀（PRE 谓词值）
	Models            []string          `json:"models"`            // 模型谓词值（空 = 不限模型）
	DefaultMapping    map[string]string `json:"defaultMapping"`    // 上游模型映射（原样展示）
	Provider          string            `json:"provider"`          // 上游 provider id
	ProviderType      string            `json:"providerType"`      // ai-proxy CR 声明 type
	ProviderProtocol  string            `json:"providerProtocol"`  // ai-proxy CR 声明 protocol
	ViaBroker         bool              `json:"viaBroker"`         // customUrl 指向 /llm-broker/（密态托管）
	HasPlaintextToken bool              `json:"hasPlaintextToken"` // CR 仍存明文 apiTokens
	Weight            int               `json:"weight"`            // 上游权重（多上游 failover）
	// 密态四字段（一等公民，缺省 unknown；由 confllm 注册表富化，老 CR 缺字段默认 unknown，§7.5）
	ConfidentialityClass string `json:"confidentialityClass"`
	Attestation          string `json:"attestation"`
	DataRetention        string `json:"dataRetention"`
	Deployment           string `json:"deployment"`
	// 举证三字段（PRD P0-3 举证边界）：均禁 omitempty —— 不得以「字段缺失」冒充通过。
	// AttestationVerdict 本期恒 unknown；VerificationStatus 本期恒 claim-unverified（§7.11 裁定：
	// wire 层一律输出 claim-unverified，内部结构保留中间态用于审计）；
	// Connectivity 恒 never-tested / pending-credential，无真实 integration 运行不写 smoke-ok。
	AttestationVerdict string `json:"attestationVerdict"`
	VerificationStatus string `json:"verificationStatus"`
	Connectivity       string `json:"connectivity"`
	// Verification 内部校验状态（审计用，保留 unverified / claim-with-reference-unverified
	// 中间态；wire 对外请以 VerificationStatus 为准）。
	Verification string `json:"verification"`
}

// modelCatalogResponse 模型目录响应。
type modelCatalogResponse struct {
	Routes []modelRouteEntry `json:"routes"`
}

// handleModels GET /v1/adminext/models：模型目录只读列表（A-1' 完成定义②：
// 无 CR / 目录缺失 → 200 空列表而非报错）。
func (h *modelCatalogHandler) handleModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireRule(w, r, epModels) {
		return
	}

	providers := h.loadProviders()
	routes := loadAIRoutes(h.settings.routesDir)

	out := make([]modelRouteEntry, 0)
	for _, rt := range routes {
		models := make([]string, 0, len(rt.ModelPredicates))
		for _, mp := range rt.ModelPredicates {
			if mp.MatchValue != "" {
				models = append(models, mp.MatchValue)
			}
		}
		path := ""
		if rt.PathPredicate != nil {
			path = rt.PathPredicate.MatchValue
		}
		for _, up := range rt.Upstreams {
			entry := modelRouteEntry{
				Route:          rt.Name,
				Path:           path,
				Models:         models,
				DefaultMapping: up.ModelMapping,
				Provider:       up.Provider,
				Weight:         up.Weight,
			}
			if p := providers[up.Provider]; p != nil {
				entry.ProviderType = p.Type
				entry.ProviderProtocol = p.Protocol
				entry.ViaBroker = strings.Contains(p.OpenaiCustomURL, brokerPathPrefix)
				entry.HasPlaintextToken = p.HasTokens
			}
			// 富化 4 密态字段（缺省 unknown；老 CR 无 confllm 匹配 → unknown，§7.5 / §7.11 B2）
			enrichWithConfidentiality(&entry)
			out = append(out, entry)
		}
	}
	writeJSON(w, http.StatusOK, modelCatalogResponse{Routes: out})
}

// loadProviders 读取 ai-proxy CR 并解析 providers（读不到 = 空目录语义，记日志不报错）。
func (h *modelCatalogHandler) loadProviders() map[string]*crProviderEntry {
	if h.settings.crFile == "" {
		return make(map[string]*crProviderEntry)
	}
	raw, err := os.ReadFile(h.settings.crFile)
	if err != nil {
		log.Printf("[models] ai-proxy CR 读取失败（按空目录呈现）：%v", err)
		return make(map[string]*crProviderEntry)
	}
	return parseAIProxyProviders(string(raw))
}
