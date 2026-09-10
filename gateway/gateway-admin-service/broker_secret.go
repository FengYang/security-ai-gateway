// Package main — broker 凭据托管端点（apiTokens Secret 化 M2 A-1）。
//
// 设计：docs/管理门户-apiTokens-Secret化-M2细化方案.md §2.1.5。
//
// 职责：
//
//	凭据 CRUD（GET 列表/详情、POST upsert、DELETE 删除）
//	文件 Secret 存储（每 provider 一个 .env，0600，**原子写入** tmp+rename）
//	配置热加载（10s 目录扫描 + 写后立即 reload，路由表原子切换）
//	漂移检测（CR 指向 broker 但 broker 无配置 → orphanDetected）
//
// 安全约束：
//   - Key 一律不回显（含 POST 2xx 响应），仅暴露不可逆的 8 位指纹供确认轮换生效；
//   - 写操作要求 role=admin（最小角色控制，见 auth.go）；
//   - Key 绝不入日志/错误信息；
//   - 空文件视为损坏（解析失败 → 保留旧配置），绝不因半写/清空而静默摘除 provider。
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// brokerAPIBase 凭据托管端点前缀（挂在 admin-ext 通用转发路径下）。
const brokerAPIBase = "/v1/adminext/broker-providers"

// 校验上限（env 与目录两种来源共用，见 config.go）。
const (
	maxProviderNameLen = 32
	minProviderKeyLen  = 8
	maxProviderKeyLen  = 4096
	maxPathPrefixes    = 16
	maxPathPrefixLen   = 128
	maxUpsertBodyBytes = 1 << 20 // 1MB，凭据体量远小于此
)

// brokerFileSuffix 凭据文件名后缀。
const brokerFileSuffix = ".env"

// reloadInterval 目录扫描周期（M2 §2.1.5：定时 reload）。
const reloadInterval = 10 * time.Second

// allowBrokerHTTP 是否允许 http 上游（缺省拒；仅本地联调显式开启）。
var allowBrokerHTTP = os.Getenv("ADMIN_BROKER_ALLOW_HTTP") == "true"

// readyzFailThreshold 连续重载失败达该次数即判 not ready（M2 A-2 /readyz 三态）。
const readyzFailThreshold = 3

// brokerSecretHandler 凭据托管端点集合。
type brokerSecretHandler struct {
	settings *brokerSettings
	broker   *brokerHandler

	mu         sync.Mutex // 保护 lastSig / failStreak（reloader goroutine 与 HTTP 写入并发访问）
	lastSig    string
	failStreak int // 连续重载失败次数（成功即清零）；≥readyzFailThreshold → /readyz 报 not ready
}

// newBrokerSecretHandler 装配凭据托管 handler。
func newBrokerSecretHandler(s *brokerSettings, b *brokerHandler) *brokerSecretHandler {
	return &brokerSecretHandler{settings: s, broker: b}
}

// healthy 连续重载失败未达阈值即视为健康（M2 A-2：/readyz 的 broker 维度）。
func (h *brokerSecretHandler) healthy() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.failStreak < readyzFailThreshold
}

// ---------- 响应/请求模型 ----------

// providerView 单个托管 provider 的对外视图（**不含 Key**）。
type providerView struct {
	Name           string `json:"name"`
	Upstream       string `json:"upstream"`
	PathCount      int    `json:"pathCount"`
	KeyFingerprint string `json:"keyFingerprint"` // SHA-256 前 8 位十六进制（不可逆推）
	UpdatedAt      string `json:"updatedAt,omitempty"`
}

// listResponse 列表响应（含漂移检测结果）。
type listResponse struct {
	Providers      []providerView `json:"providers"`
	OrphanDetected []string       `json:"orphanDetected,omitempty"`
}

// upsertRequest 写入/轮换请求体。
type upsertRequest struct {
	Upstream          string   `json:"upstream"`
	Key               string   `json:"key"`
	AllowPathPrefixes []string `json:"allowPathPrefixes"`
}

// upsertResponse 写入响应（返回 customUrl 供管理员复制到 Provider 页；**不回显 Key**）。
type upsertResponse struct {
	Name      string `json:"name"`
	CustomURL string `json:"customUrl"`
}

// deleteResponse 删除响应（含 CR 联动告警，M2 §2.1.5）。
type deleteResponse struct {
	Name              string   `json:"name"`
	AffectedProviders []string `json:"affectedProviders"`
	Warning           string   `json:"warning"`
}

// ---------- 文件 Secret 存储 ----------

// providerFileName provider 名 → 凭据文件名。
func providerFileName(name string) string { return name + brokerFileSuffix }

// providerFilePath provider 名 → 凭据文件全路径。
func providerFilePath(dir, name string) string { return filepath.Join(dir, providerFileName(name)) }

// keyFingerprint 计算 Key 指纹（SHA-256 前 8 位十六进制，不可逆推）。
func keyFingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:4])
}

// renderProviderFile 生成凭据文件内容（与 M1 环境变量命名保持一致）。
func renderProviderFile(name string, upstream string, key string, prefixes []string) string {
	upper := strings.ToUpper(name)
	var b strings.Builder
	fmt.Fprintf(&b, "ADMIN_BROKER_UPSTREAM_%s=%s\n", upper, upstream)
	fmt.Fprintf(&b, "ADMIN_BROKER_KEY_%s=%s\n", upper, key)
	fmt.Fprintf(&b, "ADMIN_BROKER_PATHS_%s=%s\n", upper, strings.Join(prefixes, ","))
	return b.String()
}

// writeProviderFile 原子写入凭据文件：tmp → fsync → rename，权限 0600。
//
// 原子性是硬要求（M2 A-1 A-4 处置）：避免扫描线程读到半写文件，也避免 truncate
// 产生的空文件被解析为"provider 不存在"而静默摘除内存配置。
func writeProviderFile(dir, name, upstream, key string, prefixes []string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("凭据目录创建失败: %w", err)
	}
	tmp := providerFilePath(dir, name) + ".tmp"
	final := providerFilePath(dir, name)

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("凭据临时文件创建失败: %w", err)
	}
	content := renderProviderFile(name, upstream, key, prefixes)
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("凭据写入失败: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("凭据落盘失败: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("凭据关闭失败: %w", err)
	}
	// 显式收紧权限（部分文件系统受 umask 影响）
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("凭据权限设置失败: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("凭据原子替换失败: %w", err)
	}
	return nil
}

// deleteProviderFile 删除凭据文件（不存在视为成功，保证 DELETE 幂等）。
func deleteProviderFile(dir, name string) error {
	err := os.Remove(providerFilePath(dir, name))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("凭据删除失败: %w", err)
	}
	return nil
}

// parseProviderFile 解析单个凭据文件（三键齐备方可；缺键 = 损坏，fail-closed）。
func parseProviderFile(path, name string) (*brokerProvider, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("凭据文件读取失败 %s: %w", name, err)
	}
	upper := strings.ToUpper(name)
	wantUpstream := "ADMIN_BROKER_UPSTREAM_" + upper
	wantKey := "ADMIN_BROKER_KEY_" + upper
	wantPaths := "ADMIN_BROKER_PATHS_" + upper

	var upstream, key, paths string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case wantUpstream:
			upstream = v
		case wantKey:
			key = v
		case wantPaths:
			paths = v
		}
	}
	// 缺键 = 文件为空/半写/被清空 → 报错（调用方保留旧配置，绝不静默摘除）
	if upstream == "" || key == "" {
		return nil, fmt.Errorf("凭据文件 %s 缺少必要字段（疑似空文件或写入未完成，fail-closed）", name)
	}

	var prefixes []string
	if paths != "" {
		prefixes = strings.Split(paths, ",")
	}
	if err := validateProviderName(name); err != nil {
		return nil, err
	}
	u, norm, err := parseProviderEntry(name, upstream, prefixes)
	if err != nil {
		return nil, err
	}
	if err := validateProviderKey(name, key); err != nil {
		return nil, err
	}
	return &brokerProvider{upstream: u, key: []byte(key), allowPathPrefixes: norm}, nil
}

// loadBrokerConfigFromDir 扫描凭据目录装配配置。
//
// 目录存在即接管：**空目录 = 合法 0 provider**（不回退环境变量，避免删除后被复活）。
// 任一文件损坏 → 整体报错（调用方保留旧配置，fail-closed，不做部分降级）。
func loadBrokerConfigFromDir(dir string) (*brokerConfig, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("凭据目录读取失败: %w", err)
	}
	providers := make(map[string]*brokerProvider)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), brokerFileSuffix) {
			continue
		}
		name := strings.TrimSuffix(e.Name(), brokerFileSuffix)
		p, err := parseProviderFile(filepath.Join(dir, e.Name()), name)
		if err != nil {
			return nil, err
		}
		providers[name] = p
	}
	return &brokerConfig{providers: providers}, nil
}

// dirSignature 目录指纹（name:mtime:size 排序拼接），用于判断是否需要 reload。
func dirSignature(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), brokerFileSuffix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return "", err
		}
		parts = append(parts, fmt.Sprintf("%s:%d:%d", e.Name(), info.ModTime().UnixNano(), info.Size()))
	}
	sort.Strings(parts)
	return strings.Join(parts, ";"), nil
}

// ---------- 热加载 ----------

// markFail 记录一次重载失败（累计指标 + 连续失败计数），供 /readyz 判定。
func (h *brokerSecretHandler) markFail() {
	metrics.incBrokerReloadFailed()
	h.mu.Lock()
	h.failStreak++
	h.mu.Unlock()
}

// markOK 标记一次重载成功（连续失败计数清零）。
func (h *brokerSecretHandler) markOK(sig string) {
	h.mu.Lock()
	h.failStreak = 0
	h.lastSig = sig
	h.mu.Unlock()
}

// reloadNow 立即重载配置并原子切换路由表；失败时保留旧配置并计数。
func (h *brokerSecretHandler) reloadNow() error {
	cfg, err := loadBrokerConfigFromDir(h.settings.secretsDir)
	if err != nil {
		h.markFail()
		log.Printf("[broker] 配置重载失败（保留旧配置，fail-closed）：%v", err)
		return err
	}
	h.broker.swap(cfg)

	sig, err := dirSignature(h.settings.secretsDir)
	if err == nil {
		h.markOK(sig)
	}
	log.Printf("[broker] 配置已重载：providers=%d", h.broker.providerCount())
	return nil
}

// startReloader 启动后台目录扫描（10s），目录变化即重载。
func (h *brokerSecretHandler) startReloader() {
	if sig, err := dirSignature(h.settings.secretsDir); err == nil {
		h.mu.Lock()
		h.lastSig = sig
		h.mu.Unlock()
	}
	go func() {
		t := time.NewTicker(reloadInterval)
		defer t.Stop()
		for range t.C {
			sig, err := dirSignature(h.settings.secretsDir)
			if err != nil {
				h.markFail() // 目录不可读同样计入连续失败（/readyz 判定依据）
				log.Printf("[broker] 目录扫描失败（保留旧配置）：%v", err)
				continue
			}
			h.mu.Lock()
			changed := sig != h.lastSig
			h.mu.Unlock()
			if !changed {
				continue
			}
			_ = h.reloadNow()
		}
	}()
}

// ---------- 漂移检测 ----------

// brokerCustomURLRe 从 CR 文本中提取 /llm-broker/{provider}/ 形态的引用。
var brokerCustomURLRe = regexp.MustCompile(`/llm-broker/([a-z0-9][a-z0-9-]*)/`)

// detectOrphans 扫描 ai-proxy CR 中指向 broker 但 broker 侧已无凭据的 provider。
//
// crFile 未配置时返回 nil（功能关闭）；读取失败返回错误（调用方降级为不展示，不阻断列表）。
func detectOrphans(crFile string, known map[string]struct{}) ([]string, error) {
	if crFile == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(crFile)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for _, m := range brokerCustomURLRe.FindAllStringSubmatch(string(raw), -1) {
		if _, ok := known[m[1]]; !ok {
			seen[m[1]] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// ---------- HTTP handlers ----------

// customURL 生成 provider 的 broker 端点地址（端口由配置决定，前端不硬编码）。
func (h *brokerSecretHandler) customURL(name string) string {
	return h.settings.publicBase + brokerPathPrefix + name + "/v1/chat/completions"
}

// handleList 列出全部托管 provider（GET，auditor 可读）。
func (h *brokerSecretHandler) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireReadAccess(w, r) {
		return
	}

	routes := h.broker.currentRoutes()
	names := make([]string, 0, len(routes))
	known := make(map[string]struct{}, len(routes))
	for name := range routes {
		names = append(names, name)
		known[name] = struct{}{}
	}
	sort.Strings(names)

	views := make([]providerView, 0, len(names))
	for _, name := range names {
		p := routes[name].p
		v := providerView{
			Name:           name,
			Upstream:       p.upstream.Scheme + "://" + p.upstream.Host,
			PathCount:      len(p.allowPathPrefixes),
			KeyFingerprint: keyFingerprint(p.key),
		}
		if info, err := os.Stat(providerFilePath(h.settings.secretsDir, name)); err == nil {
			v.UpdatedAt = info.ModTime().UTC().Format(time.RFC3339)
		}
		views = append(views, v)
	}

	resp := listResponse{Providers: views}
	orphans, err := detectOrphans(h.settings.crFile, known)
	if err != nil {
		// 漂移检测失败不阻断列表（如实降级：日志告警，字段留空）
		log.Printf("[broker] 漂移检测失败（降级为不展示）：%v", err)
	} else {
		resp.OrphanDetected = orphans
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleItem 处理 /v1/adminext/broker-providers/{name}：GET 详情 / POST upsert / DELETE 删除。
func (h *brokerSecretHandler) handleItem(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, brokerAPIBase+"/")
	if name == "" || strings.Contains(name, "/") {
		writeError(w, http.StatusNotFound, "provider 路径非法")
		return
	}
	if err := validateProviderName(name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !requireReadAccess(w, r) {
			return
		}
		h.getOne(w, name)
	case http.MethodPost, http.MethodPut:
		if !requireRole(w, r, roleAdmin) {
			return
		}
		h.upsert(w, r, name)
	case http.MethodDelete:
		if !requireRole(w, r, roleAdmin) {
			return
		}
		h.remove(w, r, name)
	default:
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET/POST/PUT/DELETE")
	}
}

// getOne 返回单个 provider 详情（不含 Key）。
func (h *brokerSecretHandler) getOne(w http.ResponseWriter, name string) {
	routes := h.broker.currentRoutes()
	route := routes[name]
	if route == nil {
		writeError(w, http.StatusNotFound, "provider 未托管: "+name)
		return
	}
	v := providerView{
		Name:           name,
		Upstream:       route.p.upstream.Scheme + "://" + route.p.upstream.Host,
		PathCount:      len(route.p.allowPathPrefixes),
		KeyFingerprint: keyFingerprint(route.p.key),
	}
	if info, err := os.Stat(providerFilePath(h.settings.secretsDir, name)); err == nil {
		v.UpdatedAt = info.ModTime().UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, v)
}

// upsert 新建或全量更新 provider 凭据（写操作，仅 admin）。
func (h *brokerSecretHandler) upsert(w http.ResponseWriter, r *http.Request, name string) {
	var req upsertRequest
	body := http.MaxBytesReader(w, r.Body, maxUpsertBodyBytes)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体解析失败: "+err.Error())
		return
	}
	if _, _, err := parseProviderEntry(name, req.Upstream, req.AllowPathPrefixes); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateProviderKey(name, req.Key); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	prefixes := req.AllowPathPrefixes
	if len(prefixes) == 0 {
		prefixes = defaultBrokerPathPrefixes
	}
	if err := writeProviderFile(h.settings.secretsDir, name, req.Upstream, req.Key, prefixes); err != nil {
		// 错误信息不含 Key（writeProviderFile 内仅包装路径/IO 错误）
		log.Printf("[broker] 凭据写入失败 provider=%s rid=%s: %v", name, r.Header.Get("X-Request-ID"), err)
		writeError(w, http.StatusInternalServerError, "凭据写入失败")
		return
	}
	if err := h.reloadNow(); err != nil {
		writeError(w, http.StatusInternalServerError, "凭据已落盘但配置重载失败（旧配置仍生效，请检查目录内容）")
		return
	}

	sub := operationSub(r)
	log.Printf("[adminext] 凭据写入 ok provider=%s sub=%s fingerprint=%s rid=%s",
		name, sub, keyFingerprint([]byte(req.Key)), r.Header.Get("X-Request-ID"))
	writeJSON(w, http.StatusOK, upsertResponse{Name: name, CustomURL: h.customURL(name)})
}

// remove 删除 provider 凭据（写操作，仅 admin），返回 CR 联动告警。
func (h *brokerSecretHandler) remove(w http.ResponseWriter, r *http.Request, name string) {
	if h.broker.currentRoutes()[name] == nil {
		writeError(w, http.StatusNotFound, "provider 未托管: "+name)
		return
	}
	if err := deleteProviderFile(h.settings.secretsDir, name); err != nil {
		log.Printf("[broker] 凭据删除失败 provider=%s rid=%s: %v", name, r.Header.Get("X-Request-ID"), err)
		writeError(w, http.StatusInternalServerError, "凭据删除失败")
		return
	}
	if err := h.reloadNow(); err != nil {
		writeError(w, http.StatusInternalServerError, "凭据已删除但配置重载失败（请检查目录内容）")
		return
	}

	// CR 联动告警（M2 §2.1.5）：broker 侧删除不自动改 CR，须显式提示管理员。
	affected := []string{}
	if orphans, err := detectOrphans(h.settings.crFile, map[string]struct{}{}); err == nil {
		for _, o := range orphans {
			if o == name {
				affected = append(affected, name)
				break
			}
		}
	}
	resp := deleteResponse{
		Name:              name,
		AffectedProviders: affected,
		Warning:           "CR 中仍有 provider 指向本托管端点，删除后其推理将返回 404；请在控制台一并停用或改回直连",
	}
	log.Printf("[adminext] 凭据删除 ok provider=%s sub=%s affected=%v rid=%s",
		name, operationSub(r), affected, r.Header.Get("X-Request-ID"))
	writeJSON(w, http.StatusOK, resp)
}

// operationSub 取当前操作人登录名（审计留痕用）。
func operationSub(r *http.Request) string {
	if c := claimsFrom(r.Context()); c != nil {
		return c.Sub
	}
	return ""
}

// writeJSON 输出 JSON 响应（统一 Content-Type）。
func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeError 输出错误响应（**不得包含敏感值**）。
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
