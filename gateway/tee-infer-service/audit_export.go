// P2-4 T-4.2：tee 侧审计链导出端点（NDJSON + 锚点，与 core 侧同构）。
//
// 路径口径（与 core 侧、T-4.1 聚合侧一致）：
//
//	GET /v1/internal/audit/chain/export?schema=tee&limit=N
//
// 安全边界（S1(6)，复用 gateway/auditexport 与 core 侧同一套实现）：
//  1. **默认关闭**：仅当 -audit-export-enabled 时注册路由；未启用 → 404；
//  2. **授权钩子**：auditexport.Authorizer，**默认 deny-all**（fail-closed）；
//     真实实现由 **T-2.3 集群身份凭证** 注入（接线点：main.go setupTeeAuditExport →
//     auditexport.Config.Authorizer），本任务不实现凭证本身；
//  3. **网络边界**：来源 IP CIDR 白名单（-audit-export-cidrs；空 = 拒绝所有来源），
//     来源只取 RemoteAddr，不信任 X-Forwarded-For。
//
// 只读语义：只读取链快照与锚定文件，**不落 WORM、不触发 anchorNow()**，
// 保证 WORM 链与锚定序列不被导出污染。
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"security-ai-gateway/gateway/auditexport"
)

// auditExportSchema tee 侧 schema 标识（T-4.1 聚合侧口径：admin|tee|core）。
const auditExportSchema = "tee"

// auditExportResult 只读导出结果（NDJSON + 链尾/锚点元信息）。
type auditExportResult struct {
	Lines     []string // 每行一条事件（json.Marshal(AuditEvent)，与 WORM 行格式一致）
	Events    int
	Total     int
	PrevHash  string // 导出区间首条的前链哈希（全量 = ""）
	TailHash  string // 链尾哈希（空链 = ""）
	Truncated bool   // 是否因 limit 截断
}

// exportNDJSON 只读导出审计链快照（limit <= 0 = 全量，受调用方上限保护）。
//
// 截断语义与 core 侧一致：保留**最近** limit 条 ⇒ TailHash 恒为链尾哈希；
// 截断导出的 PrevHash 非 ""，独立重算须以该值为起始 prev。
// 只读保证：不加任何写路径（不 append、不 anchorNow、不改 lastHex）。
func (c *auditChain) exportNDJSON(limit int) (auditExportResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := len(c.events)
	start := 0
	if limit > 0 && total > limit {
		start = total - limit
	}
	sel := c.events[start:]
	prev := ""
	if start > 0 {
		h, err := c.events[start-1].hashWithErr()
		if err != nil {
			return auditExportResult{}, fmt.Errorf("audit: 导出区间前驱事件哈希不可算: %w", err)
		}
		prev = h
	}
	tail := ""
	if len(sel) > 0 {
		h, err := sel[len(sel)-1].hashWithErr()
		if err != nil {
			return auditExportResult{}, fmt.Errorf("audit: 链尾事件哈希不可算: %w", err)
		}
		tail = h
	}
	lines := make([]string, 0, len(sel))
	for i := range sel {
		b, err := json.Marshal(sel[i])
		if err != nil {
			return auditExportResult{}, fmt.Errorf("audit: 事件序列化失败: %w", err)
		}
		lines = append(lines, string(b))
	}
	return auditExportResult{
		Lines:     lines,
		Events:    len(sel),
		Total:     total,
		PrevHash:  prev,
		TailHash:  tail,
		Truncated: start > 0,
	}, nil
}

// verifyAuditExport 对导出内容独立重算哈希链（全量导出口径：起始 prev = ""）。
func verifyAuditExport(ndjson []byte) (bool, int, error) {
	return verifyAuditExportFrom(ndjson, "")
}

// verifyAuditExportFrom 同 verifyAuditExport，但指定起始 prev（**截断导出**重算用，
// prev 取自 auditExportResult.PrevHash）。
//
// ⚠️ 截断导出只能证明区间内自洽；与创世块的衔接由链尾哈希与锚点比对完成。
func verifyAuditExportFrom(ndjson []byte, prev string) (bool, int, error) {
	scanner := bufio.NewScanner(bytes.NewReader(ndjson))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	n := 0
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var e AuditEvent
		if err := json.Unmarshal(line, &e); err != nil {
			return false, n, fmt.Errorf("audit: 导出第 %d 行解析失败: %w", n+1, err)
		}
		if e.PrevHash != prev {
			return false, n, nil
		}
		h, err := e.hashWithErr()
		if err != nil {
			return false, n, fmt.Errorf("audit: 导出第 %d 行哈希算法非法: %w", n+1, err)
		}
		prev = h
		n++
	}
	if err := scanner.Err(); err != nil {
		return false, n, fmt.Errorf("audit: 导出内容读取失败: %w", err)
	}
	return true, n, nil
}

// lastAnchorRecord 只读取锚定文件**最后一条**锚定记录。
//
// path 为空或文件不存在 → (nil, nil)（锚定未启用，非错误）。
// 末行解析失败 → 返回错误（锚定序列损坏，须可见——但导出本身仍可返回）。
func lastAnchorRecord(path string) (*AnchorRecord, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: 读取锚定文件失败: %w", err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var last *AnchorRecord
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec AnchorRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("audit: 锚定文件解析失败: %w", err)
		}
		recCopy := rec
		last = &recCopy
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("audit: 锚定文件读取失败: %w", err)
	}
	return last, nil
}

// setupTeeAuditExport 装配导出端点配置（**默认关闭**：仅 main 在
// -audit-export-enabled 时调用；未调用即不注册路由 → 404）。
//
// ⚠️ T-2.3 接线点：授权实现由 T-2.3「集群身份凭证（签发/校验/轮换/吊销）」提供
// （实现 auditexport.Authorizer），就绪后替换下方 TokenAuthorizer 临时口径：
//
//	cfg.Authorizer = clustercred.NewAuthorizer(...) // T-2.3 落地后替换
//
// 本任务不实现凭证本身；令牌为空时 TokenAuthorizer 即 deny-all。
func setupTeeAuditExport(cidrsRaw, token string, maxLimit int) (auditexport.Config, error) {
	wl, err := auditexport.NewSourceWhitelist(splitCSV(cidrsRaw))
	if err != nil {
		return auditexport.Config{}, err // CIDR 非法 → 拒绝启动（fail-closed）
	}
	if wl.Empty() {
		return auditexport.Config{}, errors.New("audit: -audit-export-cidrs 为空：白名单空 = 拒绝所有来源（请显式配置来源 CIDR 或关闭导出端点）")
	}
	if maxLimit <= 0 {
		maxLimit = auditexport.DefaultMaxLimit
	}
	return auditexport.Config{
		Enabled:   true,
		Whitelist: wl,
		MaxLimit:  maxLimit,
		// 临时联调口径（T-2.3 前）：令牌为空 → deny-all。
		Authorizer: auditexport.TokenAuthorizer{Token: token},
	}, nil
}

// auditExportAuthState 启动日志用：区分"已注入静态令牌"与"deny-all（待 T-2.3）"。
func auditExportAuthState(cfg auditexport.Config) string {
	if tk, ok := cfg.Authorizer.(auditexport.TokenAuthorizer); ok && tk.Token != "" {
		return "静态令牌（临时，待 T-2.3 集群凭证替换）"
	}
	return "deny-all（待 T-2.3 集群凭证）"
}

// splitCSV 按逗号切分并去空白（空串 → nil）。
func splitCSV(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// handleAuditExport 导出审计链（NDJSON，每行一条事件）+ 链尾/锚点响应头。
//
// body = 纯 NDJSON（与 WORM 行格式逐字节一致，可供 audit-verify 独立重算）；
// 元信息经 X-Audit-Export-* 响应头下发（与 core 侧同构字段）。
func (s *teeServer) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		auditexport.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "仅支持 GET")
		return
	}
	// 门控：未启用 → 404；授权失败 / 来源不在白名单 → 403（不回显具体原因）。
	if err := s.auditExportCfg.Check(r); err != nil {
		if errors.Is(err, auditexport.ErrDisabled) {
			auditexport.WriteError(w, http.StatusNotFound, "not_found", "端点未启用")
			return
		}
		auditexport.WriteError(w, http.StatusForbidden, "forbidden", "导出请求未被授权")
		return
	}
	schema := r.URL.Query().Get("schema")
	if schema == "" {
		schema = auditExportSchema
	}
	if schema != auditExportSchema {
		auditexport.WriteError(w, http.StatusBadRequest, "bad_schema", "schema 必须为 tee")
		return
	}
	limit, clamped, err := auditexport.ParseLimit(r.URL.Query().Get("limit"), s.auditExportCfg.MaxLimit)
	if err != nil {
		auditexport.WriteError(w, http.StatusBadRequest, "bad_limit", "limit 参数非法")
		return
	}
	res, err := s.audit.exportNDJSON(limit)
	if err != nil {
		auditexport.WriteError(w, http.StatusInternalServerError, "export_failed", "审计链导出失败")
		return
	}
	meta := auditexport.Meta{
		Schema:    auditExportSchema,
		Events:    res.Events,
		Total:     res.Total,
		PrevHash:  res.PrevHash,
		TailHash:  res.TailHash,
		Truncated: res.Truncated || clamped,
	}
	// 锚点：锚定文件最后一条记录（只读）。读取失败仅告警——导出内容本身仍可用，
	// 锚点缺失/损坏须由聚合侧可见（字段留空即"无锚点"）。
	if rec, aerr := lastAnchorRecord(s.auditAnchorPath); aerr != nil {
		log.Printf("[audit] 导出：锚定记录读取失败（锚点信息留空）: %v", aerr)
	} else if rec != nil {
		meta.AnchorHash = rec.ChainHash
		meta.AnchorAt = rec.Timestamp
		meta.AnchorEvents = rec.Events
		meta.AnchorVerified = rec.ChainHash == res.TailHash
	}
	auditexport.WriteNDJSON(w, res.Lines, meta)
}
