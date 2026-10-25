// P2-4 T-4.2：tee 侧审计链导出单测（导出可重算 / 只读 / 门控 / 锚点）。
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"security-ai-gateway/gateway/auditexport"
)

// teeAuditExportPath 导出端点路径（与 core 侧同构）。
const teeAuditExportPath = "/v1/internal/audit/chain/export"

// newTeeExportChain 构造含 n 条事件的内存审计链。
func newTeeExportChain(n int) *auditChain {
	c := newAuditChain()
	for i := 1; i <= n; i++ {
		c.append(AuditEvent{
			TenantID:   "tenant-a",
			RequestID:  fmt.Sprintf("req-%02d", i),
			Action:     "infer",
			TokensIn:   i,
			TokensOut:  i * 2,
			Result:     "ok",
			PayloadSHA: fmt.Sprintf("sha-%02d", i),
		})
	}
	return c
}

// TestTeeAuditExportRecompute **核心证据**：导出 → 独立重算 → 与链 verify() 结论一致。
func TestTeeAuditExportRecompute(t *testing.T) {
	c := newTeeExportChain(4)
	res, err := c.exportNDJSON(0)
	if err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	if res.Events != 4 || res.Total != 4 || res.Truncated || res.PrevHash != "" {
		t.Fatalf("全量导出元信息不符: %+v", res)
	}
	if len(res.Lines) != 4 {
		t.Fatalf("行数不符: %d", len(res.Lines))
	}
	// 行格式与 WORM 行序列化一致。
	worm, merr := json.Marshal(c.query("")[3])
	if merr != nil {
		t.Fatalf("序列化失败: %v", merr)
	}
	if res.Lines[3] != string(worm) {
		t.Fatalf("导出行与 WORM 行序列化不一致")
	}
	// 独立重算。
	body := []byte(strings.Join(res.Lines, "\n") + "\n")
	ok, n, verr := verifyAuditExport(body)
	if verr != nil || !ok || n != 4 {
		t.Fatalf("导出内容重算应自洽: ok=%v n=%d err=%v", ok, n, verr)
	}
	// 与链自身 verify 结论一致。
	cok, cn := c.verify()
	if cok != ok || cn != n {
		t.Fatalf("重算与链 verify 结论不一致: chain=(%v,%d) export=(%v,%d)", cok, cn, ok, n)
	}
	// 链尾哈希 = 末条事件哈希。
	last := c.query("")[3]
	want, werr := last.hashWithErr()
	if werr != nil {
		t.Fatalf("末条哈希计算失败: %v", werr)
	}
	if res.TailHash != want {
		t.Fatalf("链尾哈希不符: got %s want %s", res.TailHash, want)
	}
}

// TestTeeAuditExportTampered 导出内容被篡改 → 重算检出。
func TestTeeAuditExportTampered(t *testing.T) {
	c := newTeeExportChain(3)
	res, err := c.exportNDJSON(0)
	if err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	var e AuditEvent
	if err := json.Unmarshal([]byte(res.Lines[1]), &e); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	e.TenantID = "attacker-tenant" // 进 hash 域
	tampered, merr := json.Marshal(e)
	if merr != nil {
		t.Fatalf("序列化失败: %v", merr)
	}
	lines := append([]string{}, res.Lines...)
	lines[1] = string(tampered)
	ok, n, verr := verifyAuditExport([]byte(strings.Join(lines, "\n") + "\n"))
	if verr != nil {
		t.Fatalf("重算出错: %v", verr)
	}
	if ok {
		t.Fatalf("篡改后应检出链断裂")
	}
	if n != 2 { // 断裂于被篡改条目的下一条
		t.Fatalf("断裂应于第 3 条处检出（已通过 2 条）: got %d", n)
	}
}

// TestTeeAuditExportLimit limit 边界：截断保留最近 N 条 + PrevHash 可作重算起点。
func TestTeeAuditExportLimit(t *testing.T) {
	c := newTeeExportChain(5)
	res, err := c.exportNDJSON(2)
	if err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	if res.Events != 2 || res.Total != 5 || !res.Truncated || res.PrevHash == "" {
		t.Fatalf("截断导出元信息不符: %+v", res)
	}
	body := []byte(strings.Join(res.Lines, "\n") + "\n")
	ok, n, verr := verifyAuditExportFrom(body, res.PrevHash)
	if verr != nil || !ok || n != 2 {
		t.Fatalf("截断导出按 PrevHash 重算应自洽: ok=%v n=%d err=%v", ok, n, verr)
	}
	if ok2, _, _ := verifyAuditExport(body); ok2 {
		t.Fatalf("截断导出以空 prev 起始不应自洽")
	}
	// limit 超总长 = 全量。
	full, ferr := c.exportNDJSON(0)
	if ferr != nil {
		t.Fatalf("全量导出失败: %v", ferr)
	}
	over, oerr := c.exportNDJSON(99)
	if oerr != nil {
		t.Fatalf("超限导出失败: %v", oerr)
	}
	if strings.Join(full.Lines, "\n") != strings.Join(over.Lines, "\n") || over.Truncated {
		t.Fatalf("limit 超总长应与全量等价")
	}
	// 空链导出。
	empty := newAuditChain()
	eres, eerr := empty.exportNDJSON(0)
	if eerr != nil || eres.Events != 0 || eres.Total != 0 || eres.TailHash != "" {
		t.Fatalf("空链导出不符: %+v err=%v", eres, eerr)
	}
}

// TestTeeAuditExportReadOnly 导出只读：链状态不变、不触发锚定写入（WORM/锚定零污染）。
func TestTeeAuditExportReadOnly(t *testing.T) {
	dir := t.TempDir()
	c := newTeeExportChain(3)
	anchorPath := filepath.Join(dir, "audit.anchor")
	beforeLen := c.len()
	beforeOK, beforeN := c.verify()
	for _, l := range []int{0, 1, 2, 99} {
		if _, err := c.exportNDJSON(l); err != nil {
			t.Fatalf("导出(limit=%d)失败: %v", l, err)
		}
	}
	if c.len() != beforeLen {
		t.Fatalf("导出改变了链长度: %d → %d", beforeLen, c.len())
	}
	if ok, n := c.verify(); ok != beforeOK || n != beforeN {
		t.Fatalf("导出改变了链校验结论")
	}
	// 锚定文件不应被导出创建/写入（导出不得触发 anchorNow）。
	if _, serr := os.Stat(anchorPath); !os.IsNotExist(serr) {
		t.Fatalf("导出不得创建/写入锚定文件: stat err=%v", serr)
	}
}

// TestTeeLastAnchorRecord 只读读取锚定文件最后一条记录。
func TestTeeLastAnchorRecord(t *testing.T) {
	dir := t.TempDir()
	// 路径为空 / 文件不存在 → (nil, nil)（锚定未启用，非错误）。
	if rec, err := lastAnchorRecord(""); rec != nil || err != nil {
		t.Fatalf("空路径应返回 (nil,nil): rec=%v err=%v", rec, err)
	}
	missing := filepath.Join(dir, "nope.anchor")
	if rec, err := lastAnchorRecord(missing); rec != nil || err != nil {
		t.Fatalf("文件不存在应返回 (nil,nil): rec=%v err=%v", rec, err)
	}
	// 两条记录 → 取最后一条。
	p := filepath.Join(dir, "a.anchor")
	content := "{\"timestamp\":1,\"events\":1,\"chain_hash\":\"h1\"}\n{\"timestamp\":2,\"events\":2,\"chain_hash\":\"h2\"}\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("写锚定文件失败: %v", err)
	}
	rec, err := lastAnchorRecord(p)
	if err != nil {
		t.Fatalf("读取锚定记录失败: %v", err)
	}
	if rec == nil || rec.ChainHash != "h2" || rec.Events != 2 || rec.Timestamp != 2 {
		t.Fatalf("应取最后一条记录: %+v", rec)
	}
	// 损坏末行 → 错误（锚定序列损坏须可见）。
	bad := filepath.Join(dir, "bad.anchor")
	if err := os.WriteFile(bad, []byte("{\"timestamp\":1}\nnot-json\n"), 0o600); err != nil {
		t.Fatalf("写锚定文件失败: %v", err)
	}
	if _, err := lastAnchorRecord(bad); err == nil {
		t.Fatalf("损坏锚定行应返回错误")
	}
}

// TestTeeAuditExportHandlerGates 端点门控：默认关闭 404 / deny-all 403 / 白名单外 403 / 放行 200。
func TestTeeAuditExportHandlerGates(t *testing.T) {
	dir := t.TempDir()
	anchorPath := filepath.Join(dir, "a.anchor")
	if err := os.WriteFile(anchorPath, []byte("{\"timestamp\":9,\"events\":3,\"chain_hash\":\"\"}\n"), 0o600); err != nil {
		t.Fatalf("写锚定文件失败: %v", err)
	}
	c := newTeeExportChain(3)
	wl, err := auditexport.NewSourceWhitelist([]string{"192.0.2.1/32"}) // httptest 默认来源
	if err != nil {
		t.Fatalf("构造白名单失败: %v", err)
	}
	srvOK := &teeServer{
		audit:           c,
		auditAnchorPath: anchorPath,
		auditExportCfg: auditexport.Config{
			Enabled: true, Authorizer: auditexport.TokenAuthorizer{Token: "tok"},
			Whitelist: wl, MaxLimit: 10,
		},
	}
	do := func(s *teeServer, q, bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, teeAuditExportPath+q, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		s.handleAuditExport(rec, req)
		return rec
	}

	// 放行：200 + NDJSON + 元信息头。
	rec := do(srvOK, "", "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("授权+白名单内应 200: got %d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Fatalf("Content-Type 应为 NDJSON: %s", ct)
	}
	if got := rec.Header().Get(auditexport.HeaderPrefix + "Schema"); got != "tee" {
		t.Fatalf("schema 头应为 tee: %q", got)
	}
	if got := rec.Header().Get(auditexport.HeaderPrefix + "Events"); got != "3" {
		t.Fatalf("events 头应为 3: %q", got)
	}
	// 导出内容可重算。
	ok, n, verr := verifyAuditExport(rec.Body.Bytes())
	if verr != nil || !ok || n != 3 {
		t.Fatalf("导出内容重算应自洽: ok=%v n=%d err=%v", ok, n, verr)
	}

	// 默认关闭（端点未启用）→ 404。
	srvOff := &teeServer{audit: c, auditExportCfg: auditexport.Config{Enabled: false, Whitelist: wl}}
	if r := do(srvOff, "", "tok"); r.Code != http.StatusNotFound {
		t.Fatalf("未启用应 404: got %d", r.Code)
	}
	// deny-all（未注入授权实现）→ 403。
	srvDeny := &teeServer{audit: c, auditExportCfg: auditexport.Config{Enabled: true, Whitelist: wl}}
	if r := do(srvDeny, "", "tok"); r.Code != http.StatusForbidden {
		t.Fatalf("deny-all 应 403: got %d", r.Code)
	}
	// 令牌不匹配 → 403。
	if r := do(srvOK, "", "wrong"); r.Code != http.StatusForbidden {
		t.Fatalf("令牌不匹配应 403: got %d", r.Code)
	}
	// 来源不在白名单 → 403。
	wlOther, werr := auditexport.NewSourceWhitelist([]string{"10.0.0.0/8"})
	if werr != nil {
		t.Fatalf("构造白名单失败: %v", werr)
	}
	srvWL := &teeServer{audit: c, auditExportCfg: auditexport.Config{
		Enabled: true, Authorizer: auditexport.TokenAuthorizer{Token: "tok"}, Whitelist: wlOther,
	}}
	if r := do(srvWL, "", "tok"); r.Code != http.StatusForbidden {
		t.Fatalf("白名单外来源应 403: got %d", r.Code)
	}
	// 空白名单 = 拒绝所有来源（fail-closed）。
	srvEmpty := &teeServer{audit: c, auditExportCfg: auditexport.Config{
		Enabled: true, Authorizer: auditexport.TokenAuthorizer{Token: "tok"},
	}}
	if r := do(srvEmpty, "", "tok"); r.Code != http.StatusForbidden {
		t.Fatalf("空白名单应拒绝所有来源: got %d", r.Code)
	}
	// schema 口径：tee 放行；core → 400。
	if r := do(srvOK, "?schema=tee", "tok"); r.Code != http.StatusOK {
		t.Fatalf("schema=tee 应 200: got %d", r.Code)
	}
	if r := do(srvOK, "?schema=core", "tok"); r.Code != http.StatusBadRequest {
		t.Fatalf("schema=core 在 tee 侧应 400: got %d", r.Code)
	}
	// 非法 limit → 400。
	if r := do(srvOK, "?limit=-1", "tok"); r.Code != http.StatusBadRequest {
		t.Fatalf("负 limit 应 400: got %d", r.Code)
	}
	// 非 GET → 405。
	req := httptest.NewRequest(http.MethodPost, teeAuditExportPath, nil)
	rec = httptest.NewRecorder()
	srvOK.handleAuditExport(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("非 GET 应 405: got %d", rec.Code)
	}
	// 导出后链状态不变（只读）。
	if c.len() != 3 {
		t.Fatalf("导出改变了链长度: %d", c.len())
	}
	if ok2, n2 := c.verify(); !ok2 || n2 != 3 {
		t.Fatalf("导出后链校验结论不符: (%v,%d)", ok2, n2)
	}
}

// TestTeeAuditExportSetup 装配校验：空白名单/非法 CIDR → 错误（fail-closed 拒绝启动）。
func TestTeeAuditExportSetup(t *testing.T) {
	if _, err := setupTeeAuditExport("", "tok", 100); err == nil {
		t.Fatalf("空白名单应拒绝装配")
	}
	if _, err := setupTeeAuditExport("not-a-cidr", "tok", 100); err == nil {
		t.Fatalf("非法 CIDR 应拒绝装配")
	}
	cfg, err := setupTeeAuditExport("10.0.0.0/8, 192.168.1.1/32", "tok", 100)
	if err != nil {
		t.Fatalf("合法配置应装配成功: %v", err)
	}
	if !cfg.Enabled || cfg.MaxLimit != 100 || cfg.Whitelist.Empty() {
		t.Fatalf("装配结果不符: %+v", cfg)
	}
	// 白名单语义：允许 10.0.0.5、拒绝 192.0.2.1。
	if !cfg.Whitelist.Allows(ipOf(t, "10.0.0.5")) {
		t.Fatalf("10.0.0.5 应在白名单内")
	}
	if cfg.Whitelist.Allows(ipOf(t, "192.0.2.1")) {
		t.Fatalf("192.0.2.1 不应在白名单内")
	}
	// maxLimit<=0 → 默认上限。
	cfg2, err := setupTeeAuditExport("10.0.0.0/8", "", 0)
	if err != nil {
		t.Fatalf("装配失败: %v", err)
	}
	if cfg2.MaxLimit != auditexport.DefaultMaxLimit {
		t.Fatalf("maxLimit 应回退默认值: %d", cfg2.MaxLimit)
	}
	// 空令牌 → deny-all。
	if err := cfg2.Authorizer.Authorize(httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Fatalf("空令牌应 deny-all")
	}
}

// ipOf 解析测试用 IP。
func ipOf(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("解析 IP 失败: %s", s)
	}
	return ip
}
