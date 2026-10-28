// audit_test.go — G1 管理面审计链单测（apiTokens Secret 化 M2）。
//
// 覆盖：哈希链接（PrevHash 链式）、WORM 重启恢复、篡改检测（历史事件被改 → 启动报链断裂）、
// 写入失败 fail-closed（内存链不推进，避免 PrevHash 悬空）、未配置关闭、锚定文件、
// upsert/remove 端到端落链与审计写失败拒绝 2xx。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newAuditTestChain 构造指向临时目录的审计链。
func newAuditTestChain(t *testing.T, anchor bool) *adminAuditChain {
	t.Helper()
	file := filepath.Join(t.TempDir(), "audit.jsonl")
	anchorFile := ""
	if anchor {
		anchorFile = filepath.Join(t.TempDir(), "anchor.jsonl")
	}
	c, err := newAdminAuditChain(file, anchorFile)
	if err != nil {
		t.Fatalf("newAdminAuditChain: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestAdminAuditChainCountAction 验证 P2-5 job 对账计数：Tenant/Action 精确匹配 +
// 时间窗闭区间过滤；空 action 不退化成全量；nil 链 fail-safe 返回 (0, nil)。
func TestAdminAuditChainCountAction(t *testing.T) {
	c := newAuditTestChain(t, false)
	now := time.Now().UnixNano()
	hour := int64(time.Hour)

	append := func(tenant, action string) {
		t.Helper()
		if err := c.append(adminAuditEvent{Tenant: tenant, Action: action}); err != nil {
			t.Fatalf("append(%s,%s): %v", tenant, action, err)
		}
	}
	append("t1", "confllm_graph_submit")
	append("t1", "confllm_graph_submit")
	append("t1", "other_action")
	append("t2", "confllm_graph_submit")

	ctx := context.Background()
	cases := []struct {
		name   string
		tenant string
		action string
		fromNs int64
		toNs   int64
		want   int64
	}{
		{"t1 graph_submit 全窗口", "t1", "confllm_graph_submit", now - hour, now + hour, 2},
		{"t2 graph_submit 全窗口", "t2", "confllm_graph_submit", now - hour, now + hour, 1},
		{"t1 other_action", "t1", "other_action", now - hour, now + hour, 1},
		{"空 action 精确匹配（不退化全量）", "t1", "", now - hour, now + hour, 0},
		{"未来窗口排除（Timestamp<=toNs）", "t1", "confllm_graph_submit", now + hour, now + 2*hour, 0},
		{"过去窗口排除（Timestamp>=fromNs）", "t1", "confllm_graph_submit", now - 2*hour, now - hour, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := c.CountAction(ctx, tc.tenant, tc.action, tc.fromNs, tc.toNs)
			if err != nil {
				t.Fatalf("CountAction: %v", err)
			}
			if got != tc.want {
				t.Fatalf("tenant=%q action=%q 期望 %d 实得 %d", tc.tenant, tc.action, tc.want, got)
			}
		})
	}

	// nil 链 fail-safe：返回 (0, nil)，使对账跳过而非误判。
	var nilChain *adminAuditChain
	n, err := nilChain.CountAction(ctx, "t1", "confllm_graph_submit", 0, 0)
	if err != nil || n != 0 {
		t.Fatalf("nil 链应返回 (0, nil)，实得 (%d, %v)", n, err)
	}
}

func TestAdminAuditChainUnsetReturnsNil(t *testing.T) {
	c, err := newAdminAuditChain("", "")
	if err != nil {
		t.Fatalf("未配置审计不应报错: %v", err)
	}
	if c != nil {
		t.Fatal("ADMIN_AUDIT_FILE 未配置应返回 nil（审计关闭）")
	}
}

func TestAdminAuditChainHashLinkage(t *testing.T) {
	c := newAuditTestChain(t, false)

	e1 := adminAuditEvent{Actor: "alice", Action: auditActionCredentialUpsert,
		Provider: "phala", KeyFingerprint: "abcd1234", RequestID: "r1", Result: "ok"}
	if err := c.append(e1); err != nil {
		t.Fatalf("append#1: %v", err)
	}
	e2 := adminAuditEvent{Actor: "bob", Action: auditActionCredentialDelete,
		Provider: "phala", RequestID: "r2", Result: "ok"}
	if err := c.append(e2); err != nil {
		t.Fatalf("append#2: %v", err)
	}

	c.mu.Lock()
	first, second := c.events[0], c.events[1]
	c.mu.Unlock()
	if first.PrevHash != "" {
		t.Fatal("首条 PrevHash 应为空")
	}
	if second.PrevHash != first.hash() {
		t.Fatal("第 2 条 PrevHash 应等于第 1 条事件哈希（链式）")
	}
	if second.PrevHash == second.hash() {
		t.Fatal("哈希不应自引用")
	}
	if ok, n := c.verify(); !ok || n != 2 {
		t.Fatalf("verify 期望 (true, 2)，实际 (%v, %d)", ok, n)
	}
}

// WORM 持久化：重启后既有事件完整恢复，可继续追加且新事件 PrevHash 与恢复链衔接。
func TestAdminAuditChainRestartRecovery(t *testing.T) {
	file := filepath.Join(t.TempDir(), "audit.jsonl")

	c, err := newAdminAuditChain(file, "")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := c.append(adminAuditEvent{Actor: "u", Action: auditActionQuotaSet, Result: "ok"}); err != nil {
			t.Fatalf("append#%d: %v", i+1, err)
		}
	}
	_ = c.Close()

	c2, err := newAdminAuditChain(file, "")
	if err != nil {
		t.Fatalf("重启恢复失败: %v", err)
	}
	defer c2.Close()
	if c2.len() != 3 {
		t.Fatalf("重启后应恢复 3 条，实际 %d", c2.len())
	}
	if err := c2.append(adminAuditEvent{Actor: "u", Action: auditActionCredentialUpsert, Result: "ok"}); err != nil {
		t.Fatalf("恢复后继续追加: %v", err)
	}
	if ok, n := c2.verify(); !ok || n != 4 {
		t.Fatalf("恢复后追加应保持链完整，实际 (%v, %d)", ok, n)
	}
}

// 篡改历史事件（改 provider 字段值）→ 重启 load 时报哈希链断裂（fail-closed 拒绝启动）。
func TestAdminAuditChainTamperDetection(t *testing.T) {
	file := filepath.Join(t.TempDir(), "audit.jsonl")

	c, err := newAdminAuditChain(file, "")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := c.append(adminAuditEvent{Actor: "u", Action: auditActionCredentialUpsert,
			Provider: "victim", Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	_ = c.Close()

	// 篡改第 2 条事件内容（重哈希会变，但文件里的 prev_hash 不变 → 断裂）
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"victim"`, `"tampered"`, 1)
	if tampered == string(raw) {
		t.Fatal("篡改替换未生效（夹具问题）")
	}
	if err := os.WriteFile(file, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newAdminAuditChain(file, ""); err == nil {
		t.Fatal("篡改历史事件后重启应报哈希链断裂（fail-closed）")
	}
}

// 写入失败 fail-closed：句柄关闭后 append 返回错误且内存链不推进（避免 PrevHash 悬空）；
// 重新打开同一路径后既有链完整、可继续追加。
func TestAdminAuditChainWriteFailureKeepsChainConsistent(t *testing.T) {
	file := filepath.Join(t.TempDir(), "audit.jsonl")

	c, err := newAdminAuditChain(file, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.append(adminAuditEvent{Actor: "alice", Action: auditActionCredentialUpsert, Result: "ok"}); err != nil {
		t.Fatal(err)
	}

	_ = c.Close() // 模拟底层文件不可写
	if err := c.append(adminAuditEvent{Actor: "bob", Action: auditActionCredentialDelete, Result: "ok"}); err == nil {
		t.Fatal("句柄关闭后 append 应返回错误（fail-closed）")
	}
	if c.len() != 1 {
		t.Fatalf("写失败后内存链不得推进，期望 1 条，实际 %d", c.len())
	}

	c2, err := newAdminAuditChain(file, "")
	if err != nil {
		t.Fatalf("写失败后重启恢复应成功（链未分叉）: %v", err)
	}
	defer c2.Close()
	if c2.len() != 1 {
		t.Fatalf("重启后应恢复 1 条，实际 %d", c2.len())
	}
	if err := c2.append(adminAuditEvent{Actor: "bob", Action: auditActionCredentialDelete, Result: "ok"}); err != nil {
		t.Fatalf("恢复后追加: %v", err)
	}
	if ok, n := c2.verify(); !ok || n != 2 {
		t.Fatalf("最终链应 2 条且完整，实际 (%v, %d)", ok, n)
	}
}

func TestAdminAuditChainAnchor(t *testing.T) {
	c := newAuditTestChain(t, true)

	if err := c.append(adminAuditEvent{Actor: "alice", Action: auditActionQuotaSet, Result: "ok"}); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.writeAnchorLocked()
	last := c.lastHex
	c.mu.Unlock()

	raw, err := os.ReadFile(c.anchor.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"chain_hash"`)) {
		t.Fatal("锚定文件应含 chain_hash 字段")
	}
	if !bytes.Contains(raw, []byte(last)) {
		t.Fatal("锚定记录应绑定当前链尾哈希")
	}
}

// ---------- 端到端：upsert/remove 落链 + 审计写失败拒绝 2xx ----------

// newAuditedSecretMux 组装带审计链的凭据端点路由（与 main 同构）。
func newAuditedSecretMux(cfg *config, bs *brokerSettings, audit *adminAuditChain) *http.ServeMux {
	sh := newBrokerSecretHandler(bs, newBrokerHandler(&brokerConfig{providers: map[string]*brokerProvider{}}), audit)
	mux := http.NewServeMux()
	mux.HandleFunc(brokerAPIBase, authMiddleware(cfg, sh.handleList))
	mux.HandleFunc(brokerAPIBase+"/", authMiddleware(cfg, sh.handleItem))
	return mux
}

func TestCredentialWritesAuditedEndToEnd(t *testing.T) {
	bs := testSettings(t)
	c := newAuditTestChain(t, false)
	mux := newAuditedSecretMux(testCfg(), bs, c)
	file := c.file.Name()

	upsertBody := map[string]interface{}{"upstream": "https://inference.phala.com", "key": testKey}

	// upsert → 2xx 且落链 credential_upsert（含操作人/指纹，不含 Key 明文）
	if rec := doSecret(t, mux, testAdminUser, http.MethodPost, brokerAPIBase+"/phala", upsertBody); rec.Code != http.StatusOK {
		t.Fatalf("upsert 期望 200，实际 %d: %s", rec.Code, rec.Body.String())
	}
	// remove → 2xx 且落链 credential_delete
	if rec := doSecret(t, mux, testAdminUser, http.MethodDelete, brokerAPIBase+"/phala", nil); rec.Code != http.StatusOK {
		t.Fatalf("remove 期望 200，实际 %d: %s", rec.Code, rec.Body.String())
	}
	if c.len() != 2 {
		t.Fatalf("upsert+remove 应落 2 条审计，实际 %d", c.len())
	}

	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), testKey) {
		t.Fatal("审计链绝不得含 Key 明文")
	}
	var first adminAuditEvent
	if err := json.Unmarshal(bytes.Split(raw, []byte("\n"))[0], &first); err != nil {
		t.Fatal(err)
	}
	if first.Actor != testAdminUser || first.Action != auditActionCredentialUpsert ||
		first.Provider != "phala" || first.KeyFingerprint != keyFingerprint([]byte(testKey)) {
		t.Fatalf("upsert 审计事件内容不符：%+v", first)
	}
	var second adminAuditEvent
	if err := json.Unmarshal(bytes.Split(raw, []byte("\n"))[1], &second); err != nil {
		t.Fatal(err)
	}
	if second.Action != auditActionCredentialDelete || second.Provider != "phala" {
		t.Fatalf("remove 审计事件内容不符：%+v", second)
	}
	if second.PrevHash != first.hash() {
		t.Fatal("两条审计事件应哈希链式衔接")
	}
	if ok, _ := c.verify(); !ok {
		t.Fatal("端到端落链后链应完整")
	}
}

// 审计写失败（句柄关闭）→ upsert 拒绝 2xx（fail-closed），且指标计数增加。
func TestUpsertFailClosedWhenAuditWriteFails(t *testing.T) {
	bs := testSettings(t)
	c := newAuditTestChain(t, false)
	mux := newAuditedSecretMux(testCfg(), bs, c)

	before := metrics.auditWriteFails
	_ = c.Close() // 模拟审计文件不可写

	rec := doSecret(t, mux, testAdminUser, http.MethodPost, brokerAPIBase+"/phala",
		map[string]interface{}{"upstream": "https://inference.phala.com", "key": testKey})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("审计写失败时 upsert 应 500（fail-closed），实际 %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), testKey) {
		t.Fatal("错误信息不得泄露 Key")
	}
	metrics.mu.Lock()
	after := metrics.auditWriteFails
	metrics.mu.Unlock()
	if after != before+1 {
		t.Fatalf("审计写失败应累计指标，期望 %d，实际 %d", before+1, after)
	}
}
