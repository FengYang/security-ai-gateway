// RFC 3161 可信时间戳测试。
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

// now 当前时间（测试辅助）。
func now() time.Time { return time.Now() }

// sha256Sum 摘要计算。
func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// TestMockTSASignVerify mock TSA 签发与验证往返。
func TestMockTSASignVerify(t *testing.T) {
	tsa, err := NewMockTSA()
	if err != nil {
		t.Fatal(err)
	}
	imprint := sha256Sum([]byte("chain-hash-anchor"))
	tst, err := tsa.Sign(imprint)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if tst.Version != 1 || tst.Algorithm != "sha256" {
		t.Fatal("TST 字段异常")
	}
	if tst.MessageImprint != hex.EncodeToString(imprint) {
		t.Fatal("TST imprint 不一致")
	}
	if err := tsa.Verify(tst); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestMockTSATamper TST 篡改（时间戳/签名/imprint）必须被拒绝。
func TestMockTSATamper(t *testing.T) {
	tsa, _ := NewMockTSA()
	imprint := sha256Sum([]byte("data"))
	tst, _ := tsa.Sign(imprint)

	// 篡改签名
	bad := *tst
	bad.Signature = hex.EncodeToString(bytes.Repeat([]byte{0x01}, 32))
	if err := tsa.Verify(&bad); err == nil {
		t.Fatal("篡改签名未被拒绝")
	}
	// 篡改 imprint（替换锚定哈希）
	bad2 := *tst
	bad2.MessageImprint = hex.EncodeToString(sha256Sum([]byte("other")))
	if err := tsa.Verify(&bad2); err == nil {
		t.Fatal("篡改 imprint 未被拒绝")
	}
}

// TestAuditAnchorTST 锚定记录绑定 TST：verifyTST 通过；替换锚定哈希 → 拒绝。
func TestAuditAnchorTST(t *testing.T) {
	dir := t.TempDir()
	tsa, _ := NewMockTSA()
	audit, err := newAuditChainWORM(dir+"/events.jsonl", dir+"/anchor.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	audit.tsa = tsa
	defer audit.Close()

	audit.append(AuditEvent{EventID: "e1", TenantID: "t1", RequestID: "r1", Action: "infer", Result: "ok"})
	rec := audit.anchorNow()
	if rec == nil || rec.TST == nil {
		t.Fatal("锚定记录未绑定 TST")
	}
	if err := audit.verifyTST(rec); err != nil {
		t.Fatalf("verifyTST 失败: %v", err)
	}
	// 替换锚定哈希 → TST imprint 不匹配 → 拒绝
	rec.ChainHash = "deadbeef"
	if err := audit.verifyTST(rec); err == nil {
		t.Fatal("替换锚定哈希未被拒绝")
	}
}

// TestReconcilerMismatch 对账器（S5 起容差 0，token 级）：审计与用量一致 → true；
// 任一偏差 → false + 指标（分类见 reconcile_test.go）。
func TestReconcilerMismatch(t *testing.T) {
	audit := newAuditChain()
	usage := map[string]*usageRecord{}
	m := newMetrics()
	rec := newReconciler(audit, usage, &audit.mu, m, nil, time.Now().UnixNano())

	// 一致：审计 2 条 infer（in=1/out=1）+ 用量同口径
	for _, id := range []string{"r1", "r2"} {
		audit.append(AuditEvent{EventID: id, TenantID: "t1", RequestID: id, Action: "infer", Result: "ok", TokensIn: 1, TokensOut: 1})
	}
	usage["t1"] = &usageRecord{TokensIn: 2, TokensOut: 2, Requests: 2}
	if !rec.reconcileOnce(now()) {
		t.Fatal("一致时应返回 true（容差 0）")
	}
	// 偏差：用量少 1 个请求（同源口径下即异常）
	usage["t1"] = &usageRecord{TokensIn: 2, TokensOut: 2, Requests: 1}
	if rec.reconcileOnce(now()) {
		t.Fatal("存在偏差应返回 false")
	}
	if m.reconcile[reconcileReasonUnknown] == 0 {
		t.Fatalf("应记录不一致分类（unknown）：%+v", m.reconcile)
	}
}
