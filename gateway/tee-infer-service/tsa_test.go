// RFC 3161 可信时间戳测试。
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
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

// ---------- HTTPTSA / RFC 3161 测试 ----------

// TestHTTPTSAConstructNew 构造测试：空 endpoint 应拒绝。
func TestHTTPTSAConstructEmptyEndpoint(t *testing.T) {
	_, err := NewHTTPTSA("", nil)
	if err == nil {
		t.Fatal("空 endpoint 应报错（fail-closed）")
	}
}

// TestHTTPTSAConstructBadRootCert 构造测试：非法根证书应拒绝。
func TestHTTPTSAConstructBadRootCert(t *testing.T) {
	_, err := NewHTTPTSA("https://ts.example.com", []byte("not a pem cert"))
	if err == nil {
		t.Fatal("非法根证书应报错")
	}
}

// TestHTTPTSAConstructOK 构造测试：合法参数应成功。
func TestHTTPTSAConstructOK(t *testing.T) {
	tsa, err := NewHTTPTSA("https://timestamp.example.com", nil, WithTSATimeout(5*time.Second))
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if tsa == nil {
		t.Fatal("返回值不应为 nil")
	}
	if tsa.endpoint != "https://timestamp.example.com" {
		t.Fatalf("endpoint 不匹配: %s", tsa.endpoint)
	}
	if tsa.timeout != 5*time.Second {
		t.Fatalf("timeout 不匹配: %v", tsa.timeout)
	}
}

// TestHTTPTSAImplementsInterface 编译期检查：HTTPTSA 实现 TSASigner 接口。
func TestHTTPTSAImplementsInterface(t *testing.T) {
	var _ TSASigner = (*HTTPTSA)(nil)
}

// TestBuildTimeStampReq 构造 TimeStampReq ASN.1 DER 并验证基本结构。
func TestBuildTimeStampReq(t *testing.T) {
	tsa, _ := NewHTTPTSA("https://ts.example.com", nil)
	imprint := make([]byte, 32)
	for i := range imprint {
		imprint[i] = byte(i)
	}

	reqDER, err := tsa.buildRequest(imprint)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	if len(reqDER) == 0 {
		t.Fatal("请求 DER 为空")
	}

	// 反向解析验证结构
	var req timeStampReq
	rest, err := asn1.Unmarshal(reqDER, &req)
	if err != nil {
		t.Fatalf("反向解析失败: %v", err)
	}
	if len(rest) > 0 {
		t.Fatalf("有多余字节: %d", len(rest))
	}
	if req.Version != 1 {
		t.Fatalf("版本应为 1，got %d", req.Version)
	}
	if !req.CertReq {
		t.Fatal("CertReq 应为 true")
	}
	if len(req.MessageImprint.HashedMessage) != 32 {
		t.Fatalf("imprint 长度应为 32，got %d", len(req.MessageImprint.HashedMessage))
	}
	// 验证 imprint 内容一致
	for i := 0; i < 32; i++ {
		if req.MessageImprint.HashedMessage[i] != byte(i) {
			t.Fatalf("imprint 第 %d 字节不匹配", i)
		}
	}
}

// TestBuildTimeStampReqWithPolicy 带策略 OID 的请求构造。
func TestBuildTimeStampReqWithPolicy(t *testing.T) {
	policyOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	tsa, _ := NewHTTPTSA("https://ts.example.com", nil, WithTSAPolicy(policyOID))
	imprint := make([]byte, 32)

	reqDER, err := tsa.buildRequest(imprint)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}

	var req timeStampReq
	_, err = asn1.Unmarshal(reqDER, &req)
	if err != nil {
		t.Fatalf("反向解析失败: %v", err)
	}
	if req.ReqPolicy == nil {
		t.Fatal("应包含策略 OID")
	}
	if !req.ReqPolicy.Equal(policyOID) {
		t.Fatalf("策略 OID 不匹配: %v", req.ReqPolicy)
	}
}

// TestParseTimeStampResp 解析 mock TimeStampResp。
func TestParseTimeStampResp(t *testing.T) {
	// 构造一个 granted 状态的响应（无 token）
	resp := timeStampResp{
		Status: pkiStatusInfo{
			Status:       0, // granted
			StatusString: []string{"Operation Okay"},
		},
	}
	der, err := asn1.Marshal(resp)
	if err != nil {
		t.Fatalf("构造响应失败: %v", err)
	}

	parsed, err := parseTimeStampResp(der)
	if err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if parsed.Status.Status != 0 {
		t.Fatalf("状态应为 0，got %d", parsed.Status.Status)
	}
	if len(parsed.Status.StatusString) != 1 || parsed.Status.StatusString[0] != "Operation Okay" {
		t.Fatalf("StatusString 不匹配: %v", parsed.Status.StatusString)
	}
}

// TestParseTimeStampRespMalformed 非法响应应拒绝。
func TestParseTimeStampRespMalformed(t *testing.T) {
	_, err := parseTimeStampResp([]byte("not der"))
	if err == nil {
		t.Fatal("非法 DER 应报错")
	}
}

// TestHTTPTSASignEmptyImprint Sign 空 imprint 应拒绝。
func TestHTTPTSASignEmptyImprint(t *testing.T) {
	tsa, _ := NewHTTPTSA("https://ts.example.com", nil)
	_, err := tsa.Sign(nil)
	if err == nil {
		t.Fatal("空 imprint 应拒绝")
	}
	_, err = tsa.Sign([]byte{})
	if err == nil {
		t.Fatal("空 imprint 应拒绝")
	}
}

// TestVerifyTSTIndependentNilTST VerifyTSTIndependent 空 TST 应拒绝。
func TestVerifyTSTIndependentNilTST(t *testing.T) {
	err := VerifyTSTIndependent(nil, make([]byte, 32), nil)
	if err == nil {
		t.Fatal("nil TST 应拒绝")
	}
}

// TestVerifyTSTIndependentWrongSource 非 RFC3161 TST 应拒绝。
func TestVerifyTSTIndependentWrongSource(t *testing.T) {
	tst := &TST{
		Version: 1,
		Source:  "mock", // 不是 http_rfc3161
	}
	err := VerifyTSTIndependent(tst, make([]byte, 32), nil)
	if err == nil {
		t.Fatal("错误 source 应拒绝")
	}
}

// TestVerifyTSTIndependentBadSignature 非法 signature hex 应拒绝。
func TestVerifyTSTIndependentBadSignature(t *testing.T) {
	tst := &TST{
		Version:   1,
		Source:    "http_rfc3161",
		Signature: "not-hex-zzz",
	}
	err := VerifyTSTIndependent(tst, make([]byte, 32), nil)
	if err == nil {
		t.Fatal("非法 signature 应拒绝")
	}
	if !containsTSAErr(err, "hex") {
		t.Fatalf("错误应提及 hex: %v", err)
	}
}

// TestHTTPTSAVerifyNilTST HTTPTSA.Verify 空 TST 应拒绝。
func TestHTTPTSAVerifyNilTST(t *testing.T) {
	tsa, _ := NewHTTPTSA("https://ts.example.com", nil)
	err := tsa.Verify(nil)
	if err == nil {
		t.Fatal("nil TST 应拒绝")
	}
}

// TestHTTPTSAVerifyWrongSource 错误 source 应拒绝。
func TestHTTPTSAVerifyWrongSource(t *testing.T) {
	tsa, _ := NewHTTPTSA("https://ts.example.com", nil)
	err := tsa.Verify(&TST{Source: "mock"})
	if err == nil {
		t.Fatal("错误 source 应拒绝")
	}
}

// TestHTTPTSAWithOptions 多个 option 叠加。
func TestHTTPTSAWithOptions(t *testing.T) {
	policy := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 4146, 2, 1}
	tsa, err := NewHTTPTSA(
		"https://ts.example.com",
		nil,
		WithTSATimeout(3*time.Second),
		WithTSAPolicy(policy),
	)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if tsa.timeout != 3*time.Second {
		t.Fatalf("timeout 不匹配: %v", tsa.timeout)
	}
	if !tsa.policyOID.Equal(policy) {
		t.Fatalf("policy OID 不匹配: %v", tsa.policyOID)
	}
}

// ---- 辅助函数 ----

func containsTSAErr(err error, substr string) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
