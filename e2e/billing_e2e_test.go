//go:build e2e

package e2e

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	protocol "security-ai-gateway/protocol/go"
)

// TestE2E_Billing 覆盖 §10.3 E2E-1/3/4 + E2E-2（基础）。
//
// 用例按依赖顺序执行于同一栈上（E2E-3 篡改需 E2E-1 先产出账本条目）。
func TestE2E_Billing(t *testing.T) {
	s := startStack(t)

	t.Run("E2E-1_推理到账单", func(t *testing.T) { testE2E1(t, s) })
	t.Run("E2E-2_四档套餐与配额", func(t *testing.T) { testE2E2(t, s) })
	t.Run("E2E-3_篡改账本停出账", func(t *testing.T) { testE2E3(t, s) })
	t.Run("E2E-4_关闭billing逐字节一致", func(t *testing.T) { testE2E4(t, s) })
}

// teeInfer token 模式发起一次 vectors 推理（真实 tee-infer；固定全局 K_sig 验签）。
// 返回推理响应状态码（非 200 时调用方按期望判定，如配额超限 429）。
func teeInfer(t *testing.T, teeURL, tenant string, vectors int) (int, []byte) {
	t.Helper()
	reqID := "e2e-" + strconv.FormatInt(time.Now().UnixNano(), 36) + "-" + tenant

	// 1) 密钥签发（token 模式：X-Attest-Token）
	kb, _ := json.Marshal(map[string]string{"request_id": reqID + "-ki", "model": "mock"})
	code, body := do(t, http.MethodPost, teeURL+"/key/issue", map[string]string{
		"X-Attest-Token": teeAttestToken, "X-Tenant-ID": tenant, "Content-Type": "application/json",
	}, kb)
	if code != http.StatusOK {
		t.Fatalf("key/issue 期望 200，实际 %d: %s", code, body)
	}
	var ki struct {
		Nonce string `json:"nonce"`
	}
	mustJSON(t, body, &ki)
	nonce, err := hex.DecodeString(ki.Nonce)
	if err != nil {
		t.Fatalf("nonce 解码失败: %v", err)
	}

	// 2) 推理（vectors；掩码值不影响计量，仅需服务端解密成功并采样）
	ireq := &protocol.InferenceRequest{
		RequestID:     reqID + "-inf",
		TimestampNS:   time.Now().UnixNano(),
		Model:         "mock",
		MaxNewTokens:  1,
		Nonce:         nonce,
		CipherVectors: make([]protocol.CipherVector, vectors),
		EngineType:    protocol.EngineTypeTEEGPU,
		AttestType:    protocol.AttestTypeToken,
	}
	for i := range ireq.CipherVectors {
		ireq.CipherVectors[i] = protocol.CipherVector{Data: []uint64{uint64(i + 1)}}
	}
	ksig, _ := hex.DecodeString(teeSigKeyHex)
	protocol.SignRequest(ksig, ireq)
	enc, err := protocol.EncodeRequest(ireq)
	if err != nil {
		t.Fatalf("请求编码失败: %v", err)
	}
	code, body = do(t, http.MethodPost, teeURL+"/v1/infer", map[string]string{
		"X-Tenant-ID": tenant, "Content-Type": "application/x-otpmask",
	}, enc)
	if code == http.StatusOK {
		resp, perr := protocol.DecodeResponse(body)
		if perr != nil {
			t.Fatalf("响应解码失败: %v", perr)
		}
		if !protocol.VerifyResponse(ksig, resp) {
			t.Fatal("响应验签失败（全局 K_sig）")
		}
	}
	return code, body
}

// E2E-1：模拟推理 → 拉取 → 日结 → /bills → /verify（valid）→ 导出。
func testE2E1(t *testing.T, s *stack) {
	const tenant = "e2e-t1"
	if code, body := teeInfer(t, s.teeURL, tenant, 3); code != http.StatusOK {
		t.Fatalf("推理期望 200，实际 %d: %s", code, body)
	}
	// 等待 S-1 增量拉取入账（pull_interval=10s，R-6 下限）
	waitLedger(t, s, tenant, 90*time.Second)

	day := dayUTC8()
	code, body := do(t, http.MethodPost, s.admURL+billingBase+"/close-daily",
		authHdr(adminUser, "admin", ""), []byte(`{"tenant":"`+tenant+`","day":"`+day+`"}`))
	if code != http.StatusOK {
		t.Fatalf("日结期望 200，实际 %d: %s", code, body)
	}
	var bill struct {
		ID           string `json:"id"`
		Status       string `json:"status"`
		PriceVersion string `json:"price_version"`
		Total        int64  `json:"total"`
	}
	mustJSON(t, body, &bill)
	if bill.ID == "" || bill.Status != "issued" {
		t.Fatalf("账单异常: %+v", bill)
	}

	// /bills 列表含该账单
	code, body = do(t, http.MethodGet, s.admURL+billingBase+"/bills?tenant="+tenant,
		authHdr(adminUser, "admin", ""), nil)
	if code != http.StatusOK {
		t.Fatalf("账单列表期望 200，实际 %d: %s", code, body)
	}
	var list struct {
		Bills []struct {
			ID string `json:"id"`
		} `json:"bills"`
	}
	mustJSON(t, body, &list)
	found := false
	for _, b := range list.Bills {
		if b.ID == bill.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("账单列表未含 %s: %s", bill.ID, body)
	}

	// /verify → valid
	code, body = do(t, http.MethodGet, s.admURL+billingBase+"/bills/"+bill.ID+"/verify",
		authHdr(adminUser, "admin", ""), nil)
	if code != http.StatusOK {
		t.Fatalf("验签期望 200，实际 %d: %s", code, body)
	}
	var v struct {
		Valid bool `json:"valid"`
	}
	mustJSON(t, body, &v)
	if !v.Valid {
		t.Fatalf("账单验签应为 valid: %s", body)
	}

	// 导出 → CSV 含账单 id
	code, body = do(t, http.MethodGet, s.admURL+billingBase+"/bills/"+bill.ID+"/export",
		authHdr(adminUser, "admin", ""), nil)
	if code != http.StatusOK {
		t.Fatalf("导出期望 200，实际 %d: %s", code, body)
	}
	if !strings.Contains(string(body), bill.ID) {
		t.Fatalf("导出内容未含账单 id:\n%s", body)
	}
}

// E2E-2（基础）：4 档套餐各绑一租户 → 配额下发并**回读生效** → 超限 429。
//
// 范围说明：OverQuota 的**计价差异**（degrade/charge 超额的账单形态）由 Go 单测/集成覆盖
// （T-6.4/T-6.5/§10.2），E2E 断言"配额生效 + 超限拒绝"这一跨服务闭环。
func testE2E2(t *testing.T, s *stack) {
	type spec struct {
		id, tenant, overQuota string
		monthly               int64
	}
	specs := []spec{
		{"e2e-p1", "e2e-q1", "reject", 1},
		{"e2e-p2", "e2e-q2", "degrade", 1_000_000},
		{"e2e-p3", "e2e-q3", "charge", 1_000_000},
		{"e2e-p4", "e2e-q4", "reject", 1_000_000},
	}
	for _, sp := range specs {
		body, _ := json.Marshal(map[string]any{
			"id": sp.id, "name": "E2E " + sp.id, "over_quota": sp.overQuota,
			"pay_mode": "postpaid", "cache_tier": "none", "monthly_tokens": sp.monthly,
		})
		code, rb := do(t, http.MethodPost, s.admURL+billingBase+"/plans",
			authHdr(adminUser, "admin", ""), body)
		if code != http.StatusOK {
			t.Fatalf("建套餐 %s 期望 200，实际 %d: %s", sp.id, code, rb)
		}
		sub, _ := json.Marshal(map[string]any{"tenant": sp.tenant, "plan_id": sp.id})
		code, rb = do(t, http.MethodPost, s.admURL+billingBase+"/subscription",
			authHdr(adminUser, "admin", ""), sub)
		if code != http.StatusOK {
			t.Fatalf("绑定 %s→%s 期望 200，实际 %d: %s", sp.tenant, sp.id, code, rb)
		}
		// 回读已生效限额（M6 判据）：tee-infer GET /usage/quota?tenant=
		code, rb = do(t, http.MethodGet, s.teeURL+"/usage/quota?tenant="+sp.tenant,
			map[string]string{"X-Admin-Token": teeAdminToken}, nil)
		if code != http.StatusOK {
			t.Fatalf("回读配额期望 200，实际 %d: %s", code, rb)
		}
		var q struct {
			Limits []struct {
				Window    string `json:"window"`
				MaxTokens int64  `json:"max_tokens"`
			} `json:"limits"`
		}
		mustJSON(t, rb, &q)
		ok := false
		for _, l := range q.Limits {
			if l.Window == "month" && l.MaxTokens == sp.monthly {
				ok = true
			}
		}
		if !ok {
			t.Fatalf("%s 配额未生效（期望 month=%d）: %s", sp.tenant, sp.monthly, rb)
		}
	}

	// 超限：e2e-q1（month=1）发 3 vectors（tokens_in=3 > 1）→ 429（fail-closed）
	if code, body := teeInfer(t, s.teeURL, "e2e-q1", 3); code != http.StatusTooManyRequests {
		t.Fatalf("超配额期望 429，实际 %d: %s", code, body)
	}
}

// E2E-3：篡改账本行 → verify-chain 断裂 + 指标置位 + 停出账（fail-closed）。
func testE2E3(t *testing.T, s *stack) {
	forgeLedgerRow(t, s.billingDB)

	code, body := do(t, http.MethodPost, s.admURL+billingBase+"/verify-chain",
		authHdr(adminUser, "admin", ""), nil)
	if code != http.StatusOK {
		t.Fatalf("verify-chain 期望 200，实际 %d: %s", code, body)
	}
	var out struct {
		LedgerBrokenAt int64 `json:"ledger_broken_at"`
		LedgerBroken   bool  `json:"ledger_broken"`
	}
	mustJSON(t, body, &out)
	if !out.LedgerBroken || out.LedgerBrokenAt < 0 {
		t.Fatalf("篡改后应检出链断裂: %s", body)
	}

	// 指标 #4 置 1（驱动 §9.3 BillingLedgerChainBroken 告警的事实源）
	code, body = do(t, http.MethodGet, s.admURL+"/metrics", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("metrics 期望 200，实际 %d", code)
	}
	if !strings.Contains(string(body), "gateway_admin_billing_ledger_chain_broken 1") {
		t.Fatalf("链断裂指标未置位:\n%s", body)
	}

	// 停出账：对**无既有账单**的日结 → 409（ErrChainBroken，fail-closed）
	code, body = do(t, http.MethodPost, s.admURL+billingBase+"/close-daily",
		authHdr(adminUser, "admin", ""), []byte(`{"tenant":"e2e-t1","day":"1999-01-01"}`))
	if code != http.StatusConflict {
		t.Fatalf("链断裂应停出账（409），实际 %d: %s", code, body)
	}
}

// E2E-4：billing.enabled=false 与 true 的 `/usage` 域响应**逐字节一致**（R-1/M10/S-6）。
func testE2E4(t *testing.T, s *stack) {
	off := s.startAdminOff(t)

	from := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	to := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	path := "/v1/adminext/usage?from=" + from + "&to=" + to

	_, offBody := do(t, http.MethodGet, off+path, authHdr(adminUser, "admin", ""), nil)
	_, onBody := do(t, http.MethodGet, s.admURL+path, authHdr(adminUser, "admin", ""), nil)
	if string(offBody) != string(onBody) {
		t.Fatalf("/usage 响应在 billing 开关下不一致（R-1 违约）:\noff=%s\non=%s", offBody, onBody)
	}

	// 端点注册隔离：关闭时 /billing/* 不存在（404），开启时 200
	if code, _ := do(t, http.MethodGet, off+billingBase+"/plans", authHdr(adminUser, "admin", ""), nil); code != http.StatusNotFound {
		t.Fatalf("billing 关闭时期望 404，实际 %d", code)
	}
	if code, _ := do(t, http.MethodGet, s.admURL+billingBase+"/plans", authHdr(adminUser, "admin", ""), nil); code != http.StatusOK {
		t.Fatalf("billing 开启时期望 200，实际 %d", code)
	}
}

// ---------- 辅助 ----------

const billingBase = "/v1/adminext/billing"

// waitLedger 轮询直到某租户账本出现条目（等待 S-1 拉取入账）。
func waitLedger(t *testing.T, s *stack, tenant string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		code, body := do(t, http.MethodGet, s.admURL+billingBase+"/ledger?tenant="+tenant,
			authHdr(adminUser, "admin", ""), nil)
		if code == http.StatusOK {
			var out struct {
				Entries []json.RawMessage `json:"entries"`
			}
			if json.Unmarshal(body, &out) == nil && len(out.Entries) > 0 {
				return
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("等待账本入账超时（tenant=%s）", tenant)
}

// forgeLedgerRow 直插一条 prev_hash 悬空的伪造行（绕过 Append），破坏账本链。
func forgeLedgerRow(t *testing.T, dbPath string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("打开账本库失败: %v", err)
	}
	defer db.Close()
	const q = `INSERT INTO billing_ledger
		(tenant_id, model_key, day, tokens_in, tokens_out, requests, retry_toks,
		 std_in, std_out, source, price_ver, event_key, prev_hash, entry_hash, created_at)
		VALUES ('e2e-t1','tee_gpu/mock','1999-01-01',0,0,0,0,0,0,'pull','e2e-v1','e2e-forged','deadbeef','cafe',1)`
	var lastErr error
	for i := 0; i < 10; i++ {
		if _, lastErr = db.Exec(q); lastErr == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("伪造账本行失败（可能被占用）: %v", lastErr)
}
