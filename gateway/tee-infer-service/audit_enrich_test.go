package main

// audit_enrich_test.go — P1-7 T3a：既有落链点证据字段填充单测（§3.4 命中判定式可核）。
//
// 覆盖：① deny reason→hit_policies 映射；② deny reason→http_status 映射；
// ③ 请求级路径元数据经 context 注入/读取；④ 命中判定式 hit=(hit_policies!="")；
// ⑤ buildDenyEvent 落字段且**不影响哈希**（证据字段不进 hash，C-3/D-1）。

import (
	"context"
	"testing"
)

func TestDenyHitPolicy(t *testing.T) {
	cases := []struct {
		reason string
		want   string
	}{
		{"guardrail_A1-07", "guardrail_A1-07"}, // guardrail_* 族原样
		{"guardrail_decrypt_error", "guardrail_decrypt_error"},
		{"bad_signature", "bad_signature"},
		{"replay", "replay_attack"}, // reason 简写 → 枚举名
		{"quota_exceeded", "quota_deny"},
		{"cache_negative", "cache_negative"},
		{"shadow_reject", "shadow_reject"},
		// 非策略类拒绝 → 空（未命中）
		{"decode_error", ""},
		{"engine_unavailable", ""},
		{"envelope_error", ""},
		{"tenant_disposition", ""},
		{"route_rejected", ""},
		{"mcp_no_session", ""},
	}
	for _, c := range cases {
		if got := denyHitPolicy(c.reason); got != c.want {
			t.Fatalf("denyHitPolicy(%q)=%q want %q", c.reason, got, c.want)
		}
	}
}

// TestHitJudgmentFormula 命中判定式（§3.4）：hit = (hit_policies != "")。
func TestHitJudgmentFormula(t *testing.T) {
	hit := func(reason string) bool { return denyHitPolicy(reason) != "" }
	if !hit("guardrail_X") {
		t.Fatal("guardrail 命中应为 hit=true")
	}
	if !hit("bad_signature") {
		t.Fatal("bad_signature 命中应为 hit=true")
	}
	if hit("decode_error") {
		t.Fatal("协议解码失败应为 hit=false（未命中策略）")
	}
	if hit("engine_unavailable") {
		t.Fatal("引擎不可用应为 hit=false（未命中策略）")
	}
}

func TestDenyHTTPStatusMirrorsHandlers(t *testing.T) {
	cases := []struct {
		reason string
		want   int
	}{
		{"bad_signature", 401},
		{"tenant_disposition", 403},
		{"guardrail_A1-07", 403},
		{"guardrail_decrypt_error", 400}, // 解密失败非策略命中
		{"quota_exceeded", 429},
		{"engine_unavailable", 503},
		{"mcp_guard_not_ready", 503},
		{"encrypt_error", 500},
		{"encode_error", 500},
		{"envelope_seal_error", 500},
		{"keyissue_seal_error", 500},
		{"replay", 400},
		{"decode_error", 400},
		{"envelope_error", 400},
		{"unknown_nonce", 400},
		{"route_rejected", 400},
		{"decrypt_error", 400},
		{"text_without_session", 400},
		{"text_payload_invalid", 400},
		{"keyissue_envelope_error", 400},
		{"mcp_no_session", 400},
		{"mcp_envelope_error", 400},
		{"recompute_layer_mismatch", 400},
		{"engine_error", 400},
		{"mcp_tool_deny", 403},
		{"some_unknown_reason", 0}, // 未登记 → 0（omitempty）
	}
	for _, c := range cases {
		if got := denyHTTPStatus(c.reason); got != c.want {
			t.Fatalf("denyHTTPStatus(%q)=%d want %d", c.reason, got, c.want)
		}
	}
}

func TestAuditReqMetaContext(t *testing.T) {
	ctx := withAuditReqMeta(context.Background(), "/v1/infer?stream=1", "plain")
	m := auditReqMetaFromCtx(ctx)
	if m.Path != "/v1/infer" {
		t.Fatalf("应去 query: %q", m.Path)
	}
	if m.PathMode != "plain" {
		t.Fatalf("path_mode 不符: %q", m.PathMode)
	}
	// 缺失元数据 → 零值
	empty := auditReqMetaFromCtx(context.Background())
	if empty.Path != "" || empty.PathMode != "" {
		t.Fatalf("缺失应为零值: %+v", empty)
	}
	// nil ctx 安全
	if got := auditReqMetaFromCtx(nil); got.Path != "" {
		t.Fatalf("nil ctx 应返回零值: %+v", got)
	}
}

func TestAuditPathMode(t *testing.T) {
	if got := auditPathMode("/mcp-servers/secure-tools/x"); got != "encrypted" {
		t.Fatalf("MCP 敏感轨应 encrypted: %q", got)
	}
	if got := auditPathMode("/v1/infer"); got != "plain" {
		t.Fatalf("普通路径应 plain: %q", got)
	}
}

func TestBuildDenyEventFillsEvidenceAndPreservesHash(t *testing.T) {
	ctx := withAuditReqMeta(context.Background(), "/v1/infer", "plain")
	base := AuditEvent{
		TenantID: "t-1", RequestID: "req-1", Action: "deny",
		Result: "guardrail_A1-07", PayloadSHA: "deadbeef", HashAlg: hashAlgTag(),
	}
	ev := buildDenyEvent(ctx, base, "guardrail_A1-07")

	if ev.Path != "/v1/infer" || ev.PathMode != "plain" {
		t.Fatalf("路径证据字段未填: %+v", ev)
	}
	if ev.HitPolicies != "guardrail_A1-07" {
		t.Fatalf("hit_policies 不符: %q", ev.HitPolicies)
	}
	if ev.HTTPStatus != 403 {
		t.Fatalf("http_status 不符: %d", ev.HTTPStatus)
	}

	// C-3/D-1：证据字段不进 hash ⇒ 与未富化事件哈希一致。
	plain := base // 无证据字段
	if ev.hash() != plain.hash() {
		t.Fatalf("证据字段改变了哈希（应逐字节不变）: %s vs %s", ev.hash(), plain.hash())
	}
}

func TestMsElapsed(t *testing.T) {
	if got := msElapsed(1_000_000_000, 1_500_000_000); got != 500 {
		t.Fatalf("应得 500ms: %d", got)
	}
	if got := msElapsed(2_000_000_000, 1_000_000_000); got != 0 {
		t.Fatalf("负值应钳 0: %d", got)
	}
	if got := msElapsed(0, 0); got != 0 {
		t.Fatalf("零间隔应 0: %d", got)
	}
}
