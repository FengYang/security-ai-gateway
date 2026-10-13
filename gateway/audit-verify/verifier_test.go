package auditverify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 固定测试向量（**由独立实现算出**：PowerShell + .NET SHA256，按同样的
// 8 字节大端长度前缀编码逐字段计算，非本包 Go 代码自算）。
//
// 作用：锁死"独立验证器 ↔ 服务端 hash()"的一致性。任一端改动字段/顺序/编码，
// 本测试会立刻失败——这是本方案对抗"双实现漂移"的核心手段（见 schema.go 头部硬约束）。
const (
	vecAdminNoTarget = "462ca655ea44d3c0eb19b4566531e9694b1589643688633357236e1fb956b445"
	vecAdminTarget   = "d2a4dc5437996a082961f26129bc5cdec60732f7415b2081da49f0fce6974c4e"
	vecTee           = "bc0294225639208a169b8af3472701163ab831d47d0547948307a280f163b793"
	// core 链（gateway-core 策略变更）：同一固定事件（apply/updated rpm 60→120），
	// 由 PowerShell + .NET SHA256 独立算出（同编码规则）。
	vecCore = "e6526a8b628dc5e070de7e5b0c7ed04cafa29551663bf6c8da7dc98ae00e8e67"
)

// coreEventFixed core 链固定事件（字段与 gateway-core/internal/policyaudit.Event 一致）。
const coreEventFixed = `{"event_id":"pol-1","timestamp":1789272000000000000,"actor":"ops-admin","action":"apply","version_from":3,"version_to":4,"rule_id":"t-a-rate","change":"updated","field":"rpm","old_value":"60","new_value":"120","request_id":"req-xyz","result":"ok","prev_hash":""}`

// admin 链：evt-1（无 target）→ evt-2（带 target）。
const (
	adminEventA = `{"event_id":"evt-1","timestamp":1700000000000000000,"actor":"alice","action":"credential_upsert","provider":"phala","key_fingerprint":"6a16570c","tenant":"","max_tokens":0,"request_id":"req-1","result":"ok","prev_hash":""}`
	adminEventB = `{"event_id":"evt-2","timestamp":1700000000000000001,"actor":"bob","action":"account_create","provider":"","key_fingerprint":"","tenant":"","max_tokens":0,"target":"admin02","request_id":"req-2","result":"ok","prev_hash":"` + vecAdminNoTarget + `"}`
	teeEventC   = `{"event_id":"evt-3","timestamp":1700000000000000002,"tenant_id":"acme","user_id":"","request_id":"req-3","action":"infer","tokens_in":12,"tokens_out":34,"result":"ok","payload_hash":"aabbccdd","prev_hash":""}`
	// 第三条管理面事件（三事件链用于"中间篡改"用例：只有存在后继事件，篡改才会在下一条暴露）。
	adminEventC = `{"event_id":"evt-3","timestamp":1700000000000000003,"actor":"carol","action":"quota_set","tenant":"acme","max_tokens":1000,"request_id":"req-3","result":"ok","prev_hash":"` + vecAdminTarget + `"}`
	// P1-7 全流量审计改造（T10，MOD8）：tee 基线事件叠加**全部** P1-7 证据字段
	// （path/path_mode/ttft_ms/dur_ms/http_status/hit_policies/origin/sampled/
	// mcp_session_id/reporter_id/tenant_id_resolution，及 P1-2 的 trace_id 与既有证据字段）。
	// 这些字段均为 omitempty 证据字段、**不进 hash()**（C-3/D-1）；其存在不得改变哈希。
	teeEventCWithEvidence = `{"event_id":"evt-3","timestamp":1700000000000000002,"tenant_id":"acme","user_id":"","request_id":"req-3","action":"infer","tokens_in":12,"tokens_out":34,"result":"ok","payload_hash":"aabbccdd","prev_hash":"","path":"/v1/infer","path_mode":"encrypted","ttft_ms":123,"dur_ms":456,"http_status":200,"hit_policies":"guardrail_pii,rpm_limit","origin":"data-plane","sampled":false,"mcp_session_id":"sess-9","reporter_id":"reporter-1","tenant_id_resolution":"header","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","instance_id":"inst-1","category":"would_reject_A1-07","mode":"enforcing","policy_version":"v2","filtered_tokens":7,"is_retry":true,"engine_type":"vllm","model":"glm-5.2","transformed_hash":"deadbeef","cache_hit":false,"key_fp":"kf","metering_mode":"estimate","shadow_rule":"rpm","mcp_tool":"tools/call","mcp_reason":"rbac","mcp_policy_version":3,"old_version":"v1","sha256":"abc"}`
)

func TestVectorAdminSchema(t *testing.T) {
	schema, err := SchemaFor("admin")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		line string
		want string
	}{
		{"无 target（条件编码：空值不进哈希）", adminEventA, vecAdminNoTarget},
		{"带 target（条件编码：有值进哈希）", strings.Replace(adminEventB, `"prev_hash":"`+vecAdminNoTarget+`"`, `"prev_hash":""`, 1), vecAdminTarget},
	}
	for _, c := range cases {
		event, err := decodeEvent([]byte(c.line))
		if err != nil {
			t.Fatalf("%s：解码失败 %v", c.name, err)
		}
		got, err := schema.Hash(event)
		if err != nil {
			t.Fatalf("%s：重算失败 %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s：哈希与固定向量不符\n got=%s\nwant=%s\n（若服务端 hash() 有变更，须同步本向量）",
				c.name, got, c.want)
		}
	}
}

func TestVectorTeeSchema(t *testing.T) {
	schema, err := SchemaFor("tee")
	if err != nil {
		t.Fatal(err)
	}
	event, err := decodeEvent([]byte(teeEventC))
	if err != nil {
		t.Fatal(err)
	}
	got, err := schema.Hash(event)
	if err != nil {
		t.Fatal(err)
	}
	if got != vecTee {
		t.Errorf("tee schema 哈希与固定向量不符\n got=%s\nwant=%s", got, vecTee)
	}
}

// TestTeeSchemaIgnoresP17EvidenceFields T10（MOD8）回归向量：
// P1-7 新增证据字段（path/path_mode/ttft_ms/dur_ms/http_status/hit_policies/origin/
// sampled/mcp_session_id/reporter_id/tenant_id_resolution 及 P1-2 trace_id 等）**不进 hash()**；
// 叠加这些字段的事件，其哈希必须与仅 10 核心字段的固定向量 vecTee 完全一致。
// 若有人误将任一证据字段加入 schema.go 的 tee schema，本测试立即失败（双实现漂移防护，C-3/D-1）。
func TestTeeSchemaIgnoresP17EvidenceFields(t *testing.T) {
	schema, err := SchemaFor("tee")
	if err != nil {
		t.Fatal(err)
	}
	// 基线（仅 10 核心字段）须等于固定向量。
	base, err := decodeEvent([]byte(teeEventC))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := schema.Hash(base); got != vecTee {
		t.Fatalf("基线哈希应等于 vecTee，得 %s", got)
	}
	// 含全部 P1-7 证据字段：哈希必须不变。
	withEvidence, err := decodeEvent([]byte(teeEventCWithEvidence))
	if err != nil {
		t.Fatalf("解码含证据字段事件失败: %v", err)
	}
	got, err := schema.Hash(withEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if got != vecTee {
		t.Fatalf("含 P1-7 证据字段后哈希改变（违反 C-3/D-1 不进 hash 约束）\n got=%s\nwant=%s", got, vecTee)
	}
}

func TestVectorCoreSchema(t *testing.T) {
	schema, err := SchemaFor("core")
	if err != nil {
		t.Fatal(err)
	}
	event, err := decodeEvent([]byte(coreEventFixed))
	if err != nil {
		t.Fatal(err)
	}
	got, err := schema.Hash(event)
	if err != nil {
		t.Fatal(err)
	}
	if got != vecCore {
		t.Errorf("core schema 哈希与固定向量不符\n got=%s\nwant=%s\n（若 gateway-core policyaudit.hash() 有变更，须同步本向量）", got, vecCore)
	}
}

func TestUnknownSchema(t *testing.T) {
	if _, err := SchemaFor("nope"); err == nil {
		t.Fatal("未知 schema 应返回错误")
	}
}

func TestVerifyChainOK(t *testing.T) {
	schema, _ := SchemaFor("admin")
	res, err := VerifyReader(strings.NewReader(adminEventA+"\n"+adminEventB+"\n"), schema)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Events != 2 || res.LastHash != vecAdminTarget {
		t.Errorf("期望 OK/2 条/链尾 %s，实际 ok=%v events=%d last=%s",
			vecAdminTarget, res.OK, res.Events, res.LastHash)
	}
}

// TestDetectTamper 中间事件被篡改：其内容变化会让**下一条**的 prev_hash 对不上。
func TestDetectTamper(t *testing.T) {
	schema, _ := SchemaFor("admin")
	tampered := strings.Replace(adminEventB, `"actor":"bob"`, `"actor":"eve"`, 1)
	_, err := VerifyReader(strings.NewReader(adminEventA+"\n"+tampered+"\n"+adminEventC+"\n"), schema)
	be, ok := err.(*ChainBreakError)
	if !ok {
		t.Fatalf("中间事件被篡改应检出链断裂，实际 err=%v", err)
	}
	if be.Index != 2 {
		t.Errorf("断裂应定位在第 3 条（index=2，被篡改事件的后继），实际 %d", be.Index)
	}
	// 走文件路径：断裂时仍报告"断前已校验 2 条 + 其链尾哈希"，便于取证定位。
	// 注意断前 2 条**已包含被篡改的第 2 条**（它自身的 prev_hash 是对的，问题在无后继可比对
	// 时无法自证内容），故链尾 = 篡改行的重算哈希，必不等于原始值。
	res := verifyViaFile(t, adminEventA+"\n"+tampered+"\n"+adminEventC+"\n", schema)
	if res.OK || res.BreakIndex != 2 || res.Events != 2 || len(res.LastHash) != 64 {
		t.Errorf("断裂报告应为 ok=false/breakIndex=2/断前 2 条/64 位链尾，实际 ok=%v breakIndex=%d events=%d last=%q",
			res.OK, res.BreakIndex, res.Events, res.LastHash)
	}
	if res.LastHash == vecAdminTarget {
		t.Error("断前链尾应为被篡改行的重算哈希，不应等于原始哈希")
	}
}

// TestTailTamperNeedsAnchor 链尾事件被篡改：链式校验**发现不了**（尾部哈希只是变了，
// 无后继事件可比对）——这正是锚定文件存在的意义；用锚点即可检出。
func TestTailTamperNeedsAnchor(t *testing.T) {
	schema, _ := SchemaFor("admin")
	full := adminEventA + "\n" + adminEventB + "\n" + adminEventC + "\n"

	original, err := VerifyReader(strings.NewReader(full), schema)
	if err != nil {
		t.Fatal(err)
	}
	if !original.OK || original.Events != 3 {
		t.Fatalf("前置链应完整，实际 ok=%v events=%d", original.OK, original.Events)
	}

	tailTampered := strings.Replace(full, `"max_tokens":1000`, `"max_tokens":1`, 1)
	res := verifyViaFile(t, tailTampered, schema)
	if !res.OK {
		t.Fatalf("链尾篡改后链式校验仍应自洽（这正是需要锚点的原因），实际：%s", res.BreakReason)
	}
	if res.LastHash == original.LastHash {
		t.Fatal("链尾内容已变，链尾哈希应随之变化")
	}

	chainPath, anchorPath := writeFixtures(t, tailTampered,
		fmt.Sprintf(`{"timestamp":1,"events":3,"chain_hash":%q}`+"\n", original.LastHash))
	withAnchor, err := VerifyFile(chainPath, anchorPath, schema, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if withAnchor.AnchorOK {
		t.Fatal("锚点应检出链尾被篡改")
	}
	if !strings.Contains(withAnchor.AnchorDetail, "不符") {
		t.Errorf("明细应指出哈希不符，实际：%s", withAnchor.AnchorDetail)
	}
}

func verifyViaFile(t *testing.T, chain string, schema Schema) *Result {
	t.Helper()
	chainPath, _ := writeFixtures(t, chain, "")
	res, err := VerifyFile(chainPath, "", schema, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestVerifyEmptyChain(t *testing.T) {
	schema, _ := SchemaFor("admin")
	res, err := VerifyReader(strings.NewReader("\n\n"), schema)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Events != 0 || res.LastHash != "" {
		t.Errorf("空链应视为 OK/0 条，实际 ok=%v events=%d last=%q", res.OK, res.Events, res.LastHash)
	}
}

func TestBadJSONLine(t *testing.T) {
	schema, _ := SchemaFor("admin")
	if _, err := VerifyReader(strings.NewReader("{not json}\n"), schema); err == nil {
		t.Fatal("坏 JSON 应返回错误")
	}
}

func TestVerifyFileWithAnchorOK(t *testing.T) {
	chainPath, anchorPath := writeFixtures(t, adminEventA+"\n"+adminEventB+"\n",
		fmt.Sprintf(`{"timestamp":1700000000000000002,"events":2,"chain_hash":%q}`+"\n", vecAdminTarget))
	schema, _ := SchemaFor("admin")
	res, err := VerifyFile(chainPath, anchorPath, schema, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || !res.AnchorChecked || !res.AnchorOK {
		t.Errorf("期望链 OK 且锚点匹配，实际 ok=%v anchorChecked=%v anchorOK=%v detail=%s",
			res.OK, res.AnchorChecked, res.AnchorOK, res.AnchorDetail)
	}
}

// TestEmptyAnchorIsNotFailure 空锚点文件（尚未达到 8192 条锚定间隔）是正常情况，
// 不得判失败——如实标注"未执行比对"。
func TestEmptyAnchorIsNotFailure(t *testing.T) {
	chainPath, anchorPath := writeFixtures(t, adminEventA+"\n"+adminEventB+"\n", "")
	schema, _ := SchemaFor("admin")
	res, err := VerifyFile(chainPath, anchorPath, schema, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("链本身应完整，实际：%s", res.BreakReason)
	}
	if res.AnchorChecked {
		t.Error("空锚点应标注为未执行比对（AnchorChecked=false）")
	}
	if !strings.Contains(res.AnchorDetail, "无法判定截断") {
		t.Errorf("应说明无法判定截断，实际：%s", res.AnchorDetail)
	}
}

// TestDetectTruncation 截断检测：链内部自洽（删掉尾部后 prev_hash 依然连贯），
// 仅靠链本身无法发现；必须靠锚点声明的 (events, chain_hash) 比对。
func TestDetectTruncation(t *testing.T) {
	// 锚点声明 2 条，但链文件只剩 1 条（尾部被删）
	chainPath, anchorPath := writeFixtures(t, adminEventA+"\n",
		fmt.Sprintf(`{"timestamp":1700000000000000002,"events":2,"chain_hash":%q}`+"\n", vecAdminTarget))
	schema, _ := SchemaFor("admin")
	res, err := VerifyFile(chainPath, anchorPath, schema, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("截断后的剩余链本身应自洽（这正是截断难以发现的原因），实际 ok=%v reason=%s", res.OK, res.BreakReason)
	}
	if res.AnchorOK {
		t.Fatal("锚点应检出截断")
	}
	if !strings.Contains(res.AnchorDetail, "截断") {
		t.Errorf("截断明细应说明原因，实际：%s", res.AnchorDetail)
	}
}

func TestAnchorHashMismatch(t *testing.T) {
	chainPath, anchorPath := writeFixtures(t, adminEventA+"\n"+adminEventB+"\n",
		fmt.Sprintf(`{"timestamp":1,"events":2,"chain_hash":%q}`+"\n", strings.Repeat("0", 64)))
	schema, _ := SchemaFor("admin")
	res, err := VerifyFile(chainPath, anchorPath, schema, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.AnchorOK {
		t.Fatal("锚点哈希不符应判定失败")
	}
	if !strings.Contains(res.AnchorDetail, "不符") {
		t.Errorf("明细应指出哈希不符，实际：%s", res.AnchorDetail)
	}
}

func writeFixtures(t *testing.T, chain, anchor string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	chainPath := filepath.Join(dir, "chain.jsonl")
	anchorPath := filepath.Join(dir, "anchor.jsonl")
	if err := os.WriteFile(chainPath, []byte(chain), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(anchorPath, []byte(anchor), 0o600); err != nil {
		t.Fatal(err)
	}
	return chainPath, anchorPath
}

// ---------- 窗口抽样（入口哈希驱动；缺省重算并如实标注） ----------

// 三事件管理面链的时间戳（A/B/C，间隔与事件常量注释一致）。
const (
	tsA = int64(1700000000000000000)
	tsB = int64(1700000000000000001)
	tsC = int64(1700000000000000003)
)

const adminChain3 = adminEventA + "\n" + adminEventB + "\n" + adminEventC + "\n"

// TestWindowWithExternalEntryHash 外部入口哈希：跳过窗口前缀，窗口内逐条校验。
func TestWindowWithExternalEntryHash(t *testing.T) {
	schema, _ := SchemaFor("admin")
	chainPath, _ := writeFixtures(t, adminChain3, "")
	res, err := VerifyFile(chainPath, "", schema, Options{From: time.Unix(0, tsB), EntryHash: vecAdminNoTarget})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || !res.Scoped {
		t.Fatalf("期望窗口验证通过，实际 ok=%v scoped=%v reason=%s", res.OK, res.Scoped, res.BreakReason)
	}
	if res.Events != 2 || res.ScopeFirstIndex != 1 || res.ScopeLastIndex != 2 || res.SkipBefore != 1 {
		t.Errorf("窗口应为第 2–3 条（index 1–2，跳过 1 条），实际 events=%d first=%d last=%d skipBefore=%d",
			res.Events, res.ScopeFirstIndex, res.ScopeLastIndex, res.SkipBefore)
	}
	if res.EntryHashSource != "external" || res.EntryHash != vecAdminNoTarget {
		t.Errorf("入口哈希应标注为 external 且等于第 1 条重算哈希，实际 source=%s hash=%s",
			res.EntryHashSource, res.EntryHash)
	}
	if res.RemainAfter != 0 {
		t.Errorf("未设 -to 应读到文件尾（remain_after=0），实际 %d", res.RemainAfter)
	}
}

// TestWindowRecomputedEntryHash 未提供入口哈希：先重算到窗口起点，口径如实标注 recomputed。
func TestWindowRecomputedEntryHash(t *testing.T) {
	schema, _ := SchemaFor("admin")
	chainPath, _ := writeFixtures(t, adminChain3, "")
	res, err := VerifyFile(chainPath, "", schema, Options{From: time.Unix(0, tsB)})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Events != 2 || res.ScopeFirstIndex != 1 || res.ScopeLastIndex != 2 {
		t.Fatalf("期望窗口内 2 条通过，实际 ok=%v events=%d first=%d last=%d",
			res.OK, res.Events, res.ScopeFirstIndex, res.ScopeLastIndex)
	}
	if res.EntryHashSource != "recomputed" || res.EntryHash != vecAdminNoTarget {
		t.Errorf("入口哈希应标注 recomputed 且等于重算所得 %s，实际 source=%s hash=%s",
			vecAdminNoTarget, res.EntryHashSource, res.EntryHash)
	}
}

// TestWindowEntryHashMismatch 入口哈希与链不一致 → 判失败（抽样验证的核心断言）。
func TestWindowEntryHashMismatch(t *testing.T) {
	schema, _ := SchemaFor("admin")
	chainPath, _ := writeFixtures(t, adminChain3, "")
	res, err := VerifyFile(chainPath, "", schema, Options{From: time.Unix(0, tsB), EntryHash: strings.Repeat("0", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.BreakIndex != 1 {
		t.Fatalf("入口哈希不符应判失败并定位第 2 条，实际 ok=%v breakIndex=%d", res.OK, res.BreakIndex)
	}
	if !strings.Contains(res.BreakReason, "窗口起点哈希不符") {
		t.Errorf("应给出入口哈希不符的原因，实际：%s", res.BreakReason)
	}
}

// TestWindowToOnlyStopsEarly 仅设 -to：窗口自创世起，读到超出窗口即停（入口来源 = genesis）。
func TestWindowToOnlyStopsEarly(t *testing.T) {
	schema, _ := SchemaFor("admin")
	chainPath, _ := writeFixtures(t, adminChain3, "")
	res, err := VerifyFile(chainPath, "", schema, Options{To: time.Unix(0, tsA)})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Events != 1 || res.ScopeFirstIndex != 0 || res.ScopeLastIndex != 0 {
		t.Fatalf("期望仅第 1 条在窗口内，实际 ok=%v events=%d first=%d last=%d",
			res.OK, res.Events, res.ScopeFirstIndex, res.ScopeLastIndex)
	}
	if res.EntryHashSource != "genesis" {
		t.Errorf("未设 -from 时入口应为创世（genesis），实际 %s", res.EntryHashSource)
	}
	if res.RemainAfter != -1 {
		t.Errorf("提前停止读取应标注 remain_after=-1，实际 %d", res.RemainAfter)
	}
}

// TestWindowOutsideAnchorNotReportedAsTruncation 窗口之外的锚点**不得误报截断**（如实标注未参与判定）。
func TestWindowOutsideAnchorNotReportedAsTruncation(t *testing.T) {
	schema, _ := SchemaFor("admin")
	full, err := VerifyReader(strings.NewReader(adminChain3), schema)
	if err != nil {
		t.Fatal(err)
	}
	chainPath, anchorPath := writeFixtures(t, adminChain3,
		fmt.Sprintf(`{"timestamp":1,"events":3,"chain_hash":%q}`+"\n", full.LastHash))
	res, err := VerifyFile(chainPath, anchorPath, schema, Options{To: time.Unix(0, tsA)})
	if err != nil {
		t.Fatal(err)
	}
	if res.AnchorChecked {
		t.Errorf("窗口外锚点应标注为未参与判定，实际 checked=%v detail=%s", res.AnchorChecked, res.AnchorDetail)
	}
	if !strings.Contains(res.AnchorDetail, "超出验证窗口") {
		t.Errorf("明细应说明超出验证窗口，实际：%s", res.AnchorDetail)
	}
	if strings.Contains(res.AnchorDetail, "尾部事件被删除") {
		t.Errorf("窗口外锚点不得误报截断，实际：%s", res.AnchorDetail)
	}
}

// TestWindowAnchorBeforeWindow 早于窗口起点的锚点同样如实标注（不误报）。
func TestWindowAnchorBeforeWindow(t *testing.T) {
	schema, _ := SchemaFor("admin")
	chainPath, anchorPath := writeFixtures(t, adminChain3,
		fmt.Sprintf(`{"timestamp":1,"events":1,"chain_hash":%q}`+"\n", vecAdminNoTarget))
	res, err := VerifyFile(chainPath, anchorPath, schema, Options{From: time.Unix(0, tsC), EntryHash: vecAdminTarget})
	if err != nil {
		t.Fatal(err)
	}
	if res.AnchorChecked {
		t.Errorf("窗口之前（第 1 条）的锚点应标注为未参与判定，实际 detail=%s", res.AnchorDetail)
	}
	if !strings.Contains(res.AnchorDetail, "早于验证窗口起点") {
		t.Errorf("明细应说明锚点早于窗口起点，实际：%s", res.AnchorDetail)
	}
}

// TestWindowAnchorAtEntryValidatesEntryHash 锚点落在窗口入口位置时，等于用锚点校验调用方给的入口哈希。
func TestWindowAnchorAtEntryValidatesEntryHash(t *testing.T) {
	schema, _ := SchemaFor("admin")
	chainPath, anchorPath := writeFixtures(t, adminChain3,
		fmt.Sprintf(`{"timestamp":1,"events":1,"chain_hash":%q}`+"\n", vecAdminNoTarget))
	res, err := VerifyFile(chainPath, anchorPath, schema, Options{From: time.Unix(0, tsB), EntryHash: vecAdminNoTarget})
	if err != nil {
		t.Fatal(err)
	}
	if !res.AnchorChecked || !res.AnchorOK {
		t.Errorf("锚点应校验通过入口哈希，实际 checked=%v ok=%v detail=%s",
			res.AnchorChecked, res.AnchorOK, res.AnchorDetail)
	}
}

// TestWindowOptionsValidation 参数自洽性（入口哈希须与 -from 同用；窗口不得倒置）。
func TestWindowOptionsValidation(t *testing.T) {
	schema, _ := SchemaFor("admin")
	chainPath, _ := writeFixtures(t, adminChain3, "")
	if _, err := VerifyFile(chainPath, "", schema, Options{EntryHash: vecAdminNoTarget}); err == nil {
		t.Error("入口哈希未配 -from 应报错")
	}
	if _, err := VerifyFile(chainPath, "", schema, Options{From: time.Unix(1, 0), To: time.Unix(0, 0)}); err == nil {
		t.Error("-from 晚于 -to 应报错")
	}
}

// TestWindowBadTimestampInvalid 窗口模式下事件缺时间戳 → 输入错误（全链模式不受影响）。
func TestWindowBadTimestampInvalid(t *testing.T) {
	schema, _ := SchemaFor("admin")
	noTS := `{"event_id":"evt-1","actor":"a","action":"x","request_id":"r","result":"ok","prev_hash":""}`
	chainPath, _ := writeFixtures(t, noTS+"\n", "")
	if _, err := VerifyFile(chainPath, "", schema, Options{To: time.Unix(0, tsA)}); err == nil {
		t.Error("窗口模式下缺时间戳应报错")
	}
	if _, err := VerifyFile(chainPath, "", schema, Options{}); err != nil {
		t.Errorf("全链模式不应解析时间戳（既有行为不得变化），实际 %v", err)
	}
}

// ---------- 锚点 TST imprint 一致性（决策③：离线校验，验签属外部条件） ----------

func imprintOf(chainHash string) string {
	sum := sha256.Sum256([]byte(chainHash))
	return hex.EncodeToString(sum[:])
}

func TestTSTImprintConsistency(t *testing.T) {
	schema, _ := SchemaFor("admin")
	full, err := VerifyReader(strings.NewReader(adminChain3), schema)
	if err != nil {
		t.Fatal(err)
	}
	good := fmt.Sprintf(
		`{"timestamp":1,"events":3,"chain_hash":%q,"tst":{"version":1,"algorithm":"sha256","timestamp_ns":1,"message_imprint":%q,"signature":"ab","tsa_public_key":"cd","source":"mock"}}`+"\n",
		full.LastHash, imprintOf(full.LastHash))

	chainPath, anchorPath := writeFixtures(t, adminChain3, good)
	res, err := VerifyFile(chainPath, anchorPath, schema, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.TSTChecked || !res.TSTOK {
		t.Errorf("imprint 一致应通过，实际 checked=%v ok=%v detail=%s", res.TSTChecked, res.TSTOK, res.TSTDetail)
	}

	// 锚点记录被替换（chain_hash 另取一条自洽记录）而令牌未同步换 → imprint 不符。
	tampered := strings.Replace(good, full.LastHash, strings.Repeat("0", 64), 1)
	chainPath2, anchorPath2 := writeFixtures(t, adminChain3, tampered)
	res2, err := VerifyFile(chainPath2, anchorPath2, schema, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !res2.TSTChecked || res2.TSTOK {
		t.Errorf("imprint 不符应判失败，实际 checked=%v ok=%v detail=%s", res2.TSTChecked, res2.TSTOK, res2.TSTDetail)
	}
}

// TestTSTAbsentIsNotFailure 未携带 TST（未启用 TSA / 旧格式）属正常情况：如实标注未执行。
func TestTSTAbsentIsNotFailure(t *testing.T) {
	schema, _ := SchemaFor("admin")
	chainPath, anchorPath := writeFixtures(t, adminChain3,
		fmt.Sprintf(`{"timestamp":1,"events":3,"chain_hash":%q}`+"\n", vecAdminTarget))
	res, err := VerifyFile(chainPath, anchorPath, schema, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.TSTChecked {
		t.Errorf("无 TST 应标注未执行校验，实际 detail=%s", res.TSTDetail)
	}
	if !strings.Contains(res.TSTDetail, "未携带 TST") {
		t.Errorf("应说明未携带 TST，实际：%s", res.TSTDetail)
	}
}

// ---------- 报告导出与锚点发射（决策②/③ 工具化） ----------

func TestReportWriteAndFields(t *testing.T) {
	schema, _ := SchemaFor("admin")
	chainPath, _ := writeFixtures(t, adminChain3, "")
	res, err := VerifyFile(chainPath, "", schema, Options{})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := NewReport(chainPath, res)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tool != "audit-verify" || rep.ChainLines != 3 || rep.ChainBytes == 0 || len(rep.ChainSHA256) != 64 {
		t.Errorf("报告元信息不完整：tool=%s lines=%d bytes=%d sha=%q",
			rep.Tool, rep.ChainLines, rep.ChainBytes, rep.ChainSHA256)
	}
	if len(rep.Limitations) < len(reportLimitations) {
		t.Errorf("报告应固化已知局限声明，实际 %d 条", len(rep.Limitations))
	}
	out := filepath.Join(t.TempDir(), "report.json")
	if err := WriteReport(out, rep); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("报告应为合法 JSON: %v", err)
	}
	if back.Result == nil || !back.Result.OK || back.Result.Events != 3 {
		t.Errorf("报告结论字段缺失：%+v", back.Result)
	}
}

// TestReportIncludesWindowLimitation 窗口模式报告须附带窗口局限声明。
func TestReportIncludesWindowLimitation(t *testing.T) {
	schema, _ := SchemaFor("admin")
	chainPath, _ := writeFixtures(t, adminChain3, "")
	res, err := VerifyFile(chainPath, "", schema, Options{To: time.Unix(0, tsA)})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := NewReport(chainPath, res)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range rep.Limitations {
		if strings.Contains(l, "窗口抽样模式") {
			found = true
		}
	}
	if !found {
		t.Errorf("窗口模式报告应含窗口局限声明，实际 %v", rep.Limitations)
	}
}

// TestEmitAnchorRoundTripAndTruncation 锚点发射闭环：产出的锚点既能判通过，也能检出截断。
func TestEmitAnchorRoundTripAndTruncation(t *testing.T) {
	schema, _ := SchemaFor("admin")
	chainPath, _ := writeFixtures(t, adminChain3, "")
	res, err := VerifyFile(chainPath, "", schema, Options{})
	if err != nil {
		t.Fatal(err)
	}
	anchorPath := filepath.Join(t.TempDir(), "emitted.anchor")
	rec, err := AnchorRecordFrom(res, 42)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Events != 3 || rec.ChainHash != res.LastHash || rec.Timestamp != 42 {
		t.Fatalf("锚点记录内容不符：%+v", rec)
	}
	if err := EmitAnchor(anchorPath, rec); err != nil {
		t.Fatal(err)
	}

	ok, err := VerifyFile(chainPath, anchorPath, schema, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !ok.AnchorChecked || !ok.AnchorOK {
		t.Errorf("正常链 + 新锚点应通过，实际 checked=%v ok=%v detail=%s", ok.AnchorChecked, ok.AnchorOK, ok.AnchorDetail)
	}

	truncated, _ := writeFixtures(t, adminEventA+"\n"+adminEventB+"\n", "")
	cut, err := VerifyFile(truncated, anchorPath, schema, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !cut.AnchorChecked || cut.AnchorOK {
		t.Fatalf("截断链应被锚点检出，实际 checked=%v ok=%v detail=%s", cut.AnchorChecked, cut.AnchorOK, cut.AnchorDetail)
	}
	if !strings.Contains(cut.AnchorDetail, "截断") {
		t.Errorf("明细应说明截断，实际：%s", cut.AnchorDetail)
	}
}

// TestAnchorRecordFromEmptyResult 未校验任何事件时不得产出锚点（避免产生"空链尾哈希"锚点污染）。
func TestAnchorRecordFromEmptyResult(t *testing.T) {
	schema, _ := SchemaFor("admin")
	res, err := VerifyReader(strings.NewReader("\n"), schema)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AnchorRecordFrom(res, 1); err == nil {
		t.Error("空链不应产出锚点记录")
	}
}
