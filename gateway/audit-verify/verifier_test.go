package auditverify

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
)

// admin 链：evt-1（无 target）→ evt-2（带 target）。
const (
	adminEventA = `{"event_id":"evt-1","timestamp":1700000000000000000,"actor":"alice","action":"credential_upsert","provider":"phala","key_fingerprint":"6a16570c","tenant":"","max_tokens":0,"request_id":"req-1","result":"ok","prev_hash":""}`
	adminEventB = `{"event_id":"evt-2","timestamp":1700000000000000001,"actor":"bob","action":"account_create","provider":"","key_fingerprint":"","tenant":"","max_tokens":0,"target":"admin02","request_id":"req-2","result":"ok","prev_hash":"` + vecAdminNoTarget + `"}`
	teeEventC   = `{"event_id":"evt-3","timestamp":1700000000000000002,"tenant_id":"acme","user_id":"","request_id":"req-3","action":"infer","tokens_in":12,"tokens_out":34,"result":"ok","payload_hash":"aabbccdd","prev_hash":""}`
	// 第三条管理面事件（三事件链用于"中间篡改"用例：只有存在后继事件，篡改才会在下一条暴露）。
	adminEventC = `{"event_id":"evt-3","timestamp":1700000000000000003,"actor":"carol","action":"quota_set","tenant":"acme","max_tokens":1000,"request_id":"req-3","result":"ok","prev_hash":"` + vecAdminTarget + `"}`
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
	withAnchor, err := VerifyFile(chainPath, anchorPath, schema)
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
	res, err := VerifyFile(chainPath, "", schema)
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
	res, err := VerifyFile(chainPath, anchorPath, schema)
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
	res, err := VerifyFile(chainPath, anchorPath, schema)
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
	res, err := VerifyFile(chainPath, anchorPath, schema)
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
	res, err := VerifyFile(chainPath, anchorPath, schema)
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
