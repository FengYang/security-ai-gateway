package auditverify

// hashalg_test.go — P0-4 §5.2 测试锚：T-5.2-2（SM3 新链）、T-5.2-3（混合链）、
// T-5.2-4（未知 hash_alg → 失败）、T-5.2-5（TST 锚 algorithm 分派）、
// T-5.2-6（`hash_alg` 不进 hash 的字段列表断言）。
// T-5.2-1（SHA-256 旧链回归 / 固定向量）见 verifier_test.go。

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// T-5.2-6：`hash_alg` 不得出现在任何 schema 的哈希字段列表中（B-5.2-1）。
func TestT526HashAlgNotInSchemaFields(t *testing.T) {
	for name, s := range Schemas {
		for _, f := range s.Fields {
			if f.JSONKey == "hash_alg" {
				t.Fatalf("schema %q 的哈希字段列表含 hash_alg（B-5.2-1：不得进 hash）", name)
			}
		}
	}
}

// T-5.2-4：未知 `hash_alg` → 验证失败（R-12），且不得静默回退 SHA-256；缺省/空 → SHA-256（R-13）。
func TestT524UnknownHashAlgFailsAndR13Default(t *testing.T) {
	s, err := SchemaFor("tee")
	if err != nil {
		t.Fatal(err)
	}
	base := map[string]any{
		"event_id": "evt-1", "timestamp": json.Number("1700000000000000000"),
		"tenant_id": "acme", "user_id": "", "request_id": "req-1", "action": "infer",
		"tokens_in": json.Number("1"), "tokens_out": json.Number("2"),
		"result": "ok", "payload_hash": "aabb", "prev_hash": "",
	}
	// R-13：缺省（无字段）与显式空串均按 SHA-256，且二者结果一致
	hNoField, err := s.Hash(base)
	if err != nil {
		t.Fatalf("缺省应可用（R-13）：%v", err)
	}
	withEmpty := cloneEvent(base)
	withEmpty["hash_alg"] = ""
	hEmpty, err := s.Hash(withEmpty)
	if err != nil {
		t.Fatalf("空串应可用（R-13）：%v", err)
	}
	if hNoField != hEmpty {
		t.Fatalf("缺省与空串应等价（R-13）：%s vs %s", hNoField, hEmpty)
	}
	// R-12：未知值一律报错（含拼写相近的 "sha256"）
	for _, bad := range []string{"sha256", "SM3", "sm3 ", "md5", "sha-256"} {
		ev := cloneEvent(base)
		ev["hash_alg"] = bad
		if _, err := s.Hash(ev); err == nil {
			t.Fatalf("未知 hash_alg=%q 应验证失败（R-12）", bad)
		}
	}
}

// T-5.2-2 + T-5.2-3：SM3 事件可生成+可验；SHA→SM3 混合链无缝闭合；算法分派确实切换（非同值）。
func TestT522T523SM3AndMixedChain(t *testing.T) {
	s, err := SchemaFor("tee")
	if err != nil {
		t.Fatal(err)
	}
	ev := func(i int, alg string) map[string]any {
		e := map[string]any{
			"event_id": fmt.Sprintf("evt-%d", i), "timestamp": json.Number(strconv.Itoa(1700000000000000000 + i)),
			"tenant_id": "acme", "user_id": "", "request_id": fmt.Sprintf("req-%d", i), "action": "infer",
			"tokens_in": json.Number("1"), "tokens_out": json.Number("2"),
			"result": "ok", "payload_hash": "aabb",
		}
		if alg != "" {
			e["hash_alg"] = alg
		}
		return e
	}
	// 分派确有效果：同一事件 SHA-256 与 SM3 哈希必不同（否则说明未切换算法）
	e0 := ev(1, "")
	hSHA, err := s.Hash(e0)
	if err != nil {
		t.Fatalf("SHA 事件重算失败：%v", err)
	}
	e0sm := cloneEvent(e0)
	e0sm["hash_alg"] = "sm3"
	hSM3, err := s.Hash(e0sm)
	if err != nil {
		t.Fatalf("SM3 事件重算失败：%v", err)
	}
	if hSHA == hSM3 {
		t.Fatal("同一事件在 hash_alg=\"\" 与 \"sm3\" 下哈希相同——算法未分派")
	}

	// 混合链：①SHA-256（缺省）→ ②SM3 → ③SHA-256（缺省）；链须闭合
	chain := buildChain(t, s, []map[string]any{
		ev(1, ""),    // SHA-256
		ev(2, "sm3"), // SM3
		ev(3, ""),    // 再回 SHA-256
	})
	res, err := VerifyReader(strings.NewReader(string(chain)), s)
	if err != nil {
		t.Fatalf("混合链验证返回输入错误：%v", err)
	}
	if !res.OK {
		t.Fatalf("混合链应通过（T-5.2-3）：break=%d reason=%s", res.BreakIndex, res.BreakReason)
	}
	if res.Events != 3 {
		t.Fatalf("应校验 3 条，得 %d", res.Events)
	}

	// 链内混入未知 hash_alg → **验证失败**（R-12，Result.OK=false 带原因），非"输入不可用"
	bad := strings.Replace(string(chain), `"hash_alg":"sm3"`, `"hash_alg":"md5"`, 1)
	dir := t.TempDir()
	badPath := dir + "/bad.jsonl"
	if err := os.WriteFile(badPath, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	res2, err := VerifyFile(badPath, "", s, Options{})
	if err != nil {
		t.Fatalf("R-12 应为「验证失败」而非常规错误：%v", err)
	}
	if res2.OK {
		t.Fatal("含未知 hash_alg 的链不应通过（R-12）")
	}
	if !strings.Contains(res2.BreakReason, "hash_alg") {
		t.Fatalf("失败原因应指明 hash_alg，得：%s", res2.BreakReason)
	}
}

// T-5.2-5：TST 锚 imprint 按令牌自述 `algorithm` 分派（sm3 → SM3；空/其它 → SHA-256）。
func TestT525TSTImprintDispatch(t *testing.T) {
	const chainHash = "00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff"
	shaImprint := hex.EncodeToString(hashProvSHA256.Hash([]byte(chainHash)))
	smImprint := hex.EncodeToString(hashProvSM3.Hash([]byte(chainHash)))
	if shaImprint == smImprint {
		t.Fatal("SHA-256 与 SM3 imprint 不应相同（前置条件失败）")
	}
	cases := []struct {
		name string
		rec  AnchorRecord
		ok   bool
	}{
		{"algorithm=sha256 + SHA imprint（旧锚）", AnchorRecord{Events: 1, ChainHash: chainHash, TST: &TSTToken{Algorithm: "sha256", MessageImprint: shaImprint}}, true},
		{"algorithm 缺省 + SHA imprint（fail-safe 默认）", AnchorRecord{Events: 1, ChainHash: chainHash, TST: &TSTToken{Algorithm: "", MessageImprint: shaImprint}}, true},
		{"algorithm=sm3 + SM3 imprint（新锚）", AnchorRecord{Events: 1, ChainHash: chainHash, TST: &TSTToken{Algorithm: "sm3", MessageImprint: smImprint}}, true},
		{"algorithm=sm3 + SHA imprint（不符）", AnchorRecord{Events: 1, ChainHash: chainHash, TST: &TSTToken{Algorithm: "sm3", MessageImprint: shaImprint}}, false},
		{"algorithm 缺省 + SM imprint（不符，防伪造绕过）", AnchorRecord{Events: 1, ChainHash: chainHash, TST: &TSTToken{Algorithm: "", MessageImprint: smImprint}}, false},
	}
	for _, c := range cases {
		checked, ok, detail := checkTST([]AnchorRecord{c.rec})
		if !checked {
			t.Fatalf("%s：应执行了 imprint 比对", c.name)
		}
		if ok != c.ok {
			t.Fatalf("%s：ok=%v want=%v（%s）", c.name, ok, c.ok, detail)
		}
	}
}

// ---- 测试辅助 ----

func cloneEvent(e map[string]any) map[string]any {
	out := make(map[string]any, len(e)+1)
	for k, v := range e {
		out[k] = v
	}
	return out
}

// buildChain 按 schema 逐条计算哈希并串接 prev_hash，输出 NDJSON（模拟写入端产物）。
func buildChain(t *testing.T, s Schema, evs []map[string]any) []byte {
	t.Helper()
	prev := ""
	var sb strings.Builder
	for _, e := range evs {
		e["prev_hash"] = prev
		h, err := s.Hash(e)
		if err != nil {
			t.Fatalf("buildChain: %v", err)
		}
		prev = h
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("buildChain marshal: %v", err)
		}
		sb.Write(line)
		sb.WriteByte('\n')
	}
	return []byte(sb.String())
}
