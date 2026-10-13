package main

// audit_t1_test.go — P1-7 T1（记录模型扩展）验收 V-6：
// ① 含全部新证据字段的事件 hash() 与不含时完全相同（新字段不进 hash()，C-3/D-1）；
// ② 新字段 JSON 往返无损；③ 旧 WORM 行（无新字段）load + 链校验通过（向后兼容）。

import (
	"encoding/json"
	"os"
	"testing"
)

// 填充 §6.1(B) 全部新增证据字段（不进 hash）。
func t1FilledEvent() AuditEvent {
	e := baseEvent()
	e.Path = "/v1/infer"
	e.PathMode = "encrypted"
	e.TTFTMs = 123
	e.DurMS = 456
	e.HTTPStatus = 200
	e.HitPolicies = "guardrail_pii,rpm_limit"
	e.Origin = "data-plane"
	e.Sampled = false // 废弃不启用，恒 false
	e.MCPSessionID = "mcp-sess-xyz"
	e.ReporterID = "reporter-inst-7"
	e.TenantIDResolution = "consumer_map"
	return e
}

// V-6①：新字段事件 hash() 恒定。
func TestT1NewFieldsDoNotAffectHash(t *testing.T) {
	base := baseEvent()
	hBase, err := base.hashWithErr()
	if err != nil {
		t.Fatal(err)
	}

	filled := t1FilledEvent()
	hFilled, err := filled.hashWithErr()
	if err != nil {
		t.Fatal(err)
	}

	if hBase != hFilled {
		t.Fatalf("新证据字段不应改变哈希：base=%s filled=%s", hBase, hFilled)
	}

	// 多次变动新字段值，哈希仍恒定。
	for i := 0; i < 5; i++ {
		f := t1FilledEvent()
		f.TTFTMs = i * 10
		f.HitPolicies = "output_blocked"
		f.ReporterID = "reporter-" + string(rune('a'+i))
		h, err := f.hashWithErr()
		if err != nil {
			t.Fatal(err)
		}
		if h != hBase {
			t.Fatalf("新字段取值变化仍应恒定哈希：i=%d got=%s want=%s", i, h, hBase)
		}
	}
}

// V-6②：JSON 往返保留新字段。
func TestT1JSONRoundTrip(t *testing.T) {
	filled := t1FilledEvent()
	raw, err := json.Marshal(filled)
	if err != nil {
		t.Fatal(err)
	}
	// 反序列化后字段应存在（非 omitempty 剔除）。
	var got AuditEvent
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Path != filled.Path || got.PathMode != filled.PathMode ||
		got.TTFTMs != filled.TTFTMs || got.DurMS != filled.DurMS ||
		got.HTTPStatus != filled.HTTPStatus || got.HitPolicies != filled.HitPolicies ||
		got.Origin != filled.Origin || got.MCPSessionID != filled.MCPSessionID ||
		got.ReporterID != filled.ReporterID || got.TenantIDResolution != filled.TenantIDResolution {
		t.Fatalf("JSON 往返丢失新字段：got=%+v", got)
	}
}

// V-6③：旧 WORM 行（无新字段）load + verify 通过（向后兼容，旧链逐字节不变）。
func TestT1OldChainLoadVerifies(t *testing.T) {
	path := t.TempDir() + "/audit.jsonl"
	first := baseEvent()
	first.PrevHash = ""
	prev, err := first.hashWithErr()
	if err != nil {
		t.Fatal(err)
	}
	second := baseEvent()
	second.EventID = "evt-2"
	second.RequestID = "req-2"
	second.PrevHash = prev

	l1, _ := json.Marshal(first)
	l2, _ := json.Marshal(second)
	if err := os.WriteFile(path, append(append(l1, '\n'), append(l2, '\n')...), 0o600); err != nil {
		t.Fatal(err)
	}

	c := newAuditChain()
	if err := c.load(path); err != nil {
		t.Fatalf("旧链 load 失败：%v", err)
	}
	if ok, idx := c.verify(); !ok {
		t.Fatalf("旧链应自洽，断裂于第 %d 条", idx)
	}
	if len(c.events) != 2 {
		t.Fatalf("旧链应恢复 2 条事件，实际 %d", len(c.events))
	}
}

// V-6③延伸：含新字段的事件写入后，旧字段构成的哈希链仍可重放（append 自洽）。
func TestT1ChainWithNewFieldsSelfConsistent(t *testing.T) {
	c := newAuditChain()
	for i := 0; i < 4; i++ {
		e := t1FilledEvent()
		e.EventID = string(rune('a' + i))
		e.RequestID = "req-" + string(rune('a'+i))
		c.append(e)
	}
	if ok, idx := c.verify(); !ok {
		t.Fatalf("含新字段链应自洽，断裂于第 %d 条", idx)
	}
	// 反序列化后新字段仍在。
	raw, _ := json.Marshal(c.events[0])
	var got AuditEvent
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Path == "" || got.TenantIDResolution == "" {
		t.Fatal("落链事件应保留新证据字段")
	}
}
