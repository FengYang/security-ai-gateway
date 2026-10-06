package main

// audit_hashalg_test.go — P0-4 §5.2 写入侧测试锚：
//   T-5.2-2（SM3 新链可生成、链自洽）、T-5.2-3（SHA→SM3 混合链闭合）、
//   T-5.2-4（未知 hash_alg → 拒绝，含 WORM 恢复期 fail-closed）、
//   T-5.2-5（TST 锚 imprint 按 algorithm 分派）、T-5.2-6（`hash_alg` 不进 hash 输入）。

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// baseEvent 构造固定内容事件（HashAlg 留空 = 缺省）。
func baseEvent() AuditEvent {
	return AuditEvent{
		EventID: "evt-1", Timestamp: 1700000000000000000,
		TenantID: "acme", RequestID: "req-1", Action: "infer",
		TokensIn: 1, TokensOut: 2, Result: "ok", PayloadSHA: "aabbccdd",
	}
}

// T-5.2-6：`hash_alg` 的值**不进入** hash 输入——缺省（零值）与显式空串必须得到同一哈希。
// （该字段若被写入输入字节流，则改值必然改哈希；此处仅"算法分派"改哈希，见 T-5.2-2。）
func TestT526HashAlgNotHashed(t *testing.T) {
	e1 := baseEvent()
	e2 := baseEvent()
	e2.HashAlg = ""
	h1, err := e1.hashWithErr()
	if err != nil {
		t.Fatal(err)
	}
	h2, err := e2.hashWithErr()
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatal("HashAlg 空值与零值应得同一哈希（证明该字段不进 hash 输入，B-5.2-1）")
	}
}

// T-5.2-2：写入侧 SM3 事件与 SHA-256 事件哈希不同（分派确生效）；纯 SM3 链自洽。
func TestT522WriterSM3Chain(t *testing.T) {
	shaEv := baseEvent()
	smEv := baseEvent()
	smEv.HashAlg = "sm3"
	hSHA, err := shaEv.hashWithErr()
	if err != nil {
		t.Fatal(err)
	}
	hSM, err := smEv.hashWithErr()
	if err != nil {
		t.Fatal(err)
	}
	if hSHA == hSM {
		t.Fatal("同内容事件在缺省与 sm3 下哈希相同——算法未分派（T-5.2-2）")
	}
	c := newAuditChain()
	for i := 0; i < 3; i++ {
		e := baseEvent()
		e.EventID = string(rune('a' + i))
		e.HashAlg = "sm3"
		c.append(e)
	}
	if ok, idx := c.verify(); !ok {
		t.Fatalf("SM3 链应自洽，断裂于第 %d 条", idx)
	}
}

// T-5.2-3：SHA→SM3→SHA 混合链闭合，各事件 hash_alg 如实落链；未知算法不落链。
func TestT523WriterMixedChain(t *testing.T) {
	c := newAuditChain()
	evs := []AuditEvent{baseEvent(), baseEvent(), baseEvent()}
	evs[1].HashAlg = "sm3"
	for i := range evs {
		evs[i].EventID = string(rune('a' + i))
		c.append(evs[i])
	}
	if ok, idx := c.verify(); !ok {
		t.Fatalf("混合链应自洽（T-5.2-3），断裂于第 %d 条", idx)
	}
	if len(c.events) != 3 || c.events[0].HashAlg != "" || c.events[1].HashAlg != "sm3" || c.events[2].HashAlg != "" {
		t.Fatalf("hash_alg 未按事件如实落链：%q/%q/%q",
			c.events[0].HashAlg, c.events[1].HashAlg, c.events[2].HashAlg)
	}
	// R-12：未知算法在写入端不可达（HashAlg 仅由 hashAlgTag() 生成），但复算路径必须拒绝，
	// 且 append 的 fail-safe 分支不得把不可复算事件写入链。
	bad := baseEvent()
	bad.EventID = "evt-bad"
	bad.HashAlg = "md5"
	if _, err := bad.hashWithErr(); err == nil {
		t.Fatal("未知 hash_alg 应在复算路径报错（R-12）")
	}
	before := len(c.events)
	_ = c.append(bad)
	if len(c.events) != before {
		t.Fatal("被拒事件不应进入内存链")
	}
}

// T-5.2-4（恢复侧）：含未知 `hash_alg` 的 WORM 行 → load 拒绝（fail-closed，不得静默按 SHA-256 重算）。
func TestT524LoadRejectsUnknownHashAlg(t *testing.T) {
	path := t.TempDir() + "/audit.jsonl"
	first := baseEvent()
	first.PrevHash = ""
	h, err := first.hashWithErr()
	if err != nil {
		t.Fatal(err)
	}
	second := baseEvent()
	second.EventID = "evt-2"
	second.HashAlg = "md5"
	second.PrevHash = h

	l1, _ := json.Marshal(first)
	l2, _ := json.Marshal(second)
	if err := os.WriteFile(path, append(append(l1, '\n'), append(l2, '\n')...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := newAuditChain().load(path); err == nil {
		t.Fatal("含未知 hash_alg 的链应拒绝加载（R-12）")
	}
}

// T-5.2-5：TST 锚 imprint 按令牌自述 `algorithm` 分派；篡改 imprint → 拒绝。
func TestT525AnchorImprintDispatch(t *testing.T) {
	tsa, err := NewMockTSA()
	if err != nil {
		t.Fatal(err)
	}
	c := &auditChain{tsa: tsa}
	const chainHash = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

	// 本进程档（intl）下：imprint 用 SHA-256，令牌 algorithm="sha256"
	imprint, err := hashByAlg(hashAlgTag(), []byte(chainHash))
	if err != nil {
		t.Fatal(err)
	}
	tst, err := tsa.Sign(imprint)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.verifyTST(&AnchorRecord{ChainHash: chainHash, TST: tst}); err != nil {
		t.Fatalf("合法锚定应通过：%v", err)
	}

	// 篡改 imprint（换成 SM3 结果）→ 应拒绝
	sm, err := hashByAlg("sm3", []byte(chainHash))
	if err != nil {
		t.Fatal(err)
	}
	tampered := &AnchorRecord{ChainHash: chainHash, TST: &TST{
		Version: 1, Algorithm: tst.Algorithm,
		MessageImprint: hex.EncodeToString(sm), Signature: tst.Signature,
	}}
	if err := c.verifyTST(tampered); err == nil {
		t.Fatal("imprint 被替换应拒绝")
	}
}
