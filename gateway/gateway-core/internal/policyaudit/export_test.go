// P2-4 T-4.2：审计链导出（core schema）单测——导出可重算、截断、只读性。
package policyaudit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// exportFixtureEvent 构造第 i 条变更事件。
func exportFixtureEvent(i int) Event {
	return Event{
		EventID:     fmt.Sprintf("evt-%02d", i),
		Actor:       "tester",
		Action:      ActionApply,
		VersionFrom: i,
		VersionTo:   i + 1,
		RuleID:      fmt.Sprintf("rule-%d", i),
		Change:      ChangeUpdated,
		Field:       "rpm",
		OldValue:    fmt.Sprint(i * 10),
		NewValue:    fmt.Sprint((i + 1) * 10),
		RequestID:   fmt.Sprintf("req-%02d", i),
		Result:      ResultOK,
	}
}

// buildExportChain 构造含 n 条事件的链（内存模式）。
func buildExportChain(t *testing.T, n int) *Chain {
	t.Helper()
	c, err := New("")
	if err != nil {
		t.Fatalf("构造链失败: %v", err)
	}
	for i := 1; i <= n; i++ {
		if _, err := c.Append(exportFixtureEvent(i)); err != nil {
			t.Fatalf("追加事件失败: %v", err)
		}
	}
	return c
}

// TestExportRecomputeMatchesChainVerify **核心证据**：导出 → 独立重算 → 与链 Verify 结论一致。
func TestExportRecomputeMatchesChainVerify(t *testing.T) {
	c := buildExportChain(t, 5)
	res, err := c.Export(0) // 全量
	if err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	if res.Events != 5 || res.Total != 5 || res.Truncated {
		t.Fatalf("全量导出元信息不符: events=%d total=%d truncated=%v", res.Events, res.Total, res.Truncated)
	}
	if res.PrevHash != "" {
		t.Fatalf("全量导出 PrevHash 应为空: %q", res.PrevHash)
	}
	// 逐行 JSON 可解析，且事件条数与顺序一致。
	lines := strings.Split(strings.TrimSuffix(string(res.NDJSON), "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("NDJSON 行数不符: %d", len(lines))
	}
	for i, l := range lines {
		var e Event
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatalf("第 %d 行解析失败: %v", i+1, err)
		}
		if e.EventID != fmt.Sprintf("evt-%02d", i+1) {
			t.Fatalf("第 %d 行事件不符: %s", i+1, e.EventID)
		}
	}
	// 独立重算（等价于 audit-verify 侧复核口径）。
	ok, n, err := VerifyExport(res.NDJSON)
	if err != nil {
		t.Fatalf("重算出错: %v", err)
	}
	if !ok || n != 5 {
		t.Fatalf("导出内容重算应自洽: ok=%v n=%d", ok, n)
	}
	// 与链自身 Verify 结论一致。
	cok, cn := c.Verify()
	if cok != ok || cn != n {
		t.Fatalf("重算结论与链 Verify 不一致: chain=(%v,%d) export=(%v,%d)", cok, cn, ok, n)
	}
	// 链尾哈希 = 末条事件哈希（锚点比对基准）。
	evs := c.List(0)
	last := evs[len(evs)-1]
	want, werr := last.hashWithErr()
	if werr != nil {
		t.Fatalf("末条哈希计算失败: %v", werr)
	}
	if res.TailHash != want {
		t.Fatalf("链尾哈希不符: got %s want %s", res.TailHash, want)
	}
	// NDJSON 行格式与 WORM 行格式逐字节一致（同构保证）。
	worm, merr := json.Marshal(last)
	if merr != nil {
		t.Fatalf("序列化失败: %v", merr)
	}
	if lines[len(lines)-1] != string(worm) {
		t.Fatalf("导出行与 WORM 行序列化不一致")
	}
}

// TestExportTamperedDetected 导出内容被篡改 → 重算检出（ok=false）。
func TestExportTamperedDetected(t *testing.T) {
	c := buildExportChain(t, 3)
	res, err := c.Export(0)
	if err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(res.NDJSON), "\n"), "\n")
	// 篡改第 2 条的 actor（进 hash 域）→ 链断裂。
	var e Event
	if err := json.Unmarshal([]byte(lines[1]), &e); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	e.Actor = "attacker"
	tampered, merr := json.Marshal(e)
	if merr != nil {
		t.Fatalf("序列化失败: %v", merr)
	}
	lines[1] = string(tampered)
	ok, n, err := VerifyExport([]byte(strings.Join(lines, "\n") + "\n"))
	if err != nil {
		t.Fatalf("重算出错: %v", err)
	}
	// 篡改第 2 条的 actor（**进 hash 域**）→ 该条自身 prev_hash 仍对得上，
	// 但重算出的哈希已变 ⇒ **下一条**（第 3 条）衔接断裂，检出位置 n=2。
	if ok {
		t.Fatalf("篡改后应检出链断裂")
	}
	if n != 2 {
		t.Fatalf("断裂应于第 3 条处检出（已通过 2 条）: got %d", n)
	}
}

// TestExportLimitBoundary limit 边界：截断保留最近 N 条、PrevHash 可作为重算起点。
func TestExportLimitBoundary(t *testing.T) {
	c := buildExportChain(t, 5)
	res, err := c.Export(2)
	if err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	if res.Events != 2 || res.Total != 5 || !res.Truncated {
		t.Fatalf("截断导出元信息不符: %+v", res)
	}
	if res.PrevHash == "" {
		t.Fatalf("截断导出应带 PrevHash（重算起点）")
	}
	// 截断导出以 PrevHash 为起点重算 → 自洽；以空 prev 起始 → 不自洽（预期）。
	ok, n, err := VerifyExportFrom(res.NDJSON, res.PrevHash)
	if err != nil || !ok || n != 2 {
		t.Fatalf("截断导出按 PrevHash 重算应自洽: ok=%v n=%d err=%v", ok, n, err)
	}
	if ok2, _, _ := VerifyExport(res.NDJSON); ok2 {
		t.Fatalf("截断导出以空 prev 起始不应自洽（区间首条 prev 非创世）")
	}
	// 全量导出与 limit >= 总长等价。
	full, ferr := c.Export(0)
	if ferr != nil {
		t.Fatalf("全量导出失败: %v", ferr)
	}
	over, oerr := c.Export(99)
	if oerr != nil {
		t.Fatalf("超限导出失败: %v", oerr)
	}
	if !bytes.Equal(full.NDJSON, over.NDJSON) || over.Truncated {
		t.Fatalf("limit 超总长应与全量等价")
	}
}

// TestExportEmptyChain 空链导出：0 行、TailHash 空、重算自洽（0 条）。
func TestExportEmptyChain(t *testing.T) {
	c, err := New("")
	if err != nil {
		t.Fatalf("构造链失败: %v", err)
	}
	res, err := c.Export(0)
	if err != nil {
		t.Fatalf("空链导出失败: %v", err)
	}
	if res.Events != 0 || res.Total != 0 || res.TailHash != "" || len(res.Lines) != 0 {
		t.Fatalf("空链导出元信息不符: %+v", res)
	}
	ok, n, err := VerifyExport(res.NDJSON)
	if err != nil || !ok || n != 0 {
		t.Fatalf("空链重算应为 (true,0): ok=%v n=%d err=%v", ok, n, err)
	}
}

// TestExportReadOnly 导出只读：不改变链状态（Len/Verify/重复导出一致），
// 且 WORM 文件不被写入（导出不得污染 WORM）。
func TestExportReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/audit.jsonl"
	c, err := New(path)
	if err != nil {
		t.Fatalf("构造 WORM 链失败: %v", err)
	}
	for i := 1; i <= 3; i++ {
		if _, err := c.Append(exportFixtureEvent(i)); err != nil {
			t.Fatalf("追加失败: %v", err)
		}
	}
	beforeLen := c.Len()
	beforeOK, beforeN := c.Verify()
	first, err := c.Export(0)
	if err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	// 连续多次导出（含不同 limit）均不改变链状态。
	for _, l := range []int{0, 1, 2, 99} {
		if _, err := c.Export(l); err != nil {
			t.Fatalf("导出(limit=%d)失败: %v", l, err)
		}
	}
	after, err := c.Export(0)
	if err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	if c.Len() != beforeLen {
		t.Fatalf("导出改变了链长度: %d → %d", beforeLen, c.Len())
	}
	aok, an := c.Verify()
	if aok != beforeOK || an != beforeN {
		t.Fatalf("导出改变了校验结论")
	}
	if !bytes.Equal(first.NDJSON, after.NDJSON) {
		t.Fatalf("导出结果应幂等（链未被修改）")
	}
	// WORM 文件字节数不变（导出未追加任何行）。
	raw, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("读取 WORM 文件失败: %v", rerr)
	}
	if !bytes.Equal(raw, first.NDJSON) {
		t.Fatalf("导出污染了 WORM 文件: size=%d want=%d", len(raw), len(first.NDJSON))
	}
	_ = c.Close()
}
