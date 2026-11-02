// coord_test.go - Wire 定宽/字典序/唯一性/解析 契约测试（T01 验收项 1、2）
package route2plan

import (
	"sort"
	"strings"
	"testing"
)

// TestWireZeroPadding 定宽补零边界用例。
// 这是最容易写错的一条：一旦某个字段忘了补零，字典序就不再等于数值序
// （经典症状："12" < "9"，于是第 12 轮会排到第 9 轮前面，掩码域整体错位）。
func TestWireZeroPadding(t *testing.T) {
	cases := []struct {
		name string
		c    LayerCoord
		want string
	}{
		{
			name: "全零下界",
			c:    LayerCoord{Stage: StagePrefill, Turn: 0, Block: 0, Step: StepAttnNorm, Branch: BranchMain, Chunk: 0},
			want: "v2|1|000000|0000|00|0|00",
		},
		{
			name: "设计文档示例 block3/step1/branchQ",
			c:    LayerCoord{Stage: StagePrefill, Turn: 0, Block: 3, Step: StepKVAppend, Branch: BranchQ, Chunk: 0},
			want: "v2|1|000000|0003|01|2|00",
		},
		{
			name: "全上界 取值域最大值",
			c:    LayerCoord{Stage: StageDecode, Turn: MaxTurn, Block: MaxBlock, Step: MaxStep, Branch: MaxBranch, Chunk: MaxChunk},
			want: "v2|2|999999|9999|63|9|99",
		},
		{
			name: "turn 需补到 6 位",
			c:    LayerCoord{Stage: StageDecode, Turn: 13, Block: 0, Step: StepFFNUp, Branch: BranchMain, Chunk: 0},
			want: "v2|2|000013|0000|04|0|00",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.c.Validate(); err != nil {
				t.Fatalf("基准坐标应合法，却报错: %v", err)
			}
			if got := tc.c.Wire(); got != tc.want {
				t.Fatalf("Wire() =\n\t%q\nwant\n\t%q", got, tc.want)
			}
		})
	}
}

// TestWireFieldWidths 逐段断言六个字段的宽度（防止有人把 field 顺序或宽度改掉）。
func TestWireFieldWidths(t *testing.T) {
	c := LayerCoord{Stage: StageDecode, Turn: MaxTurn, Block: MaxBlock, Step: MaxStep, Branch: MaxBranch, Chunk: MaxChunk}
	parts := strings.Split(c.Wire(), "|")
	if len(parts) != wireFieldCount {
		t.Fatalf("Wire 段数 = %d, want %d", len(parts), wireFieldCount)
	}
	for i, width := range wireFieldWidths {
		if got := len(parts[i+1]); got != width {
			t.Errorf("第 %d 段 %q 宽度 = %d, want %d", i+1, parts[i+1], got, width)
		}
	}
	// 总长恒定：任何合法坐标的 Wire 长度都必须相同，这是字典序 == 时序的前提。
	wantLen := len(WireVersion) + 6 + sumFieldWidths()
	low := LayerCoord{Stage: StagePrefill, Turn: 0, Block: 0, Step: 0, Branch: 0, Chunk: 0}
	if got := len(low.Wire()); got != wantLen {
		t.Errorf("最小坐标 Wire 长度 = %d, want %d（字段未定宽！）", got, wantLen)
	}
	if got := len(c.Wire()); got != wantLen {
		t.Errorf("最大坐标 Wire 长度 = %d, want %d（字段未定宽！）", got, wantLen)
	}
}

// TestWireLexicographicEqualsCausal Wire 的字典序必须严格等于因果时序。
// 手法：构造一个**故意打乱**的坐标集合，用 Wire() 排序后与期望的因果序列逐项比较。
func TestWireLexicographicEqualsCausal(t *testing.T) {
	// 期望的因果序列（按 Stage → Turn → Block → Step → Branch → Chunk 升序书写）
	want := []LayerCoord{
		// Stage=1 整体先于 Stage=2
		{Stage: StagePrefill, Turn: 0, Block: 0, Step: StepAttnNorm, Branch: BranchMain, Chunk: 0},
		{Stage: StagePrefill, Turn: 0, Block: 0, Step: StepKVAppend, Branch: BranchK, Chunk: 0},
		{Stage: StagePrefill, Turn: 0, Block: 0, Step: StepKVAppend, Branch: BranchK, Chunk: 1},
		{Stage: StagePrefill, Turn: 0, Block: 0, Step: StepKVAppend, Branch: BranchV, Chunk: 0},
		{Stage: StagePrefill, Turn: 0, Block: 0, Step: StepKVAppend, Branch: BranchQ, Chunk: 0},
		{Stage: StagePrefill, Turn: 0, Block: 0, Step: StepAttnResidual, Branch: BranchMain, Chunk: 0},
		// Block 递增（含多位进位，验证补零）
		{Stage: StagePrefill, Turn: 0, Block: 2, Step: StepAttnNorm, Branch: BranchMain, Chunk: 0},
		{Stage: StagePrefill, Turn: 0, Block: 9, Step: StepAttnNorm, Branch: BranchMain, Chunk: 0},
		{Stage: StagePrefill, Turn: 0, Block: 10, Step: StepAttnNorm, Branch: BranchMain, Chunk: 0},
		{Stage: StagePrefill, Turn: 0, Block: 100, Step: StepAttnNorm, Branch: BranchMain, Chunk: 0},
		// Turn 递增（9 -> 12 是最经典的补零陷阱）
		{Stage: StagePrefill, Turn: 0, Block: 999, Step: StepAttnNorm, Branch: BranchMain, Chunk: 0},
		{Stage: StageDecode, Turn: 1, Block: 0, Step: StepAttnNorm, Branch: BranchMain, Chunk: 0},
		{Stage: StageDecode, Turn: 9, Block: 0, Step: StepAttnNorm, Branch: BranchMain, Chunk: 0},
		{Stage: StageDecode, Turn: 12, Block: 0, Step: StepAttnNorm, Branch: BranchMain, Chunk: 0},
		{Stage: StageDecode, Turn: 100, Block: 0, Step: StepAttnNorm, Branch: BranchMain, Chunk: 0},
		{Stage: StageDecode, Turn: 1000, Block: 0, Step: StepAttnNorm, Branch: BranchMain, Chunk: 0},
	}
	// 打乱顺序后按 Wire 排序
	got := make([]LayerCoord, len(want))
	copy(got, want)
	for i := len(got) - 1; i > 0; i-- {
		j := (i*7919 + 13) % (i + 1) // 确定性伪随机置换，不引入 math/rand
		got[i], got[j] = got[j], got[i]
	}
	sort.Slice(got, func(i, j int) bool { return CoordLess(got[i], got[j]) })

	for i := range want {
		if got[i].Wire() != want[i].Wire() {
			t.Errorf("排序后第 %d 项 = %s, 期望 %s", i, got[i].Wire(), want[i].Wire())
		}
	}
}

// TestWireOrderNumerically 直接断言几个关键对的相对次序。
func TestWireOrderNumerically(t *testing.T) {
	pairs := []struct {
		name    string
		earlier LayerCoord
		later   LayerCoord
	}{
		{
			name:    "stage 主导：prefill 整体早于 decode",
			earlier: LayerCoord{Stage: StagePrefill, Turn: MaxTurn, Block: MaxBlock, Step: MaxStep, Branch: MaxBranch, Chunk: MaxChunk},
			later:   LayerCoord{Stage: StageDecode, Turn: 0, Block: 0, Step: 0, Branch: 0, Chunk: 0},
		},
		{
			name:    "turn 9 必须早于 turn 12（补零陷阱）",
			earlier: LayerCoord{Stage: StageDecode, Turn: 9, Block: 0, Step: 0, Branch: 0, Chunk: 0},
			later:   LayerCoord{Stage: StageDecode, Turn: 12, Block: 0, Step: 0, Branch: 0, Chunk: 0},
		},
		{
			name:    "block 9 必须早于 block 10（补零陷阱）",
			earlier: LayerCoord{Stage: StageDecode, Turn: 5, Block: 9, Step: 0, Branch: 0, Chunk: 0},
			later:   LayerCoord{Stage: StageDecode, Turn: 5, Block: 10, Step: 0, Branch: 0, Chunk: 0},
		},
		{
			name:    "branch 在 chunk 之前比较：K/chunk=1 早于 V/chunk=0",
			earlier: LayerCoord{Stage: StagePrefill, Turn: 0, Block: 1, Step: StepKVAppend, Branch: BranchK, Chunk: 1},
			later:   LayerCoord{Stage: StagePrefill, Turn: 0, Block: 1, Step: StepKVAppend, Branch: BranchV, Chunk: 0},
		},
		{
			name:    "因果次序 K -> V -> Q",
			earlier: LayerCoord{Stage: StagePrefill, Turn: 0, Block: 1, Step: StepKVAppend, Branch: BranchV, Chunk: 0},
			later:   LayerCoord{Stage: StagePrefill, Turn: 0, Block: 1, Step: StepKVAppend, Branch: BranchQ, Chunk: 0},
		},
	}
	for _, tc := range pairs {
		t.Run(tc.name, func(t *testing.T) {
			a, b := tc.earlier.Wire(), tc.later.Wire()
			if !(a < b) {
				t.Fatalf("期望 %q < %q，实际不成立（字典序 != 时序）", a, b)
			}
			if !CoordLess(tc.earlier, tc.later) {
				t.Fatalf("CoordLess 与 Wire 比较结论不一致")
			}
		})
	}
}

// TestWireUnique 不同坐标必须有不同 Wire（掩码唯一性 B4 门禁的基础：坐标唯一 ⇒ 掩码唯一）。
func TestWireUnique(t *testing.T) {
	seen := make(map[string]LayerCoord)
	count := 0
	for st := 0; st < 2; st++ {
		stage := StagePrefill
		if st == 1 {
			stage = StageDecode
		}
		for turn := 0; turn < 300; turn += 37 {
			for block := 0; block < 40; block += 7 {
				for step := 0; step <= int(StepArgMax); step++ {
					for branch := 0; branch <= int(BranchQ); branch++ {
						c := LayerCoord{Stage: stage, Turn: uint32(turn), Block: uint16(block),
							Step: Step(step), Branch: Branch(branch), Chunk: 0}
						w := c.Wire()
						if prev, dup := seen[w]; dup {
							t.Fatalf("Wire %q 被两个不同坐标共享: %+v 与 %+v（掩码会被复用！）", w, prev, c)
						}
						seen[w] = c
						count++
					}
				}
			}
		}
	}
	if count < 500 {
		t.Fatalf("样本量 %d 过小，测不出唯一性", count)
	}
	t.Logf("唯一性样本量 = %d，全部互不相同", count)
}

// TestParseWireRoundTrip Wire -> ParseWire -> Wire 必须回到同一串。
func TestParseWireRoundTrip(t *testing.T) {
	cases := []LayerCoord{
		{Stage: StagePrefill, Turn: 0, Block: 0, Step: StepAttnNorm, Branch: BranchMain, Chunk: 0},
		{Stage: StagePrefill, Turn: 0, Block: 3, Step: StepKVAppend, Branch: BranchQ, Chunk: 0},
		{Stage: StageDecode, Turn: MaxTurn, Block: MaxBlock, Step: MaxStep, Branch: MaxBranch, Chunk: MaxChunk},
		{Stage: StageDecode, Turn: 16, Block: 2048, Step: StepFinalNorm, Branch: BranchMain, Chunk: 3},
	}
	for _, c := range cases {
		w := c.Wire()
		got, err := ParseWire(w)
		if err != nil {
			t.Fatalf("ParseWire(%q) 报错: %v", w, err)
		}
		if got != c {
			t.Fatalf("往返失真: got %+v, want %+v", got, c)
		}
		if got.Wire() != w {
			t.Fatalf("再 Wire() 失真: got %q, want %q", got.Wire(), w)
		}
	}
}

// TestParseWireRejects 格式或取值域有一处不对，ParseWire 必须拒绝（fail-closed）。
func TestParseWireRejects(t *testing.T) {
	bad := []struct {
		name string
		in   string
	}{
		{"v1 前缀", "v1|1|000000|0000|00|0|00"},
		{"未知前缀", "v3|1|000000|0000|00|0|00"},
		{"段数不足", "v2|1|000000|0000|00|0"},
		{"段数超出", "v2|1|000000|0000|00|0|00|00"},
		{"turn 未补零", "v2|1|0|0000|00|0|00"},
		{"turn 超长", "v2|1|0000000|0000|00|0|00"},
		{"block 未补零", "v2|1|000000|0|00|0|00"},
		{"含非数字", "v2|1|00000x|0000|00|0|00"},
		{"含负号", "v2|1|-00001|0000|00|0|00"},
		{"含空白", "v2|1|000001|0000|00|0| "},
		{"stage 0 非法", "v2|0|000000|0000|00|0|00"},
		{"stage 3 非法", "v2|3|000000|0000|00|0|00"},
		{"step 超出 0..63", "v2|1|000000|0000|99|0|00"},
		{"空串", ""},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if c, err := ParseWire(tc.in); err == nil {
				t.Fatalf("ParseWire(%q) 应报错却被接受: %+v", tc.in, c)
			}
		})
	}
}

// TestCoordValidateRejects 零值与越界坐标必须被 Validate 拒绝。
func TestCoordValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		c    LayerCoord
	}{
		{"零值坐标（Stage 未赋）", LayerCoord{}},
		{"Stage=0", LayerCoord{Stage: 0, Turn: 0, Block: 0, Step: 0}},
		{"Stage=3", LayerCoord{Stage: 3, Turn: 0, Block: 0, Step: 0}},
		{"Turn 越界", LayerCoord{Stage: StageDecode, Turn: MaxTurn + 1}},
		{"Block 越界", LayerCoord{Stage: StageDecode, Block: MaxBlock + 1}},
		{"Step 越界", LayerCoord{Stage: StageDecode, Step: MaxStep + 1}},
		{"Branch 越界", LayerCoord{Stage: StageDecode, Branch: MaxBranch + 1}},
		{"Chunk 越界", LayerCoord{Stage: StageDecode, Chunk: MaxChunk + 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.c.Validate(); err == nil {
				t.Fatalf("Validate() 应拒绝 %+v 却被接受", tc.c)
			}
		})
	}
}

// TestMaskDomainFormat 掩码域名 == otpmask/step/<wire>/v2，且唯一 => 域唯一。
func TestMaskDomainFormat(t *testing.T) {
	c := LayerCoord{Stage: StagePrefill, Turn: 0, Block: 3, Step: StepKVAppend, Branch: BranchQ, Chunk: 0}
	want := "otpmask/step/v2|1|000000|0003|01|2|00/v2"
	if got := c.MaskDomain(); got != want {
		t.Fatalf("MaskDomain() = %q, want %q", got, want)
	}
	// StepSpec.MaskDomain 必须与 Coord.MaskDomain 完全一致（产出步 own 掩码域，R5）
	s := StepSpec{Seq: 7, Coord: c}
	if got := s.MaskDomain(); got != want {
		t.Fatalf("StepSpec.MaskDomain() = %q, want %q（产出步必须 own 自己的掩码域）", got, want)
	}
}

// TestInjectDomainContainsStageTurn 注入域必须把 Stage/Turn 编进去，
// 否则同一 ρ_inj 会被多轮复用（§0.4 一步一掩码）。
func TestInjectDomainContainsStageAndTurn(t *testing.T) {
	d0, err := InjectDomain(StagePrefill, 0)
	if err != nil {
		t.Fatal(err)
	}
	d1, err := InjectDomain(StageDecode, 1)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := InjectDomain(StageDecode, 12)
	if err != nil {
		t.Fatal(err)
	}
	if d0 == d1 {
		t.Fatalf("prefill 与 decode 共享注入域 %q（跨阶段掩码复用）", d0)
	}
	if d1 == d2 {
		t.Fatalf("不同轮共享注入域 %q（跨轮掩码复用）", d1)
	}
	if !strings.HasPrefix(d1, InjectDomainPrefix) {
		t.Fatalf("注入域 %q 应以前缀 %q 开头", d1, InjectDomainPrefix)
	}
	if _, err := InjectDomain(Stage(9), 0); err == nil {
		t.Fatal("非法 Stage 的注入域应被拒绝")
	}
	if _, err := InjectDomain(StageDecode, MaxTurn+1); err == nil {
		t.Fatal("越界 Turn 的注入域应被拒绝")
	}
}

// sumFieldWidths 六个字段宽度之和（测试辅助）。
func sumFieldWidths() int {
	total := 0
	for _, w := range wireFieldWidths {
		total += w
	}
	return total
}
