// plan_test.go - Build 确定性 / plan 合法性 / 逐行掩码溯源 契约测试（T01 验收项 2、3、4）
package route2plan

import (
	"reflect"
	"testing"
)

// buildDemoPlan 便利函数：构建 DemoTiny 的 prefill plan。
func buildDemoPlan(t *testing.T) Plan {
	t.Helper()
	p, err := Build(DemoTiny)
	if err != nil {
		t.Fatalf("Build(DemoTiny) 报错: %v", err)
	}
	return p
}

// TestBuildDeterminism 同 cfg 两次构建必须逐字段相等（有单测强制，
// 因为这是客户端与服务端达成一致的唯一依据）。
func TestBuildDeterminism(t *testing.T) {
	p1, err := Build(DemoTiny)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := Build(DemoTinyConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p1, p2) {
		t.Fatal("同 cfg 两次 Build 结果不一致（plan 不是确定性产物！）")
	}
	// 不同 cfg 必须不同
	other := DemoTinyConfig()
	other.Blocks = 6
	p3, err := Build(other)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(p1, p3) {
		t.Fatal("不同 cfg（Blocks 6 vs 4）得到了相同 plan")
	}
	// 不同 ModelID 必须不同足够多：至少坐标全等但 Seq 不变的情况下也应视为不同 cfg
	// （ModelID 不进坐标，但进权重派生；这里只断言 plan 结构一致，权重差异由 model_weights_test 覆盖）
	other2 := DemoTinyConfig()
	other2.ModelID = "route2-demo-other"
	p4, err := Build(other2)
	if err != nil {
		t.Fatal(err)
	}
	if len(p4) != len(p1) {
		t.Fatalf("ModelID 不应改变 plan 结构，长度 %d vs %d", len(p4), len(p1))
	}
}

// TestBuildTurnDistinct 不同 (stage, turn) 必须构造出不同坐标的 plan（防掩码跨轮复用）。
func TestBuildTurnDistinct(t *testing.T) {
	pre, err := Build(DemoTiny)
	if err != nil {
		t.Fatal(err)
	}
	d1, err := BuildTurn(DemoTiny, StageDecode, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(pre) != len(d1) {
		t.Fatalf("prefill 与 decode 的 plan 长度应相同: %d vs %d", len(pre), len(d1))
	}
	same := 0
	for i := range pre {
		if pre[i].Coord == d1[i].Coord {
			same++
		}
	}
	if same != 0 {
		t.Fatalf("prefill 与 decode 有 %d 个坐标完全相同（掩码会被跨阶段复用！）", same)
	}
	// 非法 (stage, turn) 组合必须被拒
	if _, err := BuildTurn(DemoTiny, StageDecode, 0); err == nil {
		t.Fatal("decode + Turn=0 应被拒绝")
	}
	if _, err := BuildTurn(DemoTiny, StagePrefill, 1); err == nil {
		t.Fatal("prefill + Turn=1 应被拒绝")
	}
	if _, err := BuildTurn(DemoTiny, StageUnset, 0); err == nil {
		t.Fatal("StageUnset 应被拒绝")
	}
	if _, err := Build(DemoTinyConfig()); err != nil {
		t.Fatal(err)
	}
	bad := DemoTinyConfig()
	bad.Heads = 3 // Heads*HeadDim = 24 != Dim=32
	if _, err := Build(bad); err == nil {
		t.Fatal("Heads*HeadDim != Dim 的配置应被拒绝")
	}
}

// TestBuildStructure DemoTiny (Blocks=4) 的 plan 形态逐条断言。
func TestBuildStructure(t *testing.T) {
	p := buildDemoPlan(t)
	if want := PlanLen(DemoBlocks); len(p) != want {
		t.Fatalf("plan 长度 = %d, want %d", len(p), want)
	}
	blocks, err := p.Blocks()
	if err != nil {
		t.Fatal(err)
	}
	if blocks != DemoTiny.Blocks {
		t.Fatalf("Blocks() = %d, want %d", blocks, DemoTiny.Blocks)
	}
	if p.Stage() != StagePrefill {
		t.Fatalf("Stage() = %v, want prefill", p.Stage())
	}
	if p.Turn() != 0 {
		t.Fatalf("Turn() = %d, want 0", p.Turn())
	}

	type row struct {
		op       string
		step     Step
		branch   Branch
		block    uint16
		inDim    []int
		inSrc    []int
		weight   []WeightRef
		outDim   int
		writes   bool
		reads    bool
		terminal bool
	}

	q := TensorKey{Block: 0, Tensor: TensorAttnQ}
	k := TensorKey{Block: 0, Tensor: TensorAttnK}
	v := TensorKey{Block: 0, Tensor: TensorAttnV}
	o := TensorKey{Block: 0, Tensor: TensorAttnO}
	up := TensorKey{Block: 0, Tensor: TensorFFNUp}
	down := TensorKey{Block: 0, Tensor: TensorFFNDown}

	want := []row{
		// ---- block 0 ----
		{op: OpRMSNorm, step: StepAttnNorm, branch: BranchMain, block: 0,
			inDim: []int{32}, inSrc: []int{SrcInject}, weight: []WeightRef{NoWeight()}, outDim: 32},
		{op: OpKVAppendK, step: StepKVAppend, branch: BranchK, block: 0,
			inDim: []int{32}, inSrc: []int{0}, weight: []WeightRef{RefKey(k)}, outDim: 0, writes: true},
		{op: OpKVAppendV, step: StepKVAppend, branch: BranchV, block: 0,
			inDim: []int{32}, inSrc: []int{0}, weight: []WeightRef{RefKey(v)}, outDim: 0, writes: true},
		{op: OpAttention, step: StepKVAppend, branch: BranchQ, block: 0,
			inDim: []int{32}, inSrc: []int{0}, weight: []WeightRef{RefKey(q)}, outDim: 32, reads: true},
		{op: OpResidualAdd, step: StepAttnResidual, branch: BranchMain, block: 0,
			inDim: []int{32, 32}, inSrc: []int{3, SrcInject}, weight: []WeightRef{RefKey(o), NoWeight()}, outDim: 32},
		{op: OpRMSNorm, step: StepFFNNorm, branch: BranchMain, block: 0,
			inDim: []int{32}, inSrc: []int{4}, weight: []WeightRef{NoWeight()}, outDim: 32},
		{op: OpGELU, step: StepFFNUp, branch: BranchMain, block: 0,
			inDim: []int{64}, inSrc: []int{5}, weight: []WeightRef{RefKey(up)}, outDim: 64},
		{op: OpResidualAdd, step: StepFFNResidual, branch: BranchMain, block: 0,
			inDim: []int{32, 32}, inSrc: []int{6, 4}, weight: []WeightRef{RefKey(down), NoWeight()}, outDim: 32},
	}

	if len(p) < len(want) {
		t.Fatalf("plan 过短: %d", len(p))
	}
	for i, w := range want {
		got := p[i]
		if got.Op != w.op {
			t.Errorf("#%d op = %q, want %q", i, got.Op, w.op)
		}
		if got.Coord.Step != w.step {
			t.Errorf("#%d Step = %d, want %d", i, got.Coord.Step, w.step)
		}
		if got.Coord.Branch != w.branch {
			t.Errorf("#%d Branch = %d, want %d", i, got.Coord.Branch, w.branch)
		}
		if got.Coord.Block != w.block {
			t.Errorf("#%d Block = %d, want %d", i, got.Coord.Block, w.block)
		}
		if !reflect.DeepEqual(got.InDim, w.inDim) {
			t.Errorf("#%d InDim = %v, want %v", i, got.InDim, w.inDim)
		}
		if !reflect.DeepEqual(got.InSrc, w.inSrc) {
			t.Errorf("#%d InSrc = %v, want %v", i, got.InSrc, w.inSrc)
		}
		if !reflect.DeepEqual(got.InWeight, w.weight) {
			t.Errorf("#%d InWeight = %v, want %v", i, got.InWeight, w.weight)
		}
		if got.OutDim != w.outDim {
			t.Errorf("#%d OutDim = %d, want %d", i, got.OutDim, w.outDim)
		}
		if got.Writes != w.writes {
			t.Errorf("#%d Writes = %v, want %v", i, got.Writes, w.writes)
		}
		if got.Reads != w.reads {
			t.Errorf("#%d Reads = %v, want %v", i, got.Reads, w.reads)
		}
		if got.Terminal != w.terminal {
			t.Errorf("#%d Terminal = %v, want %v", i, got.Terminal, w.terminal)
		}
	}

	// block 1 的残差源必须来自 block0 的 ffn_residual(#7)，而不是注入
	if got := p[BlockBase(1)+offAttnNorm].InSrc; !reflect.DeepEqual(got, []int{7}) {
		t.Errorf("block1 attn_norm 的 InSrc = %v, want [7]", got)
	}
	if got := p[BlockBase(1)+offAttnRes].InSrc; !reflect.DeepEqual(got, []int{11, 7}) {
		t.Errorf("block1 attn_residual 的 InSrc = %v, want [11, 7]", got)
	}
	// 收尾两步
	last := len(p) - 1
	if p[last].Op != OpArgMax || !p[last].Terminal {
		t.Errorf("末步 = %s terminal=%v, want argmax/true", p[last].Op, p[last].Terminal)
	}
	if p[last].Coord.Block != uint16(DemoTiny.Blocks) {
		t.Errorf("argmax 的 Block = %d, want 哨兵块号 %d", p[last].Coord.Block, DemoTiny.Blocks)
	}
	if !reflect.DeepEqual(p[last].InDim, []int{DemoTiny.Vocab}) {
		t.Errorf("argmax 的 InDim = %v, want [%d]", p[last].InDim, DemoTiny.Vocab)
	}
	if p[last-1].Op != OpRMSNorm || p[last-1].Coord.Step != StepFinalNorm {
		t.Errorf("倒数第二步 = %s/%s, want rmsnorm/final_norm", p[last-1].Op, p[last-1].Coord.Step)
	}
}

// TestPlanWireStrictlyIncreasing plan 的 Wire 必须严格递增：
// 这同时保证了「字典序 == 时序 == 下标序」与「坐标两两不同 ⇒ 掩码域两两不同」。
func TestPlanWireStrictlyIncreasing(t *testing.T) {
	p := buildDemoPlan(t)
	for i := 1; i < len(p); i++ {
		prev, cur := p[i-1].Coord.Wire(), p[i].Coord.Wire()
		if !(prev < cur) {
			t.Fatalf("#%d 的 Wire %q 未严格大于 #%d 的 %q", i, cur, i-1, prev)
		}
	}
}

// TestPlanWireUniqueness 全 plan 的掩码域必须互不相同（B4 掩码唯一性门禁的坐标侧基础）。
func TestPlanWireUniqueness(t *testing.T) {
	p := buildDemoPlan(t)
	domains := make(map[string]int, len(p))
	for i := range p {
		d := p[i].MaskDomain()
		if _, dup := domains[d]; dup {
			t.Fatalf("掩码域 %q 在 #%d 与 #%d 重复（两步将共用同一个 r！）", d, domains[d], i)
		}
		domains[d] = i
	}
	if len(domains) != len(p) {
		t.Fatalf("掩码域去重后 %d != plan 长度 %d", len(domains), len(p))
	}
}

// TestPlanLegality InSrc 合法（无越界/无前向引用/无环）、Portal 与 argmax 位置正确。
func TestPlanLegality(t *testing.T) {
	p := buildDemoPlan(t)
	// Validate 已覆盖：同长/行数/越界/前向引用/terminal 唯一且居末/portal/payload 语义
	if err := p.Validate(); err != nil {
		t.Fatalf("Build 产出的 plan 未通过自身校验: %v", err)
	}
	// 独立性复核：InSrc 指向的前驱严格小于自身（无环的等价命题）
	for i := range p {
		for row, ref := range p[i].InSrc {
			if ref == SrcInject {
				continue
			}
			if ref >= i {
				t.Errorf("#%d 行 %d 的 InSrc=%d 前向引用/自引用", i, row, ref)
			}
		}
	}
	// 每个非注入前驱必须能被 At 取到
	for i := range p {
		for _, ref := range p[i].InSrc {
			if ref == SrcInject {
				continue
			}
			if _, err := p.At(ref); err != nil {
				t.Errorf("#%d 的 InSrc=%d 无法取值: %v", i, ref, err)
			}
		}
	}
	// Portal：首步必须引用客户端注入
	if p[0].InSrc[0] != SrcInject {
		t.Errorf("首步 InSrc[0] = %d, want SrcInject(-1)（没有 Portal 入口）", p[0].InSrc[0])
	}
}

// TestValidateRejectsTampered 篡改任何一处都要被 Validate 抓住（防止「看似合法」的静默错配）。
func TestValidateRejectsTampered(t *testing.T) {
	base := func() Plan {
		p, err := Build(DemoTiny)
		if err != nil {
			panic(err)
		}
		return p
	}
	t.Run("Seq 与位置不符", func(t *testing.T) {
		p := base()
		p[5].Seq = 4
		if err := p.Validate(); err == nil {
			t.Fatal("应被拒绝")
		}
	})
	t.Run("InSrc 前向引用", func(t *testing.T) {
		p := base()
		p[1].InSrc = []int{9} // #1 引用仍在 #9
		if err := p.Validate(); err == nil {
			t.Fatal("应被拒绝")
		}
	})
	t.Run("InSrc 自引用", func(t *testing.T) {
		p := base()
		p[4].InSrc = []int{4, SrcInject}
		if err := p.Validate(); err == nil {
			t.Fatal("应被拒绝")
		}
	})
	t.Run("InSrc 越界", func(t *testing.T) {
		p := base()
		p[5].InSrc = []int{len(p)}
		if err := p.Validate(); err == nil {
			t.Fatal("应被拒绝")
		}
	})
	t.Run("行数与 op 矛盾", func(t *testing.T) {
		p := base()
		p[4].InDim = []int{32} // residual_add 应有 2 行
		if err := p.Validate(); err == nil {
			t.Fatal("应被拒绝")
		}
	})
	t.Run("带外 op 混入 plan", func(t *testing.T) {
		p := base()
		p[2].Op = OpKVReset
		if err := p.Validate(); err == nil {
			t.Fatal("应被拒绝")
		}
	})
	t.Run("坐标重复", func(t *testing.T) {
		p := base()
		p[6].Coord.Step = p[5].Coord.Step
		p[6].Coord.Block = p[5].Coord.Block
		p[6].Coord.Branch = p[5].Coord.Branch
		if err := p.Validate(); err == nil {
			t.Fatal("应被拒绝（掩码域会被两步共用）")
		}
	})
	t.Run("Terminal 不在末步", func(t *testing.T) {
		p := base()
		p[10].Terminal = true
		if err := p.Validate(); err == nil {
			t.Fatal("应被拒绝")
		}
	})
	t.Run("末步非 Terminal", func(t *testing.T) {
		p := base()
		p[len(p)-1].Terminal = false
		if err := p.Validate(); err == nil {
			t.Fatal("应被拒绝")
		}
	})
	t.Run("Writes 与 op 不符", func(t *testing.T) {
		p := base()
		p[5].Writes = true // rmsnorm 不应写 KV
		if err := p.Validate(); err == nil {
			t.Fatal("应被拒绝")
		}
	})
	t.Run("Reads 与 op 不符", func(t *testing.T) {
		p := base()
		p[5].Reads = true
		if err := p.Validate(); err == nil {
			t.Fatal("应被拒绝")
		}
	})
	t.Run("kv_append 产出非空张量", func(t *testing.T) {
		p := base()
		p[1].OutDim = 32
		if err := p.Validate(); err == nil {
			t.Fatal("应被拒绝")
		}
	})
	t.Run("Portal 丢失", func(t *testing.T) {
		p := base()
		p[0].InSrc = []int{3}
		if err := p.Validate(); err == nil {
			t.Fatal("应被拒绝")
		}
	})
	t.Run("空 plan", func(t *testing.T) {
		empty := Plan{}
		if err := empty.Validate(); err == nil {
			t.Fatal("应被拒绝")
		}
	})
}

// TestPlanAccessors At/CoordAt/NextCoord/IndexOf 的边界行为。
func TestPlanAccessors(t *testing.T) {
	p := buildDemoPlan(t)
	if _, err := p.At(len(p)); err == nil {
		t.Fatal("越界 At 应报错")
	}
	if _, err := p.At(-1); err == nil {
		t.Fatal("负下标 At 应报错")
	}
	if _, err := p.CoordAt(len(p) + 10); err == nil {
		t.Fatal("越界 CoordAt 应报错")
	}
	if _, ok := p.NextCoord(len(p) - 1); ok {
		t.Fatal("末步不应还有下一步")
	}
	nc, ok := p.NextCoord(0)
	if !ok || nc != p[1].Coord {
		t.Fatalf("NextCoord(0) = %+v, ok=%v, want #1 坐标", nc, ok)
	}
	for i := range p {
		idx, err := p.IndexOf(p[i].Coord)
		if err != nil {
			t.Fatalf("IndexOf(#%d) 报错: %v", i, err)
		}
		if idx != i {
			t.Fatalf("IndexOf(#%d) = %d", i, idx)
		}
	}
	outside := LayerCoord{Stage: StagePrefill, Turn: 0, Block: 3, Step: StepFinalNorm, Branch: BranchMain, Chunk: 0}
	if idx, err := p.IndexOf(outside); err == nil {
		t.Fatalf("plan 外的坐标竟被找到: #%d", idx)
	}
	if p.Len() != len(p) {
		t.Fatalf("Len() = %d, want %d", p.Len(), len(p))
	}
}

// TestSrcMaskDomainFanIn 扇入步的两行必须解析出**两个不同**的掩码域，
// 且都能纯靠坐标重派生（G12/R2 的正解；这正是带外存储掩码种子所做不到的事）。
func TestSrcMaskDomainFanIn(t *testing.T) {
	p := buildDemoPlan(t)
	attnRes := BlockBase(0) + offAttnRes // #4：residual_add(Ao, h)
	spec, err := p.At(attnRes)
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.InSrc) != 2 {
		t.Fatalf("residual_add 应有 2 行输入，got %d", len(spec.InSrc))
	}
	d0, err := p.SrcMaskDomain(attnRes, 0) // Ao：来自 #3 attention 的输出
	if err != nil {
		t.Fatal(err)
	}
	d1, err := p.SrcMaskDomain(attnRes, 1) // h：来自客户端注入
	if err != nil {
		t.Fatal(err)
	}
	if d0 == d1 {
		t.Fatalf("扇入步两行掩码域相同 %q（R2：residual 两行必须各自脱掩码）", d0)
	}
	// Ao 行的域必须 == 产出步 #3（attention）自己的域
	if want := p[3].MaskDomain(); d0 != want {
		t.Fatalf("Ao 行掩码域 = %q, want 产出步 #3 自己的域 %q（掩码域归属写反了！）", d0, want)
	}
	inj, err := InjectDomain(StagePrefill, 0)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != inj {
		t.Fatalf("注入行掩码域 = %q, want %q", d1, inj)
	}

	// ffn_residual：Down 来自 #6 ffn_up，h₂ 来自 #4 attn_residual —— 同样必须不同
	ffnRes := BlockBase(0) + offFFNResidual
	f0, err := p.SrcMaskDomain(ffnRes, 0)
	if err != nil {
		t.Fatal(err)
	}
	f1, err := p.SrcMaskDomain(ffnRes, 1)
	if err != nil {
		t.Fatal(err)
	}
	if f0 == f1 {
		t.Fatalf("ffn_residual 两行掩码域相同 %q", f0)
	}
	if want := p[6].MaskDomain(); f0 != want {
		t.Fatalf("Down 行掩码域 = %q, want 产出步 #6 的域 %q", f0, want)
	}
	if want := p[4].MaskDomain(); f1 != want {
		t.Fatalf("h₂ 行掩码域 = %q, want 产出步 #4 的域 %q", f1, want)
	}

	// 越界 / 非法输入必须报错而不是返回默认域
	if _, err := p.SrcMaskDomain(attnRes, 2); err == nil {
		t.Fatal("行下标越界应报错")
	}
	if _, err := p.SrcMaskDomain(attnRes, -1); err == nil {
		t.Fatal("负行下标应报错")
	}
	if _, err := p.SrcMaskDomain(len(p), 0); err == nil {
		t.Fatal("步下标越界应报错")
	}
}

// TestSrcMaskDomainForwardRefRejected 即便有人手工把 InSrc 改成前向引用，
// SrcMaskDomain 也必须拒绝（不能悄悄返回第 i+1 步的域——那正是 R5 的旧错误）。
func TestSrcMaskDomainForwardRefRejected(t *testing.T) {
	p := buildDemoPlan(t)
	p[5].InSrc = []int{9} // 前向引用（此plan 已非法，Validate 会拒；此处单独验证取值层也 fail-closed）
	if err := p.Validate(); err == nil {
		t.Fatal("前向引用的 plan 应被 Validate 拒绝")
	}
	if _, err := p.SrcMaskDomain(5, 0); err == nil {
		t.Fatal("SrcMaskDomain 不应接受前向引用")
	}
}

// TestPlanBlocksRoundTrip 长度形态与 Blocks 反推一致。
func TestPlanBlocksRoundTrip(t *testing.T) {
	for _, blocks := range []int{1, 2, 4, 8} {
		cfg := DemoTinyConfig()
		cfg.Blocks = blocks
		p, err := Build(cfg)
		if err != nil {
			t.Fatalf("Blocks=%d Build 失败: %v", blocks, err)
		}
		if len(p) != PlanLen(blocks) {
			t.Fatalf("Blocks=%d 的 plan 长度 = %d, want %d", blocks, len(p), PlanLen(blocks))
		}
		got, err := p.Blocks()
		if err != nil {
			t.Fatal(err)
		}
		if got != blocks {
			t.Fatalf("Blocks() = %d, want %d", got, blocks)
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("Blocks=%d 的 plan 自校验失败: %v", blocks, err)
		}
	}
	// 长度形态不合法时应被拒绝
	short := buildDemoPlan(t)[:5]
	if _, err := Plan(short).Blocks(); err == nil {
		t.Fatal("过短 plan 的 Blocks() 应报错")
	}
	odd := buildDemoPlan(t)[:len(buildDemoPlan(t))-1]
	if _, err := Plan(odd).Blocks(); err == nil {
		t.Fatal("长度不满足 Blocks*8+2 的 plan 应报错")
	}
}

// TestValidOpTable op 白名单与 plan 语义一致。
func TestValidOpTable(t *testing.T) {
	for _, op := range []string{OpRMSNorm, OpGELU, OpArgMax, OpKVAppendK, OpKVAppendV, OpAttention, OpResidualAdd} {
		if !ValidOp(op) {
			t.Errorf("%q 应为 plan 内合法 op", op)
		}
	}
	if ValidOp(OpKVReset) {
		t.Errorf("%q 是带外 op，不得被视为 plan 步", OpKVReset)
	}
	if ValidOp("layernorm") {
		t.Errorf("旧 op 名 layernorm 不应混入新 plan")
	}
	if ValidOp("") {
		t.Errorf("空 op 不应合法")
	}
}

// TestStepSpecStringContainsEssentials 摘要串便于排障（不参与判定，仅防 nil panic）。
func TestStepSpecStringContainsEssentials(t *testing.T) {
	p := buildDemoPlan(t)
	for i := range p {
		s := p[i].String()
		if s == "" {
			t.Fatalf("#%d 的 String() 为空", i)
		}
	}
	_ = p[4].String()
	_ = WeightRef{}.String()
	_ = Step(200).String()
	_ = Branch(200).String()
	_ = Stage(200).String()
}
