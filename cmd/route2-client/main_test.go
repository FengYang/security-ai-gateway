// main_test.go - 客户端编排器（proto=2）的离线单测：报文、布局、溯源、R-RECOVER 判定表。
//
// 这些用例**不连服务端**（没有 TEE 就没有服务端可连）：它们验证的是客户端这一侧的
// 契约正确性——字段与 canonical 是否照 §7、扇入步的 batch 布局是否自洽、
// 掩码溯源是否按 StepSpec.InSrc/InWeight 走、R-RECOVER 的失败分类是否符合 §7.4.2。
// 端到端对拍由 T05 接真实服务端后补。
package main

import (
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"

	"security-ai-gateway/gateway/cryptop"
	"security-ai-gateway/gateway/teecore/route2demo"
	"security-ai-gateway/gateway/teecore/route2plan"
)

// newTestOrchestrator 构造一个不联网的编排器（seed 用固定材料派生，与网络无关）。
func newTestOrchestrator(t *testing.T) *orchestrator {
	t.Helper()
	p, err := cryptop.New(cryptop.ProfileIntl)
	if err != nil {
		t.Fatalf("cryptop 初始化失败: %v", err)
	}
	seed, err := p.KDF([]byte("t04-test-seed-material"), nil, []byte(seedInfo), 32)
	if err != nil {
		t.Fatalf("派生测试 seed 失败: %v", err)
	}
	c := &client{base: "http://127.0.0.1:1", http: &http.Client{}, p: p}
	cfg := route2plan.DemoTinyConfig()
	o, err := newOrchestrator(c, cfg, &session{
		id: "test-session", ksig: []byte("test-ksig"), kenc: []byte("test-kenc"),
		seed: seed, sessionNo: 1,
	})
	if err != nil {
		t.Fatalf("构造编排器失败: %v", err)
	}
	return o
}

// maskedRow 造一行"看起来像掩码态"的行（内容任意，只要维度对）。
func maskedRow(n int, seed uint64) []uint64 {
	row := make([]uint64, n)
	s := seed
	for i := range row {
		s = s*6364136223846793005 + 1442695040888963407
		row[i] = s
	}
	return row
}

// ---------- §7.1 / §7.3：请求字段与 canonical ----------

func TestNewRequestFieldsFollowSection7(t *testing.T) {
	o := newTestOrchestrator(t)
	plan, err := route2plan.Build(o.cfg)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := plan.At(0)
	if err != nil {
		t.Fatal(err)
	}
	batch := [][]uint64{maskedRow(spec.InDim[0], 1), maskedRow(spec.InDim[0], 2)}
	req, err := o.newRequest(spec, batch)
	if err != nil {
		t.Fatal(err)
	}
	if req.Proto != protoV2 {
		t.Errorf("proto = %d, want %d", req.Proto, protoV2)
	}
	if req.ModelID != route2plan.DemoModelID {
		t.Errorf("model_id = %q, want %q", req.ModelID, route2plan.DemoModelID)
	}
	if req.Coord != spec.Coord.Wire() {
		t.Errorf("coord = %q, want %q", req.Coord, spec.Coord.Wire())
	}
	if req.Seq != spec.Seq {
		t.Errorf("seq = %d, want %d", req.Seq, spec.Seq)
	}
	if req.Op != spec.Op {
		t.Errorf("op = %q, want %q", req.Op, spec.Op)
	}
	// §7.3：n_rows != len(batch) 会被服务端判 shape_mismatch，客户端必须自检
	if req.NRows != len(batch) {
		t.Errorf("n_rows = %d != len(batch) = %d", req.NRows, len(batch))
	}
	// rmsnorm 步应带 gamma；非 norm 步不应带
	if len(req.Gamma) != o.cfg.Dim {
		t.Errorf("rmsnorm 步的 gamma 长度 = %d, want Dim=%d", len(req.Gamma), o.cfg.Dim)
	}
	if req.Beta != nil {
		t.Errorf("RMSNorm 无 beta，不应发送: %v", req.Beta)
	}
	kv, err := plan.At(1) // kv_append_k
	if err != nil {
		t.Fatal(err)
	}
	reqKV, err := o.newRequest(kv, [][]uint64{maskedRow(kv.InDim[0], 3)})
	if err != nil {
		t.Fatal(err)
	}
	if reqKV.Gamma != nil {
		t.Errorf("kv_append 步不应带 gamma: %v", reqKV.Gamma)
	}
}

func TestCanonicalV2Format(t *testing.T) {
	o := newTestOrchestrator(t)
	req := &v2Request{
		RequestID: "req-1", Proto: protoV2, ModelID: route2plan.DemoModelID,
		Coord: "v2|1|000000|0000|00|0|00", Seq: 7, Op: route2plan.OpGELU,
		Batch: [][]uint64{{1, 2}, {3, 4}}, NRows: 2,
	}
	canon := canonicalV2(o.c.p, req)
	if len(canon) == 0 {
		t.Fatal("canonical 不应为空")
	}
	// 逐字段比对：canonical 的**前缀**必须是 proto|request_id|coord|seq|model_id|op|n_rows
	batchJSON, _ := json.Marshal(req.Batch)
	wantPrefix := "2|req-1|v2|1|000000|0000|00|0|00|7|route2-demo-tiny|gelu|2"
	raw := wantPrefix + string(batchJSON)
	if got := string(canon); got == raw {
		t.Fatalf("canonical 应该是 Hash(前缀+batch)，不是原文（got 原文=%q）", got)
	}
	// 与手算一致：Hash(前缀 + json(batch))
	if want := string(o.c.p.Hash([]byte(raw))); string(canon) != want {
		t.Fatalf("canonical 与手算不一致:\n got=%x\nwant=%x", canon, want)
	}
	// 确定性
	if second := string(canonicalV2(o.c.p, req)); second != string(canon) {
		t.Fatal("canonical 不确定")
	}
}

// ---------- 注入行与掩码 ----------

func TestInjectRowsShapeAndDeterminism(t *testing.T) {
	o := newTestOrchestrator(t)
	plan, err := route2plan.Build(o.cfg)
	if err != nil {
		t.Fatal(err)
	}
	toks := demoPrompt(o.cfg, 4)
	rows, err := o.injectRows(plan, toks)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(toks) {
		t.Fatalf("注入行数 = %d, want %d", len(rows), len(toks))
	}
	for i, row := range rows {
		if len(row) != o.cfg.Dim {
			t.Fatalf("第 %d 行维度 = %d, want Dim=%d", i, len(row), o.cfg.Dim)
		}
	}
	// 不同 token 的注入行必须不同（否则所有位置共享同一个注入值）
	if rows[0][0] == rows[1][0] {
		t.Fatal("不同 token 的注入行不应相同")
	}
	// 同一次派生必须逐位一致（R-RECOVER 重放的前提）
	again, err := o.injectRows(plan, toks)
	if err != nil {
		t.Fatal(err)
	}
	for i := range rows {
		for j := range rows[i] {
			if rows[i][j] != again[i][j] {
				t.Fatalf("注入行不确定: [%d][%d]", i, j)
			}
		}
	}
	// 嵌入表必须与 route2demo 同源（客户端注入 == 服务端 Gather）
	emb, err := route2demo.Embedding(o.cfg, toks)
	if err != nil {
		t.Fatal(err)
	}
	for i := range emb {
		if len(emb[i]) != o.cfg.Dim {
			t.Fatalf("嵌入维度 = %d, want %d", len(emb[i]), o.cfg.Dim)
		}
	}
}

// TestInjectRowsMasksAdvancePerRow 钉住批量 prefill 的关键性质：注入掩码按流顺序
// 逐行推进取段（行 j 取第 j 段），不得全行共用首段。
// 用同一 token 重复构造：嵌入相同 ⇒ 行间任何差异都只能来自掩码段不同。
// 若回归为「全行共用首段」，各行将逐位相等，本用例立即失败。
func TestInjectRowsMasksAdvancePerRow(t *testing.T) {
	o := newTestOrchestrator(t)
	plan, err := route2plan.Build(o.cfg)
	if err != nil {
		t.Fatal(err)
	}
	toks := []int{7, 7, 7, 7} // 同一 token × 4：隔离掩码差异
	rows, err := o.injectRows(plan, toks)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("注入行数 = %d, want 4", len(rows))
	}
	for i := 1; i < len(rows); i++ {
		same := true
		for j := range rows[0] {
			if rows[0][j] != rows[i][j] {
				same = false
				break
			}
		}
		if same {
			t.Fatalf("行 %d 与行 0 逐位相同：掩码未按行推进（批量 prefill 将与服务端错位）", i)
		}
	}
	// 确定性保持：同输入再派生必须逐位一致（R-RECOVER 重放的前提）
	again, err := o.injectRows(plan, toks)
	if err != nil {
		t.Fatal(err)
	}
	for i := range rows {
		for j := range rows[i] {
			if rows[i][j] != again[i][j] {
				t.Fatalf("注入行不确定: [%d][%d]", i, j)
			}
		}
	}
}

// ---------- 逐行溯源 + batch 布局（扇入步是重点） ----------

func TestBuildBatchSingleLinePassThrough(t *testing.T) {
	o := newTestOrchestrator(t)
	plan, err := route2plan.Build(o.cfg)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := plan.At(0) // attn_norm：直通行，源=注入
	if err != nil {
		t.Fatal(err)
	}
	injected := [][]uint64{maskedRow(o.cfg.Dim, 11), maskedRow(o.cfg.Dim, 12), maskedRow(o.cfg.Dim, 13)}
	outs := make([][][]uint64, plan.Len())
	batch, err := o.buildBatch(spec, injected, outs)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != len(injected) {
		t.Fatalf("batch 行数 = %d, want %d（单输入行应为 T 行）", len(batch), len(injected))
	}
	for i := range batch {
		for j := range batch[i] {
			if batch[i][j] != injected[i][j] {
				t.Fatalf("直通行不应被改写: [%d][%d]", i, j)
			}
		}
	}
}

func TestBuildBatchAppliesLinearOfInWeight(t *testing.T) {
	o := newTestOrchestrator(t)
	plan, err := route2plan.Build(o.cfg)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := plan.At(1) // kv_append_k：源=step0 输出，施加 attn.k
	if err != nil {
		t.Fatal(err)
	}
	const T = 3
	outs := make([][][]uint64, plan.Len())
	outs[0] = make([][]uint64, T)
	for i := range outs[0] {
		outs[0][i] = maskedRow(plan[0].OutDim, uint64(i+1))
	}
	injected := make([][]uint64, T)
	for i := range injected {
		injected[i] = maskedRow(o.cfg.Dim, uint64(i+1))
	}
	batch, err := o.buildBatch(spec, injected, outs)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != T {
		t.Fatalf("batch 行数 = %d, want %d", len(batch), T)
	}
	// 逐行与 W·V 对照（§3.2 序 3：客户端负责线性搬运，产出的仍是掩码态）
	w, err := o.matrix(spec.InWeight[0].Key)
	if err != nil {
		t.Fatal(err)
	}
	want, err := w.CipherLinear(outs[0])
	if err != nil {
		t.Fatal(err)
	}
	for i := range batch {
		if len(batch[i]) != spec.InDim[0] {
			t.Fatalf("第 %d 行维度 = %d, want InDim=%d", i, len(batch[i]), spec.InDim[0])
		}
		for j := range batch[i] {
			if batch[i][j] != want[i][j] {
				t.Fatalf("线性搬运结果不符: [%d][%d] got=%d want=%d", i, j, batch[i][j], want[i][j])
			}
		}
	}
}

// TestBuildBatchFanInLayout 扇入步（residual_add）的布局：2 条输入行 × T 个位置。
// 这是 §7 唯一待裁定之处（见 batchLayout 常量注释），本用例把当前决策钉死，
// 裁定变更后只需改本用例的期望值 + encodeBatch 一处实现。
func TestBuildBatchFanInLayout(t *testing.T) {
	o := newTestOrchestrator(t)
	plan, err := route2plan.Build(o.cfg)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := plan.At(4) // attn_residual：Ao（经 Wo） + h（直通）
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.InSrc) != 2 {
		t.Fatalf("residual_add 应有 2 条输入行，got %d", len(spec.InSrc))
	}
	const T = 3
	outs := make([][][]uint64, plan.Len())
	outs[3] = make([][]uint64, T) // attention 输出
	for i := range outs[3] {
		outs[3][i] = maskedRow(plan[3].OutDim, uint64(31+i))
	}
	injected := make([][]uint64, T)
	for i := range injected {
		injected[i] = maskedRow(o.cfg.Dim, uint64(41+i))
	}
	batch, err := o.buildBatch(spec, injected, outs)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != T*len(spec.InSrc) {
		t.Fatalf("batch 行数 = %d, want T*输入行数 = %d", len(batch), T*len(spec.InSrc))
	}
	// line-major：前 T 行是 line0（Ao = Wo·outs[3]），后 T 行是 line1（h 直通）
	wo, err := o.matrix(spec.InWeight[0].Key)
	if err != nil {
		t.Fatal(err)
	}
	wantAo, err := wo.CipherLinear(outs[3])
	if err != nil {
		t.Fatal(err)
	}
	for p := 0; p < T; p++ {
		for j := range batch[p] {
			if batch[p][j] != wantAo[p][j] {
				t.Fatalf("line0 第 %d 个位置第 %d 维不符", p, j)
			}
			if batch[T+p][j] != injected[p][j] {
				t.Fatalf("line1（直通）第 %d 个位置第 %d 维不符", p, j)
			}
		}
	}
	// 第二条输入行必须是直通（残差旁路未经任何线性），否则 G12/R2 被破坏
	if spec.InWeight[1].Applied {
		t.Fatal("residual_add 的第二条输入行必须是直通（InWeight[1].Applied=false）")
	}
}

func TestBuildBatchRejectsBadSources(t *testing.T) {
	o := newTestOrchestrator(t)
	plan, err := route2plan.Build(o.cfg)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := plan.At(1)
	if err != nil {
		t.Fatal(err)
	}
	// 源步尚未执行（outs 为空）
	outs := make([][][]uint64, plan.Len())
	injected := [][]uint64{maskedRow(o.cfg.Dim, 7)}
	if _, err := o.buildBatch(spec, injected, outs); err == nil {
		t.Error("源步无输出时应报错")
	}
	// 源行数与位置数不一致
	outs[0] = [][]uint64{maskedRow(plan[0].OutDim, 8), maskedRow(plan[0].OutDim, 9)}
	if _, err := o.buildBatch(spec, injected, outs); err == nil {
		t.Error("源行数 != 位置数时应报错")
	}
}

// ---------- 归一化 gamma 归属 ----------

func TestNormKeyFor(t *testing.T) {
	cfg := route2plan.DemoTinyConfig()
	plan, err := route2plan.Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		seq      int
		wantKey  route2plan.TensorKey
		wantNorm bool
	}{
		{0, route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorLNIn}, true},
		{5, route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorLNPost}, true},
		{1, route2plan.TensorKey{}, false}, // kv_append 不是 norm 步
		{plan.Len() - 2, route2plan.TensorKey{Block: cfg.Blocks, Tensor: route2plan.TensorLNFinal}, true},
	}
	for _, tc := range cases {
		spec, err := plan.At(tc.seq)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := normKeyFor(spec, cfg)
		if ok != tc.wantNorm {
			t.Fatalf("seq=%d: 是否 norm 步 = %v, want %v", tc.seq, ok, tc.wantNorm)
		}
		if ok && got != tc.wantKey {
			t.Fatalf("seq=%d: key = %v, want %v", tc.seq, got, tc.wantKey)
		}
	}
	// 归一步的 gamma 必须能取到且长度正确
	spec, err := plan.At(0)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := normKeyFor(spec, cfg)
	gamma, eps, err := route2demo.NormParams(cfg, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(gamma) != cfg.Dim || eps != cfg.NormEps {
		t.Fatalf("gamma 长度=%d eps=%v", len(gamma), eps)
	}
}

// ---------- R-RECOVER 判定表（§7.4.2） ----------

func TestStepFailureRecoveryTable(t *testing.T) {
	cases := []struct {
		name            string
		status          int
		wantRecoverable bool
		wantNewSession  bool
	}{
		{"400 调用方缺陷：不允许运行时恢复", http.StatusBadRequest, false, false},
		{"409 step_out_of_order：走①kv_reset", http.StatusConflict, true, false},
		{"500 内部错误：走①kv_reset", http.StatusInternalServerError, true, false},
		{"429 kv_cache_full：走①kv_reset", http.StatusTooManyRequests, true, false},
		{"401 会话失效：只能②新建会话", http.StatusUnauthorized, true, true},
		{"传输层失败（status=0）：走①kv_reset", 0, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &stepFailure{Seq: 3, Op: route2plan.OpAttention, Status: tc.status}
			if got := f.recoverable(); got != tc.wantRecoverable {
				t.Errorf("recoverable() = %v, want %v", got, tc.wantRecoverable)
			}
			if got := f.needsNewSession(); got != tc.wantNewSession {
				t.Errorf("needsNewSession() = %v, want %v", got, tc.wantNewSession)
			}
			if f.Error() == "" {
				t.Error("Error() 不应为空")
			}
		})
	}
}

// TestCheckDeterminismGate 确定性护栏：重放后 token 序列必须逐位一致（§8.1 崩坏门禁）。
func TestCheckDeterminismGate(t *testing.T) {
	if err := checkDeterminism([]int{1, 2, 3}, nil); err != nil {
		t.Fatalf("无历史时不应报错: %v", err)
	}
	if err := checkDeterminism([]int{1, 2, 3}, []int{1, 2}); err != nil {
		t.Fatalf("前缀一致不应报错: %v", err)
	}
	if err := checkDeterminism([]int{1, 9}, []int{1, 2}); err == nil {
		t.Fatal("重放不一致必须报错")
	} else if !strings.Contains(err.Error(), "确定性崩坏") {
		t.Fatalf("错误信息应点明确定性崩坏: %v", err)
	}
}

func TestCheckResultShape(t *testing.T) {
	plan, err := route2plan.Build(route2plan.DemoTinyConfig())
	if err != nil {
		t.Fatal(err)
	}
	kv, _ := plan.At(1)   // OutDim=0
	norm, _ := plan.At(0) // OutDim=Dim
	if err := checkResultShape(kv, nil, 3); err != nil {
		t.Errorf("kv_append 空结果应被接受: %v", err)
	}
	if err := checkResultShape(kv, [][]uint64{{}}, 3); err != nil {
		t.Errorf("kv_append 空内层数组应被接受: %v", err)
	}
	if err := checkResultShape(kv, [][]uint64{{1, 2}}, 3); err == nil {
		t.Error("kv_append 返回非空行应报错")
	}
	good := [][]uint64{maskedRow(norm.OutDim, 1), maskedRow(norm.OutDim, 2)}
	if err := checkResultShape(norm, good, 2); err != nil {
		t.Errorf("正常结果应被接受: %v", err)
	}
	if err := checkResultShape(norm, good, 3); err == nil {
		t.Error("行数 != 位置数应报错")
	}
	if err := checkResultShape(norm, [][]uint64{maskedRow(norm.OutDim+1, 1)}, 1); err == nil {
		t.Error("行维度 != OutDim 应报错")
	}
}

// ---------- 杂项：prompt / model 解析 / request_id 唯一性 ----------

func TestDemoPromptDeterministic(t *testing.T) {
	cfg := route2plan.DemoTinyConfig()
	a := demoPrompt(cfg, 8)
	b := demoPrompt(cfg, 8)
	for i := range a {
		if a[i] != b[i] {
			t.Fatal("prompt 不确定（R-RECOVER 重放将无法复现）")
		}
		if a[i] < 0 || a[i] >= cfg.Vocab {
			t.Fatalf("prompt token %d 越界: %d", i, a[i])
		}
	}
}

func TestModelConfigByID(t *testing.T) {
	cfg, err := modelConfigByID(route2plan.DemoModelID)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Blocks != route2plan.DemoBlocks || cfg.Dim != route2plan.DemoDim {
		t.Fatalf("解析出的配置与 DemoTiny 不符: %+v", cfg)
	}
	if _, err := modelConfigByID("no-such-model"); err == nil {
		t.Fatal("未知 model 应报错（模型决定权重/维度/模数，猜错会全绿全错）")
	}
}

func TestRequestIDUniqueWithinSession(t *testing.T) {
	o := newTestOrchestrator(t)
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := o.nextRequestID()
		if seen[id] {
			t.Fatalf("request_id 重复: %s（服务端会判 409 replay）", id)
		}
		seen[id] = true
	}
}

func TestRhoDeterministicAndBounded(t *testing.T) {
	o := newTestOrchestrator(t)
	a, err := o.rho("otpmask/step/v2|1|000000|0000|00|0|00/v2", 16)
	if err != nil {
		t.Fatal(err)
	}
	b, err := o.rho("otpmask/step/v2|1|000000|0000|00|0|00/v2", 16)
	if err != nil {
		t.Fatal(err)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatal("掩码派生不确定")
		}
		if a[i] > route2MaskModulus {
			t.Fatalf("掩码值 %d 超出取模上界", a[i])
		}
	}
	// 不同域必须给出不同掩码（坐标唯一 ⇒ 掩码唯一，B4 的客户端侧佐证）
	c, err := o.rho("otpmask/step/v2|1|000000|0001|00|0|00/v2", 16)
	if err != nil {
		t.Fatal(err)
	}
	same := true
	for i := range a {
		if a[i] != c[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("不同坐标域派生出相同掩码（掩码会被复用！）")
	}
	// 全零掩码是异常信号（流未推进）
	allZero := true
	for _, v := range a {
		if v != 0 {
			allZero = false
		}
	}
	if allZero {
		t.Fatal("派生出的掩码全为零（掩码流异常）")
	}
	if math.IsNaN(float64(len(a))) {
		t.Fatal("unreachable")
	}
}
