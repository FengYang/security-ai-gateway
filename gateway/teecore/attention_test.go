// attention_test.go - 可信域 attention 算子测试（T02 验收项 3、4）
package teecore

import (
	"math"
	"testing"
)

// demoHeads / demoHeadDim / demoTheta 与 route2plan.DemoTiny 对齐（Heads=4, HeadDim=8, theta=1e4）。
// 这里刻意不 import route2plan：teecore 必须保持对上层零依赖，故测试内写死同值并断言一致性。
const (
	demoHeads   = 4
	demoHeadDim = 8
	demoTheta   = 1e4
)

// synthVec 生成确定性伪随机向量（不引入 math/rand 的全局状态）。
func synthVec(n int, seed int64) []float64 {
	out := make([]float64, n)
	s := seed
	for i := range out {
		s = s*6364136223846793005 + 1442695040888963407
		out[i] = float64(int64(s>>11)%2001-1000) / 1000 // [-1, 1)
	}
	return out
}

// ---------- RoPE ----------

// TestRoPEHeadDimErrorCases RoPE 的参数纪律（headDim 必须为偶数、theta 必须为正等）。
func TestRoPEHeadDimErrorCases(t *testing.T) {
	vec := synthVec(demoHeads*demoHeadDim, 1)
	if _, err := ApplyRoPE(vec, 0, demoHeadDim+1, demoTheta); err == nil {
		t.Error("headDim 为奇数应报错（RoPE 成对旋转）")
	}
	if _, err := ApplyRoPE(vec, 0, 0, demoTheta); err == nil {
		t.Error("headDim=0 应报错")
	}
	if _, err := ApplyRoPE(vec[:7], 0, demoHeadDim, demoTheta); err == nil {
		t.Error("长度非 headDim 整数倍应报错")
	}
	if _, err := ApplyRoPE(vec, -1, demoHeadDim, demoTheta); err == nil {
		t.Error("负 pos 应报错")
	}
	if _, err := ApplyRoPE(vec, 0, demoHeadDim, 0); err == nil {
		t.Error("theta<=0 应报错")
	}
	if err := ApplyRoPEInPlace(vec, 0, demoHeadDim+1, demoTheta); err == nil {
		t.Error("InPlace 版本同样应拒绝奇数 headDim")
	}
	// 副本版本不得修改入参
	orig := append([]float64(nil), vec...)
	if _, err := ApplyRoPE(vec, 3, demoHeadDim, demoTheta); err != nil {
		t.Fatal(err)
	}
	for i := range orig {
		if vec[i] != orig[i] {
			t.Fatal("ApplyRoPE 不应修改入参（应返回新切片）")
		}
	}
}

// TestRoPEPosZeroIsIdentity pos=0 时旋转角为 0，RoPE 必须是恒等变换。
func TestRoPEPosZeroIsIdentity(t *testing.T) {
	vec := synthVec(demoHeads*demoHeadDim, 2)
	got, err := ApplyRoPE(vec, 0, demoHeadDim, demoTheta)
	if err != nil {
		t.Fatal(err)
	}
	for i := range vec {
		if got[i] != vec[i] {
			t.Fatalf("pos=0 应恒等，第 %d 项 %v != %v", i, got[i], vec[i])
		}
	}
}

// TestRoPEIsOrthogonal 旋转矩阵正交 ⇒ 同一 pos 下内积与范数保持不变。
func TestRoPEIsOrthogonal(t *testing.T) {
	a := synthVec(demoHeadDim, 3)
	b := synthVec(demoHeadDim, 4)
	dotRaw, normRaw := 0.0, 0.0
	for i := range a {
		dotRaw += a[i] * b[i]
		normRaw += a[i] * a[i]
	}
	ra, err := ApplyRoPE(a, 17, demoHeadDim, demoTheta)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := ApplyRoPE(b, 17, demoHeadDim, demoTheta)
	if err != nil {
		t.Fatal(err)
	}
	dotRot, normRot := 0.0, 0.0
	for i := range ra {
		dotRot += ra[i] * rb[i]
		normRot += ra[i] * ra[i]
	}
	if math.Abs(dotRot-dotRaw) > 1e-12 || math.Abs(normRot-normRaw) > 1e-12 {
		t.Fatalf("RoPE 破坏正交性: dot %v -> %v, norm %v -> %v", dotRaw, dotRot, normRaw, normRot)
	}
}

// TestRoPERelativePosition RoPE 的核心性质（验收项 3）：
// 点积只依赖**相对位置**差，不依赖绝对值。
//
// 这条最容易写错的地方是「忘了指数里的 -2i/headDim，写成常数角」——那样仍然满足正交性，
// 但不满足相对位置不变性，模型位置感知会失效，且不报任何错。
func TestRoPERelativePosition(t *testing.T) {
	q := synthVec(demoHeadDim, 5)
	k := synthVec(demoHeadDim, 6)

	score := func(qPos, kPos int) float64 {
		rq, err := ApplyRoPE(q, qPos, demoHeadDim, demoTheta)
		if err != nil {
			t.Fatal(err)
		}
		rk, err := ApplyRoPE(k, kPos, demoHeadDim, demoTheta)
		if err != nil {
			t.Fatal(err)
		}
		var s float64
		for i := range rq {
			s += rq[i] * rk[i]
		}
		return s
	}

	cases := []struct{ qPos, kPos int }{
		{0, 0}, {3, 3}, {7, 7}, {13, 13},
	}
	for _, c := range cases {
		got := score(c.qPos, c.kPos)
		base := score(0, 0)
		if math.Abs(got-base) > 1e-12 {
			t.Errorf("相对位置差为 0 时点积应恒定: pos=%d -> %v vs %v", c.qPos, got, base)
		}
	}
	// 相对位置差相同的两组必须用出同一个分数
	for _, d := range []int{0, 1, 2, 5, 11} {
		for _, shift := range []int{0, 4, 29, 100} {
			a := score(shift+d, shift)
			b := score(d, 0)
			if math.Abs(a-b) > 1e-10 {
				t.Errorf("相对差=%d shift=%d: 点积 %v != %v（RoPE 依赖了绝对位置）", d, shift, a, b)
			}
		}
	}
	// 负的相对差同样成立（k 在 q 之后）
	if got, want := score(5, 9), score(0, 4); math.Abs(got-want) > 1e-10 {
		t.Errorf("负相对差也应成立: %v vs %v", got, want)
	}

	// 【反向护栏】RoPE 绝不能退化成恒等变换。
	// 上面所有"相对位置"断言在「指数写成 0」「压根没施加 RoPE」「theta 传成 1」时**仍然全绿**——
	// 因为恒等变换同样满足"只依赖相对位置（恒不依赖）"。若没有这一条，
	// 一个完全失效的 RoPE 会被整组相对位置用例放行（这是本组断言最危险的盲区）。
	base := score(0, 0)
	for _, d := range []int{1, 3, 7} {
		if got := score(d, 0); math.Abs(got-base) < 1e-9 {
			t.Errorf("相对差=%d 时点积 %v 与相对差=0 的 %v 几乎相同（RoPE 退化为恒等？）", d, got, base)
		}
	}
}

// TestRoPEPairExplicit 直接校验单对旋转公式与手工 sin/cos 一致。
func TestRoPEPairExplicit(t *testing.T) {
	x, y := 0.6, -0.35
	pairIdx, headDim, pos, theta := 2, 8, 5, 1e4
	ang := float64(pos) * math.Pow(theta, -float64(2*pairIdx)/float64(headDim))
	wantX := x*math.Cos(ang) - y*math.Sin(ang)
	wantY := x*math.Sin(ang) + y*math.Cos(ang)
	gotX, gotY := RoPEPair(x, y, pairIdx, headDim, pos, theta)
	if math.Abs(gotX-wantX) > 1e-15 || math.Abs(gotY-wantY) > 1e-15 {
		t.Fatalf("RoPEPair = (%v,%v), want (%v,%v)", gotX, gotY, wantX, wantY)
	}
}

// ---------- Scores / CausalMask / Softmax / WeightedSum ----------

// TestScoresMultiHeadLayout 多头切分：DemoTiny Heads=4/HeadDim=8/AttnDim=32。
func TestScoresMultiHeadLayout(t *testing.T) {
	heads, headDim := demoHeads, demoHeadDim
	nKV := 5
	q := synthVec(heads*headDim, 7)
	kRows := make([][]float64, nKV)
	for j := range kRows {
		kRows[j] = synthVec(heads*headDim, int64(11+j))
	}
	scores, err := Scores(q, kRows, heads, headDim)
	if err != nil {
		t.Fatal(err)
	}
	if len(scores) != heads {
		t.Fatalf("scores 外层长度 = %d, want heads=%d", len(scores), heads)
	}
	for h := 0; h < heads; h++ {
		if len(scores[h]) != nKV {
			t.Fatalf("head %d 的 scores 长度 = %d, want %d", h, len(scores[h]), nKV)
		}
		// 逐项复算：只包含该 head 的切片
		for j := 0; j < nKV; j++ {
			var want float64
			for d := 0; d < headDim; d++ {
				want += q[h*headDim+d] * kRows[j][h*headDim+d]
			}
			want /= math.Sqrt(float64(headDim))
			if math.Abs(scores[h][j]-want) > 1e-12 {
				t.Errorf("head=%d j=%d scores=%v want=%v（多头切分错位？）", h, j, scores[h][j], want)
			}
		}
	}
	// 换一个 head 的输入必须在对应 head 上反映出来：把 head 2 的 k 清零，scores[2] 全 0
	onlyTwo := make([][]float64, nKV)
	for j := range onlyTwo {
		v := synthVec(heads*headDim, int64(31+j))
		for d := 0; d < headDim; d++ {
			v[2*headDim+d] = 0
		}
		onlyTwo[j] = v
	}
	s2, err := Scores(q, onlyTwo, heads, headDim)
	if err != nil {
		t.Fatal(err)
	}
	for j := 0; j < nKV; j++ {
		if s2[2][j] != 0 {
			t.Fatalf("head 2 的 K 归零后 scores[2][%d]=%v 应为 0", j, s2[2][j])
		}
		if s2[1][j] == 0 {
			t.Fatalf("head 1 不应被影响")
		}
	}
}

// TestScoresRejectsBadShapes 维度不匹配必须报错（fail-closed，不静默缩并）。
func TestScoresRejectsBadShapes(t *testing.T) {
	kRows := [][]float64{synthVec(demoHeads*demoHeadDim, 9)}
	if _, err := Scores(synthVec(demoHeads*demoHeadDim-1, 9), kRows, demoHeads, demoHeadDim); err == nil {
		t.Error("q 维度不符应报错")
	}
	if _, err := Scores(synthVec(demoHeads*demoHeadDim, 9), [][]float64{synthVec(7, 9)}, demoHeads, demoHeadDim); err == nil {
		t.Error("k 维度不符应报错")
	}
	if _, err := Scores(synthVec(demoHeads*demoHeadDim, 9), kRows, 0, demoHeadDim); err == nil {
		t.Error("heads=0 应报错")
	}
	if _, err := Scores(synthVec(demoHeads*demoHeadDim, 9), kRows, demoHeads, 0); err == nil {
		t.Error("headDim=0 应报错")
	}
}

// TestCausalMaskValue 因果掩码必须写 -1e30（有限值），而不是 -Inf（D9 / R9）。
func TestCausalMaskValue(t *testing.T) {
	if math.IsInf(CausalMaskValue, 0) {
		t.Fatalf("CausalMaskValue 不得为 Inf：%v", CausalMaskValue)
	}
	if CausalMaskValue != -1e30 {
		t.Fatalf("CausalMaskValue = %v, want -1e30（设计 D9）", CausalMaskValue)
	}
}

// TestCausalMaskFutureBlocked 未来位置必须被掩码，过去与自身必须保留。
func TestCausalMaskFutureBlocked(t *testing.T) {
	scores := [][]float64{
		{0.1, 0.2, 0.3, 0.4, 0.5},
		{0.5, 0.4, 0.3, 0.2, 0.1},
	}
	// kvStart=0，qPos=2 ⇒ 允许 j<=2（位置 0,1,2），屏蔽 j=3,4
	got := CausalMask(scores, 2, 0)
	for h := range got {
		for j := range got[h] {
			if j <= 2 && got[h][j] == CausalMaskValue {
				t.Errorf("head=%d j=%d（位置 %d <= qPos 2）不应被掩码", h, j, j)
			}
			if j > 2 && got[h][j] != CausalMaskValue {
				t.Errorf("head=%d j=%d（未来位置）必须被掩码，got %v", h, j, got[h][j])
			}
		}
	}
	// kvStart 偏移：kvStart=10, qPos=12 ⇒ 同样允许 j<=2
	shift := [][]float64{{0, 0, 0, 0, 0}}
	CausalMask(shift, 12, 10)
	for j := range shift[0] {
		if j <= 2 && shift[0][j] == CausalMaskValue {
			t.Errorf("kvStart 偏移下 j=%d 不应被掩码", j)
		}
		if j > 2 && shift[0][j] != CausalMaskValue {
			t.Errorf("kvStart 偏移下 j=%d 必须被掩码", j)
		}
	}
}

// TestSoftmaxNoNaNAllMasked 边界用例（验收项 4）：整行全掩码时不得产生 NaN。
//
// 这正是 D9 选 -1e30 而非 -Inf 的原因：-Inf 在 Softmax 里会得到 `-Inf - (-Inf)` = NaN。
func TestSoftmaxNoNaNAllMasked(t *testing.T) {
	// -1e30 全掩码行：softmax 退化为均匀分布
	row := []float64{CausalMaskValue, CausalMaskValue, CausalMaskValue, CausalMaskValue}
	prob, err := SoftmaxScores([][]float64{row})
	if err != nil {
		t.Fatalf("全掩码行不应报错: %v", err)
	}
	for i, p := range prob[0] {
		if math.IsNaN(p) {
			t.Fatalf("全掩码行的 softmax[%d] 是 NaN（D9 失效）", i)
		}
		if math.Abs(p-0.25) > 1e-15 {
			t.Fatalf("全掩码行应退化为均匀分布，got %v", p)
		}
	}

	// 对照组：用 -Inf 直接喂 teecore.Softmax 必须真的产生 NaN——这是 D9 的存在理由，
	// 若哪天这个断言失败（Softmax 变了），说明 -1e30 约定可以重新评估。
	raw := Softmax([]float64{math.Inf(-1), math.Inf(-1)})
	hasNaN := false
	for _, p := range raw {
		if math.IsNaN(p) {
			hasNaN = true
		}
	}
	if !hasNaN {
		t.Fatalf("预期 -Inf 输入会让 Softmax 出 NaN，实测未出（%v）——D9 的前提变了，请复查", raw)
	}
}

// TestSoftmaxScoresRejectsNonFinite SoftmaxScores 的护栏：-Inf/NaN 输入必须报错而非放行。
func TestSoftmaxScoresRejectsNonFinite(t *testing.T) {
	if _, err := SoftmaxScores([][]float64{{math.Inf(-1), 0}}); err == nil {
		t.Error("含 -Inf 的 scores 应被拒绝（否则 NaN 会流向下游）")
	}
	if _, err := SoftmaxScores([][]float64{{math.NaN(), 0}}); err == nil {
		t.Error("含 NaN 的 scores 应被拒绝")
	}
	if _, err := SoftmaxScores(nil); err == nil {
		t.Error("空 scores 应被拒绝")
	}
	if _, err := SoftmaxScores([][]float64{{}}); err == nil {
		t.Error("空行应被拒绝（KV 行数为 0）")
	}
}

// TestSoftmaxScoresSumsToOne 常规输入的 softmax 归一化。
func TestSoftmaxScoresSumsToOne(t *testing.T) {
	prob, err := SoftmaxScores([][]float64{{0.1, 0.4, -0.2, CausalMaskValue}})
	if err != nil {
		t.Fatal(err)
	}
	sum := 0.0
	for _, p := range prob[0] {
		sum += p
	}
	if math.Abs(sum-1) > 1e-15 {
		t.Fatalf("概率和 = %v, want 1", sum)
	}
	if prob[0][3] != 0 {
		t.Fatalf("被掩码位置的概率应严格为 0（数量级 1e-30 已被下溢吞掉），got %v", prob[0][3])
	}
}

// TestWeightedSum 加权求和与手算一致。
func TestWeightedSum(t *testing.T) {
	probs := [][]float64{{0.5, 0.5}, {0.25, 0.75}}
	vRows := [][]float64{
		{1, 2, 3, 4, 5, 6, 7, 8},
		{8, 7, 6, 5, 4, 3, 2, 1},
	}
	// 单头：probs 只有 1 行（== heads），V 每行长度 == headDim
	out, err := WeightedSum(probs[:1], vRows, 1, 8)
	if err != nil {
		t.Fatal(err)
	}
	want := []float64{4.5, 4.5, 4.5, 4.5, 4.5, 4.5, 4.5, 4.5}
	for i := range want {
		if math.Abs(out[i]-want[i]) > 1e-12 {
			t.Fatalf("out[%d] = %v, want %v", i, out[i], want[i])
		}
	}
	// 多头：head0/hd1 各自独立
	multi := [][]float64{
		{1, 1, 1, 1, 10, 10, 10, 10},
		{2, 2, 2, 2, 20, 20, 20, 20},
	}
	out, err = WeightedSum([][]float64{{0.5, 0.5}, {0.5, 0.5}}, multi, 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	for i, w := range []float64{1.5, 1.5, 1.5, 1.5, 15, 15, 15, 15} {
		if math.Abs(out[i]-w) > 1e-12 {
			t.Fatalf("多头 out[%d] = %v, want %v（head 切片错位？）", i, out[i], w)
		}
	}
	// 行数不一致必须报错
	if _, err := WeightedSum([][]float64{{1}}, vRows, 1, 8); err == nil {
		t.Error("probs 长度 != KV 行数应报错")
	}
	// 行维度不符必须报错：heads*headDim=8，而 V 行只有 4 个元素
	if _, err := WeightedSum([][]float64{{0.5, 0.5}, {0.5, 0.5}}, [][]float64{{1, 2, 3, 4}, {1, 2, 3, 4}}, 2, 4); err == nil {
		t.Error("V 行维度不符应报错")
	}
}

// ---------- 组合算子 Attention ----------

// TestAttentionSelfAttendOnly 单步 decode（KV 里只有自己）：注意力必须退化为 V 自身。
func TestAttentionSelfAttendOnly(t *testing.T) {
	q := synthVec(demoHeads*demoHeadDim, 21)
	k := synthVec(demoHeads*demoHeadDim, 22)
	v := synthVec(demoHeads*demoHeadDim, 23)
	out, err := Attention(q, [][]float64{k}, [][]float64{v}, demoHeads, demoHeadDim, 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != demoHeads*demoHeadDim {
		t.Fatalf("输出长度 = %d, want %d", len(out), demoHeads*demoHeadDim)
	}
	for i := range v {
		if math.Abs(out[i]-v[i]) > 1e-12 {
			t.Fatalf("单行 KV 下 out[%d] = %v, want V[%d] = %v", i, out[i], i, v[i])
		}
	}
}

// TestAttentionCausalIgnoresFuture 因果性：追加"未来"行不得改变已算出的结果。
func TestAttentionCausalIgnoresFuture(t *testing.T) {
	q := synthVec(demoHeads*demoHeadDim, 31)
	kRows := [][]float64{synthVec(demoHeads*demoHeadDim, 32), synthVec(demoHeads*demoHeadDim, 33)}
	vRows := [][]float64{synthVec(demoHeads*demoHeadDim, 34), synthVec(demoHeads*demoHeadDim, 35)}
	// qPos=0 ⇒ 只看第 0 行
	only0, err := Attention(q, kRows, vRows, demoHeads, demoHeadDim, 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	expect, err := Attention(q, kRows[:1], vRows[:1], demoHeads, demoHeadDim, 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := range expect {
		if math.Abs(only0[i]-expect[i]) > 1e-12 {
			t.Fatalf("未来行影响了注意力输出: %v vs %v", only0[i], expect[i])
		}
	}
	// qPos=1 ⇒ 能看到两行，结果必须变化
	both, err := Attention(q, kRows, vRows, demoHeads, demoHeadDim, 0, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	diff := 0.0
	for i := range both {
		diff += math.Abs(both[i] - only0[i])
	}
	if diff == 0 {
		t.Fatal("qPos=1 应能看到第二行，输出却与 qPos=0 相同（因果掩码写成全通了？）")
	}
}

// TestAttentionNonCausal causal=false 时不得施加掩码。
func TestAttentionNonCausal(t *testing.T) {
	q := synthVec(demoHeads*demoHeadDim, 41)
	kRows := [][]float64{synthVec(demoHeads*demoHeadDim, 42), synthVec(demoHeads*demoHeadDim, 43)}
	vRows := [][]float64{synthVec(demoHeads*demoHeadDim, 44), synthVec(demoHeads*demoHeadDim, 45)}
	all, err := Attention(q, kRows, vRows, demoHeads, demoHeadDim, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	only0, err := Attention(q, kRows[:1], vRows[:1], demoHeads, demoHeadDim, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	diff := 0.0
	for i := range all {
		diff += math.Abs(all[i] - only0[i])
	}
	if diff == 0 {
		t.Fatal("causal=false 时第二行应参与计算")
	}
}

// TestAttentionErrorCases Attention 的入参纪律。
func TestAttentionErrorCases(t *testing.T) {
	q := synthVec(demoHeads*demoHeadDim, 51)
	k := [][]float64{synthVec(demoHeads*demoHeadDim, 52)}
	v := [][]float64{synthVec(demoHeads*demoHeadDim, 53)}
	if _, err := Attention(q, k, append(v, v...), demoHeads, demoHeadDim, 0, 0, true); err == nil {
		t.Error("K/V 行数不一致应报错")
	}
	if _, err := Attention(q, nil, nil, demoHeads, demoHeadDim, 0, 0, true); err == nil {
		t.Error("空 KV 应报错")
	}
	if _, err := Attention(q, k, v, demoHeads, demoHeadDim, 0, -1, true); err == nil {
		t.Error("负 qPos 应报错")
	}
	if _, err := Attention(q, k, v, demoHeads, demoHeadDim, 5, 0, true); err == nil {
		t.Error("causal 下 qPos < kvStart 应报错（整行全掩码是配置错误而非合法场景）")
	}
}

// TestDemoTinyAlignment 与 route2plan.DemoTiny 的 head 配置在数值上保持一致
// （本文件不 import route2plan，改由常量 + 这里的注释锁定；若 Demo 配置变更请同步）。
func TestDemoTinyAlignment(t *testing.T) {
	if demoHeads*demoHeadDim != 32 {
		t.Fatalf("Heads*HeadDim = %d, want Dim=32", demoHeads*demoHeadDim)
	}
	if demoHeadDim%2 != 0 {
		t.Fatal("HeadDim 必须为偶数")
	}
	if demoTheta != 1e4 {
		t.Fatalf("theta = %v, want 1e4（D8）", demoTheta)
	}
}
