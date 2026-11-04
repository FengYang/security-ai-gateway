package trustedops

import (
	"math"
	"testing"
)

func TestReLU(t *testing.T) {
	cases := []struct{ in, want float64 }{
		{5.0, 5.0}, {-1.0, 0.0}, {0.0, 0.0}, {-0.5, 0.0},
	}
	for _, c := range cases {
		if got := ReLU(c.in); got != c.want {
			t.Fatalf("ReLU(%v)=%v want %v", c.in, got, c.want)
		}
	}
}

func TestGELU(t *testing.T) {
	// GELU(0) = 0；GELU(1) ≈ 0.8413；GELU(-1) ≈ -0.1587
	if got := GELU(0); math.Abs(got) > 1e-9 {
		t.Fatalf("GELU(0)=%v want 0", got)
	}
	if got := GELU(1); math.Abs(got-0.8413) > 1e-3 {
		t.Fatalf("GELU(1)=%v want ~0.8413", got)
	}
	if got := GELU(-1); math.Abs(got+0.1587) > 1e-3 {
		t.Fatalf("GELU(-1)=%v want ~-0.1587", got)
	}
}

func TestPerHeadRMSNorm(t *testing.T) {
	// 长度 6 = 2 头 × head_dim 3；第 0..2 与 3..5 段各自独立归一。
	// 手工构造：段 A = [1,2,3] → mean²= (1+4+9)/3=14/3, invStd=1/sqrt(14/3+1e-6)≈0.506
	// 段 B = [4,5,6] → mean²= (16+25+36)/3=77/3, invStd≈0.218
	v := []float64{1, 2, 3, 4, 5, 6}
	gamma := []float64{2, 2, 2} // head_dim=3
	eps := 1e-6
	out, err := PerHeadRMSNorm(v, gamma, 3, eps)
	if err != nil {
		t.Fatalf("PerHeadRMSNorm 不应报错: %v", err)
	}
	if len(out) != len(v) {
		t.Fatalf("输出长度=%d want %d", len(out), len(v))
	}
	// 段 A 归一后乘 gamma
	invStdA := 1 / math.Sqrt((1+4+9)/3.0+eps)
	for i := 0; i < 3; i++ {
		want := v[i] * invStdA * gamma[i]
		if math.Abs(out[i]-want) > 1e-9 {
			t.Fatalf("PerHeadRMSNorm 段A[%d]=%v want %v", i, out[i], want)
		}
	}
	invStdB := 1 / math.Sqrt((16+25+36)/3.0+eps)
	for i := 3; i < 6; i++ {
		want := v[i] * invStdB * gamma[i%3]
		if math.Abs(out[i]-want) > 1e-9 {
			t.Fatalf("PerHeadRMSNorm 段B[%d]=%v want %v", i, out[i], want)
		}
	}
	// 护栏：长度非整数倍 / gamma 长度错配必须 fail-closed
	if _, err := PerHeadRMSNorm([]float64{1, 2, 3, 4}, gamma, 3, eps); err == nil {
		t.Fatal("长度非 head_dim 整数倍应报错")
	}
	if _, err := PerHeadRMSNorm(v, []float64{1, 2}, 3, eps); err == nil {
		t.Fatal("gamma 长度错配应报错")
	}
}

func TestSoftmax(t *testing.T) {
	v := []float64{1, 2, 3}
	out := Softmax(v)
	var sum float64
	for _, x := range out {
		sum += x
	}
	if math.Abs(sum-1) > 1e-9 {
		t.Fatalf("softmax 概率和=%v want 1", sum)
	}
	// 单调性：out[2] > out[1] > out[0]
	if !(out[2] > out[1] && out[1] > out[0]) {
		t.Fatalf("softmax 单调性错误: %v", out)
	}
}

func TestLayerNorm(t *testing.T) {
	x := []float64{1, 2, 3, 4}
	out := LayerNorm(x, nil, nil, 1e-5)
	// 归一化后均值≈0，方差≈1
	var mean float64
	for _, v := range out {
		mean += v
	}
	mean /= float64(len(out))
	if math.Abs(mean) > 1e-9 {
		t.Fatalf("LayerNorm 均值=%v want 0", mean)
	}
	var variance float64
	for _, v := range out {
		d := v - mean
		variance += d * d
	}
	variance /= float64(len(out))
	if math.Abs(variance-1) > 1e-4 {
		t.Fatalf("LayerNorm 方差=%v want 1", variance)
	}
	// gamma/beta 仿射
	g := []float64{2, 2, 2, 2}
	bb := []float64{1, 1, 1, 1}
	out2 := LayerNorm(x, g, bb, 1e-5)
	for i := range out2 {
		if math.Abs(out2[i]-(out[i]*2+1)) > 1e-6 {
			t.Fatalf("LayerNorm 仿射错误 idx=%d", i)
		}
	}
}

func TestArgMax(t *testing.T) {
	if got := ArgMax([]float64{0.1, 0.9, 0.5}); got != 1 {
		t.Fatalf("ArgMax=%d want 1", got)
	}
	if got := ArgMax(nil); got != -1 {
		t.Fatalf("ArgMax(nil)=%d want -1", got)
	}
}

func TestSiLU(t *testing.T) {
	// SiLU(0) = 0；SiLU(1) ≈ 0.7311；SiLU(-1) ≈ -0.2689；对称性 SiLU(-x) = -SiLU(x)*... 验证单调与 δ=0 过零。
	if got := SiLU(0); math.Abs(got) > 1e-9 {
		t.Fatalf("SiLU(0)=%v want 0", got)
	}
	if got := SiLU(1); math.Abs(got-0.7311) > 1e-3 {
		t.Fatalf("SiLU(1)=%v want ~0.7311", got)
	}
	if got := SiLU(-1); math.Abs(got+0.2689) > 1e-3 {
		t.Fatalf("SiLU(-1)=%v want ~-0.2689", got)
	}
	// 单调性：x 增大 SiLU(x) 严格增大（非奇非偶，不满足 SiLU(-x)=-SiLU(x)）。
	for _, x := range []float64{-3.0, -0.5, 0.0, 0.5, 2.0, 10.0} {
		if x > 0 && SiLU(x) <= 0 {
			t.Fatalf("SiLU(%v)=%v 应 > 0", x, SiLU(x))
		}
		if x < 0 && SiLU(x) >= 0 {
			t.Fatalf("SiLU(%v)=%v 应 < 0", x, SiLU(x))
		}
	}
}

func TestSiLUMul(t *testing.T) {
	gate := []float64{1.0, 2.0, -1.0}
	up := []float64{0.5, -1.0, 3.0}
	out, err := SiLUMul(gate, up)
	if err != nil {
		t.Fatalf("SiLUMul 不应报错: %v", err)
	}
	if len(out) != len(gate) {
		t.Fatalf("SiLUMul 输出长度=%d want %d", len(out), len(gate))
	}
	for i := range gate {
		want := SiLU(gate[i]) * up[i]
		if math.Abs(out[i]-want) > 1e-9 {
			t.Fatalf("SiLUMul[%d]=%v want %v", i, out[i], want)
		}
	}
	// 长度错配必须 fail-closed
	if _, err := SiLUMul([]float64{1, 2}, []float64{1}); err == nil {
		t.Fatal("长度错配的 SiLUMul 应报错")
	}
}
