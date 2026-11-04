// rope_half_test.go - Qwen/LLaMA 前后半劈 RoPE 的约定锁定
//
// 这组断言的意义：相邻对与前后半劈在 headDim=2 时**恰好等价**（只有一对），
// 所以任何只测 headDim=2 的用例都无法区分二者。必须用 headDim>=4 且带非零 pos
// 才能锁定"配对方式"，否则又回到"两条路径同款错、全绿"的老坑（T5 实测踩过）。
package trustedops

import (
	"math"
	"testing"
)

// TestRoPEHalfPairing headDim=4、pos=1、单位向量：旋转落在 (0,2) 上，而不是 (0,1)。
func TestRoPEHalfPairing(t *testing.T) {
	vec := []float64{1, 0, 0, 0}
	out, err := ApplyRoPEHalf(vec, 1, 4, 1e6)
	if err != nil {
		t.Fatal(err)
	}
	// i=0 的角度 = pos * theta^0 = 1 rad
	want0, want2 := math.Cos(1), math.Sin(1)
	if math.Abs(out[0]-want0) > 1e-12 || math.Abs(out[2]-want2) > 1e-12 {
		t.Fatalf("前后半劈应旋转 (0,2) 对：got [%v %v %v %v]，want [%v 0 %v 0]",
			out[0], out[1], out[2], out[3], want0, want2)
	}
	if out[1] != 0 || out[3] != 0 {
		t.Fatalf("非配对分量必须保持 0：got [%v %v %v %v]", out[0], out[1], out[2], out[3])
	}
}

// TestRoPEHalfVsInterleaved headDim=4 时两种约定必须不同（否则说明某个实现退化成了另一个）。
func TestRoPEHalfVsInterleaved(t *testing.T) {
	base := []float64{1, 0.5, -0.25, 2}
	half, err := ApplyRoPEHalf(base, 3, 4, 1e6)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := ApplyRoPE(base, 3, 4, 1e6)
	if err != nil {
		t.Fatal(err)
	}
	same := true
	for i := range half {
		if math.Abs(half[i]-inter[i]) > 1e-12 {
			same = false
		}
	}
	if same {
		t.Fatal("headDim=4 且 pos!=0 时前后半劈与相邻对不应相同（实现可能退化）")
	}
	// headDim=2 时二者恰好等价（只有一对），这是可解释的巧合，不是 bug。
	a, _ := ApplyRoPEHalf([]float64{1, 2}, 5, 2, 1e4)
	b, _ := ApplyRoPE([]float64{1, 2}, 5, 2, 1e4)
	if math.Abs(a[0]-b[0]) > 1e-12 || math.Abs(a[1]-b[1]) > 1e-12 {
		t.Fatalf("headDim=2 时两种约定应等价：half=%v inter=%v", a, b)
	}
}

// TestRoPEHalfPreservesHeadNorm 旋转是正交变换：每个头的 L2 范数必须守恒。
func TestRoPEHalfPreservesHeadNorm(t *testing.T) {
	vec := []float64{0.3, -1.2, 0.7, 2.1, 0.05, -0.4, 1.1, -0.9} // 两个 head（headDim=4）
	out, err := ApplyRoPEHalf(vec, 7, 4, 1e6)
	if err != nil {
		t.Fatal(err)
	}
	for head := 0; head < 2; head++ {
		var before, after float64
		for i := 0; i < 4; i++ {
			k := head*4 + i
			before += vec[k] * vec[k]
			after += out[k] * out[k]
		}
		if math.Abs(before-after) > 1e-10 {
			t.Fatalf("head %d 范数不守恒：%v vs %v", head, before, after)
		}
	}
}

// TestRoPEHalfGuards 参数护栏（与相邻对版本同款 fail-closed）。
func TestRoPEHalfGuards(t *testing.T) {
	cases := []struct {
		name    string
		vec     []float64
		pos     int
		headDim int
		theta   float64
	}{
		{"headDim 奇数", []float64{1, 2, 3}, 0, 3, 1e4},
		{"headDim=0", []float64{1, 2}, 0, 0, 1e4},
		{"长度非整数倍", []float64{1, 2, 3, 4, 5}, 0, 4, 1e4},
		{"pos 为负", []float64{1, 2, 3, 4}, -1, 4, 1e4},
		{"theta=0", []float64{1, 2, 3, 4}, 0, 4, 0},
	}
	for _, c := range cases {
		if err := ApplyRoPEHalfInPlace(c.vec, c.pos, c.headDim, c.theta); err == nil {
			t.Errorf("%s：应报错却被接受", c.name)
		}
	}
}
