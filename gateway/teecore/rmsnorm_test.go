// rmsnorm_test.go - RMSNorm 算子数值测试
package teecore

import (
	"math"
	"testing"
)

func TestRMSNorm(t *testing.T) {
	x := []float64{1.0, 2.0, 3.0, 4.0}
	gamma := []float64{1.0, 1.0, 1.0, 1.0}
	out := RMSNorm(x, gamma, 1e-6)

	// 参考实现：x / sqrt(mean(x^2) + eps)
	var sqSum float64
	for _, v := range x {
		sqSum += v * v
	}
	invStd := 1 / math.Sqrt(sqSum/float64(len(x))+1e-6)
	for i, v := range x {
		want := v * invStd
		if math.Abs(out[i]-want) > 1e-12 {
			t.Fatalf("RMSNorm[%d] = %v, want %v", i, out[i], want)
		}
	}

	// gamma 缩放生效
	gamma2 := []float64{2.0, 2.0, 2.0, 2.0}
	out2 := RMSNorm(x, gamma2, 1e-6)
	if math.Abs(out2[0]-2*out[0]) > 1e-12 {
		t.Fatalf("gamma 缩放未生效: %v vs %v", out2[0], out[0])
	}

	// 空输入
	if len(RMSNorm(nil, nil, 1e-6)) != 0 {
		t.Fatal("空输入应返回空切片")
	}

	// eps 影响（大 eps 拉平输出）
	outEps := RMSNorm([]float64{1.0, 1.0, 1.0}, []float64{1, 1, 1}, 100.0)
	for _, v := range outEps {
		if math.Abs(v-1.0/math.Sqrt(101.0)) > 1e-12 {
			t.Fatalf("eps 行为异常: %v", v)
		}
	}
}
