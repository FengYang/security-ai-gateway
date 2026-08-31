package teecore

import (
	"math"
	"testing"
	"time"
)

// ---------- KeyManager ----------

func TestKeyIssueDerive(t *testing.T) {
	km, err := NewKeyManager(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer km.Close()

	seed1, nonce1, err := km.Issue("req-1", "mock")
	if err != nil {
		t.Fatal(err)
	}
	seed2, nonce2, err := km.Issue("req-2", "mock")
	if err != nil {
		t.Fatal(err)
	}
	if nonce1 == nonce2 {
		t.Fatal("nonce 重复")
	}
	if len(seed1) != 32 || len(seed2) != 32 {
		t.Fatal("请求密钥长度 != 32")
	}
	// 不同请求派生不同密钥
	same := true
	for i := range seed1 {
		if seed1[i] != seed2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("不同请求的派生密钥相同")
	}

	// 回溯一致性
	got, ok := km.Lookup(nonce1)
	if !ok {
		t.Fatal("nonce 回溯失败")
	}
	for i := range got {
		if got[i] != seed1[i] {
			t.Fatal("回溯密钥不一致")
		}
	}
	// 未知 nonce
	if _, ok := km.Lookup("deadbeef"); ok {
		t.Fatal("未知 nonce 应回溯失败")
	}
}

func TestKeyRotationForwardSecrecy(t *testing.T) {
	km, err := NewKeyManager(50 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer km.Close()

	before := km.MasterID()
	time.Sleep(120 * time.Millisecond)
	after := km.MasterID()
	if after <= before {
		t.Fatalf("主密钥未轮换: %d -> %d", before, after)
	}
}

func TestKeyIssueDeterministicDerive(t *testing.T) {
	// 验证派生是 HMAC(master, reqID||model||ts) —— 相同入参结果相同（内部一致性）
	km, err := NewKeyManager(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer km.Close()
	km.mu.Lock()
	a := km.deriveLocked("req-x", "mock", 12345)
	b := km.deriveLocked("req-x", "mock", 12345)
	km.mu.Unlock()
	if string(a) != string(b) {
		t.Fatal("相同入参派生结果不一致")
	}
}

// ---------- nonlinear ----------

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
