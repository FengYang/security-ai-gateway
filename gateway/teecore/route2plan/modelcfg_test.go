// modelcfg_test.go - 配置校验与 DemoTiny 常量源测试（T01 验收项 4）
package route2plan

import (
	"strings"
	"testing"
)

// TestDemoTinyIsValid D6 裁定的 demo 配置必须能通过全部校验。
func TestDemoTinyIsValid(t *testing.T) {
	if err := DemoTiny.Validate(); err != nil {
		t.Fatalf("DemoTiny 未通过校验: %v", err)
	}
}

// TestDemoTinyValues demo 配置的每个数字都锚定 D6，防止被悄悄改掉而无人察觉。
func TestDemoTinyValues(t *testing.T) {
	cfg := DemoTinyConfig()
	if cfg.ModelID != DemoModelID {
		t.Errorf("ModelID = %q", cfg.ModelID)
	}
	if cfg.Blocks != 4 {
		t.Errorf("Blocks = %d, want 4", cfg.Blocks)
	}
	if cfg.Dim != 32 {
		t.Errorf("Dim = %d, want 32", cfg.Dim)
	}
	if cfg.Heads != 4 {
		t.Errorf("Heads = %d, want 4", cfg.Heads)
	}
	if cfg.HeadDim != 8 {
		t.Errorf("HeadDim = %d, want 8", cfg.HeadDim)
	}
	if cfg.FFNDim != 64 {
		t.Errorf("FFNDim = %d, want 64", cfg.FFNDim)
	}
	if cfg.Vocab != 64 {
		t.Errorf("Vocab = %d, want 64", cfg.Vocab)
	}
	if cfg.MaxTokens != 128 {
		t.Errorf("MaxTokens = %d, want 128", cfg.MaxTokens)
	}
	if cfg.NormEps != 1e-6 {
		t.Errorf("NormEps = %v, want 1e-6", cfg.NormEps)
	}
	if cfg.RopeTheta != 1e4 {
		t.Errorf("RopeTheta = %v, want 1e4", cfg.RopeTheta)
	}
	if cfg.AttnDim() != cfg.Dim {
		t.Errorf("AttnDim() = %d, want == Dim=%d", cfg.AttnDim(), cfg.Dim)
	}
	// KV 峰值内存估算（§6.1）：2·Blocks·MaxTokens·Dim·8B = 256 KiB
	bytes := 2 * cfg.Blocks * cfg.MaxTokens * cfg.Dim * 8
	if bytes != 256*1024 {
		t.Errorf("KV 峰值内存 = %d B, want %d B（256 KiB）", bytes, 256*1024)
	}
}

// TestDemoTinyConfigReturnsCopy DemoTinyConfig() 必须返回副本，改动不得污染全局常量。
func TestDemoTinyConfigReturnsCopy(t *testing.T) {
	c := DemoTinyConfig()
	c.Blocks = 99
	c.ModelID = "tampered"
	if DemoTiny.Blocks != DemoBlocks {
		t.Fatalf("全局常量被污染: Blocks = %d", DemoTiny.Blocks)
	}
	if DemoTiny.ModelID != DemoModelID {
		t.Fatalf("全局常量被污染: ModelID = %q", DemoTiny.ModelID)
	}
}

// TestValidateRejects 逐条负面用例：任何一项不合法都必须拦下（fail-closed）。
func TestValidateRejects(t *testing.T) {
	ok := DemoTinyConfig()
	base := func() ModelConfig { return ok }

	cases := []struct {
		name    string
		mutate  func(c *ModelConfig)
		wantSub string
	}{
		{"ModelID 为空", func(c *ModelConfig) { c.ModelID = "" }, "ModelID"},
		{"ModelID 含斜杠", func(c *ModelConfig) { c.ModelID = "a/b" }, "禁用字符"},
		{"ModelID 含竖线", func(c *ModelConfig) { c.ModelID = "a|b" }, "禁用字符"},
		{"ModelID 含空格", func(c *ModelConfig) { c.ModelID = "a b" }, "禁用字符"},
		{"ModelID 超长", func(c *ModelConfig) { c.ModelID = strings.Repeat("x", MaxModelIDLen+1) }, "长度"},
		{"Blocks=0", func(c *ModelConfig) { c.Blocks = 0 }, "Blocks"},
		{"Blocks 越界", func(c *ModelConfig) { c.Blocks = int(MaxModelBlocks) + 1 }, "Blocks"},
		{"Dim=0", func(c *ModelConfig) { c.Dim = 0 }, "Dim"},
		{"Heads=0", func(c *ModelConfig) { c.Heads = 0 }, "Heads"},
		{"HeadDim 奇数（RoPE 需要成对）", func(c *ModelConfig) { c.HeadDim = 7; c.Heads = 4 }, "偶数"},
		{"FFNDim=0", func(c *ModelConfig) { c.FFNDim = 0 }, "FFNDim"},
		{"RopeStyle 非法", func(c *ModelConfig) { c.RopeStyle = "half-split" }, "RopeStyle"},
		{"Vocab=1（argmax 无法抉择）", func(c *ModelConfig) { c.Vocab = 1 }, "Vocab"},
		{"NormEps=0", func(c *ModelConfig) { c.NormEps = 0 }, "NormEps"},
		{"NormEps 为负", func(c *ModelConfig) { c.NormEps = -1e-6 }, "NormEps"},
		{"RopeTheta=0", func(c *ModelConfig) { c.RopeTheta = 0 }, "RopeTheta"},
		{"MaxTokens=0", func(c *ModelConfig) { c.MaxTokens = 0 }, "MaxTokens"},
		{"MaxTokens 越界", func(c *ModelConfig) { c.MaxTokens = MaxModelTokens + 1 }, "MaxTokens"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("Validate() 应拒绝该配置却被接受: %+v", c)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("错误信息 %q 应包含 %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestValidateAcceptsModelIDCharset ModelID 的合法字符集边界。
func TestValidateAcceptsModelIDCharset(t *testing.T) {
	for _, id := range []string{"m", "model-1", "MODEL_2", "a.b.c", strings.Repeat("z", MaxModelIDLen)} {
		c := DemoTinyConfig()
		c.ModelID = id
		if err := c.Validate(); err != nil {
			t.Errorf("ModelID %q 应合法却报错: %v", id, err)
		}
	}
}

// TestMaxModelBlocksFitsWire 哨兵块号 cfg.Blocks 必须能塞进 Block 的 4 位定宽，
// 否则收尾坐标（ln_final / argmax）的 Wire 会溢出。
func TestMaxModelBlocksFitsWire(t *testing.T) {
	c := DemoTinyConfig()
	c.Blocks = int(MaxModelBlocks)
	if err := c.Validate(); err != nil {
		t.Fatalf("边界 Blocks=%d 应合法: %v", c.Blocks, err)
	}
	tail := LayerCoord{Stage: StagePrefill, Turn: 0, Block: uint16(c.Blocks), Step: StepFinalNorm, Branch: BranchMain}
	if err := tail.Validate(); err != nil {
		t.Fatalf("收尾坐标 Block=%d 溢出 Wire 定宽: %v", c.Blocks, err)
	}
	w := tail.Wire()
	if got := strings.Count(w, "|"); got != wireFieldCount-1 {
		t.Fatalf("Wire %q 段数异常: %d", w, got)
	}
}
