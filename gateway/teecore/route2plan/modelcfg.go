package route2plan

import (
	"errors"
	"fmt"
)

// ---------- 模型配置（T01 的 demo 真值源，勿在别处再抄一份数字） ----------

// ModelConfig 模型结构配置。同一份 cfg 必须同时喂给：
//   - 客户端编排器（决定 offload 哪些投影矩阵、行维度多少）；
//   - 可信域服务端（决定 StepSpec 的行维度校验、KV cache 容量与 derive 方式）。
//
// 两侧一旦数字不一致，表现为「层序校验全绿但数值全错」——即 §2.5.2 所述最坏失败模式。
// 故本结构体必须由 Build(cfg) 消费，禁止在调用点的代码里写死维度。
type ModelConfig struct {
	// ModelID 模型标识。决定权重派生盐、维度与模数；T03 首次请求后冻结，
	// 变更⇒recompute_model_mismatch（§7.3）。字符集受限以保证派生 key 无歧义。
	ModelID string
	// Blocks Transformer block 数量，取值 1..MaxModelBlocks。
	Blocks int
	// Dim d_model，同时也是每行的特征维数。
	Dim int
	// Heads 注意力头数。
	Heads int
	// HeadDim 每头维度，必须为偶数（RoPE 成对旋转），且 Heads*HeadDim == Dim。
	HeadDim int
	// FFNDim FFN 升维宽度（D4：无门控 MLP，up: Dim→FFNDim，down: FFNDim→Dim）。
	FFNDim int
	// Vocab 词表大小，>= 2（argmax 至少要能在两个 logit 间抉择）。
	Vocab int
	// NormEps RMSNorm 的 epsilon，> 0。
	NormEps float64
	// RopeTheta RoPE 基频（D8 默认 1e4），> 0。
	RopeTheta float64
	// MaxTokens 单会话 KV 行数上限，取值 1..MaxModelTokens（fail-closed 硬顶）。
	MaxTokens int
}

// 配置取值域边界（fail-closed：Validate 一律拦截越界）。
const (
	// MaxModelBlocks 上界由两项约束决定：① 收尾步要用哨兵块号 cfg.Blocks，
	// 必须落在 Block 的定宽 4 位之内；② demo 规模（D6/D7）远小于此。
	MaxModelBlocks = MaxBlock - 1 // 9998
	// MaxModelDim 单请求行维度上界（既有 4096 总上限不动，此处仅防配置笔误）。
	MaxModelDim = 65535
	// MaxModelTokens 单会话 KV 行数上限的上界。超出了就是配置笔误，拒。
	MaxModelTokens = 1 << 16
	// MaxModelIDLen ModelID 最大长度（派生 key 的长度约束）。
	MaxModelIDLen = 64
	// MaxModelFFNDim / MaxModelVocab 同上的维度护栏。
	MaxModelFFNDim = MaxModelDim
	MaxModelVocab  = MaxModelDim
)

// ---- DemoTiny：demo 模型的**唯一配置常量源**（设计 §2.6 D6） ----
//
// 客户端与服务端一律引用本值（或直接引用 DemoTinyConfig()），禁止各自再抄一份数字：
// 抄写漂移会让「两边都对」变成「掩码/维度错配而全绿通过」。
const (
	DemoModelID   = "route2-demo-tiny"
	DemoBlocks    = 4
	DemoDim       = 32
	DemoHeads     = 4
	DemoHeadDim   = 8
	DemoFFNDim    = 64
	DemoVocab     = 64
	DemoMaxTokens = 128
	DemoNormEps   = 1e-6
	DemoRopeTheta = 1e4
)

// DemoTiny demo 模型配置常量。
//
// 【只读约定】本值是全局共享的，调用方必须按值传递（ModelConfig 为纯值类型），
// 严禁就地修改其字段；需要可变副本请用 DemoTinyConfig()。
// KV 峰值内存估算（§6.1）：2·4·128·32·8B = 256 KiB。
var DemoTiny = ModelConfig{
	ModelID:   DemoModelID,
	Blocks:    DemoBlocks,
	Dim:       DemoDim,
	Heads:     DemoHeads,
	HeadDim:   DemoHeadDim,
	FFNDim:    DemoFFNDim,
	Vocab:     DemoVocab,
	NormEps:   DemoNormEps,
	RopeTheta: DemoRopeTheta,
	MaxTokens: DemoMaxTokens,
}

// DemoTinyConfig 返回 DemoTiny 的按值副本，供需要就地微调（如测试期缩小 Blocks）
// 的调用方使用，避免污染全局常量。
func DemoTinyConfig() ModelConfig {
	return DemoTiny
}

// AttnDim 注意力投影的输出宽度 Heads*HeadDim（Validate 保证其 == Dim）。
func (c ModelConfig) AttnDim() int {
	return c.Heads * c.HeadDim
}

// Validate 逐字段校验配置合法性；fail-closed，任一不合法即返回显式 error。
//
// 注意这里把「Heads*HeadDim == Dim」写成硬约束：一旦不等，
// attention 的 concat-heads 输出与残差流的 Dim 就对不上，
// 错误会以「行维度不匹配」的形式在很后面才炸，届时排查成本极高（§2.2 G6）。
func (c ModelConfig) Validate() error {
	if err := validateModelID(c.ModelID); err != nil {
		return err
	}
	if c.Blocks < 1 || c.Blocks > int(MaxModelBlocks) {
		return fmt.Errorf("route2plan: Blocks=%d 超出取值域 1..%d", c.Blocks, int(MaxModelBlocks))
	}
	if c.Dim < 1 || c.Dim > MaxModelDim {
		return fmt.Errorf("route2plan: Dim=%d 超出取值域 1..%d", c.Dim, MaxModelDim)
	}
	if c.Heads < 1 || c.Heads > c.Dim {
		return fmt.Errorf("route2plan: Heads=%d 非法（须 1..Dim=%d）", c.Heads, c.Dim)
	}
	if c.HeadDim < 2 || c.HeadDim > c.Dim {
		return fmt.Errorf("route2plan: HeadDim=%d 非法（须 2..Dim=%d）", c.HeadDim, c.Dim)
	}
	if c.HeadDim%2 != 0 {
		return fmt.Errorf("route2plan: HeadDim=%d 必须为偶数（RoPE 成对旋转，见 D8）", c.HeadDim)
	}
	if got := c.AttnDim(); got != c.Dim {
		return fmt.Errorf("route2plan: Heads*HeadDim=%d != Dim=%d（注意力输出无法与残差流对齐）", got, c.Dim)
	}
	if c.FFNDim < 1 || c.FFNDim > MaxModelFFNDim {
		return fmt.Errorf("route2plan: FFNDim=%d 超出取值域 1..%d", c.FFNDim, MaxModelFFNDim)
	}
	if c.Vocab < 2 || c.Vocab > MaxModelVocab {
		return fmt.Errorf("route2plan: Vocab=%d 超出取值域 2..%d", c.Vocab, MaxModelVocab)
	}
	if !(c.NormEps > 0) {
		return fmt.Errorf("route2plan: NormEps=%v 必须为正", c.NormEps)
	}
	if !(c.RopeTheta > 0) {
		return fmt.Errorf("route2plan: RopeTheta=%v 必须为正", c.RopeTheta)
	}
	if c.MaxTokens < 1 || c.MaxTokens > MaxModelTokens {
		return fmt.Errorf("route2plan: MaxTokens=%d 超出取值域 1..%d", c.MaxTokens, MaxModelTokens)
	}
	return nil
}

// validateModelID 约束 ModelID 字符集。
//
// 之所以拒绝 '/'、'|'、空白等字符：ModelID 会进入两处字符串——① 权重派生 key
// `<modelID>/<block>/<tensor>/<i>-<j>`；② Wire / 掩码域相关串。含分隔符会导致
// 两段 key 解析出同一个字符串（碰撞），从而两条不同配置派生出同一份"权重"。
func validateModelID(id string) error {
	if id == "" {
		return errors.New("route2plan: ModelID 不可为空")
	}
	if len(id) > MaxModelIDLen {
		return fmt.Errorf("route2plan: ModelID 长度 %d 超出上限 %d", len(id), MaxModelIDLen)
	}
	for i := 0; i < len(id); i++ {
		ch := id[i]
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '-' || ch == '_' || ch == '.':
		default:
			return fmt.Errorf("route2plan: ModelID %q 含禁用字符 %q（仅允许 [A-Za-z0-9._-]）", id, string(ch))
		}
	}
	return nil
}
