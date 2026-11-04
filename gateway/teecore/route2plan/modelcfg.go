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
	// HeadDim 每头维度，必须为偶数（RoPE 成对旋转），且 <= Dim。
	// 注意 Heads*HeadDim（即 AttnDim）**不要求**等于 Dim：真实 Qwen3-0.6B 为 2048≠1024，
	// 注意力拼接输出经 Wo([Dim, AttnDim]) 映回 Dim 汇入残差流（见 AttnDim/KVDim）。
	HeadDim int
	// KVHeads GQA 的 KV 头数（num_key_value_heads）。<= Heads 且必须整除 Heads。
	// 0 表示未显式设置，等价于 KVHeads==Heads（即无 GQA 的 MHA 退化情形，见 KVDim）。
	// GQA 下 K/V 投影输出宽度 = KVHeads*HeadDim（< Dim），注意力前需把 KV 从 KV 头布局
	// 扩展回 Q 头布局（见 trustedops.ExpandGQA 与 route2step 注意力分支）。
	KVHeads int
	// FFNDim FFN 升维宽度（D4：无门控 MLP，up: Dim→FFNDim，down: FFNDim→Dim）。
	FFNDim int
	// FFNType FFN 结构类型："" 或 "gelu" 退化为经典无门控 MLP（up→GELU→down）；
	// "swiglu" 走门控 FFN（up / gate / silu(gate)⊙up / down），真实 Qwen3 即此结构。
	// 默认 "" 等价于 "gelu"，以保证既有 demo 配置零改动向后兼容。
	FFNType string
	// Vocab 词表大小，>= 2（argmax 至少要能在两个 logit 间抉择）。
	Vocab int
	// NormEps RMSNorm 的 epsilon，> 0。
	NormEps float64
	// RopeTheta RoPE 基频（D8 默认 1e4），> 0。
	RopeTheta float64
	// RopeStyle Q/K 旋转的配对约定："" 或 "interleaved" 为**相邻对** (2i, 2i+1)
	// （GPT-J/NeoX 风格，demo 默认，保证零改动）；"half" 为**前后半劈** (i, i+headDim/2)
	// （Qwen2/Qwen3、LLaMA、HuggingFace 风格）。
	// 两种约定的旋转角度表相同、配对方式不同，headDim>2 时结果完全不同，且错用不报错，
	// 只能靠外部 golden 发现（见 T5 实测与 trustedops.ApplyRoPEHalfInPlace 注释）。
	RopeStyle string
	// QKNorm 是否在 Q/K 投影之后、RoPE 之前对各注意力头做逐头 RMSNorm
	// （真实 Qwen3 的 QK-norm）。默认 false（经典无 QK-norm）。true 时权重须提供
	// TensorQNorm / TensorKNorm（逐头 gamma，长度 == HeadDim，见 route2demo）。
	QKNorm bool
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
	// MaxModelVocab 词表上界独立于 MaxModelDim：真实模型的词表普遍远大于 d_model
	// （Qwen3-0.6B: 151936；Llama-3: 128256；Gemma: 256000），故不再复用 65535 这个
	// "笔误护栏"，放宽到 1<<20（覆盖当前全部主流分词器，仍足以拦住明显笔误）。
	// Vocab 不参与 Wire 坐标的定宽编码，放宽不影响掩码域/编码纪律。
	MaxModelVocab = 1 << 20
)

// FFN 类型常量（见 ModelConfig.FFNType）。
const (
	// FFNTypeGELU 经典无门控 MLP：up: Dim→FFNDim → GELU → down: FFNDim→Dim。
	// 空字符串 "" 也按 GELU 处理，以保证既有 demo 配置零改动向后兼容。
	FFNTypeGELU = "gelu"
	// FFNTypeSwiGLU 门控 FFN：up / gate / silu(gate)⊙up / down（真实 Qwen3 结构）。
	FFNTypeSwiGLU = "swiglu"
)

// RoPE 配对约定常量（见 ModelConfig.RopeStyle）。
const (
	// RopeStyleInterleaved 相邻对 (2i, 2i+1)（GPT-J/NeoX）；空字符串等价于本值。
	RopeStyleInterleaved = "interleaved"
	// RopeStyleHalf 前后半劈 (i, i+headDim/2)（Qwen2/Qwen3、LLaMA、HuggingFace）。
	RopeStyleHalf = "half"
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

// AttnDim 注意力投影的输出宽度 Heads*HeadDim。
//
// 真实 Qwen3 起允许与 Dim 解耦（0.6B: attnDim=2048 ≠ Dim=1024）：Q/K/V 投影输出 attnDim
// 宽、K/V cache 按 KVDim 宽、注意力原始拼接输出 attnDim 宽，再经 Wo([Dim, attnDim]) 映回
// Dim 汇入残差流。故 attnDim 与 Dim 不再强制相等（旧约束见 T4 评估修复说明）。
func (c ModelConfig) AttnDim() int {
	return c.Heads * c.HeadDim
}

// KVDim KV 投影的输出宽度 KVHeads*HeadDim。
//
// GQA 下 < Dim（多个 Q 头共享一组 KV 头）；MHA 下（KVHeads 未设置或 == Heads）== Dim。
// 注意力前须把 KV cache 的 KV 头布局（KVHeads*HeadDim）扩展回 Q 头布局（Heads*HeadDim），
// 见 trustedops.ExpandGQA。KVHeads==0 时按 Heads 处理（向后兼容既有未显式设置 KVHeads 的配置）。
func (c ModelConfig) KVDim() int {
	if c.KVHeads <= 0 {
		return c.Heads * c.HeadDim
	}
	return c.KVHeads * c.HeadDim
}

// Validate 逐字段校验配置合法性；fail-closed，任一不合法即返回显式 error。
//
// 历史上曾把「Heads*HeadDim == Dim」写成硬约束。自真实 Qwen3 接入（T4）起该约束被解除：
// attention 的 concat-heads 输出宽为 AttnDim，由 Wo([Dim, AttnDim]) 映回 Dim 汇入残差流，
// K/V 投影输出宽为 KVDim，三者本就无须相等。为免"行维度不匹配"在很靠后才炸（§2.2 G6），
// 改由 plan 构造期按 AttnDim/KVDim 精确赋值各步 InDim/OutDim 来保证布局自洽。
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
	// GQA 约束（KVHeads 未设置即 MHA，等价于 KVHeads==Heads）。
	if c.KVHeads < 0 {
		return fmt.Errorf("route2plan: KVHeads=%d 不可为负", c.KVHeads)
	}
	if c.KVHeads > 0 {
		if c.KVHeads > c.Heads {
			return fmt.Errorf("route2plan: KVHeads=%d 超出 Heads=%d（GQA 组大小须 <= Heads）", c.KVHeads, c.Heads)
		}
		if c.Heads%c.KVHeads != 0 {
			return fmt.Errorf("route2plan: KVHeads=%d 不能整除 Heads=%d（GQA 组大小须为整数）", c.KVHeads, c.Heads)
		}
	}
	// 注意：自真实 Qwen3 起 attnDim(=Heads*HeadDim) 允许与 Dim 解耦（0.6B: 2048≠1024）。
	// 注意力原始输出宽 attnDim，由 Wo([Dim, attnDim]) 映回 Dim 汇入残差流，故不再强制相等。
	// 仍要求 Heads/HeadDim 合法（上面已校验），attnDim 自然为正。
	switch c.FFNType {
	case "", FFNTypeGELU, FFNTypeSwiGLU:
	default:
		return fmt.Errorf("route2plan: FFNType=%q 非法（合法值：\"\" / %q / %q）", c.FFNType, FFNTypeGELU, FFNTypeSwiGLU)
	}
	switch c.RopeStyle {
	case "", RopeStyleInterleaved, RopeStyleHalf:
	default:
		return fmt.Errorf("route2plan: RopeStyle=%q 非法（合法值：\"\" / %q / %q）",
			c.RopeStyle, RopeStyleInterleaved, RopeStyleHalf)
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
