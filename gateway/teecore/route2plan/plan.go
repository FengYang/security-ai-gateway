package route2plan

import (
	"errors"
	"fmt"
	"sort"
)

// ---------- 张量标识与权重溯源 ----------

// TensorKey 一张有权重/仿射参数张量的标识。
//
// 位置说明：设计 §2.4.5 把 TensorKey 与 ModelWeights 同框列出但未指定归属包。
// 本实现把它落在 route2plan 而非 route2demo，理由有二：
//  1. StepSpec.InWeight 需要引用张量身份，而 route2plan 必须保持「只依赖标准库」
//     才能被服务端/客户端/测试三方零成本共享；若反向依赖 route2demo（它依赖
//     maskedinfer），plan 就被绑进重量级包里。
//  2. 放在 plan 侧可以保证 StepSpec 引用的 key 与 route2demo 实际能加载的 key
//     是同一份枚举，杜绝「plan 写 attn_q、加载器认 attn.q」这类拼写漂移。
type TensorKey struct {
	// Block block 序号；收尾张量（ln_final / lm_head）取哨兵值 cfg.Blocks。
	Block int
	// Tensor 张量名，取值见下列常量。
	Tensor string
}

// 合法张量名（设计 §2.4.5）。注意这里刻意用「点号 + 小写」拼写，全局唯一。
const (
	TensorAttnQ   = "attn.q"      // Dim -> Heads*HeadDim，Q 投影
	TensorAttnK   = "attn.k"      // Dim -> KVHeads*HeadDim（GQA 下窄于 Q），K 投影
	TensorAttnV   = "attn.v"      // Dim -> KVHeads*HeadDim（同上），V 投影
	TensorAttnO   = "attn.o"      // Heads*HeadDim -> Dim，输出投影
	TensorFFNUp   = "ffn.up"      // Dim -> FFNDim，FFN 升维
	TensorFFNDown = "ffn.down"    // FFNDim -> Dim，FFN 降维
	TensorGate    = "ffn.gate"    // Dim -> FFNDim，SwiGLU 门控投影（仅 FFNType=swiglu 时存在）
	TensorLNIn    = "ln_in"       // attention 前的 RMSNorm gamma（每 block 一份）
	TensorLNPost  = "ln_post"     // FFN 前的 RMSNorm gamma（每 block 一份）
	TensorLNFinal = "ln_final"    // 收尾 RMSNorm gamma（全局一份）
	TensorQNorm   = "attn.q_norm" // 每 block 的 Q 逐头归一 gamma（Qwen3；长度 = HeadDim，所有头共享）
	TensorKNorm   = "attn.k_norm" // 每 block 的 K 逐头归一 gamma（Qwen3；长度 = HeadDim，所有头共享）
	TensorLMHead  = "lm_head"     // Dim -> Vocab；非方阵（Rows != Cols）由 QuantizedMatrix 的 Rows/Cols 分离天然支持，无需改动数值内核
	// TensorTokEmb token 嵌入表：Vocab -> Dim 的查表（Gather），全局一份。
	// 补录原因（T02 发现的设计漏项）：§2.4.5 的张量枚举原本只有 attn.*/ffn.*/ln_*/lm_head，
	// 而**没有嵌入就跑不了前向**。客户端注入与服务端 Gather 必须共用同一张表，
	// 各派生一份是不可接受的（漂移症状是"输出随机错 token"且极难查）。
	// 它与其他收尾张量一样取哨兵块号 cfg.Blocks（见 route2demo.checkBlockBounds）。
	TensorTokEmb = "tok.emb"
)

// normTensorSet 仿射参数（gamma/eps）类张量；它们不产生 QuantizedMatrix。
var normTensorSet = map[string]bool{
	TensorLNIn:    true,
	TensorLNPost:  true,
	TensorLNFinal: true,
	TensorQNorm:   true,
	TensorKNorm:   true,
}

// matrixTensorSet 线性权重类张量；它们产生 QuantizedMatrix。
var matrixTensorSet = map[string]bool{
	TensorAttnQ:   true,
	TensorAttnK:   true,
	TensorAttnV:   true,
	TensorAttnO:   true,
	TensorFFNUp:   true,
	TensorFFNDown: true,
	TensorGate:    true,
	TensorLMHead:  true,
	TensorTokEmb:  true,
}

// Validate 校验张量名合法且 block 号非负（fail-closed）。
func (k TensorKey) Validate() error {
	if k.Block < 0 {
		return fmt.Errorf("route2plan: TensorKey.Block=%d 不可为负", k.Block)
	}
	if !normTensorSet[k.Tensor] && !matrixTensorSet[k.Tensor] {
		return fmt.Errorf("route2plan: 未知张量名 %q（合法值见 TensorAttnQ..TensorLMHead 常量）", k.Tensor)
	}
	return nil
}

// IsNorm 该张量是否为仿射参数（走 NormParams 而非 TensorWeights）。
func (k TensorKey) IsNorm() bool {
	return normTensorSet[k.Tensor]
}

// String 人类可读表示 "<tensor>@<block>"。
func (k TensorKey) String() string {
	return fmt.Sprintf("%s@%d", k.Tensor, k.Block)
}

// WeightRef 一行输入的**线性溯源**（解 G12 的关键字段）。
//
// 语义：第 i 步的第 row 行输入不是凭空来的，它是「某个源步的输出」被线性算子（可选）
// 施加后送进不可信加速器做了一次 CipherLinear 的结果：
//
//	V_row = ToMaskDomain(W · x_src) + W · ρ_src   (mod R)
//
// 要把这一行还原成明文，服务端必须同时知道：
//   - 产出 x_src 的那一步的坐标 ⇒ 其掩码 ρ_src（由 InSrc 重派生，不需存储）
//   - 施加于该行的线性权重 W ⇒ InWeight
//
// 于是 masked image = MaskImage(W, ρ_src)，Unmask(V_row, image) 即得结果。
type WeightRef struct {
	// Applied 该行是否真的经过了线性算子。
	// false 表示「直通」：残差分支、归一化输入、客户端注入行。
	// 此时该行携带的掩码就是 ρ_src 本身，不存在线性搬运项，故 Key 无意义。
	// 这条分支最容易写错：直通行若误去算 MaskImage，会得到一个无意义的掩码像，
	// 脱掩码结果是乱码且**层序校验全绿**（§2.2 G12 / R2）。
	Applied bool
	// Key Applied=true 时的权重身份。
	Key TensorKey
}

// RefKey 构造一条「经过线性算子」的溯源记录。
func RefKey(k TensorKey) WeightRef {
	return WeightRef{Applied: true, Key: k}
}

// NoWeight 构造一条「直通」溯源记录（无线性搬运项，掩码恒等于源步掩码）。
func NoWeight() WeightRef {
	return WeightRef{Applied: false, Key: TensorKey{}}
}

// String 人类可读表示（仅日志/审计用）。
func (w WeightRef) String() string {
	if !w.Applied {
		return "直通(nil)"
	}
	return w.Key.String()
}

// ---------- 步规格 ----------

// CoordRef 指向 Plan 下标的引用。-1 表示「客户端第 0 步注入」（Portal 入口）。
type CoordRef = int

// SrcInject InSrc 的下标哨兵：该行来自客户端注入，掩码域为 InjectDomain(Stage, Turn)。
const SrcInject CoordRef = -1

// 合法 op 名（§7.1 白名单；plan 内出现的一律在此列）。
const (
	OpRMSNorm     = "rmsnorm"
	OpGELU        = "gelu"
	OpLinear      = "linear" // 投影步的占位非线性：脱掩码后原样透传（SwiGLU 的 up/gate 投影用）
	OpArgMax      = "argmax"
	OpKVAppendK   = "kv_append_k"
	OpKVAppendV   = "kv_append_v"
	OpAttention   = "attention"
	OpResidualAdd = "residual_add"
	OpSwiGLUMul   = "swiglu_mul" // 逐元素 silu(gate) ⊙ up（SwiGLU 门控，arity=2）
	// OpKVReset 会话级 KV 复位。它是**带外 op**（走同一 HTTP 端点但不占 plan 下标，
	// 见 D10），故不得出现在任何 StepSpec.Op 中，Plan.Validate() 会据此拒绝。
	OpKVReset = "kv_reset"
)

// opArity plan 内合法 op 的输入行数（键 -> 行数）。
// OpKVReset 刻意不在表内：它不是 plan 步。
var opArity = map[string]int{
	OpRMSNorm:     1,
	OpGELU:        1,
	OpLinear:      1,
	OpArgMax:      1,
	OpKVAppendK:   1,
	OpKVAppendV:   1,
	OpAttention:   1,
	OpResidualAdd: 2,
	OpSwiGLUMul:   2,
}

// ValidOp op 是否属于 plan 内合法 op（OpKVReset 返回 false）。
func ValidOp(op string) bool {
	_, ok := opArity[op]
	return ok
}

// StepSpec plan 中的一步。
//
// 【最重要的不变式 · 掩码域归属】plan[i] 的输出被 ρ_i 掩盖，而
//
//	ρ_i 的域 == plan[i].Coord.MaskDomain()
//
// 由**产出步自己 own**。旧实现「第 L+1 层的域给第 L 层的输出重掩码」整整差一位
// （recompute.go:168/175），移植时必须整体翻转。见 StepSpec.MaskDomain()。
//
// 【第二个不变式 · 逐行溯源】InSrc / InDim / InWeight 三个切片**同长且按下标对齐**：
// 第 row 行的 (来源步, 行维度, 线性溯源) 分别是 InSrc[row] / InDim[row] / InWeight[row]。
// 扇入步（residual_add）的两行来源不同 ⇒ 两行的 ρ_src 不同 ⇒ 必须逐行分别脱掩码，
// 绝不能「默认两行共用同一个掩码」（这是 G12/R2 的正解）。
type StepSpec struct {
	// Seq plan 下标，恒等于该 StepSpec 在 Plan 中的位置（冗余字段，便于日志与响应回显）。
	Seq int
	// Coord 该步坐标：既是服务端正序校验的键（§2.5.4），也唯一决定本步输出掩码的域。
	Coord LayerCoord
	// Op 算子名，取值见 OpRMSNorm..OpResidualAdd。
	Op string
	// InDim 各输入行的维度，按行序。
	InDim []int
	// InSrc 各输入行的产出坐标（plan 下标；SrcInject 表示客户端注入）。
	InSrc []int
	// InWeight 各输入行的线性溯源，决定脱掩码时要不要用 MaskImage 以及用哪张 W。
	InWeight []WeightRef
	// OutDim 输出行维度。0 表示该步**不产出张量**（kv_append_* 的产出直接落 KV cache）。
	OutDim int
	// Writes 是否写 KV cache（仅 kv_append_k / kv_append_v 为真）。
	Writes bool
	// Reads 是否读 KV cache（仅 attention 为真）。
	Reads bool
	// Terminal 终止步（argmax）：输出为 token，明文下行，不再重掩码（D12 注明下行未加密）。
	Terminal bool
}

// MaskDomain 返回覆盖本步**输出**的掩码域。
//
// 【R5 哨位 · 反复强调】这是「产出步 own 输出掩码」的唯一正确入口：任何需要为某步
// 输出生成/重派生掩码的地方都必须走本方法（或等价的 Coord.MaskDomain()），
// 绝不能用 plan[i+1] 的坐标去派生 plan[i] 的输出掩码。
func (s StepSpec) MaskDomain() string {
	return s.Coord.MaskDomain()
}

// String 人类可读一行摘要（仅日志/审计用）。
func (s StepSpec) String() string {
	return fmt.Sprintf("#%d %s op=%s in=%v src=%v w=%v out=%d%s%s",
		s.Seq, s.Coord.String(), s.Op, s.InDim, s.InSrc, s.InWeight, s.OutDim,
		flagStr(s.Writes, " W"), flagStr(s.Terminal, " T"))
}

// Plan 确定性执行序列。== []StepSpec，下标即 Seq，次序即因果次序。
//
// 设计约束：本类型为纯切片，不携带 ModelConfig（以免打破 §2.4.2 的签名）；
// 需要 cfg 的调用方请自行持有——cfg 决定 plan 的形态，plan 不反向记住 cfg。
type Plan []StepSpec

// 每 block 的 plan 条目数（注意：6 个 Step 槽位 ≠ 8 条条目，
// 差在 StepKVAppend 有 K/V/Q 三条 Branch，见 coord.go 的 Step 注释）。
const StepsPerBlock = 8

// TailSteps 收尾条目数：ln_final + argmax（设计 §3.3 的序 13 与序 15）。
const TailSteps = 2

// 每 block 内各条目的相对偏移（GELU 布局；与 Step 枚举值不同，差在 StepKVAppend 的三分支）。
const (
	offAttnNorm    = 0 // StepAttnNorm
	offKVAppendK   = 1 // StepKVAppend + BranchK
	offKVAppendV   = 2 // StepKVAppend + BranchV
	offAttention   = 3 // StepKVAppend + BranchQ
	offAttnRes     = 4 // StepAttnResidual
	offFFNNorm     = 5 // StepFFNNorm
	offFFNUp       = 6 // StepFFNUp
	offFFNResidual = 7 // StepFFNResidual
)

// SwiGLU 布局的 block 内相对偏移（仅 FFNType=swiglu 时使用，条目数 = 10）。
// 前 6 条（attn_norm→ffn_norm）与 GELU 布局完全共用；FFN 尾段改为
// up(StepFFNUp/BranchMain) → gate(StepFFNUp/BranchV) → swiglu_mul(StepFFNResidual/BranchV)
// → down(StepFFNResidual/BranchQ)，其 Wire 次序 04b0<04b1<05b1<05b2 严格递增（见 §2.5.1）。
const (
	offSwiGLUGate     = 7 // StepFFNUp + BranchV
	offSwiGLUMul      = 8 // StepFFNResidual + BranchV
	offSwiGLUResidual = 9 // StepFFNResidual + BranchQ
	// StepsPerBlockSwiGLU SwiGLU 布局每 block 条目数。
	StepsPerBlockSwiGLU = 10
)

// stepsPerBlock 按 FFNType 返回每 block 的 plan 条目数（GELU=8 / SwiGLU=10）。
func stepsPerBlock(cfg ModelConfig) int {
	if cfg.FFNType == FFNTypeSwiGLU {
		return StepsPerBlockSwiGLU
	}
	return StepsPerBlock
}

// PlanLen plan 总条目数 == Blocks*StepsPerBlock + TailSteps。
// 为向后兼容既有调用点（plan_test / route2ref），cfg 省略时按 GELU 布局（8）计算；
// SwiGLU 配置须显式传 cfg 以取得 10 步布局。
func PlanLen(blocks int, cfg ...ModelConfig) int {
	spb := StepsPerBlock
	if len(cfg) > 0 {
		spb = stepsPerBlock(cfg[0])
	}
	return blocks*spb + TailSteps
}

// BlockBase 第 b 个 block 的首条目下标。cfg 省略时按 GELU 布局。
func BlockBase(b int, cfg ...ModelConfig) int {
	spb := StepsPerBlock
	if len(cfg) > 0 {
		spb = stepsPerBlock(cfg[0])
	}
	return b * spb
}

// ---------- 构建 ----------

// Build 生成 **prefill 阶段**（Stage=StagePrefill, Turn=0）的完整 plan。
//
// 这是客户端与服务端唯一的步序真值源：两端各调一次，得到的 Plan 必须逐字段相等
// （有单测强制），否则物理量（行维度、掩码域）必错。
func Build(cfg ModelConfig) (Plan, error) {
	return BuildTurn(cfg, StagePrefill, 0)
}

// BuildTurn 生成指定阶段/轮次的 plan。
//
// Stage/Turn 的取值约束（fail-closed，偏离即拒）：
//   - prefill：Stage=1 且 Turn 恒 0（设计 §2.5.5）；
//   - decode ：Stage=2 且 Turn >= 1（Turn=0 被 prefill 独占，防止同一 ρ 被两阶段复用）。
//
// 之所以**每个 turn 一份 plan**而非「一份 plan 覆盖全部 turn」：Turn 进入坐标 →
// 进入 Wire → 进入掩码域；一轮一份才能让「第 k 轮的第 i 步」有独立的 ρ，
// 服务端推进 pos 时也能逐字段比对自己的 plan[pos].Coord。
func BuildTurn(cfg ModelConfig, stage Stage, turn uint32) (Plan, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("route2plan: 模型配置非法: %w", err)
	}
	if !stage.Valid() {
		return nil, fmt.Errorf("route2plan: Stage=%d 非法（%d=prefill / %d=decode）",
			uint8(stage), uint8(StagePrefill), uint8(StageDecode))
	}
	if turn > MaxTurn {
		return nil, fmt.Errorf("route2plan: Turn=%d 超出 Wire 定宽上限 %d", turn, MaxTurn)
	}
	if stage == StagePrefill && turn != 0 {
		return nil, errors.New("route2plan: prefill 阶段的 Turn 必须为 0")
	}
	if stage == StageDecode && turn == 0 {
		return nil, errors.New("route2plan: decode 阶段的 Turn 必须 >= 1（Turn=0 由 prefill 独占）")
	}
	tailBlock := uint16(cfg.Blocks) // 收尾步的哨兵块号；cfg.Blocks <= MaxBlock-1 已由 Validate 保证
	attnDim := cfg.AttnDim()        // 多头拼接宽度（真实 Qwen3 下 != Dim，由 Wo 回映）

	p := make(Plan, 0, PlanLen(cfg.Blocks, cfg))
	// emit 追加一步；Seq 由下标自动写入，杜绝手抄下标错位。
	emit := func(c LayerCoord, op string, inDim, inSrc []int, inW []WeightRef, outDim int, writes, reads, terminal bool) {
		p = append(p, StepSpec{
			Seq:      len(p),
			Coord:    c,
			Op:       op,
			InDim:    inDim,
			InSrc:    inSrc,
			InWeight: inW,
			OutDim:   outDim,
			Writes:   writes,
			Reads:    reads,
			Terminal: terminal,
		})
	}
	// coord 构造闭包：Block/Step/Branch 之外的三个字段在本次 Build 中恒定。
	coordOf := func(block uint16, step Step, branch Branch) LayerCoord {
		return LayerCoord{Stage: stage, Turn: turn, Block: block, Step: step, Branch: branch, Chunk: 0}
	}

	for b := 0; b < cfg.Blocks; b++ {
		blk := uint16(b)
		base := BlockBase(b, cfg)
		// 本布局下「block 末步」偏移：GELU=offFFNResidual(7)，SwiGLU=offSwiGLUResidual(9)。
		// 它产出流向下一块的残差流 h，故作为下一块 attn_norm 的直通来源。
		lastOff := offFFNResidual
		if cfg.FFNType == FFNTypeSwiGLU {
			lastOff = offSwiGLUResidual
		}
		// 残差直通来源：第 0 块来自客户端注入；其余来自上一块的末步输出。
		// （注意是「上一块的最后一条」，不是「本块任何一步」，写错就会自引用成环。）
		residualSrc := SrcInject
		if b > 0 {
			residualSrc = BlockBase(b-1, cfg) + lastOff
		}

		// (0) attn_norm：RMSNorm(h) -> V_hn，掩码 ρ_{base+0}。
		emit(coordOf(blk, StepAttnNorm, BranchMain), OpRMSNorm,
			[]int{cfg.Dim}, []int{residualSrc}, []WeightRef{NoWeight()},
			cfg.Dim, false, false, false)

		// (1) kv_append_k：K̂ = Wk·V_hn -> 脱掩码->RoPE->写 KV。不产出张量（OutDim=0）。
		// 输入宽 == KVDim（KVHeads*HeadDim）：GQA 下 K/V 投影输出宽度是 KVDim，而非 attnDim
		// （仅 Q 与注意力原始输出为 attnDim，经 Wo 映回 Dim）；MHA 时 KVDim==attnDim 退化一致。
		emit(coordOf(blk, StepKVAppend, BranchK), OpKVAppendK,
			[]int{cfg.KVDim()}, []int{base + offAttnNorm},
			[]WeightRef{RefKey(TensorKey{Block: b, Tensor: TensorAttnK})},
			0, true, false, false)

		// (2) kv_append_v：V̂ = Wv·V_hn（V 不做 RoPE，见 D8）。输入宽同 KVDim。
		emit(coordOf(blk, StepKVAppend, BranchV), OpKVAppendV,
			[]int{cfg.KVDim()}, []int{base + offAttnNorm},
			[]WeightRef{RefKey(TensorKey{Block: b, Tensor: TensorAttnV})},
			0, true, false, false)

		// (3) attention：Q̂ = Wq·V_hn -> 全注意核（可信域明文，D1）-> V_ao（宽 attnDim）。
		// 注意输出宽 == attnDim（Heads*HeadDim），而非 Dim：注意力原始拼接输出是多头宽，
		// 由下一步 Wo([Dim, attnDim]) 映回 Dim 后才汇入残差流（Qwen3 attnDim≠Dim 亦成立）。
		emit(coordOf(blk, StepKVAppend, BranchQ), OpAttention,
			[]int{attnDim}, []int{base + offAttnNorm},
			[]WeightRef{RefKey(TensorKey{Block: b, Tensor: TensorAttnQ})},
			attnDim, false, true, false)

		// (4) attn_residual：两行扇入——Ao（经 Wo，宽 attnDim→Dim）与 h（直通，宽 Dim）。
		// 第一输入宽度须 == attnDim（即上一步 attention 的输出宽），Wo 将其映回 Dim；
		// 第二输入为残差 h（宽 Dim）。两条掩码不同（G12/R2）。
		emit(coordOf(blk, StepAttnResidual, BranchMain), OpResidualAdd,
			[]int{attnDim, cfg.Dim}, []int{base + offAttention, residualSrc},
			[]WeightRef{RefKey(TensorKey{Block: b, Tensor: TensorAttnO}), NoWeight()},
			cfg.Dim, false, false, false)

		// (5) ffn_norm：RMSNorm(h₂) -> V_hn2。输入是本块 (4) 的输出，无 Linear 搬运。
		emit(coordOf(blk, StepFFNNorm, BranchMain), OpRMSNorm,
			[]int{cfg.Dim}, []int{base + offAttnRes}, []WeightRef{NoWeight()},
			cfg.Dim, false, false, false)

		// (6)/(7)/(9) FFN 段：按 FFNType 分两条布局，二者前 6 条（attn_norm→ffn_norm）完全共用。
		if cfg.FFNType == FFNTypeSwiGLU {
			// SwiGLU：up(线性) → gate(线性) → silu(gate)⊙up → down(残差加)，共 4 条。
			// up：Wup·V_hn2 -> 脱掩码后原样透传（OpLinear 占位非线性），宽 FFNDim。
			emit(coordOf(blk, StepFFNUp, BranchMain), OpLinear,
				[]int{cfg.FFNDim}, []int{base + offFFNNorm},
				[]WeightRef{RefKey(TensorKey{Block: b, Tensor: TensorFFNUp})},
				cfg.FFNDim, false, false, false)

			// gate：Wgate·V_hn2 -> 脱掩码后原样透传，宽 FFNDim。
			emit(coordOf(blk, StepFFNUp, BranchV), OpLinear,
				[]int{cfg.FFNDim}, []int{base + offFFNNorm},
				[]WeightRef{RefKey(TensorKey{Block: b, Tensor: TensorGate})},
				cfg.FFNDim, false, false, false)

			// swiglu_mul：逐元素 silu(gate) ⊙ up，宽 FFNDim。两行均直通（无线性搬运项）。
			emit(coordOf(blk, StepFFNResidual, BranchV), OpSwiGLUMul,
				[]int{cfg.FFNDim, cfg.FFNDim}, []int{base + offFFNUp, base + offSwiGLUGate},
				[]WeightRef{NoWeight(), NoWeight()},
				cfg.FFNDim, false, false, false)

			// down：Down（经 Wdown）与 h₂（= 本块 attn_residual 输出，直通）相加 -> h_{b+1}。
			emit(coordOf(blk, StepFFNResidual, BranchQ), OpResidualAdd,
				[]int{cfg.Dim, cfg.Dim}, []int{base + offSwiGLUMul, base + offAttnRes},
				[]WeightRef{RefKey(TensorKey{Block: b, Tensor: TensorFFNDown}), NoWeight()},
				cfg.Dim, false, false, false)
		} else {
			// GELU（默认，§7.9 既有布局，零变化）：up(GELU) → down(残差加)，共 2 条。
			// (6) ffn_up：Up = Wup·V_hn2 + b_up -> GELU -> V_f1，宽 FFNDim。
			emit(coordOf(blk, StepFFNUp, BranchMain), OpGELU,
				[]int{cfg.FFNDim}, []int{base + offFFNNorm},
				[]WeightRef{RefKey(TensorKey{Block: b, Tensor: TensorFFNUp})},
				cfg.FFNDim, false, false, false)

			// (7) ffn_residual：Down（经 Wdown）与 h₂（= 本块 (4) 的输出，直通）相加 -> h_{b+1}。
			emit(coordOf(blk, StepFFNResidual, BranchMain), OpResidualAdd,
				[]int{cfg.Dim, cfg.Dim}, []int{base + offFFNUp, base + offAttnRes},
				[]WeightRef{RefKey(TensorKey{Block: b, Tensor: TensorFFNDown}), NoWeight()},
				cfg.Dim, false, false, false)
		}
	}

	// ---- 收尾：ln_final + argmax（设计 §3.3）----
	// 取「最后一个 block 的末步输出」作为 ln_final 的输入（GELU=offFFNResidual / SwiGLU=offSwiGLUResidual）。
	lastOff := offFFNResidual
	if cfg.FFNType == FFNTypeSwiGLU {
		lastOff = offSwiGLUResidual
	}
	lastBlockResidual := BlockBase(cfg.Blocks-1, cfg) + lastOff
	// ln_final：RMSNorm(h_{B}) -> V_final，掩码 ρ_{B*8}。InWeight=nil（无线性搬运）。
	finalIdx := BlockBase(cfg.Blocks, cfg)
	emit(coordOf(tailBlock, StepFinalNorm, BranchMain), OpRMSNorm,
		[]int{cfg.Dim}, []int{lastBlockResidual}, []WeightRef{NoWeight()},
		cfg.Dim, false, false, false)

	// argmax：logits = Wlm_head·V_final + b_lm（加速器完成）-> 脱掩码 -> ArgMax -> token。
	emit(coordOf(tailBlock, StepArgMax, BranchMain), OpArgMax,
		[]int{cfg.Vocab}, []int{finalIdx},
		[]WeightRef{RefKey(TensorKey{Block: cfg.Blocks, Tensor: TensorLMHead})},
		1, false, false, true)

	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// ---------- 取值 ----------

// Len plan 条目数。
func (p Plan) Len() int {
	return len(p)
}

// At 取第 seq 步；越界即 error（fail-closed，不返回零值让它流向脱掩码）。
func (p Plan) At(seq int) (StepSpec, error) {
	if seq < 0 || seq >= len(p) {
		return StepSpec{}, fmt.Errorf("route2plan: plan 下标 %d 越界（len=%d）", seq, len(p))
	}
	return p[seq], nil
}

// CoordAt 取第 seq 步的坐标（T03 校验 req.Coord == plan[pos].Coord 用）。
func (p Plan) CoordAt(seq int) (LayerCoord, error) {
	s, err := p.At(seq)
	if err != nil {
		return LayerCoord{}, err
	}
	return s.Coord, nil
}

// NextCoord 取第 seq 步之后的下一步坐标；已到末步返回 ok=false。
// 服务端用它生成响应里的 next_coord / mask_next（HMAC 的输入必须是这条指纹）。
func (p Plan) NextCoord(seq int) (LayerCoord, bool) {
	if seq+1 >= len(p) {
		return LayerCoord{}, false
	}
	return p[seq+1].Coord, true
}

// IndexOf 按坐标反查 plan 下标（找不到即 error）。
//
// 前置条件：plan 必须已通过 Validate()（坐标 Wire 严格递增），本函数据此二分查找。
func (p Plan) IndexOf(c LayerCoord) (int, error) {
	w := c.Wire()
	i := sort.Search(len(p), func(i int) bool { return p[i].Coord.Wire() >= w })
	if i < len(p) && p[i].Coord.Wire() == w {
		return i, nil
	}
	return -1, fmt.Errorf("route2plan: 坐标 %s 不在 plan 内", w)
}

// Stage plan 所属阶段（plan 为空时返回 StageUnset）。
func (p Plan) Stage() Stage {
	if len(p) == 0 {
		return StageUnset
	}
	return p[0].Coord.Stage
}

// Turn plan 所属轮次（plan 为空时返回 0）。
func (p Plan) Turn() uint32 {
	if len(p) == 0 {
		return 0
	}
	return p[0].Coord.Turn
}

// Blocks 反推 plan 覆盖的 block 数（兼容 GELU=8 / SwiGLU=10 两种 block 布局）。
func (p Plan) Blocks() (int, error) {
	if len(p) < StepsPerBlock+TailSteps {
		return 0, fmt.Errorf("route2plan: plan 长度 %d 过短，不足一个 block+收尾所需 %d",
			len(p), StepsPerBlock+TailSteps)
	}
	n := len(p) - TailSteps
	// 优先 SwiGLU(10) 整除，回退 GELU(8)；两者皆不整除即形态非法。
	if n%StepsPerBlockSwiGLU == 0 {
		return n / StepsPerBlockSwiGLU, nil
	}
	if n%StepsPerBlock == 0 {
		return n / StepsPerBlock, nil
	}
	return 0, fmt.Errorf("route2plan: plan 长度 %d 不满足 Blocks*%d+%d 或 Blocks*%d+%d 形态",
		len(p), StepsPerBlockSwiGLU, TailSteps, StepsPerBlock, TailSteps)
}

// SrcMaskDomain 返回第 seq 步第 row 行输入所携带的掩码域。
//
// 这是「 fan-in 时两行掩码不同、且都能纯靠坐标重派生而不需存储」的具体实现
// （设计 G12 / R2）：
//   - InSrc[row] >= 0         → 取 plan[InSrc[row]].MaskDomain()（产出步 own 自己的 ρ）
//   - InSrc[row] == SrcInject → 取 InjectDomain(Stage, Turn)
//
// 服务端绝不得信任客户端提交的掩码种子；ρ 一律由本函数 + 会话密钥重派生。
func (p Plan) SrcMaskDomain(seq, row int) (string, error) {
	s, err := p.At(seq)
	if err != nil {
		return "", err
	}
	if row < 0 || row >= len(s.InSrc) {
		return "", fmt.Errorf("route2plan: step#%d 只有 %d 行输入，行下标 %d 越界", seq, len(s.InSrc), row)
	}
	ref := s.InSrc[row]
	if ref == SrcInject {
		return InjectDomain(s.Coord.Stage, s.Coord.Turn)
	}
	if ref < 0 || ref >= len(p) {
		return "", fmt.Errorf("route2plan: step#%d 行 %d 的 InSrc=%d 越界", seq, row, ref)
	}
	if ref >= seq {
		return "", fmt.Errorf("route2plan: step#%d 行 %d 的 InSrc=%d 为前向引用/自引用（无环性被破坏）",
			seq, row, ref)
	}
	// 【R5】产出步 own 自己的输出掩码：ρ_src 的域就是源步自己的坐标域。
	return p[ref].MaskDomain(), nil
}

// ---------- 合法性校验 ----------

// Validate 对 plan 做结构自检。BuildTurn 在返回前会调用它；测试与被篡改的数据
// 也可单独调用。fail-closed：任何不满足即返回显式 error。
//
// 检查项：
//  1. 下标自洽（Seq == 位置）、坐标取值域合法；
//  2. InSrc / InDim / InWeight 三者同长且等于 op 规定行数；
//  3. InSrc 只能指向合法的前驱步（>=0 时必须 < 当前下标 ⇒ 无环、无前向引用、无越界）；
//  4. 坐标按 Wire 严格递增 ⇒ 字典序 == 时序 == 下标序，且**坐标互不相同**（掩码唯一性 B4 的前提）；
//  5. Writes/Reads 与 op 语义一致（只有 kv_append_* 写、只有 attention 读）；
//  6. Terminal 唯一且必须位于末步，其 op 必须是 argmax；
//  7. 首步必须以客户端注入为输入（Portal 入口）；
//  8. op 必须是 plan 内 op（kv_reset 属带外 op，不得入 plan）。
func (p Plan) Validate() error {
	if len(p) == 0 {
		return errors.New("route2plan: 空 plan")
	}
	for i := range p {
		s := &p[i]
		if s.Seq != i {
			return fmt.Errorf("route2plan: step#%d 的 Seq=%d 与位置不一致", i, s.Seq)
		}
		if err := s.Coord.Validate(); err != nil {
			return fmt.Errorf("route2plan: step#%d 坐标非法: %w", i, err)
		}
		arity, ok := opArity[s.Op]
		if !ok {
			return fmt.Errorf("route2plan: step#%d 的 op=%q 非法（%q 是带外 op，不得进入 plan）",
				i, s.Op, OpKVReset)
		}
		if len(s.InSrc) != arity || len(s.InDim) != arity || len(s.InWeight) != arity {
			return fmt.Errorf("route2plan: step#%d(op=%s) 的行数不一致 InSrc=%d InDim=%d InWeight=%d，应均为 %d",
				i, s.Op, len(s.InSrc), len(s.InDim), len(s.InWeight), arity)
		}
		if s.OutDim < 0 {
			return fmt.Errorf("route2plan: step#%d 的 OutDim=%d 不可为负", i, s.OutDim)
		}
		for row := 0; row < arity; row++ {
			if s.InDim[row] <= 0 {
				return fmt.Errorf("route2plan: step#%d 行 %d 的 InDim=%d 非正", i, row, s.InDim[row])
			}
			ref := s.InSrc[row]
			if ref == SrcInject {
				continue
			}
			if ref < 0 || ref >= len(p) {
				return fmt.Errorf("route2plan: step#%d 行 %d 的 InSrc=%d 越界（len=%d）", i, row, ref, len(p))
			}
			if ref >= i {
				return fmt.Errorf("route2plan: step#%d 行 %d 的 InSrc=%d 为前向引用/自引用（无环性被破坏）",
					i, row, ref)
			}
			if s.InWeight[row].Applied {
				if err := s.InWeight[row].Key.Validate(); err != nil {
					return fmt.Errorf("route2plan: step#%d 行 %d 的权重 key 非法: %w", i, row, err)
				}
			}
		}
		// Writes/Reads 语义一致性
		isKVAppend := s.Op == OpKVAppendK || s.Op == OpKVAppendV
		if s.Writes != isKVAppend {
			return fmt.Errorf("route2plan: step#%d(op=%s) 的 Writes=%v 与 op 语义不符", i, s.Op, s.Writes)
		}
		if s.Reads != (s.Op == OpAttention) {
			return fmt.Errorf("route2plan: step#%d(op=%s) 的 Reads=%v 与 op 语义不符", i, s.Op, s.Reads)
		}
		if isKVAppend && s.OutDim != 0 {
			return fmt.Errorf("route2plan: step#%d(op=%s) 写 KV 不应产出张量，OutDim=%d 应为 0", i, s.Op, s.OutDim)
		}
		if s.Op == OpAttention && s.OutDim <= 0 {
			return fmt.Errorf("route2plan: step#%d(attention) 必须产出注意力结果，OutDim=%d 非正", i, s.OutDim)
		}
		// 坐标严格递增（⇒ 坐标互不相同 ⇒ 掩码域互不相同）
		if i > 0 {
			prev, cur := p[i-1].Coord.Wire(), s.Coord.Wire()
			if !(prev < cur) {
				return fmt.Errorf("route2plan: step#%d 的坐标 %s 未严格大于前驱 %s（字典序==时序 被破坏）",
					i, cur, prev)
			}
		}
	}
	// Terminal 唯一且在末步
	last := len(p) - 1
	for i := range p {
		if p[i].Terminal && i != last {
			return fmt.Errorf("route2plan: step#%d 是 Terminal 但不在末步 %d", i, last)
		}
	}
	if !p[last].Terminal {
		return fmt.Errorf("route2plan: 末步 #%d 必须是 Terminal（argmax）", last)
	}
	if p[last].Op != OpArgMax {
		return fmt.Errorf("route2plan: 末步 #%d 的 op=%q 应为 %q", last, p[last].Op, OpArgMax)
	}
	// Portal：首步必须以客户端注入为输入
	found := false
	for _, ref := range p[0].InSrc {
		if ref == SrcInject {
			found = true
			break
		}
	}
	if !found {
		return errors.New("route2plan: 首步必须含客户端注入（SrcInject）行，否则 plan 没有 Portal 入口")
	}
	return nil
}

// flagStr String() 的小辅助：cond 为真时返回 tail，否则返回空串。
func flagStr(cond bool, tail string) string {
	if cond {
		return tail
	}
	return ""
}
