// Package route2plan 路线 2 · M2 的「层坐标系 + plan 真值源」。
//
// 本包是整个 M2 的**公共契约**：客户端编排器（cmd/route2-client）与可信域服务端
// （gateway/tee-infer-service）一律依赖本包派生各自的行为，二者不再各自维护一份
// 层序假设（消灭设计 §2.2 的 G9）。T02/T03/T04 均建立在以下三条硬规则之上：
//
// 规则 1（字段次序 ≡ 因果次序）：坐标六元组
//
//	(Stage, Turn, Block, Step, Branch, Chunk)
//
// 逐级嵌套且与物理执行顺序完全一致；配合 Wire() 的**定宽补零**，
// Wire() 输出的字典序即全局时序次序（sort 一下就是时间线）。
//
// 规则 2（坐标唯一 ⇒ 掩码唯一）：掩码域名唯一地由产出坐标派生
//
//	otpmask/step/<wire>/v2
//
// 坐标互不相同 ⇒ 掩码流互不相同 ⇒ 杜绝两步共用同一个 r（§2.2 G3）。
// 这是一条**安全性**要求而非整洁性要求：攻击者一旦见到同一个 r 掩盖的两个不同
// 明文，即可直接求出二者差值（§0.4）。
//
// 规则 3（服务端为权威）：plan 是 Build(cfg) 的确定性产物，两端同包共享；
// 客户端只能请求 plan[pos]，不得提交任何解释性状态（pos / mask_seed /
// cache_len 一律服务端自持）。
//
// 【掩码域归属 · R5 哨位】新约定下，**掩码域由产出步自己 own**：
//
//	ρ_i 的域 == plan[i].Coord.MaskDomain()
//
// 即「第 i 步的输出」被第 i 步自己的坐标所派生的掩码覆盖。
// 旧代码 gateway/tee-infer-service/recompute.go:168/175 用的是
// 「第 L+1 层的域给第 L 层的输出重掩码」——**整整差一位**，两者语义相反。
// 移植旧代码到本包时必须先读本段注释，不得沿用旧的 off-by-one 约定。
//
// 依赖纪律：本包只允许依赖标准库（禁止 maskedinfer / route2demo 等反向依赖），
// 以保证服务端、客户端、测试三方都能零成本引用同一份坐标定义。
package route2plan

import (
	"fmt"
	"strconv"
	"strings"
)

// ---------- Wire 规范串常量 ----------

// WireVersion Wire 规范串的版本前缀。
// 设计 §2.5.2 方案 B（硬切换 + 版本门禁）裁定：只认 v2；缺 coord 或 proto!=2 的旧
// 客户端一律以独立审计码拒绝，不与既有 recompute_layer_mismatch 混淆。
const WireVersion = "v2"

// MaskDomainPrefix / MaskDomainSuffix 掩码域名三段式：otpmask/step/<wire>/v2。
const (
	MaskDomainPrefix = "otpmask/step/"
	MaskDomainSuffix = "/v2"
)

// InjectDomainPrefix 客户端第 0 步注入掩码的域前缀（§3.1 记号 ρ_inj）。
//
// 【实现裁定 · 需团队确认】设计 §3.1 把注入域写成不带参数的 otpmask/inject/v2，
// 但 §4 的 d0 又写作 ρ_inj(turn=k)——二者不自洽：若 prefill 与全部 decode 轮共用
// 一个注入域，则同一 ρ_inj 会被用来掩盖多个不同明文（不同轮的 token 嵌入），
// 直接违反 §0.4「一步一掩码、绝不重用」。
// 故本实现把 (Stage, Turn) 一并编入注入域，见 InjectDomain()。
const InjectDomainPrefix = "otpmask/inject/v2"

// wireFieldCount Wire 段数：版本前缀 1 段 + 定宽字段 6 段。
const wireFieldCount = 7

// wireFieldWidths 六个坐标字段在 Wire 中的**定宽位数**，次序 ≡ 字段因果次序：
// Stage(1) | Turn(6) | Block(4) | Step(2) | Branch(1) | Chunk(2)。
// 任何改动都会改变字典序语义，属 §9 明令禁止回头修改的坐标系定义。
var wireFieldWidths = [6]int{1, 6, 4, 2, 1, 2}

// 取值域上限（同时约束 Validate 与 Wire 的定宽不溢出）。
const (
	// MaxStageDigits 由 Stage 定宽 1 位推出，实际合法 Stage 只有 1/2。
	MaxTurn   uint32 = 999999
	MaxBlock  uint16 = 9999
	MaxStep   Step   = 63 // 设计 §2.4.1：Step 取值域 0..63
	MaxBranch Branch = 9  // 定宽 1 位 ⇒ 0..9
	MaxChunk  uint16 = 99 // 定宽 2 位 ⇒ 0..99
)

// ---------- Stage / Step / Branch 枚举 ----------

// Stage 推理阶段。prefill 与 decode 共用同一 HTTP 端点，靠本字段区分（§2.5.5）。
type Stage uint8

const (
	// StageUnset 零值非法（fail-closed：未显式赋值即零值的坐标必须被 Validate 拒绝）。
	StageUnset Stage = 0
	// StagePrefill 预填：一个 batch = 提示词的 T 个位置，Turn 恒 0。
	StagePrefill Stage = 1
	// StageDecode 逐 token 生成：一个 batch = 1 个新位置，Turn >= 1。
	StageDecode Stage = 2
)

// Valid 阶段是否合法。
func (s Stage) Valid() bool {
	return s == StagePrefill || s == StageDecode
}

// String 人类可读名（仅日志/审计用，不参与任何协议判定）。
func (s Stage) String() string {
	switch s {
	case StagePrefill:
		return "prefill"
	case StageDecode:
		return "decode"
	default:
		return fmt.Sprintf("stage(%d)", uint8(s))
	}
}

// Step 块内子步枚举。设计 §2.4.1 给出前 6 个（0..5），本实现追加 2 个收尾值。
//
// 【实现补充说明】6 个 Step 槽位无法完整表达 §3.2 的 8 条 plan 条目：
// kv_append_k / kv_append_v / attention 三者同属 StepKVAppend，靠 Branch
// （BranchK=0 / BranchV=1 / BranchQ=2）区分，Branch 的取值次序即因果次序。
// 故「1 block = 6 Step = 8 plan 条目」，见 plan.go 的 StepsPerBlock。
type Step uint8

const (
	// StepAttnNorm 注意力前的 RMSNorm（ln_in）。
	StepAttnNorm Step = iota // 00
	// StepKVAppend K/V 入 cache 与 Q 分支的 attention（三 Branch，见 Branch 注释）。
	StepKVAppend // 01
	// StepAttnResidual 注意力残差相加（扇入 2 行，G12 的扇入点之一）。
	StepAttnResidual // 02
	// StepFFNNorm FFN 前的 RMSNorm（ln_post）。
	StepFFNNorm // 03
	// StepFFNUp FFN 升维后的 GELU（D4：无门控 MLP FFN，SwiGLU 留后）。
	StepFFNUp // 04
	// StepFFNResidual FFN 残差相加（扇入 2 行），输出即下一 block 的输入 h。
	StepFFNResidual // 05

	// ---- 以下两项为设计 §2.4.1 未列出的收尾步，由 §3.3 的数据流倒逼补全 ----
	// 【实现裁定 · 需团队确认】
	// StepFinalNorm 收尾 RMSNorm（ln_final），Block 取哨兵值 cfg.Blocks。
	StepFinalNorm // 06
	// StepArgMax 收尾 argmax（lm_head 已由加速器完成投影），Block 取哨兵值 cfg.Blocks。
	StepArgMax // 07
)

// Valid 子步是否在 0..63 取值域内。
func (s Step) Valid() bool {
	return s <= MaxStep
}

// String 人类可读名（仅日志/审计用）。
func (s Step) String() string {
	switch s {
	case StepAttnNorm:
		return "attn_norm"
	case StepKVAppend:
		return "kv_append"
	case StepAttnResidual:
		return "attn_residual"
	case StepFFNNorm:
		return "ffn_norm"
	case StepFFNUp:
		return "ffn_up"
	case StepFFNResidual:
		return "ffn_residual"
	case StepFinalNorm:
		return "final_norm"
	case StepArgMax:
		return "argmax"
	default:
		return fmt.Sprintf("step(%d)", uint8(s))
	}
}

// Branch 同子步内的并行分支；取值次序 ≡ 因果次序，故 Wire 字典序天然正确。
type Branch uint8

const (
	// BranchMain 单输出步的统一占位（值取 0）。
	BranchMain Branch = 0
	// BranchK K 分支（= BranchMain，扇出步的第一条，最先执行）。
	BranchK Branch = 0
	// BranchV V 分支（V 不做 RoPE，见 D8）。
	BranchV Branch = 1
	// BranchQ Q 分支（attention），因果次序排在 K/V 追加之后。
	BranchQ Branch = 2
)

// String 人类可读名（仅日志/审计用）。
func (b Branch) String() string {
	switch b {
	case BranchMain:
		return "main"
	case BranchV:
		return "v"
	case BranchQ:
		return "q"
	default:
		return fmt.Sprintf("branch(%d)", uint8(b))
	}
}

// ---------- LayerCoord ----------

// LayerCoord 层坐标：取代旧代码里那个无法表达 block/子步/阶段的单一 int layer
// （消灭 G1）。
//
// 字段次序即因果次序：(Stage, Turn, Block, Step, Branch, Chunk) 逐级嵌套。
// 零值 LayerCoord{} 的 Stage 非法，任何使用点都必须先过 Validate()。
type LayerCoord struct {
	// Stage 预填 / 生成阶段。
	Stage Stage
	// Turn decode 生成轮次；prefill 恒 0，decode >= 1。
	Turn uint32
	// Block Transformer block 序号；收尾步（ln_final / argmax）取哨兵值 cfg.Blocks。
	Block uint16
	// Step 块内子步，取值域 0..63。
	Step Step
	// Branch 同子步并行分支，取值域 0..9。
	Branch Branch
	// Chunk 大 batch 分片序号（M2 预留，恒 0，见 D7）；取值域 0..99。
	Chunk uint16
}

// Wire 返回坐标的**定宽**规范串，同时被配置为字典序 == 时序次序：
//
//	格式：v2|<stage:1>|<turn:6>|<block:4>|<step:2>|<branch:1>|<chunk:2>
//	例：  v2|1|000000|0003|01|2|00
//
// 三个性质（全部有单测覆盖）：
//  1. 每个字段补零到固定宽度 ⇒ 同长度字符串逐字符比较 == 元组字典序比较；
//     分隔符 '|'(0x7C) > 数字字符集中不会出现，故各字段之间不会互相穿透。
//  2. 字符串总长恒定 ⇒ 不存在「12 排在 9 前面」这类未补零导致的次序反转。
//  3. 对本坐标集合而言，Wire 是单射 ⇒ 掩码域互不相同（规则 2）。
//
// 前置条件：坐标必须已通过 Validate()；越界值的 Wire 未定义（不保证定宽）。
// 需要 fail-closed 语义的调用方请先用 Validate() 或改用 ParseWire 的产物。
func (c LayerCoord) Wire() string {
	fields := [6]string{
		padLeft(uint64(c.Stage), wireFieldWidths[0]),
		padLeft(uint64(c.Turn), wireFieldWidths[1]),
		padLeft(uint64(c.Block), wireFieldWidths[2]),
		padLeft(uint64(c.Step), wireFieldWidths[3]),
		padLeft(uint64(c.Branch), wireFieldWidths[4]),
		padLeft(uint64(c.Chunk), wireFieldWidths[5]),
	}
	var b strings.Builder
	b.WriteString(WireVersion)
	for i := range fields {
		b.WriteByte('|')
		b.WriteString(fields[i])
	}
	return b.String()
}

// String 人类可读表示（仅日志/审计用）；协议面一律使用 Wire()。
func (c LayerCoord) String() string {
	return fmt.Sprintf("%s(%s,t=%d,b=%d,%s,%s,c=%d)",
		WireVersion, c.Stage, c.Turn, c.Block, c.Step, c.Branch, c.Chunk)
}

// MaskDomain 返回「掩盖本步输出」的掩码 ρ 的派生域：
//
//	otpmask/step/<wire>/v2
//
// 【掩码域归属 · R5】由**产出步自己 own**：plan[i].Coord.MaskDomain() 得到的域，
// 派生出的掩码就是「掩盖第 i 步输出」的那一条 ρ_i。
// 旧实现（recompute.go:168/175）用 layer+1 的域给 layer 的输出重掩码，差一位，
// 任何移植都不得沿用。
func (c LayerCoord) MaskDomain() string {
	return MaskDomainPrefix + c.Wire() + MaskDomainSuffix
}

// Validate 逐字段校验取值域（fail-closed：凡不合法一律 error，不做静默纠正）。
func (c LayerCoord) Validate() error {
	if !c.Stage.Valid() {
		return fmt.Errorf("route2plan: Stage=%d 非法（合法值：%d=%s / %d=%s）",
			uint8(c.Stage), uint8(StagePrefill), StagePrefill, uint8(StageDecode), StageDecode)
	}
	if c.Turn > MaxTurn {
		return fmt.Errorf("route2plan: Turn=%d 超出定宽上限 %d", c.Turn, MaxTurn)
	}
	if c.Block > MaxBlock {
		return fmt.Errorf("route2plan: Block=%d 超出定宽上限 %d", c.Block, MaxBlock)
	}
	if !c.Step.Valid() {
		return fmt.Errorf("route2plan: Step=%d 超出取值域 0..%d", uint8(c.Step), uint8(MaxStep))
	}
	if c.Branch > MaxBranch {
		return fmt.Errorf("route2plan: Branch=%d 超出定宽上限 %d", uint8(c.Branch), uint8(MaxBranch))
	}
	if c.Chunk > MaxChunk {
		return fmt.Errorf("route2plan: Chunk=%d 超出定宽上限 %d", c.Chunk, MaxChunk)
	}
	return nil
}

// InjectDomain 返回客户端第 0 步注入掩码 ρ_inj 的派生域。
//
// 之所以把 (Stage, Turn) 编入：若全部轮次共用一个注入域，则同一个 ρ_inj 会掩盖
// 多个不同明文（不同轮的 token 嵌入），违反 §0.4 的一步一掩码。
// 返回串示例：otpmask/inject/v2/2/000013。
func InjectDomain(stage Stage, turn uint32) (string, error) {
	if !stage.Valid() {
		return "", fmt.Errorf("route2plan: 注入域的 Stage=%d 非法", uint8(stage))
	}
	if turn > MaxTurn {
		return "", fmt.Errorf("route2plan: 注入域的 Turn=%d 超出定宽上限 %d", turn, MaxTurn)
	}
	return fmt.Sprintf("%s/%d/%s", InjectDomainPrefix, uint8(stage), padLeft(uint64(turn), wireFieldWidths[1])), nil
}

// ParseWire 解析 Wire() 的输出，**格式与取值域双校验**，任一不符即 error。
//
// 与 lenient 解析的区别：本函数①要求段数恰为 7；②要求每段长度恰等于定宽
// （拒绝 "1|0|0|0|0|0" 这类未补零的写法）；③要求每段全为 ASCII 数字；
// ④最后过一遍 Validate()。任何一项不过即拒绝，绝不静默纠正——因为
// 「坐标静默纠正」等价于「掩码域名静默错位」，是最坏的失败模式（§2.5.2）。
func ParseWire(s string) (LayerCoord, error) {
	parts := strings.Split(s, "|")
	if len(parts) != wireFieldCount {
		return LayerCoord{}, fmt.Errorf("route2plan: Wire %q 段数 %d != %d", s, len(parts), wireFieldCount)
	}
	if parts[0] != WireVersion {
		return LayerCoord{}, fmt.Errorf("route2plan: Wire %q 版本前缀 %q != %q（§2.5.2 硬切换，不接受 v1）",
			s, parts[0], WireVersion)
	}
	vals := make([]uint64, len(wireFieldWidths))
	for i, width := range wireFieldWidths {
		field := parts[i+1]
		if len(field) != width {
			return LayerCoord{}, fmt.Errorf("route2plan: Wire %q 第 %d 段 %q 宽度 %d != 定宽 %d",
				s, i+1, field, len(field), width)
		}
		for _, ch := range field {
			if ch < '0' || ch > '9' {
				return LayerCoord{}, fmt.Errorf("route2plan: Wire %q 第 %d 段 %q 含非数字字符 %q",
					s, i+1, field, string(ch))
			}
		}
		v, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return LayerCoord{}, fmt.Errorf("route2plan: Wire %q 第 %d 段解析失败: %w", s, i+1, err)
		}
		vals[i] = v
	}
	c := LayerCoord{
		Stage:  Stage(vals[0]),
		Turn:   uint32(vals[1]),
		Block:  uint16(vals[2]),
		Step:   Step(vals[3]),
		Branch: Branch(vals[4]),
		Chunk:  uint16(vals[5]),
	}
	if err := c.Validate(); err != nil {
		return LayerCoord{}, fmt.Errorf("route2plan: %w", err)
	}
	return c, nil
}

// CoordLess 按 Wire() 的字典序比较两个坐标。
// 由于 Wire 定宽且字段次序 == 因果次序，Less 即「是否更早发生」。
// 供调用方排序/优先队列使用（实现刻意不引入额外比较逻辑，避免与 Wire 语义分叉）。
func CoordLess(a, b LayerCoord) bool {
	return a.Wire() < b.Wire()
}

// padLeft 把无符号整数补零到定宽 width。
// 若位数已超过 width（只可能来自未通过 Validate 的越界坐标），原样返回——
// 调用方须先用 Validate() 兜住；此处不做静默截断，以免产出一个看起来合法的 Wire。
func padLeft(v uint64, width int) string {
	s := strconv.FormatUint(v, 10)
	if len(s) >= width {
		return s
	}
	return strings.Repeat("0", width-len(s)) + s
}
