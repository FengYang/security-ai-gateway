// kvcache.go - 路线2 的 KV cache（可信域明文驻留结构，清零是安全性质而非内存优化）
//
// 【本文件的三条硬前提（改动本文件前必读）】
//
//  1. KVCache.mu 是**最内层**锁。本文件禁止反向回调任何上层结构
//     （teeServer / recomputeStates / recomputeState），依赖严格单向，
//     以保证取锁次序无环；KVCache 也不持有任何上层句柄、不提供 K/V 外发能力。
//
//  2. Reset() / Release() 会**就地清零**行元素，因此它们必须与 Read* 在更外层
//     串行化。生产路径上调用方在调用本结构之前已持有 recomputeState.mu，
//     天然满足。若 QA 写「Read 与 Reset 并发」的用例并报 race，
//     那是用例违反了锁序约定，不是本结构的问题——按本条挡回，不要改本结构。
//
//  3. 锁序硬约束（禁止任何反向取锁）：
//
//     teeServer.mu → recomputeStates.mu → recomputeState.mu → KVCache.mu
package route2step

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/FengYang/masked-infer/plan"
)

// ---- 哨兵 error（上层据此映射 HTTP 码与审计码，故一律用可 errors.Is 判定的哨兵）----
var (
	// ErrKVCacheReleased cache 已释放。释放后任何操作一律 fail-closed 返回本错误，不 panic。
	ErrKVCacheReleased = errors.New("kvcache: 已释放")
	// ErrBlockOutOfRange block 号越界（须落在 0..Blocks-1）。
	ErrBlockOutOfRange = errors.New("kvcache: block 越界")
	// ErrVecLength 追加向量的长度不等于 Heads*HeadDim（== Dim）。
	ErrVecLength = errors.New("kvcache: 向量长度不等于 KVHeads*HeadDim（即 KVDim）")
	// ErrKVCacheFull 行数已达 cfg.MaxTokens 上限。
	ErrKVCacheFull = errors.New("kvcache: 行数已达 MaxTokens 上限")
	// ErrKVCacheBytesExceeded 字节占用已达 kvMaxBytes 上限。
	ErrKVCacheBytesExceeded = errors.New("kvcache: 字节占用已达上限")
	// ErrKVNotPaired kv_append_k 与 kv_append_v 未成对。
	// 这是最隐蔽的一类 bug：K/V 行数一旦错开一位，attention 会把第 t 个 Q 与第 t±1 个
	// K/V 对齐，层序校验与维度校验全绿，只有输出 token 是错的。故此处在**追加时**就拦。
	//
	// 成对的粒度是「run」而非「单行」：plan step-major 接入下，一个 kv_append_k 步
	// 一次携带全部 T 个位置（prefill 批量），必然是 T 行 K 连续到达、再由 kv_append_v
	// 步携 T 行 V 连续配对（FIFO 顺序逐行配对）。故语义为：**同一 block 内允许一段
	// K-run，随后必须紧跟等长、同 block 的 V-run**；以下形态一律 fail-closed：
	// 孤立 V（无待配对 K）、V 的 block 与 K-run 不一致、run 未配对完就推进 turn、
	// K-run 未闭合就换 block 追加 K。配对一旦完成，len(k)==len(v) 的逐行对齐仍由
	// 数据结构本身保证（V 行按下标与 K 行一一对应）。
	ErrKVNotPaired = errors.New("kvcache: kv_append_k / kv_append_v 未成对")
	// ErrKVBlockUnaligned 各 block 行数不对齐：一轮扫描结束后所有 block 的行数必须相等，
	// 否则说明 plan 漏了某一层的 kv_append —— 该层的注意力只会读到较短的历史，
	// 且**不报错、不崩溃、输出悄悄错**，正是本项目要消灭的失败形态。
	// 校验点在轮次结算（AdvanceTurn），**不在**每次 append：step-major 接入下
	// 「block0 已写入、block1..B 尚未开始」是合法的在途中间态，不能在途判错。
	ErrKVBlockUnaligned = errors.New("kvcache: 各 block 行数不对齐（漏扫了某些 block）")
	// ErrKVTurnOverflow turn 超出 route2plan.MaxTurn（Wire 定宽 6 位）。
	ErrKVTurnOverflow = errors.New("kvcache: turn 超出 route2plan.MaxTurn 定宽上限")
)

// ---- 容量上限（双上限，先到先生效；超限一律 fail-closed 报错，绝不静默截断）----
const (
	// kvFloat64Bytes 一个 float64 的宽度；Bytes() 的算式里显式出现，勿写死 8。
	kvFloat64Bytes = 8
	// kvMaxBytes 单会话 KV cache 的字节硬顶（8 MiB）。
	//
	// 为什么在 MaxTokens 之外还要一道字节上限：MaxTokens 只能防「每个会话的行数变多」，
	// 防不住「配置被改成大模型」——把 Dim/Blocks 调大几十倍，行数照样是 128，
	// 峰值内存却涨了两个数量级。字节上限覆盖的正是后一种（配置维度被篡改/笔误）。
	kvMaxBytes int64 = 8 << 20
)

// kvLayer 单个 block 的 K/V 行存储。
//
// k/v 均为 [rows][attnDim]，下标即 token 序；同一 block 内恒有 len(k) == len(v)
// 或 len(k) == len(v)+n（后者是「K-run 已追加、V-run 尚未配对完」的尾部 n 行，
// 对 attention 不可见，n 由 KVCache.pendingCount 跟踪）。行一旦 publish（append
// 进 k/v）就不再被就地改写，唯一的例外是 Reset/Release 的逐元素清零（mu 保护下）。
type kvLayer struct {
	k [][]float64
	v [][]float64
}

// KVCache 单会话的 KV cache。
//
// 【它在可信域是明文——这不是缺陷，是前提】整个 attention 方案成立的前提就是
// K/V 不跨出可信域：因 K = x·W_k 且 W_k 对不可信加速器是明文，一旦把 K 明文交出去，
// 对方可用伪逆 x ≈ K·W_k⁺ 直接恢复输入 x，等于泄漏提示词。故本结构的敏感点
// **不在于「它是明文」**（非线性层的中间激活在可信域同样是明文），而在于两条：
//  1. 不得跨出可信域 ⇒ 本结构不提供任何把 K/V 序列化/外发的能力，也不持有任何
//     上层句柄；依赖严格单向（KVCache 不回调 teeServer / recomputeState）。
//  2. 不得超过预定驻留规模 ⇒ 双上限（MaxTokens 与 kvMaxBytes）fail-closed。
//
// 【行数模型】行数以 **per-block** 为准（一个 block 的第 t 行 == 第 t 个 token 的 K/V）。
// 之所以不假设「各 block 行数恒等」：接入次序是 **plan step-major** ——
// 同一个 kv_append 步会一次携带全部 T 个 token，故执行 block 0 的 kv_append 时
// block 1..B 本来就是 0 行，这是在途的合法中间态。对齐只在**轮次结算**时要求
// （见 CheckAligned / AdvanceTurn）。
//
// 【锁序】mu 是**最内层**锁，取锁次序见文件头。本结构不得反向回调任何上层函数。
//
// 【并发】生产路径上同一会话的 KV 操作本就被 recomputeState.mu 串行化；
// 本结构额外自带 mu，使得即便调用方不串行化也不会出现数据竞争。
// 唯一例外：Reset/Release 会就地写行元素（清零），故它们必须与 Read/Append
// 在更外层串行化——生产路径天然满足，见文件头第 2 条。
type KVCache struct {
	// mu 保护以下全部字段；是最内层锁，临界区内不做浮点运算、不做 O(tokens²) 运算。
	mu sync.Mutex

	cfg     route2plan.ModelConfig
	attnDim int // == cfg.KVDim()（GQA 下为 KVHeads*HeadDim，<= Dim）
	// layers 按 block 预分配；行切片（内层 []float64）按需增长。
	layers []kvLayer

	// tokens 各 block 中最大的 V 行数，即当前会话已写入的 token 数。
	// 单调递增（Reset/Release 归零）。扫描途中各 block 可能不等，取最大值。
	tokens int
	// turn 当前会话轮次（与 route2plan 的 Turn 同义），Reset 归零。
	turn uint32

	// pending / pendingBlock / pendingCount 记录「K-run 进行中、V 尚未配对完」。
	// pendingCount 为已追加但尚未配对 V 的 K 行数；pendingCount==0 即 pending==false。
	// 全局至多一个未完成 run；pendingBlock 为 -1 表示无待配对行。
	pending      bool
	pendingBlock int
	pendingCount int

	released bool
}

// NewKVCache 按 cfg 建立空 cache。
//
// 预分配策略：先建 cfg.Blocks 个层结构；每层的行指针切片按
// min(MaxTokens, kvMaxBytes/每 token 全块字节数) 预留容量，**行的 []float64 本身按需分配**。
// 之所以不直接按 MaxTokens 满配：MaxTokens 上界 65536、Blocks 上界 9998，满配行指针
// 一次性就是数百 MB，而真正装得下的数据受 kvMaxBytes 约束远小于此；按字节倒推预留
// 可保证预留量恒在预算内，且对 demo 规模等于满配（不产生增长抖动）。
//
// 注意：本函数**不**因「满载字节 > kvMaxBytes」拒绝配置——那属于合法但写不满的配置，
// 真正的 fail-closed 发生在 AppendK/AppendV（见 kvMaxBytes）。
func NewKVCache(cfg route2plan.ModelConfig) (*KVCache, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("kvcache: 模型配置非法: %w", err)
	}
	attnDim := cfg.KVDim()
	rowsCap := kvPreallocRows(cfg, attnDim)
	c := &KVCache{
		cfg:          cfg,
		attnDim:      attnDim,
		layers:       make([]kvLayer, cfg.Blocks),
		pendingBlock: -1,
	}
	for i := range c.layers {
		c.layers[i].k = make([][]float64, 0, rowsCap)
		c.layers[i].v = make([][]float64, 0, rowsCap)
	}
	return c, nil
}

// kvPreallocRows 每层的行指针预留容量（详见 NewKVCache 注释）。
func kvPreallocRows(cfg route2plan.ModelConfig, attnDim int) int {
	perToken := int64(2) * int64(cfg.Blocks) * int64(attnDim) * int64(kvFloat64Bytes)
	rowsCap := cfg.MaxTokens
	if perToken > 0 {
		if n := kvMaxBytes / perToken; int64(rowsCap) > n {
			rowsCap = int(n)
		}
	}
	if rowsCap < 1 {
		rowsCap = 1
	}
	return rowsCap
}

// ---- 写入 ----

// AppendK 向 block 层追加一行 K。vec 长度必须等于 KVHeads*HeadDim（即 KVDim）。
func (c *KVCache) AppendK(block int, vec []float64) error {
	return c.appendRow(block, vec, true)
}

// AppendV 向 block 层追加一行 V。必须与前一次 AppendK 同 block 且紧随其后。
func (c *KVCache) AppendV(block int, vec []float64) error {
	return c.appendRow(block, vec, false)
}

// appendRow K/V 追加的公共实现（isK=true 走 K，否则走 V）。
//
// 校验次序（fail-closed，任一项不通过即原样返回、内部状态不变）：
//  1. 已释放；
//  2. block 越界；
//  3. 向量长度；
//  4. 成对性（K-run / V-run 语义，见 ErrKVNotPaired）：
//     K：不得存在**其它 block** 未闭合的 K-run（同 block 连续 K 即 run 追加）；
//     V：必须存在待配对的 K-run 且 block 一致（V 行按下标 FIFO 配对 K 行）；
//  5. 行数上限 MaxTokens（按本 block 追加后的行数判）；
//  6. 字节上限 kvMaxBytes（按「追加后各 block 最大行数」判，宁严勿松）。
//
// 第 5/6 项对同一 run 内的 K 行与配对的 V 行给出**完全相同的判决**（K-run 期间
// rowsAfter 逐行 +1；V-run 期间 len(k) 恒为 run 落定后的总行数），故不会出现
// 「K 通过、配对的 V 被拦」而残留未配对 K 的中间态。
//
// 注意：这里**不做**跨 block 对齐校验——step-major 接入下在途中间态本就不对齐，
// 对齐是轮次结算时的事（CheckAligned / AdvanceTurn）。
func (c *KVCache) appendRow(block int, vec []float64, isK bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.released {
		return ErrKVCacheReleased
	}
	if block < 0 || block >= len(c.layers) {
		return fmt.Errorf("%w: block=%d 不在 0..%d 内", ErrBlockOutOfRange, block, len(c.layers)-1)
	}
	if len(vec) != c.attnDim {
		return fmt.Errorf("%w: got=%d want=%d(KVHeads*HeadDim)", ErrVecLength, len(vec), c.attnDim)
	}
	if isK {
		if c.pending && c.pendingBlock != block {
			return fmt.Errorf("%w: block %d 的 K-run 未闭合，不得向 block %d 追加 K",
				ErrKVNotPaired, c.pendingBlock, block)
		}
	} else {
		if !c.pending || c.pendingBlock != block {
			return fmt.Errorf("%w: 收到 block %d 的 V，但当前待配对的是 %s",
				ErrKVNotPaired, block, kvPendingDesc(c.pending, c.pendingBlock, c.pendingCount))
		}
	}
	// 本行落定后该 block 的行数：K 追加后 +1；V 追加时 K 已在，故等于 len(k)。
	rowsAfter := len(c.layers[block].k)
	if isK {
		rowsAfter++
	}
	if rowsAfter > c.cfg.MaxTokens {
		return fmt.Errorf("%w: block %d 追加后为第 %d 行，上限 MaxTokens=%d",
			ErrKVCacheFull, block, rowsAfter, c.cfg.MaxTokens)
	}
	worstRows := rowsAfter
	if c.tokens > worstRows {
		worstRows = c.tokens
	}
	if nb := c.bytesLocked(worstRows); nb > kvMaxBytes {
		return fmt.Errorf("%w: 追加后 %d 字节 > 上限 %d 字节（Blocks=%d attnDim=%d rows=%d）",
			ErrKVCacheBytesExceeded, nb, kvMaxBytes, len(c.layers), c.attnDim, worstRows)
	}

	// 拷一份自有行：绝不把调用方的切片挂进 cache（否则调用方事后改写会污染可信状态，
	// 而这类污染表现为「attention 结果偶发错乱」，极难定位）。
	row := make([]float64, c.attnDim)
	copy(row, vec)

	if isK {
		c.layers[block].k = append(c.layers[block].k, row)
		c.pending = true
		c.pendingBlock = block
		c.pendingCount++
		return nil
	}
	c.layers[block].v = append(c.layers[block].v, row)
	c.pendingCount--
	if c.pendingCount == 0 {
		c.pending = false
		c.pendingBlock = -1
	}
	if n := len(c.layers[block].v); n > c.tokens {
		c.tokens = n
	}
	return nil
}

// ---- 读取 ----

// Tokens 当前会话已写入的 token 数（各 block 行数的最大值）。
// 扫描途中各 block 可能不等（step-major 接入），此时取最大值。
func (c *KVCache) Tokens() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tokens
}

// Rows 第 block 层已落定的完整 K/V 行数（不含尚未配对的半行 K）。
// 已释放返回 ErrKVCacheReleased，越界返回 ErrBlockOutOfRange。
func (c *KVCache) Rows(block int) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.released {
		return 0, ErrKVCacheReleased
	}
	if block < 0 || block >= len(c.layers) {
		return 0, fmt.Errorf("%w: block=%d 不在 0..%d 内", ErrBlockOutOfRange, block, len(c.layers)-1)
	}
	return len(c.layers[block].v), nil
}

// Bytes 当前 KV 占用的字节数（算式）：2 · Blocks · tokens · (KVHeads*HeadDim) · 8。
//
// 这是**名义**占用：扫描途中少数 block 尚未写入本行时，实际占用略小于该值；
// 容量上限的判定（appendRow）另取「追加后最大行数」计算，故不会因为这里偏小
// 而放过超限。已释放后返回 0。
func (c *KVCache) Bytes() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytesLocked(c.tokens)
}

// bytesLocked 按给定行数算字节数；调用方须持锁。
func (c *KVCache) bytesLocked(tokens int) int64 {
	return int64(2) * int64(len(c.layers)) * int64(tokens) * int64(c.attnDim) * int64(kvFloat64Bytes)
}

// ReadK 返回 block 层 K 的**快照**：[rows][KVHeads*HeadDim]（即 KVDim）深拷贝。
//
// 返回快照而非内部切片的两个理由：
//  1. 调用方改写返回值不应污染 cache（K/V 是可信域明文，被污染等于注意力结果被投毒）；
//  2. cache 后续追加不应影响调用方已取到的切片（否则 attention 读到半写状态）。
//
// 行数取**已配对的完整行**：尚缺 V 的半行 K 一律不暴露，
// 以保证 len(ReadK(b)) == len(ReadV(b)) 恒成立。
//
// 【为什么不返回 nil 表示异常】nil 与「空 KV」在调用方眼里不可区分：按
// `for i := range rows` 处理会得到空注意力，进而算出全零/退化的输出——
// 不报错、不崩溃、静默错误。故本方法显式返回 error：
// ErrKVCacheReleased / ErrBlockOutOfRange，成功时 error 恒为 nil。
//
// 【临界区内只做浅拷贝】深拷贝是 O(rows·attnDim) 的数据搬运，若压在锁内会把
// KVCache.mu 的持有时间拉到与注意力同量级，违背「mu 是最内层锁」的锁序约定。
// 故实现为：锁内只拷外层行指针，出锁后再逐行 copy——真正的浮点运算（注意力）
// 全程在锁外。
func (c *KVCache) ReadK(block int) ([][]float64, error) {
	return c.readRows(block, true)
}

// ReadV 同 ReadK，返回 V 的快照。
func (c *KVCache) ReadV(block int) ([][]float64, error) {
	return c.readRows(block, false)
}

// readRows ReadK/ReadV 的公共实现。
func (c *KVCache) readRows(block int, isK bool) ([][]float64, error) {
	c.mu.Lock()
	if c.released {
		c.mu.Unlock()
		return nil, ErrKVCacheReleased
	}
	if block < 0 || block >= len(c.layers) {
		c.mu.Unlock()
		return nil, fmt.Errorf("%w: block=%d 不在 0..%d 内", ErrBlockOutOfRange, block, len(c.layers)-1)
	}
	lay := &c.layers[block]
	// 完整行数 == len(v)：K 侧据此裁掉可能存在的半行。
	n := len(lay.v)
	src := lay.v
	if isK {
		src = lay.k
	}
	if len(src) < n {
		n = len(src)
	}
	shallow := make([][]float64, n)
	copy(shallow, src[:n])
	dim := c.attnDim
	c.mu.Unlock()

	// 出锁后深拷贝：shallow 里的行已 publish，除 Reset/Release 的清零外不会被就地改写
	// （而 Reset/Release 须由调用方在更外层串行化，见文件头第 2 条）。
	out := make([][]float64, n)
	for t := 0; t < n; t++ {
		row := make([]float64, dim)
		copy(row, shallow[t])
		out[t] = row
	}
	return out, nil
}

// CheckAligned 校验各 block 的行数是否对齐。
//
// 规则：**已开始**（行数 > 0）的 block 之间行数必须相等，否则返回 ErrKVBlockUnaligned
// （错误信息里带各层行数，便于排障）。0 行的 block 视为「本轮还没扫到」而不参与比较，
// 因为在 plan step-major 接入下「block0 已写完、block1..B 还没开始」是合法的在途
// 中间态，不能在途判错（这就是对齐校验不放在 appendRow 里的原因）。
//
// 相应地，本校验只在**轮次结算**时才有完整效力：AdvanceTurn 会额外要求
// 「已开始的 block 必须覆盖全部 block」，从而把「某 block 被整轮漏扫（0 行）」
// 一并拦住——见 checkAlignedLocked(strict=true)。
func (c *KVCache) CheckAligned() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.checkAlignedLocked(false)
}

// checkAlignedLocked 对齐校验实现；调用方须持锁。
//
// strict=false（CheckAligned）：0 行的 block 视为未开始，豁免比较。
// strict=true（AdvanceTurn 的结算语义）：额外要求「只要有任何 block 有行，
// 所有 block 都必须有行」，即整轮漏扫也判为不对齐。
func (c *KVCache) checkAlignedLocked(strict bool) error {
	if c.released {
		return ErrKVCacheReleased
	}
	var sb strings.Builder
	ref := -1
	started := 0
	for b := range c.layers {
		n := len(c.layers[b].v)
		if b > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, "b%d=%d", b, n)
		if n == 0 {
			continue
		}
		started++
		if ref < 0 {
			ref = n
			continue
		}
		if n != ref {
			return fmt.Errorf("%w: 各 block 行数不等 [%s]", ErrKVBlockUnaligned, sb.String())
		}
	}
	if strict && started > 0 && started != len(c.layers) {
		return fmt.Errorf("%w: 仅 %d/%d 个 block 有行，其余被整轮漏扫 [%s]",
			ErrKVBlockUnaligned, started, len(c.layers), sb.String())
	}
	return nil
}

// Turn 当前会话轮次。
func (c *KVCache) Turn() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.turn
}

// AdvanceTurn 结束当前轮并推进到下一轮，返回推进后的轮次。
//
// 推进前有两项 fail-closed 校验：
//  1. 不得有「已追加 K 但未配对 V」的半行（ErrKVNotPaired）；
//  2. 各 block 行数必须对齐（ErrKVBlockUnaligned，结算语义：含整轮漏扫）。
//
// 任一不通过即**原样返回、不隐式 Reset**：证据必须保留到调用方显式 Reset 为止，
// 否则就把「plan 漏了一条 kv_append」这类 bug 的现场抹掉了。
// 同理，本轮不推进 ⇒ turn 不变。
func (c *KVCache) AdvanceTurn() (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.released {
		return 0, ErrKVCacheReleased
	}
	if c.pending {
		return c.turn, fmt.Errorf("%w: block %d 的 K 尚未配对 V，不得推进 turn", ErrKVNotPaired, c.pendingBlock)
	}
	if err := c.checkAlignedLocked(true); err != nil {
		return c.turn, err
	}
	if c.turn >= route2plan.MaxTurn {
		return c.turn, fmt.Errorf("%w: turn=%d 已是定宽上限", ErrKVTurnOverflow, c.turn)
	}
	c.turn++
	return c.turn, nil
}

// ---- 生命周期 ----

// Reset 会话级复位：行数归零、turn 归零，**逐元素清零后再复用**行切片。
//
// 【为什么必须逐元素清零】K/V 是提示词的明文中间激活。只置 tokens=0 的话，
// 上一轮会话的明文仍完整留在堆上的行数组里：① 任何越界读（或后续实现的 bug）
// 会读到别人的提示词；② 进程 core dump / 堆转储会带上它；③ 复用时虽会整体覆盖，
// 但半行等边界情形未必覆盖干净。故清零是安全性质，不是内存优化。
//
// 清零后保留切片容量以便复用（避免每轮重新申请）。已释放时为空操作。
// 本方法是「对齐/半行」类故障的**唯一**恢复手段（调用方须显式调用）。
func (c *KVCache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.released {
		return
	}
	for i := range c.layers {
		lay := &c.layers[i]
		kvZeroRows(lay.k)
		kvZeroRows(lay.v)
		lay.k = lay.k[:0]
		lay.v = lay.v[:0]
	}
	c.tokens = 0
	c.turn = 0
	c.pending = false
	c.pendingBlock = -1
	c.pendingCount = 0
}

// Release 释放 cache：逐元素清零 → 丢弃切片引用 → 置已释放标志。
//
// 释放后所有写操作返回 ErrKVCacheReleased（fail-closed，不 panic）；
// 读操作返回零值 + 同一哨兵 error。本方法幂等。
func (c *KVCache) Release() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.released {
		return
	}
	for i := range c.layers {
		kvZeroRows(c.layers[i].k)
		kvZeroRows(c.layers[i].v)
		c.layers[i].k = nil
		c.layers[i].v = nil
	}
	c.layers = nil
	c.tokens = 0
	c.turn = 0
	c.pending = false
	c.pendingBlock = -1
	c.pendingCount = 0
	c.released = true
}

// kvZeroRows 逐元素清零一批行（不做任何长度变更，容量保持不变）。
func kvZeroRows(rows [][]float64) {
	for _, r := range rows {
		for i := range r {
			r[i] = 0
		}
	}
}

// kvPendingDesc 把「待配对状态」渲染成人类可读串（仅错误信息用）。
func kvPendingDesc(pending bool, block, count int) string {
	if !pending {
		return "无待配对的 K"
	}
	return fmt.Sprintf("block %d 的 K-run（剩 %d 行未配对 V）", block, count)
}
