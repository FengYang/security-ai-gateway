// kvcache_test.go - KVCache 的行为与安全性测试
package route2step

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"security-ai-gateway/gateway/teecore/route2plan"
)

// ---- 工具 ----

// kvVec 构造可定位的测试行：block*100000 + token*1000 + i，浮点精确可表示。
func kvVec(block, token, dim int) []float64 {
	v := make([]float64, dim)
	for i := 0; i < dim; i++ {
		v[i] = float64(block*100000 + token*1000 + i)
	}
	return v
}

// kvMustNew 建 cache，失败即终止用例。
func kvMustNew(t *testing.T, cfg route2plan.ModelConfig) *KVCache {
	t.Helper()
	c, err := NewKVCache(cfg)
	if err != nil {
		t.Fatalf("NewKVCache: %v", err)
	}
	return c
}

// kvAppendPair 对全部 block 追加第 token 行的一对 K/V。
func kvAppendPair(t *testing.T, c *KVCache, blocks, dim, token int) {
	t.Helper()
	for b := 0; b < blocks; b++ {
		if err := c.AppendK(b, kvVec(b, token, dim)); err != nil {
			t.Fatalf("AppendK(block=%d,token=%d): %v", b, token, err)
		}
		if err := c.AppendV(b, kvVec(b, token, dim)); err != nil {
			t.Fatalf("AppendV(block=%d,token=%d): %v", b, token, err)
		}
	}
}

// kvReadK / kvReadV 读快照并断言无错（仅用于「预期成功」的调用点）。
func kvReadK(t *testing.T, c *KVCache, block int) [][]float64 {
	t.Helper()
	rows, err := c.ReadK(block)
	if err != nil {
		t.Fatalf("ReadK(block=%d): %v", block, err)
	}
	return rows
}

func kvReadV(t *testing.T, c *KVCache, block int) [][]float64 {
	t.Helper()
	rows, err := c.ReadV(block)
	if err != nil {
		t.Fatalf("ReadV(block=%d): %v", block, err)
	}
	return rows
}

// kvAssertZeroed 断言一批行的**每个元素**都是 0（而非只断言行数归零）。
func kvAssertZeroed(t *testing.T, what string, rows [][]float64) {
	t.Helper()
	for i, r := range rows {
		for j, v := range r {
			if v != 0 {
				t.Fatalf("%s: 行 %d 元素 %d 未清零，残留值 %v", what, i, j, v)
			}
		}
	}
}

// ---- 构造与校验 ----

func TestNewKVCacheRejectsBadConfig(t *testing.T) {
	bad := route2plan.DemoTinyConfig()
	bad.Blocks = 0
	if _, err := NewKVCache(bad); err == nil {
		t.Fatal("Blocks=0 的配置必须被拒（fail-closed）")
	}
	bad = route2plan.DemoTinyConfig()
	bad.MaxTokens = 0
	if _, err := NewKVCache(bad); err == nil {
		t.Fatal("MaxTokens=0 的配置必须被拒（fail-closed）")
	}
	// 合法配置必须成功，且 blocks 层结构已建好。
	c := kvMustNew(t, route2plan.DemoTinyConfig())
	defer c.Release()
	if got, want := len(c.layers), route2plan.DemoBlocks; got != want {
		t.Fatalf("layers=%d want=%d", got, want)
	}
	if got := c.Tokens(); got != 0 {
		t.Fatalf("新建 cache 的 Tokens=%d want=0", got)
	}
}

func TestKVCacheAppendReadRoundTrip(t *testing.T) {
	cfg := route2plan.DemoTinyConfig()
	c := kvMustNew(t, cfg)
	defer c.Release()

	const nTok = 5
	for tok := 0; tok < nTok; tok++ {
		kvAppendPair(t, c, cfg.Blocks, cfg.AttnDim(), tok)
	}
	if got, want := c.Tokens(), nTok; got != want {
		t.Fatalf("Tokens=%d want=%d", got, want)
	}

	// 多 block、多头拼接顺序：ReadK(b)[tok][i] 必须逐元素还原。
	for b := 0; b < cfg.Blocks; b++ {
		k := kvReadK(t, c, b)
		v := kvReadV(t, c, b)
		if len(k) != nTok || len(v) != nTok {
			t.Fatalf("block %d: len(k)=%d len(v)=%d want=%d", b, len(k), len(v), nTok)
		}
		for tk := 0; tk < nTok; tk++ {
			if len(k[tk]) != cfg.AttnDim() || len(v[tk]) != cfg.AttnDim() {
				t.Fatalf("block %d token %d: 行宽 %d/%d want=%d", b, tk, len(k[tk]), len(v[tk]), cfg.AttnDim())
			}
			for i := 0; i < cfg.AttnDim(); i++ {
				want := float64(b*100000 + tk*1000 + i)
				if k[tk][i] != want || v[tk][i] != want {
					t.Fatalf("block %d token %d 元素 %d: k=%v v=%v want=%v", b, tk, i, k[tk][i], v[tk][i], want)
				}
			}
		}
	}
}

func TestKVCacheCopiesInputVec(t *testing.T) {
	cfg := route2plan.DemoTinyConfig()
	c := kvMustNew(t, cfg)
	defer c.Release()

	vec := kvVec(0, 0, cfg.AttnDim())
	if err := c.AppendK(0, vec); err != nil {
		t.Fatalf("AppendK: %v", err)
	}
	if err := c.AppendV(0, vec); err != nil {
		t.Fatalf("AppendV: %v", err)
	}
	// 改写调用方切片不得污染 cache（cache 必须持有自有副本）。
	for i := range vec {
		vec[i] = -1
	}
	got := kvReadK(t, c, 0)
	for i, want := range kvVec(0, 0, cfg.AttnDim()) {
		if got[0][i] != want {
			t.Fatalf("元素 %d 被调用方改写污染：got=%v want=%v", i, got[0][i], want)
		}
	}
}

// ---- 快照语义 ----

func TestKVCacheReadIsSnapshot(t *testing.T) {
	cfg := route2plan.DemoTinyConfig()
	c := kvMustNew(t, cfg)
	defer c.Release()

	kvAppendPair(t, c, cfg.Blocks, cfg.AttnDim(), 0)
	snapK := kvReadK(t, c, 0)
	snapV := kvReadV(t, c, 0)

	// (1) 改写返回值不得影响内部。
	for i := range snapK[0] {
		snapK[0][i] = 999
		snapV[0][i] = -999
	}
	againK := kvReadK(t, c, 0)
	againV := kvReadV(t, c, 0)
	for i, want := range kvVec(0, 0, cfg.AttnDim()) {
		if againK[0][i] != want || againV[0][i] != want {
			t.Fatalf("改写快照污染了内部：元素 %d got k=%v v=%v want=%v", i, againK[0][i], againV[0][i], want)
		}
	}

	// (2) 内部继续追加不得影响已取到的快照。
	snapLen := len(snapK)
	kvAppendPair(t, c, cfg.Blocks, cfg.AttnDim(), 1)
	kvAppendPair(t, c, cfg.Blocks, cfg.AttnDim(), 2)
	if len(snapK) != snapLen {
		t.Fatalf("已取快照被后续追加改变长度：%d -> %d", snapLen, len(snapK))
	}
	for i := range snapK[0] {
		if snapK[0][i] != 999 {
			t.Fatalf("快照元素 %d 被后续追加改写：got=%v want=999", i, snapK[0][i])
		}
	}
	if got := len(kvReadK(t, c, 0)); got != 3 {
		t.Fatalf("内部行数应已增长到 3，got=%d", got)
	}

	// (3) 两次读取之间不共享底层数组。
	a := kvReadK(t, c, 1)
	b := kvReadK(t, c, 1)
	a[0][0] = 123456
	if b[0][0] == 123456 {
		t.Fatal("两次 ReadK 的返回共享底层数组（不是深拷贝快照）")
	}
}

// ---- 成对性（防 K/V 行数错位；K-run / V-run 语义，见 ErrKVNotPaired）----

func TestKVCacheKVPairingEnforced(t *testing.T) {
	cfg := route2plan.DemoTinyConfig()
	dim := cfg.AttnDim()

	// K-run 未闭合时不得向其它 block 追加 K（同 block 连续 K 即 run 追加，是
	// prefill 批量的合法形态；跨 block 才是错位）。
	c := kvMustNew(t, cfg)
	defer c.Release()
	if err := c.AppendK(0, kvVec(0, 0, dim)); err != nil {
		t.Fatalf("AppendK: %v", err)
	}
	if err := c.AppendK(1, kvVec(1, 0, dim)); !errors.Is(err, ErrKVNotPaired) {
		t.Fatalf("K-run 未闭合时跨 block 追加 K 应报 ErrKVNotPaired，got=%v", err)
	}
	if got := c.Tokens(); got != 0 {
		t.Fatalf("K-run 未配对时不得计入 Tokens，got=%d want=0", got)
	}
	if got := len(kvReadK(t, c, 0)); got != 0 {
		t.Fatalf("K-run 未配对时不得被 attention 读到，got=%d want=0", got)
	}
	// run 未闭合态下推进 turn 一律 fail-closed，直到显式 Reset。
	if _, err := c.AdvanceTurn(); !errors.Is(err, ErrKVNotPaired) {
		t.Fatalf("K-run 未闭合时推进 turn 应报 ErrKVNotPaired，got=%v", err)
	}
	c.Reset()
	if err := c.AppendK(0, kvVec(0, 0, dim)); err != nil {
		t.Fatalf("Reset 后应可恢复追加，got=%v", err)
	}

	// 没有待配对的 K 时直接 AppendV 应报错。
	c2 := kvMustNew(t, cfg)
	defer c2.Release()
	if err := c2.AppendV(0, kvVec(0, 0, dim)); !errors.Is(err, ErrKVNotPaired) {
		t.Fatalf("孤立 AppendV 应报 ErrKVNotPaired，got=%v", err)
	}

	// V 的 block 与待配对的 K-run 不一致应报错；报错不闭合 run，
	// 正确的同 block V 仍能把 run 配对应成功。
	c3 := kvMustNew(t, cfg)
	defer c3.Release()
	if err := c3.AppendK(1, kvVec(1, 0, dim)); err != nil {
		t.Fatalf("AppendK: %v", err)
	}
	if err := c3.AppendV(2, kvVec(2, 0, dim)); !errors.Is(err, ErrKVNotPaired) {
		t.Fatalf("跨 block 配对应报 ErrKVNotPaired，got=%v", err)
	}
	if err := c3.AppendV(0, kvVec(0, 0, dim)); !errors.Is(err, ErrKVNotPaired) {
		t.Fatalf("错位 block 的 V 应报 ErrKVNotPaired，got=%v", err)
	}
	if err := c3.AppendV(1, kvVec(1, 0, dim)); err != nil {
		t.Fatalf("报错后 run 仍在，同 block 配对应成功: %v", err)
	}
	// run 闭合后应可继续向其它 block 追加（错位拒绝不得留下粘连状态）。
	if err := c3.AppendK(0, kvVec(0, 1, dim)); err != nil {
		t.Fatalf("run 闭合后应可向其它 block 追加 K: %v", err)
	}

	// 正常成对：K/V 行数严格相等，Tokens 递增。
	c4 := kvMustNew(t, cfg)
	defer c4.Release()
	for tok := 0; tok < 3; tok++ {
		kvAppendPair(t, c4, cfg.Blocks, dim, tok)
		if got, want := c4.Tokens(), tok+1; got != want {
			t.Fatalf("第 %d 对后 Tokens=%d want=%d", tok, got, want)
		}
		for b := 0; b < cfg.Blocks; b++ {
			if len(kvReadK(t, c4, b)) != len(kvReadV(t, c4, b)) {
				t.Fatalf("block %d 的 K/V 行数不等：%d vs %d", b, len(kvReadK(t, c4, b)), len(kvReadV(t, c4, b)))
			}
		}
	}
}

// TestKVCacheKRunVRunBatch 覆盖 prefill 批量形态：一个 kv_append_k 步携带 T 行 K
// 连续到达（K-run），随后 kv_append_v 步携 T 行 V 连续配对（FIFO 逐行对应）。
// 这正是 step_exec.go 在 nPos>1 时产生的访问序列；旧「逐行严格交替」语义下该序列在
// 第 2 行 K 即被拒（ErrKVNotPaired），导致批量 prefill 整体不可用（真机实测
// -prompt-len 4 在 step#1 HTTP 500）。本用例把该访问序列钉成合法并验证配对对齐。
func TestKVCacheKRunVRunBatch(t *testing.T) {
	cfg := route2plan.DemoTinyConfig()
	dim := cfg.AttnDim()
	const batch = 4 // 与真实 prefill 步 nPos>1 同形的任意批量

	c := kvMustNew(t, cfg)
	defer c.Release()

	// K-run：同 block 连续 T 行 K 合法；run 中途对 attention 不可见、不计 Tokens。
	for j := 0; j < batch; j++ {
		if err := c.AppendK(0, kvVec(0, j, dim)); err != nil {
			t.Fatalf("K-run 第 %d 行: %v", j, err)
		}
	}
	if got := c.Tokens(); got != 0 {
		t.Fatalf("K-run 未配对时 Tokens=%d want=0", got)
	}
	if got := len(kvReadK(t, c, 0)); got != 0 {
		t.Fatalf("K-run 期间 ReadK 应为空（未配对行对 attention 不可见），got=%d", got)
	}
	if got := len(kvReadV(t, c, 0)); got != 0 {
		t.Fatalf("K-run 期间 ReadV 应为空，got=%d", got)
	}

	// V-run：T 行 V 连续到达，FIFO 闭合 run。
	for j := 0; j < batch; j++ {
		if err := c.AppendV(0, kvVec(0, j, dim)); err != nil {
			t.Fatalf("V-run 第 %d 行: %v", j, err)
		}
	}
	if got := c.Tokens(); got != batch {
		t.Fatalf("配对完成后 Tokens=%d want=%d", got, batch)
	}

	// 配对后 K/V 逐行下标对齐（K 行 j 与 V 行 j 配对），内容未被错位。
	k, v := kvReadK(t, c, 0), kvReadV(t, c, 0)
	if len(k) != batch || len(v) != batch {
		t.Fatalf("配对后行数 k=%d v=%d want=%d", len(k), len(v), batch)
	}
	for j := 0; j < batch; j++ {
		for i := 0; i < dim; i++ {
			if k[j][i] != kvVec(0, j, dim)[i] || v[j][i] != kvVec(0, j, dim)[i] {
				t.Fatalf("行 %d 元素 %d 错位: k=%v v=%v", j, i, k[j][i], v[j][i])
			}
		}
	}

	// V-run 超长（比 K-run 多一行）必须 fail-closed，不得静默吞行。
	if err := c.AppendV(0, kvVec(0, batch, dim)); !errors.Is(err, ErrKVNotPaired) {
		t.Fatalf("超长 V-run 应报 ErrKVNotPaired，got=%v", err)
	}

	// 批量 run 之后再走逐行 decode 形态（K,V 交替）仍合法：两种形态可自由混接。
	for tok := batch; tok < batch+2; tok++ {
		if err := c.AppendK(0, kvVec(0, tok, dim)); err != nil {
			t.Fatalf("混接逐行 AppendK(tok=%d): %v", tok, err)
		}
		if err := c.AppendV(0, kvVec(0, tok, dim)); err != nil {
			t.Fatalf("混接逐行 AppendV(tok=%d): %v", tok, err)
		}
	}
	if got := c.Tokens(); got != batch+2 {
		t.Fatalf("混接后 Tokens=%d want=%d", got, batch+2)
	}
}

// ---- 参数校验哨兵（含 Read* 的 error 化）----

func TestKVCacheArgSentinels(t *testing.T) {
	cfg := route2plan.DemoTinyConfig()
	c := kvMustNew(t, cfg)
	defer c.Release()
	dim := cfg.AttnDim()

	for _, blk := range []int{-1, cfg.Blocks, cfg.Blocks + 100} {
		if err := c.AppendK(blk, kvVec(0, 0, dim)); !errors.Is(err, ErrBlockOutOfRange) {
			t.Fatalf("AppendK(block=%d) 应报 ErrBlockOutOfRange，got=%v", blk, err)
		}
		if err := c.AppendV(blk, kvVec(0, 0, dim)); !errors.Is(err, ErrBlockOutOfRange) {
			t.Fatalf("AppendV(block=%d) 应报 ErrBlockOutOfRange，got=%v", blk, err)
		}
		// Read* 越界：必须返回哨兵 error 且切片为 nil（不能用 nil 混淆「空 KV」）。
		rows, err := c.ReadK(blk)
		if !errors.Is(err, ErrBlockOutOfRange) {
			t.Fatalf("ReadK(block=%d) 应报 ErrBlockOutOfRange，got=%v", blk, err)
		}
		if rows != nil {
			t.Fatalf("ReadK(block=%d) 出错时应返回 nil 切片，got=%v", blk, rows)
		}
		rows, err = c.ReadV(blk)
		if !errors.Is(err, ErrBlockOutOfRange) {
			t.Fatalf("ReadV(block=%d) 应报 ErrBlockOutOfRange，got=%v", blk, err)
		}
		if rows != nil {
			t.Fatalf("ReadV(block=%d) 出错时应返回 nil 切片，got=%v", blk, rows)
		}
		if _, err := c.Rows(blk); !errors.Is(err, ErrBlockOutOfRange) {
			t.Fatalf("Rows(block=%d) 应报 ErrBlockOutOfRange，got=%v", blk, err)
		}
	}
	for _, n := range []int{0, dim - 1, dim + 1, dim * 2} {
		if err := c.AppendK(0, make([]float64, n)); !errors.Is(err, ErrVecLength) {
			t.Fatalf("AppendK(len=%d) 应报 ErrVecLength，got=%v", n, err)
		}
	}
	// 长度错误后不得留下半行。
	if err := c.AppendK(0, kvVec(0, 0, dim)); err != nil {
		t.Fatalf("长度错误不应残留状态：%v", err)
	}
}

// ---- 跨 block 对齐（轮次结算点）----

// ② step-major 的合法在途中间态（block0 已写入、block1..B 尚未开始）不得报错。
func TestKVCacheInFlightStateIsNotUnaligned(t *testing.T) {
	cfg := route2plan.DemoTinyConfig()
	c := kvMustNew(t, cfg)
	defer c.Release()
	dim := cfg.AttnDim()

	// 模拟 step-major：同一个 kv_append 步一次携带全部 T 个 token，
	// 故先只把 block 0 的 3 行写完，其余 block 仍是 0 行。
	const T = 3
	for tok := 0; tok < T; tok++ {
		if err := c.AppendK(0, kvVec(0, tok, dim)); err != nil {
			t.Fatalf("AppendK(b0,tok=%d): %v", tok, err)
		}
		if err := c.AppendV(0, kvVec(0, tok, dim)); err != nil {
			t.Fatalf("AppendV(b0,tok=%d): %v", tok, err)
		}
	}
	// 在途：不得因对齐校验而失败。
	if err := c.CheckAligned(); err != nil {
		t.Fatalf("在途中间态（b0=%d 行、其余 0 行）不得判为不对齐，got=%v", T, err)
	}
	if got := c.Tokens(); got != T {
		t.Fatalf("Tokens=%d want=%d", got, T)
	}
	if n, err := c.Rows(0); err != nil || n != T {
		t.Fatalf("Rows(0)=(%d,%v) want=(%d,nil)", n, err, T)
	}
	if n, err := c.Rows(1); err != nil || n != 0 {
		t.Fatalf("Rows(1)=(%d,%v) want=(0,nil)", n, err)
	}

	// 扫完剩余 block 后，对齐成立，轮次可以正常结算。
	for b := 1; b < cfg.Blocks; b++ {
		for tok := 0; tok < T; tok++ {
			if err := c.AppendK(b, kvVec(b, tok, dim)); err != nil {
				t.Fatalf("AppendK(b%d,tok=%d): %v", b, tok, err)
			}
			if err := c.AppendV(b, kvVec(b, tok, dim)); err != nil {
				t.Fatalf("AppendV(b%d,tok=%d): %v", b, tok, err)
			}
		}
	}
	if err := c.CheckAligned(); err != nil {
		t.Fatalf("扫描完成后应已对齐，got=%v", err)
	}
	turn, err := c.AdvanceTurn()
	if err != nil || turn != 1 {
		t.Fatalf("AdvanceTurn=(%d,%v) want=(1,nil)", turn, err)
	}
}

// ① 少写一个 block 的 kv_append ⇒ 结算点必须报错（且不得隐式 Reset）。
func TestKVCacheBlockUnalignedAtSettlement(t *testing.T) {
	cfg := route2plan.DemoTinyConfig()
	dim := cfg.AttnDim()

	// 部分漏写：block 3 少一轮 ⇒ 行数比其他层少 1。
	c := kvMustNew(t, cfg)
	defer c.Release()
	kvAppendPair(t, c, cfg.Blocks, dim, 0)
	if turn, err := c.AdvanceTurn(); err != nil || turn != 1 {
		t.Fatalf("第一轮 AdvanceTurn=(%d,%v) want=(1,nil)", turn, err)
	}
	for b := 0; b < cfg.Blocks-1; b++ { // 漏掉最后一个 block
		if err := c.AppendK(b, kvVec(b, 1, dim)); err != nil {
			t.Fatalf("AppendK(b%d): %v", b, err)
		}
		if err := c.AppendV(b, kvVec(b, 1, dim)); err != nil {
			t.Fatalf("AppendV(b%d): %v", b, err)
		}
	}
	err := c.CheckAligned()
	if !errors.Is(err, ErrKVBlockUnaligned) {
		t.Fatalf("少写一个 block 后 CheckAligned 应报 ErrKVBlockUnaligned，got=%v", err)
	}
	if !strings.Contains(err.Error(), "b3=") {
		t.Fatalf("错误信息应带上各层行数以便排障，got=%q", err.Error())
	}
	turn, err := c.AdvanceTurn()
	if !errors.Is(err, ErrKVBlockUnaligned) {
		t.Fatalf("少写一个 block 后 AdvanceTurn 应报 ErrKVBlockUnaligned，got=%v", err)
	}
	if turn != 1 {
		t.Fatalf("结算失败时 turn 不得推进，got=%d want=1", turn)
	}
	// 不得隐式 Reset：证据必须保留。
	if got := c.Tokens(); got != 2 {
		t.Fatalf("结算失败后 Tokens=%d want=2（不得隐式 Reset 抹掉现场）", got)
	}
	if n, err2 := c.Rows(cfg.Blocks - 1); err2 != nil || n != 1 {
		t.Fatalf("结算失败后 Rows(%d)=(%d,%v) want=(1,nil)", cfg.Blocks-1, n, err2)
	}
	// 补上漏掉的 block 后即可正常结算。
	if err := c.AppendK(cfg.Blocks-1, kvVec(cfg.Blocks-1, 1, dim)); err != nil {
		t.Fatalf("AppendK: %v", err)
	}
	if err := c.AppendV(cfg.Blocks-1, kvVec(cfg.Blocks-1, 1, dim)); err != nil {
		t.Fatalf("AppendV: %v", err)
	}
	if err := c.CheckAligned(); err != nil {
		t.Fatalf("补齐后应已对齐，got=%v", err)
	}
	if turn, err := c.AdvanceTurn(); err != nil || turn != 2 {
		t.Fatalf("补齐后 AdvanceTurn=(%d,%v) want=(2,nil)", turn, err)
	}

	// 整轮漏扫（某 block 恒为 0 行）：CheckAligned 按「未开始」豁免，
	// 但结算点（AdvanceTurn，严格语义）必须拦下——否则该层注意力读到 0 行而静默出错。
	c2 := kvMustNew(t, cfg)
	defer c2.Release()
	for b := 0; b < cfg.Blocks-1; b++ {
		if err := c2.AppendK(b, kvVec(b, 0, dim)); err != nil {
			t.Fatalf("AppendK(b%d): %v", b, err)
		}
		if err := c2.AppendV(b, kvVec(b, 0, dim)); err != nil {
			t.Fatalf("AppendV(b%d): %v", b, err)
		}
	}
	if err := c2.CheckAligned(); err != nil {
		t.Fatalf("0 行的 block 按「尚未开始」豁免，CheckAligned 不应报错，got=%v", err)
	}
	if _, err := c2.AdvanceTurn(); !errors.Is(err, ErrKVBlockUnaligned) {
		t.Fatalf("整轮漏扫应在结算点报 ErrKVBlockUnaligned，got=%v", err)
	}
}

func TestKVCacheRowsAccessor(t *testing.T) {
	cfg := route2plan.DemoTinyConfig()
	c := kvMustNew(t, cfg)
	defer c.Release()

	for b := 0; b < cfg.Blocks; b++ {
		n, err := c.Rows(b)
		if err != nil || n != 0 {
			t.Fatalf("Rows(%d)=(%d,%v) want=(0,nil)", b, n, err)
		}
	}
	kvAppendPair(t, c, cfg.Blocks, cfg.AttnDim(), 0)
	kvAppendPair(t, c, cfg.Blocks, cfg.AttnDim(), 1)
	for b := 0; b < cfg.Blocks; b++ {
		n, err := c.Rows(b)
		if err != nil || n != 2 {
			t.Fatalf("Rows(%d)=(%d,%v) want=(2,nil)", b, n, err)
		}
	}
	// Rows 与 ReadK/ReadV 的行数必须一致（半行不计数）。
	if err := c.AppendK(0, kvVec(0, 2, cfg.AttnDim())); err != nil {
		t.Fatalf("AppendK: %v", err)
	}
	if n, err := c.Rows(0); err != nil || n != 2 {
		t.Fatalf("半行不得计入 Rows：got=(%d,%v) want=(2,nil)", n, err)
	}
}

// ---- 双上限：行数 ----

func TestKVCacheMaxTokensLimit(t *testing.T) {
	cfg := route2plan.DemoTinyConfig()
	cfg.MaxTokens = 2
	c := kvMustNew(t, cfg)
	defer c.Release()
	dim := cfg.AttnDim()

	kvAppendPair(t, c, cfg.Blocks, dim, 0)
	kvAppendPair(t, c, cfg.Blocks, dim, 1)
	if got := c.Tokens(); got != 2 {
		t.Fatalf("Tokens=%d want=2", got)
	}

	// 第三行：先撞行数上限，且不得静默截断。
	err := c.AppendK(0, kvVec(0, 2, dim))
	if !errors.Is(err, ErrKVCacheFull) {
		t.Fatalf("超出 MaxTokens 应报 ErrKVCacheFull，got=%v", err)
	}
	if got := c.Tokens(); got != 2 {
		t.Fatalf("超限后 Tokens=%d want=2（不得截断/覆盖）", got)
	}
	for b := 0; b < cfg.Blocks; b++ {
		k := kvReadK(t, c, b)
		if len(k) != 2 {
			t.Fatalf("block %d 超限后行数 %d want=2（不得静默截断）", b, len(k))
		}
		for i, want := range kvVec(b, 0, dim) {
			if k[0][i] != want {
				t.Fatalf("block %d 第 0 行被截断/覆盖：元素 %d got=%v want=%v", b, i, k[0][i], want)
			}
		}
		for i, want := range kvVec(b, 1, dim) {
			if k[1][i] != want {
				t.Fatalf("block %d 第 1 行被截断/覆盖：元素 %d got=%v want=%v", b, i, k[1][i], want)
			}
		}
	}
	if c.pending {
		t.Fatal("被拒的 AppendK 不应留下半行 K")
	}
}

// ---- 双上限：字节 ----

func TestKVCacheBytesLimit(t *testing.T) {
	// 行上限放宽到 8192；每个 token 全块字节 = 2*4*32*8 = 2048，
	// 故 8 MiB 的字节上限会在第 4097 行（下标 4096）先于行上限触发。
	cfg := route2plan.DemoTinyConfig()
	cfg.MaxTokens = 8192
	c := kvMustNew(t, cfg)
	defer c.Release()
	dim := cfg.AttnDim()

	perToken := int64(2) * int64(cfg.Blocks) * int64(dim) * int64(kvFloat64Bytes)
	if perToken != 2048 {
		t.Fatalf("每 token 全块字节=%d want=2048（算式约定变更需同步本用例）", perToken)
	}
	limitTokens := int(kvMaxBytes / perToken) // 4096：恰好等于上限的最后一行为合法
	for tok := 0; tok < limitTokens; tok++ {
		kvAppendPair(t, c, cfg.Blocks, dim, tok)
	}
	if got, want := c.Tokens(), limitTokens; got != want {
		t.Fatalf("Tokens=%d want=%d", got, want)
	}
	if got, want := c.Bytes(), kvMaxBytes; got != want {
		t.Fatalf("Bytes=%d want=%d（满载恰等于上限时须放行）", got, want)
	}

	err := c.AppendK(0, kvVec(0, limitTokens, dim))
	if !errors.Is(err, ErrKVCacheBytesExceeded) {
		t.Fatalf("超出 kvMaxBytes 应报 ErrKVCacheBytesExceeded，got=%v", err)
	}
	if got := c.Tokens(); got != limitTokens {
		t.Fatalf("超限后 Tokens=%d want=%d（不得静默截断）", got, limitTokens)
	}
	if got := len(kvReadK(t, c, 0)); got != limitTokens {
		t.Fatalf("超限后行数=%d want=%d（不得静默截断）", got, limitTokens)
	}
	last := kvReadK(t, c, 0)
	for i, want := range kvVec(0, limitTokens-1, dim) {
		if last[limitTokens-1][i] != want {
			t.Fatalf("末行被覆盖：元素 %d got=%v want=%v", i, last[limitTokens-1][i], want)
		}
	}
	if c.pending {
		t.Fatal("被拒的 AppendK 不应留下半行 K")
	}
}

// ---- 容量算式 ----

func TestKVCacheBytesFormulaAtFullLoad(t *testing.T) {
	cfg := route2plan.DemoTinyConfig() // Blocks=4, Dim=32, MaxTokens=128
	c := kvMustNew(t, cfg)
	defer c.Release()

	for tok := 0; tok < cfg.MaxTokens; tok++ {
		kvAppendPair(t, c, cfg.Blocks, cfg.AttnDim(), tok)
	}
	// 2 · Blocks · tokens · (Heads*HeadDim) · 8 = 2*4*128*32*8 = 262144（256 KiB）
	const want int64 = 2 * 4 * 128 * 32 * 8
	if got := c.Bytes(); got != want {
		t.Fatalf("满载 Bytes=%d want=%d", got, want)
	}
	if got := c.Tokens(); got != cfg.MaxTokens {
		t.Fatalf("满载 Tokens=%d want=%d", got, cfg.MaxTokens)
	}
	// 再追加一行必撞行上限（双上限先到先生效：此处行上限先到）。
	if err := c.AppendK(0, kvVec(0, cfg.MaxTokens, cfg.AttnDim())); !errors.Is(err, ErrKVCacheFull) {
		t.Fatalf("满载后应报 ErrKVCacheFull，got=%v", err)
	}
}

// ---- Reset / Release 的逐元素清零 ----

func TestKVCacheResetZeroesElements(t *testing.T) {
	cfg := route2plan.DemoTinyConfig()
	c := kvMustNew(t, cfg)
	defer c.Release()

	kvAppendPair(t, c, cfg.Blocks, cfg.AttnDim(), 0)
	kvAppendPair(t, c, cfg.Blocks, cfg.AttnDim(), 1)
	kvAppendPair(t, c, cfg.Blocks, cfg.AttnDim(), 2)
	if _, err := c.AdvanceTurn(); err != nil {
		t.Fatalf("AdvanceTurn: %v", err)
	}
	if got := c.Turn(); got != 1 {
		t.Fatalf("Turn=%d want=1", got)
	}
	// 预留下半行：Reset 也必须把它清掉。
	if err := c.AppendK(0, kvVec(0, 3, cfg.AttnDim())); err != nil {
		t.Fatalf("AppendK: %v", err)
	}
	// 记住底层数组（含 cap 区间内已用过的行），Reset 之后回头验清零。
	held := make([][][]float64, cfg.Blocks)
	for b := 0; b < cfg.Blocks; b++ {
		used := c.layers[b].k[:cap(c.layers[b].k)]
		held[b] = make([][]float64, len(used))
		copy(held[b], used)
	}

	c.Reset()

	if got := c.Tokens(); got != 0 {
		t.Fatalf("Reset 后 Tokens=%d want=0", got)
	}
	if got := c.Turn(); got != 0 {
		t.Fatalf("Reset 后 Turn=%d want=0", got)
	}
	if got := c.Bytes(); got != 0 {
		t.Fatalf("Reset 后 Bytes=%d want=0", got)
	}
	if c.pending || c.pendingBlock != -1 {
		t.Fatalf("Reset 后仍残留待配对状态 pending=%v block=%d", c.pending, c.pendingBlock)
	}
	// 逐元素断言：不是只断言行数归零。
	for b := 0; b < cfg.Blocks; b++ {
		kvAssertZeroed(t, "Reset 后 K 残留（含半行）", held[b])
		kvAssertZeroed(t, "Reset 后 K(len 区间)", c.layers[b].k)
		kvAssertZeroed(t, "Reset 后 V(len 区间)", c.layers[b].v)
		if len(c.layers[b].k) != 0 || len(c.layers[b].v) != 0 {
			t.Fatalf("block %d: Reset 后行数 %d/%d want 0/0", b, len(c.layers[b].k), len(c.layers[b].v))
		}
		if got := len(kvReadK(t, c, b)); got != 0 {
			t.Fatalf("Reset 后 ReadK(block=%d) 行数=%d want=0", b, got)
		}
	}

	// 清零后可复用：容量保留，重新追加值正确。
	kvAppendPair(t, c, cfg.Blocks, cfg.AttnDim(), 0)
	if got := c.Tokens(); got != 1 {
		t.Fatalf("复用后 Tokens=%d want=1", got)
	}
	for i, want := range kvVec(1, 0, cfg.AttnDim()) {
		if got := kvReadK(t, c, 1)[0][i]; got != want {
			t.Fatalf("复用后元素 %d got=%v want=%v", i, got, want)
		}
	}
}

func TestKVCacheReleaseZeroesElementsAndFailClosed(t *testing.T) {
	cfg := route2plan.DemoTinyConfig()
	c := kvMustNew(t, cfg)

	kvAppendPair(t, c, cfg.Blocks, cfg.AttnDim(), 0)
	kvAppendPair(t, c, cfg.Blocks, cfg.AttnDim(), 1)
	// 再留一个半行：Release 也必须把它清掉。
	if err := c.AppendK(2, kvVec(2, 2, cfg.AttnDim())); err != nil {
		t.Fatalf("AppendK: %v", err)
	}
	// 记住底层数组，Release 之后回头验清零。
	heldK := make([][][]float64, cfg.Blocks)
	heldV := make([][][]float64, cfg.Blocks)
	for b := 0; b < cfg.Blocks; b++ {
		heldK[b] = make([][]float64, len(c.layers[b].k))
		copy(heldK[b], c.layers[b].k)
		heldV[b] = make([][]float64, len(c.layers[b].v))
		copy(heldV[b], c.layers[b].v)
	}

	c.Release()

	for b := 0; b < cfg.Blocks; b++ {
		kvAssertZeroed(t, "Release 后 K 残留", heldK[b])
		kvAssertZeroed(t, "Release 后 V 残留", heldV[b])
	}
	if c.layers != nil {
		t.Fatal("Release 后应丢弃层切片引用")
	}

	// 释放后所有方法 fail-closed，不 panic。
	if err := c.AppendK(0, kvVec(0, 0, cfg.AttnDim())); !errors.Is(err, ErrKVCacheReleased) {
		t.Fatalf("释放后 AppendK 应报 ErrKVCacheReleased，got=%v", err)
	}
	if err := c.AppendV(0, kvVec(0, 0, cfg.AttnDim())); !errors.Is(err, ErrKVCacheReleased) {
		t.Fatalf("释放后 AppendV 应报 ErrKVCacheReleased，got=%v", err)
	}
	if _, err := c.AdvanceTurn(); !errors.Is(err, ErrKVCacheReleased) {
		t.Fatalf("释放后 AdvanceTurn 应报 ErrKVCacheReleased，got=%v", err)
	}
	if err := c.CheckAligned(); !errors.Is(err, ErrKVCacheReleased) {
		t.Fatalf("释放后 CheckAligned 应报 ErrKVCacheReleased，got=%v", err)
	}
	if _, err := c.Rows(0); !errors.Is(err, ErrKVCacheReleased) {
		t.Fatalf("释放后 Rows 应报 ErrKVCacheReleased，got=%v", err)
	}
	if got := c.Tokens(); got != 0 {
		t.Fatalf("释放后 Tokens=%d want=0", got)
	}
	if got := c.Bytes(); got != 0 {
		t.Fatalf("释放后 Bytes=%d want=0", got)
	}
	if got := c.Turn(); got != 0 {
		t.Fatalf("释放后 Turn=%d want=0", got)
	}
	for _, blk := range []int{0, 1, cfg.Blocks - 1} {
		rows, err := c.ReadK(blk)
		if !errors.Is(err, ErrKVCacheReleased) {
			t.Fatalf("释放后 ReadK(%d) 应报 ErrKVCacheReleased，got=%v", blk, err)
		}
		if rows != nil {
			t.Fatalf("释放后 ReadK(%d) 应返回 nil 切片，got=%v", blk, rows)
		}
		rows, err = c.ReadV(blk)
		if !errors.Is(err, ErrKVCacheReleased) {
			t.Fatalf("释放后 ReadV(%d) 应报 ErrKVCacheReleased，got=%v", blk, err)
		}
		if rows != nil {
			t.Fatalf("释放后 ReadV(%d) 应返回 nil 切片，got=%v", blk, rows)
		}
	}
	// 幂等：重复 Reset / Release 不得 panic。
	c.Reset()
	c.Release()
}

// ---- turn ----

func TestKVCacheTurnAdvance(t *testing.T) {
	cfg := route2plan.DemoTinyConfig()
	c := kvMustNew(t, cfg)
	defer c.Release()

	if got := c.Turn(); got != 0 {
		t.Fatalf("初始 Turn=%d want=0", got)
	}
	for want := uint32(1); want <= 3; want++ {
		kvAppendPair(t, c, cfg.Blocks, cfg.AttnDim(), int(want))
		got, err := c.AdvanceTurn()
		if err != nil {
			t.Fatalf("AdvanceTurn: %v", err)
		}
		if got != want {
			t.Fatalf("AdvanceTurn=%d want=%d", got, want)
		}
	}
	// 跨 turn 的行是累加的（KV cache 的全部意义所在）。
	if got, want := c.Tokens(), 3; got != want {
		t.Fatalf("跨 turn 累加后 Tokens=%d want=%d", got, want)
	}
}

// ---- 并发（-race）----

func TestKVCacheConcurrentReadWrite(t *testing.T) {
	cfg := route2plan.DemoTinyConfig()
	c := kvMustNew(t, cfg)
	defer c.Release()

	const readers = 4
	const rounds = 200

	var wg sync.WaitGroup

	// 单个写者：模拟 recompute 路径按 block 顺序成对追加。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for tok := 0; tok < cfg.MaxTokens; tok++ {
			for b := 0; b < cfg.Blocks; b++ {
				if err := c.AppendK(b, kvVec(b, tok, cfg.AttnDim())); err != nil {
					t.Errorf("并发 AppendK: %v", err)
					return
				}
				if err := c.AppendV(b, kvVec(b, tok, cfg.AttnDim())); err != nil {
					t.Errorf("并发 AppendV: %v", err)
					return
				}
			}
		}
	}()

	// 多个读者：在锁外对快照做浮点运算，并**就地改写**返回值（验证快照独立）。
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func(r int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				b := (r + i) % cfg.Blocks
				k, errK := c.ReadK(b)
				v, errV := c.ReadV(b)
				if errK != nil || errV != nil {
					t.Errorf("并发 ReadK/ReadV: %v %v", errK, errV)
					return
				}
				var sum float64
				for tk := range k {
					for j := range k[tk] {
						sum += k[tk][j] + v[tk][j]
						k[tk][j] = 0 // 就地改写快照
					}
				}
				_ = sum
				_ = c.Tokens()
				_ = c.Bytes()
				// ReadK 与 ReadV 是两次独立快照，中间写者可能又追加了几行，
				// 故只能断言单调性：k 的行数不得多于稍后读到的 v 的行数
				// （同一次快照内 K/V 行数恒等，由 TestKVCacheKVPairingEnforced 与
				// TestKVCacheConcurrentAppendersStayConsistent 断言）。
				if len(k) > len(v) {
					t.Errorf("block %d: K 行数 %d 多于稍后读到的 V 行数 %d", b, len(k), len(v))
					return
				}
				if n := c.Tokens(); len(v) > n {
					t.Errorf("block %d: 读到 %d 行 > Tokens=%d", b, len(v), n)
					return
				}
			}
		}(r)
	}
	wg.Wait()

	if got, want := c.Tokens(), cfg.MaxTokens; got != want {
		t.Fatalf("并发追加后 Tokens=%d want=%d", got, want)
	}
	// 读者的就地改写不得污染 cache。
	for b := 0; b < cfg.Blocks; b++ {
		k := kvReadK(t, c, b)
		for tk := 0; tk < cfg.MaxTokens; tk++ {
			for i, want := range kvVec(b, tk, cfg.AttnDim()) {
				if k[tk][i] != want {
					t.Fatalf("block %d token %d 元素 %d 被读者改写污染：got=%v want=%v", b, tk, i, k[tk][i], want)
				}
			}
		}
	}
}

func TestKVCacheConcurrentAppendersStayConsistent(t *testing.T) {
	cfg := route2plan.DemoTinyConfig()
	c := kvMustNew(t, cfg)
	defer c.Release()

	// 多个写者并发追加：本结构不承诺「并发追加都能成功」（成对协议要求串行），
	// 但必须承诺：不 panic、只返回哨兵错误、且内部状态恒满足下列不变式（K-run/V-run 语义）：
	//   - 每个 block：len(k) >= len(v)（V 绝不先于配对 K 落定）；
	//   - 只有 pendingBlock 允许 len(k) > len(v)，且其差恰为全局 pendingCount；
	//   - tokens == 各 block 中 len(v) 的最大值。
	const writers = 4
	const perWriter = 50
	var wg sync.WaitGroup
	kvOK := func(err error) bool {
		return err == nil || errors.Is(err, ErrKVNotPaired) ||
			errors.Is(err, ErrKVCacheFull) || errors.Is(err, ErrKVCacheBytesExceeded)
	}
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				b := (w + i) % cfg.Blocks
				if err := c.AppendK(b, kvVec(b, i, cfg.AttnDim())); !kvOK(err) {
					t.Errorf("AppendK 非预期错误: %v", err)
					return
				} else if err != nil {
					continue
				}
				if err := c.AppendV(b, kvVec(b, i, cfg.AttnDim())); !kvOK(err) {
					t.Errorf("AppendV 非预期错误: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	c.mu.Lock()
	defer c.mu.Unlock()
	maxV := 0
	totalDiff := 0
	for b := 0; b < cfg.Blocks; b++ {
		lk, lv := len(c.layers[b].k), len(c.layers[b].v)
		if lk < lv {
			t.Fatalf("block %d: K 行数 %d < V 行数 %d（V 先于配对 K 落定）", b, lk, lv)
		}
		if d := lk - lv; d > 0 {
			if !c.pending || c.pendingBlock != b {
				t.Fatalf("block %d: 有 %d 行未配对 K，但 pending=%v pendingBlock=%d",
					b, d, c.pending, c.pendingBlock)
			}
			totalDiff += d
		}
		if lv > maxV {
			maxV = lv
		}
	}
	if maxV != c.tokens {
		t.Fatalf("tokens=%d 与各 block 最大行数 %d 不自洽", c.tokens, maxV)
	}
	if c.pendingCount != totalDiff {
		t.Fatalf("pendingCount=%d 与各 block 未配对 K 总数 %d 不自洽", c.pendingCount, totalDiff)
	}
	if c.pending && (c.pendingBlock < 0 || c.pendingBlock >= cfg.Blocks) {
		t.Fatalf("待配对 block 号 %d 越界", c.pendingBlock)
	}
	// run 闭合（无未配对 K）时，所有 block 的 K/V 行数必须严格相等（attention 不错位的前提）。
	if !c.pending {
		for b := 0; b < cfg.Blocks; b++ {
			if len(c.layers[b].k) != len(c.layers[b].v) {
				t.Fatalf("block %d: run 闭合后 K/V 行数仍不等 %d vs %d", b, len(c.layers[b].k), len(c.layers[b].v))
			}
		}
	}
}
