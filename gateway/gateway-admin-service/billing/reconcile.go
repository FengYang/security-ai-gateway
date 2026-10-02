package billing

import (
	"context"
	"fmt"
	"time"
)

// ---------- L2 对账（T5/T13，§6.12） ----------

// NetMeteringReader 计量侧净量读取器（tee-infer 审计链净量三元组）。
// 由调用方注入（P0 可复用 pull 源聚合，或直接读审计）。
type NetMeteringReader interface {
	// NetAggregate 返回某租户某区间（闭区间 dayFrom..dayTo）的净量。
	// 返回 tokens_in_net / tokens_out_net / retry_tokens（与账本同口径 A-42）。
	NetAggregate(tenant, dayFrom, dayTo string) (NetTotals, error)
}

// Reconciler L2 对账器（账本净量 vs 计量侧净量）。
type Reconciler struct {
	ledger *sqliteLedgerStore
	reader NetMeteringReader
	// alertRatio 差异率告警阈值（默认 0.001 = 0.1%，R-20；仅用于分级，不改变"拒出账"硬门禁）
	alertRatio float64
}

// NewReconciler 构造对账器。reader 为 nil 时 L2 直接通过（未接入计量侧的降级模式）。
func NewReconciler(ledger *sqliteLedgerStore, reader NetMeteringReader, alertRatio float64) *Reconciler {
	return &Reconciler{ledger: ledger, reader: reader, alertRatio: alertRatio}
}

// NewReconcilerForStore 构造绑定 Store 的对账器（供 main 接线 S-4；包外无法引用账本具体类型）。
// reader 为 nil 时 L2 直接通过（降级）。
func NewReconcilerForStore(store Store, reader NetMeteringReader, alertRatio float64) *Reconciler {
	var l *sqliteLedgerStore
	if store != nil {
		if c, ok := store.Ledger().(*sqliteLedgerStore); ok {
			l = c
		}
	}
	return &Reconciler{ledger: l, reader: reader, alertRatio: alertRatio}
}

// L2Result 对账结果。
type L2Result struct {
	Diff      int64   // 差异绝对值（入/出 token + 请求数 三项差之和）
	Ratio     float64 // 差异率 = diff / max(1, 计量侧三元组总量)
	Pass      bool    // 零容差：diff == 0
	ShouldFrz bool    // ratio > alertRatio → 冻结候选（A-22）
}

// L2 执行对账（零容差判据 M1）。
func (r *Reconciler) L2(tenant, dayFrom, dayTo string) (L2Result, error) {
	if r.reader == nil || r.ledger == nil {
		return L2Result{Pass: true}, nil // 降级：无计量侧可比 / 账本不可用
	}
	ledgerNet, err := r.ledger.SumNet(tenant, dayFrom, dayTo)
	if err != nil {
		return L2Result{}, err
	}
	remoteNet, err := r.reader.NetAggregate(tenant, dayFrom, dayTo)
	if err != nil {
		return L2Result{}, fmt.Errorf("billing: reconcile read metering: %w", err)
	}

	// 净量差异三元组（§6.12.2）：入 / 出 / 请求数。
	// **retry 不入本对账**（另列 RetryToks，由 M9 单独校验平台成本口径）。
	diffIn := abs64(ledgerNet.TokensIn - remoteNet.TokensIn)
	diffOut := abs64(ledgerNet.TokensOut - remoteNet.TokensOut)
	diffReq := abs64(ledgerNet.Requests - remoteNet.Requests)
	diff := diffIn + diffOut + diffReq

	remoteTotal := remoteNet.TokensIn + remoteNet.TokensOut + remoteNet.Requests
	if remoteTotal <= 0 {
		remoteTotal = 1
	}
	ratio := float64(diff) / float64(remoteTotal)

	return L2Result{
		Diff:      diff,
		Ratio:     ratio,
		Pass:      diff == 0,             // 零容差硬门禁
		ShouldFrz: ratio > r.alertRatio,  // A-22：>0.1% 冻结候选
	}, nil
}

func abs64(a int64) int64 {
	if a < 0 {
		return -a
	}
	return a
}

// ---------- 计量侧读取器（L2 数据源，§6.12.2） ----------

// pullNetReader 以 PullSource 为计量侧数据源，实现 NetMeteringReader（审计链侧净量三元组）。
type pullNetReader struct {
	src     PullSource
	timeout time.Duration
}

// NewPullNetReader 构造 L2 计量侧读取器（复用拉取源）。
// 注：NetMeteringReader 接口无 ctx，内部自设超时（默认 30s）。
func NewPullNetReader(src PullSource) NetMeteringReader {
	return &pullNetReader{src: src, timeout: 30 * time.Second}
}

// NetAggregate 拉取 [dayFrom, dayTo]（UTC+8 自然日闭区间）并取该租户的净量三元组。
// 租户在窗口内零用量 → 返回零值（对账侧按 0 处理）。
func (r *pullNetReader) NetAggregate(tenant, dayFrom, dayTo string) (NetTotals, error) {
	if r.src == nil {
		return NetTotals{}, fmt.Errorf("billing: net reader: pull source is nil")
	}
	fromNs, toNs, err := dayRangeNs(dayFrom, dayTo)
	if err != nil {
		return NetTotals{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	win, err := r.src.Pull(ctx, fromNs, toNs)
	if err != nil {
		return NetTotals{}, err
	}
	if win == nil || win.Tenants == nil {
		return NetTotals{}, nil
	}
	ta := win.Tenants[tenant]
	if ta == nil {
		return NetTotals{}, nil // 该租户零用量
	}
	return NetTotals{
		TokensIn:  ta.TokensIn,
		TokensOut: ta.TokensOut,
		RetryToks: ta.RetryToks,
		Requests:  ta.Requests,
	}, nil
}

// dayRangeNs 把 UTC+8 自然日闭区间 [dayFrom, dayTo] 转为 UTC 纳秒左闭右开区间。
func dayRangeNs(dayFrom, dayTo string) (int64, int64, error) {
	loc := time.FixedZone("UTC+8", utc8Offset)
	from, err := time.ParseInLocation(dayLayout, dayFrom, loc)
	if err != nil {
		return 0, 0, fmt.Errorf("billing: net reader: bad dayFrom %q: %w", dayFrom, err)
	}
	to, err := time.ParseInLocation(dayLayout, dayTo, loc)
	if err != nil {
		return 0, 0, fmt.Errorf("billing: net reader: bad dayTo %q: %w", dayTo, err)
	}
	return from.UnixNano(), to.AddDate(0, 0, 1).UnixNano(), nil
}
