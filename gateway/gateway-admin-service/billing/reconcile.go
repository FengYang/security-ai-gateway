package billing

import (
	"fmt"
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

// L2Result 对账结果。
type L2Result struct {
	Diff      int64   // 差异绝对值（token）
	Ratio     float64 // 差异率 = diff / max(1, 计量侧总量)
	Pass      bool    // 零容差：diff == 0
	ShouldFrz bool    // ratio > alertRatio → 冻结候选（A-22）
}

// L2 执行对账（零容差判据 M1）。
func (r *Reconciler) L2(tenant, dayFrom, dayTo string) (L2Result, error) {
	if r.reader == nil {
		return L2Result{Pass: true}, nil // 降级：无计量侧可比
	}
	ledgerNet, err := r.ledger.SumNet(tenant, dayFrom, dayTo)
	if err != nil {
		return L2Result{}, err
	}
	remoteNet, err := r.reader.NetAggregate(tenant, dayFrom, dayTo)
	if err != nil {
		return L2Result{}, fmt.Errorf("billing: reconcile read metering: %w", err)
	}

	// 净量差异（入 + 出 + retry 三项各自差之和，取绝对值汇总）
	diffIn := abs64(ledgerNet.TokensIn - remoteNet.TokensIn)
	diffOut := abs64(ledgerNet.TokensOut - remoteNet.TokensOut)
	diffRetry := abs64(ledgerNet.RetryToks - remoteNet.RetryToks)
	diff := diffIn + diffOut + diffRetry

	remoteTotal := remoteNet.TokensIn + remoteNet.TokensOut + remoteNet.RetryToks
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
