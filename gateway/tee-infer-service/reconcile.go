// reconcile.go - 审计与计费对账
package main

import (
	"log"
	"sync"
	"time"
)

const reconcileInterval = 5 * time.Minute

const reconcileMismatchThreshold = 1

type reconciler struct {
	audit   *auditChain
	usage   map[string]*usageRecord
	mu      *sync.Mutex
	metrics *otpmaskMetrics
}

func newReconciler(a *auditChain, usage map[string]*usageRecord, mu *sync.Mutex, m *otpmaskMetrics) *reconciler {
	return &reconciler{audit: a, usage: usage, mu: mu, metrics: m}
}

// reconcileOnce 执行一次对账
func (r *reconciler) reconcileOnce(now time.Time) bool {
	auditInfer := r.audit.countByAction("infer")
	r.mu.Lock()
	var usageRequests int
	for _, rec := range r.usage {
		usageRequests += rec.Requests
	}
	r.mu.Unlock()

	diff := auditInfer - usageRequests
	if diff < 0 {
		diff = -diff
	}
	if diff > reconcileMismatchThreshold {
		r.metrics.incReconcileMismatch(int64(diff))
		log.Printf("[reconcile] 审计-计费偏差告警: 审计 infer=%d 用量 requests=%d 偏差=%d", auditInfer, usageRequests, diff)
		return false
	}
	return true
}

// run 定时对账
func (r *reconciler) run() {
	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()
	for range ticker.C {
		r.reconcileOnce(time.Now())
	}
}
