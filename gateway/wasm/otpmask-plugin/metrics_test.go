package main

// W-1 metrics 单测：hostcall 守卫下计数 no-op 不 panic；计数器命名正确。
// TestMain 置 metricsHostGuard=true——go:wasmimport 在宿主测试进程不可调用，
// 全包测试均在守卫下运行（与 streamdone_test 纯逻辑策略一致）。

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	metricsHostGuard = true
	os.Exit(m.Run())
}

func TestMetricIncrGuardedNoop(t *testing.T) {
	// 守卫下 incr 必须为安全 no-op（不触发 hostcall / 不 panic）。
	for _, c := range []*pwCounter{metricRequests, metricFailClosed, metricDecryptError, metricKeysIssued, metricKeysDeleted} {
		c.incr()
		c.incr()
	}
}

func TestMetricNames(t *testing.T) {
	want := map[string]string{
		"otpmask_request_total":       metricRequests.name,
		"otpmask_fail_closed_total":   metricFailClosed.name,
		"otpmask_decrypt_error_total": metricDecryptError.name,
		"otpmask_keys_issued_total":   metricKeysIssued.name,
		"otpmask_keys_deleted_total":  metricKeysDeleted.name,
	}
	for name, got := range want {
		if name != got {
			t.Fatalf("计数器命名不符: want %q got %q", name, got)
		}
	}
}
