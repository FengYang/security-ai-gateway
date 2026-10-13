// P0-1 修复防回归测试：
//   - sentences_total counter 真实对外暴露且计数正确；
//   - PrometheusRule 引用的每个 otpmask_ 指标必须是 tee-infer-service 真实定义的指标
//     （拦截 P0-1 根因：yaml 监控代码里根本不存在的指标）；
//   - 旧缺陷特征不得回潮（output_guard_overload 幽灵 reason、requests 按 category 分组）。
package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// knownExposedMetrics metrics.go 中 tee-infer-service 实际定义的全部 otpmask_ 指标名。
// 新增/删除指标时须同步更新本清单（测试失败即提醒同步，防 yaml 与代码脱节）。
var knownExposedMetrics = map[string]bool{
	"otpmask_inference_requests_total": true,
	"otpmask_tokens_in_total":          true,
	"otpmask_tokens_out_total":         true,
	"otpmask_denies_total":             true,
	"otpmask_quota_denies_total":       true,
	"otpmask_shadow_reports_total":     true,
	"otpmask_guard_classifier_total":   true,
	"otpmask_guard_failclosed_total":   true,
	"otpmask_guard_sidecar_healthy":    true,
	"otpmask_audit_retention_days":     true,
	"otpmask_key_issue_total":          true,
	"otpmask_reconcile_mismatch_total": true,
	"otpmask_shadow_would_reject_total": true,
	"otpmask_reconcile_diff_tokens":    true,
	"otpmask_billing_blocked_total":    true,
	"otpmask_billing_suppressed_total": true,
	"otpmask_attest_token_traffic_total": true,
	"otpmask_recompute_ops_total":      true,
	"otpmask_recompute_duration_ms_total": true,
	"otpmask_output_guard_requests_total":                 true,
	"otpmask_output_guard_l1_hit_total":                   true,
	"otpmask_output_guard_would_reject_total":             true,
	"otpmask_output_guard_blocked_total":                  true,
	"otpmask_output_guard_masked_total":                   true,
	"otpmask_output_guard_forced_split_total":             true,
	"otpmask_output_guard_unmapped_total":                 true,
	"otpmask_output_guard_degraded_total":                 true,
	"otpmask_output_guard_policy_rollback_total":          true,
	"otpmask_output_guard_policy_activate_total":          true,
	"otpmask_output_guard_l2_call_total":                  true,
	"otpmask_output_guard_l2_only_hit_total":              true,
	"otpmask_output_guard_buffer_queue_depth":             true,
	"otpmask_output_guard_buffer_full_total":              true,
	"otpmask_output_guard_sentences_total":                true,
	"otpmask_output_guard_l2_duration_seconds":            true,
	"otpmask_output_guard_l2_cascade_ratio":               true,
	"otpmask_output_guard_failclosed_sentences_ratio":     true,
	"otpmask_output_guard_inflight_bytes":                 true,
	"otpmask_output_guard_mode":                           true,
	"otpmask_output_guard_policy_version":                 true,
	"otpmask_output_guard_restart_detected":               true,
	"otpmask_output_guard_c_first_chunk_skip_l2_total":    true,
	"otpmask_content_label_enabled":                       true,
	"otpmask_content_label_requests_total":                true,
	"otpmask_content_label_frames_total":                  true,
	"otpmask_billing_blocked":                             true,
	"otpmask_audit_events":                                true,
	"otpmask_worm_write_failed_total":                     true, // P1-8 M-7 审计 WORM 写入失败（source=tee，真实暴露）
	"otpmask_reconcile_last_run_timestamp_seconds":        true,
	// ---- P1-7 全流量审计改造（T7，MOD5 容量管控）新增附加指标族 ----
	"otpmask_audit_bytes":                     true,
	"otpmask_audit_records_tier":              true,
	"otpmask_audit_sampled_total":             true,
	"otpmask_audit_write_failures_total":      true,
	"otpmask_audit_archive_failures_total":    true,
	"otpmask_audit_duplicate_requests_total":  true,
	"otpmask_audit_redact_truncated_total":    true,
	"otpmask_audit_report_dropped_total":      true,
	"otpmask_audit_unregistered_result_total": true,
}

// externalMetricsAllowed 非本服务暴露、但允许在告警规则中引用的外部指标。
var externalMetricsAllowed = map[string]bool{
	"kube_pod_container_status_restarts_total": true, // kube-state-metrics
}

var (
	otpmaskMetricRE = regexp.MustCompile(`otpmask_[a-z_]+`)
	kubeMetricRE    = regexp.MustCompile(`kube_[a-z_]+`)
)

// TestOGSentencesTotalExposed 判定单元 counter 真实暴露且计数正确。
func TestOGSentencesTotalExposed(t *testing.T) {
	m := newMetrics()
	a := newAuditChain()

	og, err := newOutputGuard(
		outputGuardConfig{
			Mode: outputGuardShadow,
			// 默认 strategy=A → sentence unit，一句一个判定单元
		},
		fakeL2Classifier{}, fakeL2Classifier{}, m, a, "acme", "req-sent-total",
	)
	if err != nil {
		t.Fatalf("newOutputGuard: %v", err)
	}
	if og == nil {
		t.Fatal("og 不应为 nil")
	}

	rec := &frameRecorder{}
	// 三个完整句子（句末标点触发判定单元）
	for _, s := range []string{"第一句话。", "第二句话。", "第三句话。"} {
		if err := og.Process(s, rec.emit); err != nil {
			t.Fatalf("Process: %v", err)
		}
	}
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	var buf bytes.Buffer
	m.render(&buf, 0)
	body := buf.String()
	if !strings.Contains(body, "# TYPE otpmask_output_guard_sentences_total counter") {
		t.Fatalf("应暴露 sentences_total counter\n---\n%s", body)
	}
	if !strings.Contains(body, "otpmask_output_guard_sentences_total 3") {
		t.Fatalf("sentences_total 计数应为 3\n---\n%s", body)
	}
}

// TestPrometheusRuleReferencedMetricsExist 告警规则引用的指标必须真实存在。
func TestPrometheusRuleReferencedMetricsExist(t *testing.T) {
	raw := readPrometheusRule(t)

	// otpmask_ 指标：逐一核对是否本服务定义
	for _, name := range unique(otpmaskMetricRE.FindAllString(string(raw), -1)) {
		if !knownExposedMetrics[name] {
			t.Errorf("告警规则引用了 tee-infer 未定义的指标 %q（P0-1 根因复现）", name)
		}
	}
	// kube_ 指标：须在允许的外部清单内
	for _, name := range unique(kubeMetricRE.FindAllString(string(raw), -1)) {
		if !externalMetricsAllowed[name] {
			t.Errorf("告警规则引用了未登记的外部指标 %q", name)
		}
	}
}

// TestPrometheusRuleOldDefectsGone 旧缺陷特征不得回潮。
func TestPrometheusRuleOldDefectsGone(t *testing.T) {
	raw := string(readPrometheusRule(t))

	// 幽灵 reason：output_guard_overload 全代码库无写入点
	if strings.Contains(raw, "output_guard_overload") {
		t.Error("不得再引用幽灵 reason=output_guard_overload（无写入点，告警永不触发）")
	}
	// 截断率告警分母 requests_total 无 category 标签，不得对其 by(category) 分组
	if regexp.MustCompile(`requests_total\{[^}]*\}\[[^\]]+\]\)\s*by\s*\(category\)`).MatchString(raw) {
		t.Error("不得对 requests_total 按 category 分组（该指标无 category 标签，向量匹配为空）")
	}
	// 最小流量门应存在（防小样本噪声）
	if !strings.Contains(raw, "> 0.5") {
		t.Error("截断率告警应保留最小流量门 0.5 rps")
	}
}

// TestPrometheusRuleAlertsComplete 告警线齐备（含后备规则与低流量绝对计数兜底）且有对应 runbook 标注。
func TestPrometheusRuleAlertsComplete(t *testing.T) {
	raw := string(readPrometheusRule(t))
	for _, alert := range []string{
		"OutputGuardBlockRateHigh",
		"OutputGuardBlockRateCritical",
		"OutputGuardBlockBurstLowTraffic", // P1-3：低流量绝对计数兜底（比率告警流量门盲区）
		"OutputGuardPodRestarting",
		"OutputGuardPodCrashLoop",
		"OutputGuardPodRestartingFallback", // 无 kube-state-metrics 环境后备
		"OutputGuardSentenceDegradationHigh",
		"OutputGuardSlotsFullTerminating",
	} {
		if !strings.Contains(raw, "- alert: "+alert) {
			t.Errorf("缺失告警 %s", alert)
		}
	}
}

// ---- 辅助函数 ----

func readPrometheusRule(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "output-guard", "GA-输出侧-告警规则-PrometheusRule.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		// 该 yaml 属 .gitignore 白名单之外的本地资产（不入库）：在无此文件的环境
		// （CI／他人 clone／部署单位）应跳过而非失败——避免把"环境缺件"误报为代码缺陷；
		// 本地与交付环境仍执行完整强校验。
		if errors.Is(err, os.ErrNotExist) {
			t.Skipf("跳过：未找到本地 PrometheusRule 资产 %s（该文件不入库）", path)
		}
		t.Fatalf("读取 PrometheusRule 失败: %v", err)
	}
	return raw
}

func unique(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// TestAuditCapacityRuleReferencedMetricsExist P1-7 T7 容量告警规则引用的指标必须真实存在
// （防 P0-1 根因：yaml 引用代码里根本不存在的指标）。本文件为交付物（入库），缺失即视为缺陷。
func TestAuditCapacityRuleReferencedMetricsExist(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "monitoring", "audit-capacity-rules.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 P1-7 审计容量告警规则失败（该文件须随交付入库）: %v", err)
	}
	for _, name := range unique(otpmaskMetricRE.FindAllString(string(raw), -1)) {
		if !knownExposedMetrics[name] {
			t.Errorf("审计容量告警规则引用了 tee-infer 未定义的指标 %q", name)
		}
	}
	for _, name := range unique(kubeMetricRE.FindAllString(string(raw), -1)) {
		if !externalMetricsAllowed[name] {
			t.Errorf("审计容量告警规则引用了未登记的外部指标 %q", name)
		}
	}
}

// TestAuditCapacityRuleAlertsComplete P1-7 T7 七类告警线齐备（§8 集成清单 / 文档 v1.12）。
func TestAuditCapacityRuleAlertsComplete(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "monitoring", "audit-capacity-rules.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 P1-7 审计容量告警规则失败: %v", err)
	}
	for _, alert := range []string{
		"AuditCapacityWarning",        // ① 容量水位 70%
		"AuditCapacityCritical",       // ① 容量水位 85%
		"AuditCapacityPage",           // ① 容量水位 95%
		"AuditWriteFailure",           // ② WORM 写失败
		"AuditChainBroken",            // ③ 链断裂
		"AuditArchiveFailure",         // ④ 归档失败
		"AuditDuplicateRateAnomaly",   // ⑤ 重复率异常
		"AuditReportDropped",          // ⑥ 上报丢弃率 >0（A3-14）
		"AuditUnregisteredResult",     // ⑦ 非登记 result（A3-20）
	} {
		if !strings.Contains(string(raw), "- alert: "+alert) {
			t.Errorf("缺失审计容量告警 %s", alert)
		}
	}
}
