package cryptopsvc

// metrics_module_test.go —— S3 模块指标测试（P1-5 M5，附录 B cryptop_module_*）。
//
// 覆盖：
//   - 渲染单测（单后端）：fakeModuleBackend 无 Snapshot 方法 → 走 backend.Health() 路径；
//   - 渲染单测（主备）：fakeFailoverBackend 带 Snapshot → 走快照路径（双 peer + 切换计数）；
//   - 装配单测：mock 后端经 NewServer 走真实接线（bindModule + SetOpObserver）；
//   - 档位单测：intl 档不发射任何 cryptop_module_* 序列。

import (
	"strings"
	"testing"

	"security-ai-gateway/gateway/cryptop"
	cryptopmodule "security-ai-gateway/gateway/cryptop/module"
)

// fakeModuleBackend 测试替身（单后端语义）：仅实现指标层经可选接口消费的方法。
// 嵌入 nil ModuleBackend——未用到的方法一旦被调用即 panic，防止假通过。
// 注意：本类型**不实现** Snapshot()，指标层据此走"无主备"分支。
type fakeModuleBackend struct {
	cryptopmodule.ModuleBackend
	slot   string
	health cryptopmodule.HealthLevel
	stats  cryptopmodule.PoolStats
	rand   cryptopmodule.RandHealthStatus
}

func (f *fakeModuleBackend) Health() cryptopmodule.HealthLevel          { return f.health }
func (f *fakeModuleBackend) PoolStats() cryptopmodule.PoolStats         { return f.stats }
func (f *fakeModuleBackend) SlotLabel() string                          { return f.slot }
func (f *fakeModuleBackend) RandHealth() cryptopmodule.RandHealthStatus { return f.rand }

// fakeFailoverBackend 测试替身（主备语义）：在 fakeModuleBackend 基础上实现
// Snapshot()，指标层据此走快照分支（每 peer 一条 health + 切换计数）。
type fakeFailoverBackend struct {
	fakeModuleBackend
	snap cryptopmodule.FailoverSnapshot
}

func (f *fakeFailoverBackend) Snapshot() cryptopmodule.FailoverSnapshot { return f.snap }

// renderWith 以指定后端渲染指标文本（不建 Server，直接测指标层）。
func renderWith(t *testing.T, b cryptopmodule.ModuleBackend, ops map[string]float64) string {
	t.Helper()
	m := newMetrics()
	m.bindModule(b)
	for op, sec := range ops {
		m.ObserveModuleOp(op, sec)
	}
	var sb strings.Builder
	m.render(&sb)
	return sb.String()
}

func TestModuleMetricsSingleBackendRender(t *testing.T) {
	b := &fakeModuleBackend{
		slot:   "0",
		health: cryptopmodule.HealthOK,
		stats:  cryptopmodule.PoolStats{Max: 4, InUse: 2, Idle: 2},
		rand:   cryptopmodule.RandHealthPassed,
	}
	raw := renderWith(t, b, map[string]float64{"rand": 0.0002, "seal": 0.0015})

	// rand_health（附录 B required；1=通过）。
	if !strings.Contains(raw, `cryptop_module_rand_health{slot="0"} 1`) {
		t.Fatalf("缺 rand_health 序列:\n%s", raw)
	}
	// health（单后端：仅 primary 一条）。
	if !strings.Contains(raw, `cryptop_module_health{peer="primary",slot="0"} 1`) {
		t.Fatalf("缺 health 序列:\n%s", raw)
	}
	if strings.Contains(raw, `peer="backup"`) {
		t.Fatalf("单后端不应有 backup 序列:\n%s", raw)
	}
	// sessions_active = InUse。
	if !strings.Contains(raw, `cryptop_module_sessions_active{slot="0"} 2`) {
		t.Fatalf("sessions_active 应为 InUse=2:\n%s", raw)
	}
	// latency 直方图（op + slot 标签；_count/_sum 与 _bucket 同标签集）。
	if !strings.Contains(raw, `cryptop_module_latency_seconds_count{op="rand",slot="0"} 1`) {
		t.Fatalf("latency rand 计数缺失:\n%s", raw)
	}
	if !strings.Contains(raw, `cryptop_module_latency_seconds_count{op="seal",slot="0"} 1`) {
		t.Fatalf("latency seal 计数缺失:\n%s", raw)
	}
	if !strings.Contains(raw, `cryptop_module_latency_seconds_sum{op="seal",slot="0"} 0.0015`) {
		t.Fatalf("latency seal sum 异常:\n%s", raw)
	}
	// 单后端无 failover 装配 → 无 failover_total。
	if strings.Contains(raw, "cryptop_module_failover_total") {
		t.Fatalf("单后端不应有 failover_total:\n%s", raw)
	}
}

func TestModuleMetricsFailoverRender(t *testing.T) {
	b := &fakeFailoverBackend{
		fakeModuleBackend: fakeModuleBackend{
			slot:   "unknown",
			health: cryptopmodule.HealthOK, // 有快照时不用（快照优先）
			rand:   cryptopmodule.RandHealthUnknown,
		},
		snap: cryptopmodule.FailoverSnapshot{
			State:        cryptopmodule.StateSwitched,
			ActivePeer:   cryptopmodule.PeerBackup,
			PrimaryLevel: cryptopmodule.HealthDown,
			BackupLevel:  cryptopmodule.HealthOK,
			HasBackup:    true,
			PrimarySlot:  "0",
			BackupSlot:   "1",
			FailoverCounts: map[string]int64{
				"primary|backup|primary_down": 2,
				"backup|primary|switchback":   1,
			},
		},
	}
	raw := renderWith(t, b, nil)

	// 每 peer 一条 health（各带自身槽位）。
	if !strings.Contains(raw, `cryptop_module_health{peer="primary",slot="0"} 0`) {
		t.Fatalf("primary health 应为 0（down）:\n%s", raw)
	}
	if !strings.Contains(raw, `cryptop_module_health{peer="backup",slot="1"} 1`) {
		t.Fatalf("backup health 应为 1（ok）:\n%s", raw)
	}
	// failover_total：from_slot/to_slot 标签值承载 peer 角色（附录 B 命名沿用）。
	if !strings.Contains(raw, `cryptop_module_failover_total{from_slot="primary",to_slot="backup",reason="primary_down"} 2`) {
		t.Fatalf("failover_total primary_down=2 缺失:\n%s", raw)
	}
	if !strings.Contains(raw, `cryptop_module_failover_total{from_slot="backup",to_slot="primary",reason="switchback"} 1`) {
		t.Fatalf("failover_total switchback=1 缺失:\n%s", raw)
	}
	// rand_health 零值（未检）→ -1（M4-2 既定语义：1=通过/0=失败/-1=尚未自检，
	// 供上层区分"未检"与"失败"，不把未检误报成失败）。
	if !strings.Contains(raw, `cryptop_module_rand_health{slot="unknown"} -1`) {
		t.Fatalf("rand_health 未检状态应为 -1:\n%s", raw)
	}
}

func TestModuleMetricsIntlProfileNoSeries(t *testing.T) {
	s, _, _ := newTestServer(t, cryptop.ProfileIntl)
	raw := renderMetrics(t, s)
	if strings.Contains(raw, "cryptop_module_") {
		t.Fatalf("intl 档不应发射任何 cryptop_module_* 序列:\n%s", raw)
	}
}

// TestModuleMetricsWiringMockBackend 装配接线（真 NewServer + mock 后端）：
// bindModule + SetOpObserver 生效；/v1/rand 过后 latency 直方图出现 rand 序列。
func TestModuleMetricsWiringMockBackend(t *testing.T) {
	s, ts, _ := newModuleTestServer(t)
	if code, _ := postJSON(t, ts, "/v1/rand", map[string]any{"n": 16}, nil); code != 200 {
		t.Fatalf("/v1/rand HTTP %d", code)
	}
	raw := renderMetrics(t, s)
	// mock 有 PoolStats + SlotLabel（无 RandHealth / 无主备快照）。
	if !strings.Contains(raw, `cryptop_module_health{peer="primary",slot="mock"} 1`) {
		t.Fatalf("health 序列缺失:\n%s", raw)
	}
	if !strings.Contains(raw, `cryptop_module_sessions_active{slot="mock"}`) {
		t.Fatalf("sessions_active 序列缺失:\n%s", raw)
	}
	if !strings.Contains(raw, `cryptop_module_latency_seconds_count{op="rand",slot="mock"} 1`) {
		t.Fatalf("latency rand 序列缺失（SetOpObserver 未生效？）:\n%s", raw)
	}
	// mock 无随机数自检语义 → 无 rand_health 序列（如实，不冒充）。
	if strings.Contains(raw, "cryptop_module_rand_health") {
		t.Fatalf("mock 不应发射 rand_health:\n%s", raw)
	}
}
