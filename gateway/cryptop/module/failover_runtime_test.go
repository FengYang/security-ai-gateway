//go:build pkcs11

// failover_runtime_test.go —— V-7 故障注入切换 < 30s 运行时演练（M5-a 故障切换 + §7.6）。
//
// 运行前提（.248 联调机，真实 SoftHSM PKCS#11 HSM）：
//
//	P11_LIVE=1                      启用（未设置则 Skip，不以 mock 冒充真机）
//	P11_LIVE_LIB=/usr/lib/softhsm/libsofthsm2.so
//	P11_LIVE_PIN=0000               口令（测试内以 env: 载体传入，验证 R-S3-2 链路）
//	SOFTHSM2_CONF=/path/to/v7/softhsm2.conf   自建双 token 配置（slot0=primary, slot1=backup）
//	FAIL_INTERVAL=3s                健康探针周期（默认 3s；生产建议 3-5s，见 §6.5）
//	FAIL_COUNT=3                    连续失败判定 down（默认 3）
//
// 场景：主/备均为真实 SoftHSM PKCS#11 后端（slot0 / slot1 两个独立 token）。
// 故障注入 = 对主模块 Close()（模拟 HSM 模块崩溃/卸载：C_Finalize → closed=true →
// Health() 返回 Down）。度量从注入到 FailoverManager 切到备且备真实 Rand 成功
// 的耗时，断言 < 30s（V-7 业务中断 < 30s 判据）。
//
// 注：这是"模块进程崩溃/卸载"形态的故障注入，等价 HSM 不可达的可观测结果
// （HealthDown）。其它形态（token 丢失/网络断开）经同一 Health() 判定路径生效。
package cryptopmodule

import (
	"os"
	"strconv"
	"testing"
	"time"
)

// v7LiveConfig 构造指向指定 slot 的真实 SoftHSM 后端配置。
// 主/备使用不同库副本（P11_LIVE_LIB / P11_LIVE_LIB_BACKUP）以模拟两台独立
// HSM 模块：PKCS#11 的 C_Initialize 为进程级单例，同一 .so 二次 Initialize
// 会返回 CKR_CRYPTOKI_ALREADY_INITIALIZED（已实测），生产主备为独立 HSM/网络
// 端点故各自独立 Initialize；软件 HSM 演练以库副本等价模拟（见 §9.1 证据注）。
func v7LiveConfig(t *testing.T, slot int) *Config {
	t.Helper()
	if os.Getenv("P11_LIVE") != "1" {
		t.Skip("P11_LIVE != 1，跳过 V-7 真机演练（不以 mock 冒充真机）")
	}
	cfg := DefaultConfig()
	cfg.Backend = BackendPKCS11
	lib := envOr("P11_LIVE_LIB", "/usr/lib/softhsm/libsofthsm2.so")
	if slot == 1 {
		lib = envOr("P11_LIVE_LIB_BACKUP", lib)
	}
	cfg.LibPath = lib
	cfg.Slot = slot
	cfg.PinRef = "env:P11_LIVE_PIN"
	cfg.MaxSessions = 4
	cfg.SessionQueueSize = 2
	// SoftHSM 仅 rand 恒可用（无 SM 机制）；V-7 只验证切换时效与备真实服务，
	// RequiredMechanisms 收窄为 ["rand"]（与 M4 真机口径一致）。
	cfg.RequiredMechanisms = []string{MechRand}
	return cfg
}

func parseDurEnv(t *testing.T, key string, def time.Duration) time.Duration {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		t.Fatalf("%s=%q 非法时长: %v", key, v, err)
	}
	return d
}

func parseIntEnv(t *testing.T, key string, def int) int {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		t.Fatalf("%s=%q 非法整数: %v", key, v, err)
	}
	return n
}

// TestFailoverRuntimeSwitchWithin30s V-7 运行时演练：故障注入 → 主备切换 < 30s。
func TestFailoverRuntimeSwitchWithin30s(t *testing.T) {
	interval := parseDurEnv(t, "FAIL_INTERVAL", 3*time.Second)
	failCount := parseIntEnv(t, "FAIL_COUNT", 3)

	primaryCfg := v7LiveConfig(t, 0)
	backupCfg := v7LiveConfig(t, 1)

	primary, err := NewBackend(primaryCfg)
	if err != nil {
		t.Fatalf("NewBackend(primary slot0): %v", err)
	}
	backup, err := NewBackend(backupCfg)
	if err != nil {
		t.Fatalf("NewBackend(backup slot1): %v", err)
	}

	fm := NewFailoverManager(primary, backup, FailoverConfig{
		Mode:             FailoverFailover,
		HealthInterval:   interval,
		HealthFailCount:  failCount,
		BreakerThreshold: failCount,
	}, nil)
	fb := NewFailoverBackend(fm)
	if err := fb.Init(primaryCfg); err != nil {
		t.Fatalf("FailoverBackend.Init: %v", err)
	}
	defer func() { _ = fb.Close() }()

	// 预热：确认 normal 且主模块真实服务。
	if snap := fm.Snapshot(); snap.State != StateNormal {
		t.Fatalf("预热态应为 normal，实得 %s", snap.State)
	}
	if _, err := fb.Rand(16); err != nil {
		t.Fatalf("预热主模块 Rand 失败: %v", err)
	}

	// 注入故障：主模块崩溃/卸载（C_Finalize → closed=true → HealthDown）。
	t0 := time.Now()
	if err := primary.Close(); err != nil {
		t.Fatalf("primary.Close(故障注入): %v", err)
	}
	t.Logf("[t0=+0ms] 故障注入(主模块 Close)：simulated HSM module crash")
	if h := primary.Health(); h != HealthDown {
		t.Fatalf("注入后主 Health=%v want down", h)
	}

	// 轮询至切到备（StateSwitched）且备真实 Rand 成功。
	deadline := t0.Add(30 * time.Second)
	var lastState FailoverState
	switchedAt := time.Time{}
	probeLog := func(snap FailoverSnapshot) {
		if snap.State != lastState {
			t.Logf("[+%s] 状态→%s (activePeer=%s primaryLevel=%s backupLevel=%s)",
				time.Since(t0).Round(time.Millisecond),
				snap.State, snap.ActivePeer, snap.PrimaryLevel, snap.BackupLevel)
			lastState = snap.State
		}
	}
	for time.Now().Before(deadline) {
		snap := fm.Snapshot()
		probeLog(snap)
		if snap.State == StateSwitched {
			// 验证备模块真实服务（真实 SoftHSM 运算）。
			if _, err := fb.Rand(16); err != nil {
				t.Fatalf("切到备后 Rand 失败（业务未恢复）: %v", err)
			}
			switchedAt = time.Now()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if switchedAt.IsZero() {
		snap := fm.Snapshot()
		t.Fatalf("V-7 失败：30s 内未切到备；最后快照=%+v", snap)
	}

	elapsed := switchedAt.Sub(t0)
	t.Logf("V-7 实测：interval=%s failcount=%d 切换耗时=%s | <30s=%v",
		interval, failCount, elapsed.Round(time.Millisecond), elapsed < 30*time.Second)

	// 备持续服务验证（切换后多次调用）。
	for i := 0; i < 3; i++ {
		if _, err := fb.Rand(16); err != nil {
			t.Fatalf("切换后备模块第 %d 次 Rand 失败: %v", i+1, err)
		}
	}

	if elapsed >= 30*time.Second {
		t.Fatalf("V-7 判据失败：切换耗时 %s 超出 <30s", elapsed.Round(time.Millisecond))
	}
}
