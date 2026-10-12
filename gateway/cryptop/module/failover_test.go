package cryptopmodule

// failover_test.go —— FailoverManager / FailoverBackend 测试（P1-5 M5，D-6/GM2-08/R-S3-9）。
//
// 策略：以 MockBackend + FailHealth 模拟 Down，HealthInterval=0（不启动周期循环），
// 手动调用 Probe() 推进状态机，保证确定性。

import (
	"bytes"
	"errors"
	"testing"
)

// probeN 连续 Probe n 次，模拟周期探针推进（判 Down 需连续 HealthFailCount 次失败，见 failover.go）。
func probeN(m *FailoverManager, n int) {
	for i := 0; i < n; i++ {
		m.Probe()
	}
}

// newFailoverPair 构造主/备 MockBackend（均已 Init）与未启动的管理器。
func newFailoverPair(t *testing.T, mode string) (*FailoverManager, *MockBackend, *MockBackend) {
	t.Helper()
	primary := NewMockBackend()
	cfg := DefaultConfig()
	cfg.Backend = BackendMock
	cfg.FailoverMode = mode
	if mode == FailoverDegrade {
		cfg.DegradeAck = true // R-S3-3：degrade 须显式确认
	}
	if err := primary.Init(cfg); err != nil {
		t.Fatalf("primary Init: %v", err)
	}
	// fail_closed 模式无备（符合生产装配：NeedsBackup(fail_closed)=false）。
	// 注意：经接口传 typed-nil（*MockBackend(nil)）会使接口非 nil，故用真 nil 接口。
	var backup *MockBackend
	var backupBackend ModuleBackend
	if mode != FailoverFailClosed {
		backup = NewMockBackend()
		if err := backup.Init(cfg); err != nil {
			t.Fatalf("backup Init: %v", err)
		}
		backupBackend = backup
	}
	m := NewFailoverManager(primary, backupBackend, FailoverConfigFrom(cfg), nil)
	t.Cleanup(func() {
		_ = primary.Close()
		if backup != nil {
			_ = backup.Close()
		}
	})
	return m, primary, backup
}

func TestFailoverFailClosedMode(t *testing.T) {
	m, primary, _ := newFailoverPair(t, FailoverFailClosed)
	primary.FailHealth = true // 主 Down
	probeN(m, m.cfg.HealthFailCount)
	if m.State() != StateClosed {
		t.Fatalf("fail_closed 主 Down 应 StateClosed，got %s", m.State())
	}
	if _, _, err := m.Active(); err == nil {
		t.Fatal("fail_closed 应返回 ErrModuleUnavailable")
	}
}

func TestFailoverSwitchToBackup(t *testing.T) {
	m, primary, backup := newFailoverPair(t, FailoverFailover)
	primary.FailHealth = true
	probeN(m, m.cfg.HealthFailCount)
	if m.State() != StateSwitched {
		t.Fatalf("failover 主 Down 应 StateSwitched，got %s", m.State())
	}
	b, peer, err := m.Active()
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if peer != PeerBackup || b != ModuleBackend(backup) {
		t.Fatalf("Active 应返回备模块，got peer=%s", peer)
	}
	// 主恢复 → 默认不自动回切（AutoSwitchBack=false）。
	primary.FailHealth = false
	m.Probe()
	if m.State() != StateSwitched {
		t.Fatalf("默认不自动回切，应仍 StateSwitched，got %s", m.State())
	}
}

func TestFailoverNoBackupFailClosed(t *testing.T) {
	primary := NewMockBackend()
	cfg := DefaultConfig()
	cfg.Backend = BackendMock
	cfg.FailoverMode = FailoverFailover
	if err := primary.Init(cfg); err != nil {
		t.Fatalf("primary Init: %v", err)
	}
	// 无备：backup=nil。
	m := NewFailoverManager(primary, nil, FailoverConfigFrom(cfg), nil)
	t.Cleanup(func() { _ = primary.Close() })
	primary.FailHealth = true
	probeN(m, m.cfg.HealthFailCount)
	if m.State() != StateClosed {
		t.Fatalf("failover 无备且主 Down 应 StateClosed，got %s", m.State())
	}
	if _, _, err := m.Active(); err == nil {
		t.Fatal("应返回 ErrModuleUnavailable")
	}
}

func TestFailoverDegradeWithBackup(t *testing.T) {
	m, primary, backup := newFailoverPair(t, FailoverDegrade)
	primary.FailHealth = true
	probeN(m, m.cfg.HealthFailCount)
	if m.State() != StateDegraded {
		t.Fatalf("degrade 主 Down 应 StateDegraded，got %s", m.State())
	}
	b, peer, err := m.Active()
	if err != nil {
		t.Fatalf("degrade 有备应可用: %v", err)
	}
	if peer != PeerBackup || b != ModuleBackend(backup) {
		t.Fatalf("degrade 应切到备，got peer=%s", peer)
	}
}

func TestFailoverDegradeNoBackup(t *testing.T) {
	primary := NewMockBackend()
	cfg := DefaultConfig()
	cfg.Backend = BackendMock
	cfg.FailoverMode = FailoverDegrade
	cfg.DegradeAck = true // R-S3-3：degrade 须显式确认
	if err := primary.Init(cfg); err != nil {
		t.Fatalf("primary Init: %v", err)
	}
	m := NewFailoverManager(primary, nil, FailoverConfigFrom(cfg), nil)
	t.Cleanup(func() { _ = primary.Close() })
	primary.FailHealth = true
	probeN(m, m.cfg.HealthFailCount)
	if m.State() != StateDegraded {
		t.Fatalf("degrade 无备主 Down 应 StateDegraded（模块层 fail-closed），got %s", m.State())
	}
	if _, _, err := m.Active(); err == nil {
		t.Fatal("degrade 无备仍应拒绝服务（真正软件降级属 Provider 层）")
	}
}

func TestFailoverAutoSwitchBack(t *testing.T) {
	m, primary, _ := newFailoverPair(t, FailoverFailover)
	m.cfg.AutoSwitchBack = true
	m.cfg.SwitchBackCooldown = 0
	m.cfg.SwitchBackHealthyCount = 2
	m.cfg.HealthFailCount = 2

	// 主健康 → 主在用。
	m.Probe()
	if m.State() != StateNormal {
		t.Fatalf("初始应 Normal，got %s", m.State())
	}
	// 主 Down → 切备（连续 2 次探活失败）。
	primary.FailHealth = true
	probeN(m, m.cfg.HealthFailCount)
	if m.State() != StateSwitched {
		t.Fatalf("主 Down 应 Switched，got %s", m.State())
	}
	// 主恢复：连续健康达标前不回切。
	primary.FailHealth = false
	m.Probe()
	if m.State() != StateSwitched {
		t.Fatalf("达标前不应回切，got %s", m.State())
	}
	// 再探一次（连续健康达标）→ 回切主。
	m.Probe()
	if m.State() != StateNormal {
		t.Fatalf("达标后应回切 Normal，got %s", m.State())
	}
	b, peer, err := m.Active()
	if err != nil || peer != PeerPrimary || b != ModuleBackend(primary) {
		t.Fatalf("回切后 Active 应为主，got peer=%s err=%v", peer, err)
	}
}

func TestFailoverBreakerTripsToBackup(t *testing.T) {
	m, primary, backup := newFailoverPair(t, FailoverFailover)
	m.cfg.BreakerThreshold = 2
	m.cfg.HealthFailCount = 5 // 健康探针不触发，仅熔断触发
	m.Probe()                 // 初始正常：主在用

	// 主运算连续失败（FailSeal），Health 仍 OK。
	primary.FailSeal = errors.New("inject seal failure")
	for i := 0; i < m.cfg.BreakerThreshold+1; i++ {
		if _, err := primary.Seal(KeyRef("x"), []byte("n"), []byte("pt"), nil); err == nil {
			t.Fatalf("seal 应失败（probe %d）", i)
		}
		m.ReportOpError(PeerPrimary)
	}
	// 熔断触发后需一次 Probe 重算状态。
	m.Probe()
	if m.State() != StateSwitched {
		t.Fatalf("熔断触发应切备，got %s", m.State())
	}
	b, peer, err := m.Active()
	if err != nil || peer != PeerBackup || b != ModuleBackend(backup) {
		t.Fatalf("熔断后 Active 应为备，got peer=%s err=%v", peer, err)
	}
}

func TestFailoverBackendDelegates(t *testing.T) {
	m, primary, backup := newFailoverPair(t, FailoverFailover)
	m.Probe() // 主在用
	fb := NewFailoverBackend(m)

	// 正常委派到主。
	key := bytes.Repeat([]byte{0x11}, 16)
	tok, err := fb.ImportKey("sm4-128", key, "k1")
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	// 备模块预置同一密钥（模拟主备密钥同步，R-S3-7 前置）。
	if _, err := backup.ImportKey("sm4-128", key, "k1"); err != nil {
		t.Fatalf("backup ImportKey: %v", err)
	}
	nonce := bytes.Repeat([]byte{0x02}, 12)
	ct, err := fb.Seal(tok, nonce, []byte("hello"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	pt, err := fb.Open(tok, nonce, ct, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, []byte("hello")) {
		t.Fatal("Open 应还原明文")
	}

	// 主 Down → 运算自动路由到备（fail-closed 之外）。
	primary.FailHealth = true
	probeN(m, m.cfg.HealthFailCount)
	if m.State() != StateSwitched {
		t.Fatalf("应已切备，got %s", m.State())
	}
	// 用同一 token 在备上再封（mock 按 alias 重新导入，结果可解）。
	ct2, err := fb.Seal(tok, nonce, []byte("world"), nil)
	if err != nil {
		t.Fatalf("切备后 Seal 应成功: %v", err)
	}
	pt2, err := fb.Open(tok, nonce, ct2, nil)
	if err != nil {
		t.Fatalf("切备后 Open 应成功: %v", err)
	}
	if !bytes.Equal(pt2, []byte("world")) {
		t.Fatal("切备后 Open 应还原明文")
	}
}
