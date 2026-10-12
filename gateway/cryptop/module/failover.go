package cryptopmodule

// failover.go —— 主备故障切换 + 分级健康 + 熔断（P1-5 M5，D-6 / GM2-08 / R-S3-7 / R-S3-9）。
//
// 设计要点（务必如实，避免冒充合规）：
//   - 默认 fail-closed：模块不可用即拒绝服务，**绝不静默降级到软件实现冒充合规**（C-3 / D-6）；
//   - 仅连续 HealthFailCount 次探活失败（或熔断触发）才判 Down 并切换；Degraded 仅告警不切换；
//   - 同一时刻仅一个 active 后端（单主保证，R-S3-9）；主恢复后默认不自动回切，须显式
//     module_failover_auto_switch_back + 冷静期 + 连续健康达标（R-S3-9）；
//   - 熔断：运算连续失败计入降级判定（与探针共用阈值），与分级健康共用"连续失败"口径；
//   - degrade 模式：模块不可用时切到备（若有）；否则在模块层 fail-closed——
//     真正的"降级到 sm-software"属 Provider 层切换（M8 管理端点），此处仅暴露降级态。
//
// 装配方式：以 FailoverBackend（实现 ModuleBackend，委派给 FailoverManager.Active()）
// 包裹 moduleProvider 的后端，使 Provider 20 方法零改动获得主备/熔断能力。

import (
	"sync"
	"time"
)

// Peer 角色（主 / 备）。
type Peer string

const (
	// PeerPrimary 主模块。
	PeerPrimary Peer = "primary"
	// PeerBackup 备模块。
	PeerBackup Peer = "backup"
)

// FailoverState 全局故障切换状态（供只读端点 / 指标）。
type FailoverState int

const (
	// StateNormal 主模块在用。
	StateNormal FailoverState = iota
	// StateSwitched 已切到备模块（failover 模式）。
	StateSwitched
	// StateDegraded 降级态（degrade 模式；备在用或模块层 fail-closed）。
	StateDegraded
	// StateClosed fail-closed：拒绝服务（无可用后端）。
	StateClosed
)

// String 状态名（端点 / 指标 / 日志）。
func (s FailoverState) String() string {
	switch s {
	case StateNormal:
		return "normal"
	case StateSwitched:
		return "switched"
	case StateDegraded:
		return "degraded"
	case StateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// MetricsSink 指标 / 审计回调（避免 import 环；调用方注入真实 Prometheus 指标实现）。
type MetricsSink interface {
	// RecordHealth 上报某 peer 健康级别（调用方在标签里带 slot）。
	RecordHealth(peer string, level HealthLevel)
	// RecordFailover 上报一次主备切换（from/to ∈ {primary,backup}，reason 见代码）。
	RecordFailover(from, to, reason string)
	// RecordDegrade 上报降级开关状态（on=true 表示当前处于降级态）。
	RecordDegrade(on bool)
}

// noopSink 默认空实现（未注入真实指标时，不报错、不产出指标）。
type noopSink struct{}

func (noopSink) RecordHealth(string, HealthLevel) {}
func (noopSink) RecordFailover(string, string, string) {}
func (noopSink) RecordDegrade(bool)                   {}

// FailoverConfig 故障切换配置（由 §6.4 module_* 配置项映射）。
type FailoverConfig struct {
	Mode                   string        // FailoverFailClosed | FailoverFailover | FailoverDegrade
	HealthInterval         time.Duration // module_health_interval
	HealthFailCount        int           // module_health_fail_count
	AutoSwitchBack         bool          // module_failover_auto_switch_back
	SwitchBackCooldown     time.Duration // module_switch_back_cooldown
	SwitchBackHealthyCount int           // 回切前连续健康达标次数
	BreakerThreshold       int           // 熔断阈值（连续运算失败，默认 = HealthFailCount）
}

// FailoverManager 主备管理 + 健康状态机 + 熔断。
type FailoverManager struct {
	cfg     FailoverConfig
	primary ModuleBackend
	backup  ModuleBackend
	sink    MetricsSink

	mu                sync.RWMutex
	state             FailoverState
	activePeer        Peer
	prevActivePeer    Peer
	primaryLevel      HealthLevel
	backupLevel       HealthLevel
	primaryConsecDown int // 连续探活失败（含健康探针）
	backupConsecDown  int
	primaryOpConsec   int // 连续运算失败（熔断）
	backupOpConsec    int
	breakerPrimary    bool
	breakerBackup     bool
	switchedAt        time.Time
	healthyStreak     int // 主恢复后连续健康计数（回切判定）

	started bool
	stop    chan struct{}
	done    chan struct{}
}

// NewFailoverManager 构造故障切换管理器。
// backup 可为 nil（failover / degrade 无备时按 fail-closed 或降级态处理）。
func NewFailoverManager(primary, backup ModuleBackend, cfg FailoverConfig, sink MetricsSink) *FailoverManager {
	if cfg.HealthFailCount < 1 {
		cfg.HealthFailCount = 3
	}
	if cfg.BreakerThreshold < 1 {
		cfg.BreakerThreshold = cfg.HealthFailCount
	}
	if cfg.SwitchBackHealthyCount < 1 {
		cfg.SwitchBackHealthyCount = cfg.HealthFailCount
	}
	if sink == nil {
		sink = noopSink{}
	}
	return &FailoverManager{
		cfg:            cfg,
		primary:        primary,
		backup:         backup,
		sink:           sink,
		state:          StateNormal,
		activePeer:     PeerPrimary,
		prevActivePeer: PeerPrimary,
	}
}

// Start 启动周期探针（立即探一次；HealthInterval<=0 时仅探一次不启动循环，便于测试）。
func (m *FailoverManager) Start() {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.stop = make(chan struct{})
	m.done = make(chan struct{})
	m.mu.Unlock()

	go func() {
		defer close(m.done)
		m.Probe() // 立即探一次
		if m.cfg.HealthInterval <= 0 {
			return
		}
		ticker := time.NewTicker(m.cfg.HealthInterval)
		defer ticker.Stop()
		for {
			select {
			case <-m.stop:
				return
			case <-ticker.C:
				m.Probe()
			}
		}
	}()
}

// Stop 停止探针并等待退出。
func (m *FailoverManager) Stop() {
	m.mu.Lock()
	if !m.started {
		m.mu.Unlock()
		return
	}
	m.started = false
	close(m.stop)
	done := m.done
	m.mu.Unlock()
	<-done
}

// Probe 执行一次探针 + 状态重算（导出供测试与手动探针）。
func (m *FailoverManager) Probe() {
	m.mu.Lock()
	pl := m.primary.Health()
	if pl == HealthDown {
		m.primaryConsecDown++
	} else {
		m.primaryConsecDown = 0
	}
	m.primaryLevel = pl
	m.sink.RecordHealth(string(PeerPrimary), pl)

	if m.backup != nil {
		bl := m.backup.Health()
		if bl == HealthDown {
			m.backupConsecDown++
		} else {
			m.backupConsecDown = 0
		}
		m.backupLevel = bl
		m.sink.RecordHealth(string(PeerBackup), bl)
	}
	m.recomputeLocked()
	m.mu.Unlock()
}

// recomputeLocked 依据探测与熔断状态重算 active 后端与全局状态（调用方持 mu）。
func (m *FailoverManager) recomputeLocked() {
	primaryDown := m.primaryConsecDown >= m.cfg.HealthFailCount || m.breakerPrimary
	backupDown := m.backup == nil || m.backupConsecDown >= m.cfg.HealthFailCount || m.breakerBackup

	if !primaryDown {
		m.healthyStreak++
		if m.activePeer != PeerPrimary {
			// 已切走：满足"自动回切 + 冷静期 + 连续健康达标"才回切（R-S3-9）。
			if m.cfg.AutoSwitchBack &&
				time.Since(m.switchedAt) >= m.cfg.SwitchBackCooldown &&
				m.healthyStreak >= m.cfg.SwitchBackHealthyCount {
				m.recordSwitch(m.prevActivePeer, PeerPrimary, "switchback")
				m.activePeer = PeerPrimary
				m.state = StateNormal
				m.healthyStreak = 0
			}
			// 否则保持当前 active（不自动回切）。
		} else {
			m.activePeer = PeerPrimary
			m.state = StateNormal
		}
		m.sink.RecordDegrade(false)
		return
	}

	// 主 Down：重置健康连击计数（用于回切判定）。
	m.healthyStreak = 0
	if m.backup != nil && !backupDown {
		if m.activePeer != PeerBackup {
			m.recordSwitch(m.prevActivePeer, PeerBackup, "primary_down")
			m.switchedAt = time.Now()
		}
		m.activePeer = PeerBackup
		if m.cfg.Mode == FailoverDegrade {
			m.state = StateDegraded
			m.sink.RecordDegrade(true)
		} else {
			m.state = StateSwitched
			m.sink.RecordDegrade(false)
		}
		return
	}

	// 无健康备：模块层 fail-closed（degrade 无备时暴露"降级态"，真正的软件降级属 Provider 层切换）。
	m.activePeer = ""
	if m.cfg.Mode == FailoverDegrade {
		m.state = StateDegraded
		m.sink.RecordDegrade(true)
	} else {
		m.state = StateClosed
		m.sink.RecordDegrade(false)
	}
}

// recordSwitch 记录切换事件（仅在状态实际改变时发出，避免重复计数）。
func (m *FailoverManager) recordSwitch(from, to Peer, reason string) {
	if from == to {
		return
	}
	m.sink.RecordFailover(string(from), string(to), reason)
	m.prevActivePeer = to
}

// Active 返回当前可用后端与角色；fail-closed 无可用后端时返回 ErrModuleUnavailable。
func (m *FailoverManager) Active() (ModuleBackend, Peer, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	switch m.activePeer {
	case PeerPrimary:
		if m.primary != nil {
			return m.primary, PeerPrimary, nil
		}
	case PeerBackup:
		if m.backup != nil {
			return m.backup, PeerBackup, nil
		}
	}
	return nil, "", ErrModuleUnavailable
}

// State 当前全局故障切换状态。
func (m *FailoverManager) State() FailoverState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// PeerHealth 返回指定 peer 的最近探测级别。
func (m *FailoverManager) PeerHealth(peer Peer) HealthLevel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if peer == PeerBackup {
		return m.backupLevel
	}
	return m.primaryLevel
}

// ReportOpError 上报一次运算失败（熔断：达阈值即强制该 peer Down）。
func (m *FailoverManager) ReportOpError(peer Peer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if peer == PeerBackup {
		m.backupOpConsec++
		if m.backupOpConsec >= m.cfg.BreakerThreshold {
			m.breakerBackup = true
		}
	} else {
		m.primaryOpConsec++
		if m.primaryOpConsec >= m.cfg.BreakerThreshold {
			m.breakerPrimary = true
		}
	}
}

// ReportOpSuccess 上报一次运算成功（熔断复位）。
func (m *FailoverManager) ReportOpSuccess(peer Peer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if peer == PeerBackup {
		m.backupOpConsec = 0
		m.breakerBackup = false
	} else {
		m.primaryOpConsec = 0
		m.breakerPrimary = false
	}
}

// ---- 装配辅助（由 §6.4 配置项派生；供 cryptop 包 buildModuleProvider 使用）----

// NeedsBackup 是否需构建备模块：failover 必备；degrade 有备则切备（无备降级态 + 模块层 fail-closed）。
func NeedsBackup(c *Config) bool {
	switch c.FailoverMode {
	case FailoverFailover, FailoverDegrade:
		return c.BackupLibPath != "" || c.BackupEndpoint != ""
	default:
		return false
	}
}

// BackupConfigFrom 由主配置派生备模块配置（本地形态：库/槽位/口令；网络形态：端点 + mTLS）。
func BackupConfigFrom(c *Config) *Config {
	bc := *c
	bc.LibPath = c.BackupLibPath
	bc.Slot = c.BackupSlot
	bc.PinRef = c.BackupPinRef
	bc.BackupEndpoint = c.BackupEndpoint
	bc.BackupTLSCARef = c.BackupTLSCARef
	bc.BackupTLSCertRef = c.BackupTLSCertRef
	// 备模块不再带二级备份（防递归装配）。
	bc.BackupLibPath = ""
	bc.BackupSlot = 0
	bc.BackupPinRef = ""
	return &bc
}

// FailoverConfigFrom 由主配置映射故障切换参数。
func FailoverConfigFrom(c *Config) FailoverConfig {
	return FailoverConfig{
		Mode:                   c.FailoverMode,
		HealthInterval:         c.HealthInterval,
		HealthFailCount:        c.HealthFailCount,
		AutoSwitchBack:         c.FailoverAutoSwitchBack,
		SwitchBackCooldown:     c.SwitchBackCooldown,
		SwitchBackHealthyCount: c.HealthFailCount,
	}
}
