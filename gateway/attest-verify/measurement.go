// Package attestverify — 度量白名单校验（P1-8 T2，GAP-03）。
//
// 职责：对 TDX Quote 的 MRTD/RTMR 与白名单基线做常量时间比对，
// 支持 shadow（仅比对计数不拒绝）与 enforce（默认，不符即拒）两种灰度模式。
//
// 真完整性证据在 Quote 的 MRTD/RTMR，由验证方（attest-verify sidecar）解析；
// 本文件只负责白名单比对与配置加载，Quote 解析与签名链验证由 DcapVerifier 负责（T1）。
//
// fail-closed 原则：
//   - 配置缺失 → NewMeasurementAllowlist 报错（不静默通过）
//   - 度量项缺失（长度不符） → 拒绝
//   - 任一比对失败 → 拒绝
//
// 与既有 Allowlist（app_hash 基线）的关系：
//   - MeasurementAllowlist 是 TDX 真度量的白名单（MRTD + RTMR[0..3]）
//   - 既有 Allowlist 保留供 BuiltinVerifier 使用（mock/CI 自签协议）
//   - 两者互不影响，可分别配置
package attestverify

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
)

// MeasurementMode 度量校验模式。
type MeasurementMode int

const (
	// MeasurementModeEnforce 强制模式（默认）：度量不匹配即拒绝。
	MeasurementModeEnforce MeasurementMode = iota
	// MeasurementModeShadow 影子模式：仅比对并记录，不拒绝（白名单标定期用）。
	MeasurementModeShadow
)

// measurementHashSize TDX 度量哈希长度（SHA-384 = 48 字节）。
const measurementHashSize = 48

// MeasurementAllowlist TDX 度量白名单基线。
//
// 字段对应 TDX Quote V4 的 TdQuoteBody：
//   - mrtd  = MRTD（初始度量，48B）
//   - rtmr[0..3] = RTMR0..RTMR3（运行时度量扩展寄存器，各 48B）
//
// 线程安全：构造后只读，比对无需加锁。
type MeasurementAllowlist struct {
	mu         sync.RWMutex
	platform   string            // 平台标识（必须为 "tdx"）
	definition string            // 白名单定义版本（与字段口径绑定）
	mrtd       []byte            // MRTD，48B
	rtmr       [4][]byte         // RTMR[0..3]，各 48B
	appHash    map[string]bool   // 保留：app_hash 基线（向后兼容 BuiltinVerifier 场景）
	mode       MeasurementMode   // shadow / enforce
}

// MeasurementAllowlistConfig 配置文件结构（YAML/JSON 通用）。
//
// 示例 JSON：
//
//	{
//	  "platform": "tdx",
//	  "definition": "v1.0",
//	  "mrtd": "aabbccdd...",
//	  "rtmr": ["111...", "222...", "333...", "444..."],
//	  "app_hash": ["abc123", "def456"]
//	}
type MeasurementAllowlistConfig struct {
	Platform   string   `json:"platform"`
	Definition string   `json:"definition"`
	MRTD       string   `json:"mrtd"`
	RTMR       []string `json:"rtmr"`
	AppHash    []string `json:"app_hash,omitempty"`
}

// NewMeasurementAllowlist 从配置文件加载度量白名单。
//
// 配置缺失 / 格式非法 / 长度不符 → 报错（fail-closed，不静默通过）。
// mode 默认 enforce；传 MeasurementModeShadow 启用影子模式。
func NewMeasurementAllowlist(path string, mode MeasurementMode) (*MeasurementAllowlist, error) {
	if path == "" {
		return nil, errors.New("attestverify: 度量白名单配置路径为空")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("attestverify: 读取度量白名单配置失败: %w", err)
	}
	var cfg MeasurementAllowlistConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("attestverify: 解析度量白名单配置失败: %w", err)
	}
	return newMeasurementAllowlistFromConfig(&cfg, mode)
}

// newMeasurementAllowlistFromConfig 从配置结构构造白名单（包内复用，便于测试）。
func newMeasurementAllowlistFromConfig(cfg *MeasurementAllowlistConfig, mode MeasurementMode) (*MeasurementAllowlist, error) {
	if cfg == nil {
		return nil, errors.New("attestverify: 度量白名单配置为空")
	}
	if cfg.Platform != "tdx" {
		return nil, fmt.Errorf("attestverify: 度量白名单 platform 必须为 tdx，got %q", cfg.Platform)
	}

	mrtd, err := hex.DecodeString(cfg.MRTD)
	if err != nil {
		return nil, fmt.Errorf("attestverify: MRTD hex 解码失败: %w", err)
	}
	if len(mrtd) != measurementHashSize {
		return nil, fmt.Errorf("attestverify: MRTD 长度应为 %d 字节，got %d", measurementHashSize, len(mrtd))
	}

	if len(cfg.RTMR) != 4 {
		return nil, fmt.Errorf("attestverify: RTMR 必须为 4 项，got %d", len(cfg.RTMR))
	}
	var rtmr [4][]byte
	for i := 0; i < 4; i++ {
		b, err := hex.DecodeString(cfg.RTMR[i])
		if err != nil {
			return nil, fmt.Errorf("attestverify: RTMR[%d] hex 解码失败: %w", i, err)
		}
		if len(b) != measurementHashSize {
			return nil, fmt.Errorf("attestverify: RTMR[%d] 长度应为 %d 字节，got %d", i, measurementHashSize, len(b))
		}
		rtmr[i] = b
	}

	appHash := make(map[string]bool, len(cfg.AppHash))
	for _, h := range cfg.AppHash {
		appHash[h] = true
	}

	return &MeasurementAllowlist{
		platform:   cfg.Platform,
		definition: cfg.Definition,
		mrtd:       mrtd,
		rtmr:       rtmr,
		appHash:    appHash,
		mode:       mode,
	}, nil
}

// SetMode 动态切换校验模式（运行时热切换，影子标定期使用）。
func (a *MeasurementAllowlist) SetMode(mode MeasurementMode) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mode = mode
}

// Mode 返回当前校验模式。
func (a *MeasurementAllowlist) Mode() MeasurementMode {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.mode
}

// Definition 返回白名单定义版本。
func (a *MeasurementAllowlist) Definition() string {
	return a.definition
}

// CheckQuoteMeasurements 逐项常量时间比对 Quote 度量与白名单基线。
//
// 返回匹配成功的度量名列表；任一缺失或不符 → error。
// shadow 模式下即使不匹配也不返回 error（仅返回已匹配项），
// 调用方应通过 MeasurementMismatch 辅助函数获取不匹配详情。
//
// q = TDX Quote V4；度量字段在 q.TdQuoteBody。
func (a *MeasurementAllowlist) CheckQuoteMeasurements(q *tdxpb.QuoteV4) ([]string, error) {
	if q == nil {
		return nil, errors.New("attestverify: Quote 为空（度量校验）")
	}
	body := q.GetTdQuoteBody()
	if body == nil {
		return nil, errors.New("attestverify: Quote 缺少 TdQuoteBody（度量校验）")
	}

	matched := make([]string, 0, 5) // mrtd + rtmr0..3
	var firstErr error

	// MRTD
	mrtd := body.GetMrTd()
	if len(mrtd) != measurementHashSize {
		firstErr = fmt.Errorf("attestverify: MRTD 长度应为 %d 字节，got %d", measurementHashSize, len(mrtd))
	} else if subtle.ConstantTimeCompare(mrtd, a.mrtd) != 1 {
		firstErr = errors.New("attestverify: MRTD 与白名单基线不匹配")
	} else {
		matched = append(matched, "mrtd")
	}

	// RTMR[0..3]
	rtmrs := body.GetRtmrs()
	if firstErr == nil {
		for i := 0; i < 4; i++ {
			if i >= len(rtmrs) || len(rtmrs[i]) != measurementHashSize {
				firstErr = fmt.Errorf("attestverify: RTMR%d 缺失或长度不符", i)
				break
			}
			if subtle.ConstantTimeCompare(rtmrs[i], a.rtmr[i]) != 1 {
				firstErr = fmt.Errorf("attestverify: RTMR%d 与白名单基线不匹配", i)
				break
			}
			matched = append(matched, fmt.Sprintf("rtmr%d", i))
		}
	}

	// shadow 模式：不拒绝，仅返回已匹配项（调用方可通过 firstErr 日志告警）
	if firstErr != nil && a.mode == MeasurementModeShadow {
		return matched, nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return matched, nil
}

// ContainsAppHash app_hash 是否在白名单基线内（保留兼容 BuiltinVerifier）。
func (a *MeasurementAllowlist) ContainsAppHash(hash string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.appHash[hash]
}

// MeasurementModeFromString 字符串转模式（配置解析用）。
func MeasurementModeFromString(s string) (MeasurementMode, error) {
	switch s {
	case "", "enforce":
		return MeasurementModeEnforce, nil
	case "shadow":
		return MeasurementModeShadow, nil
	default:
		return MeasurementModeEnforce, fmt.Errorf("attestverify: 未知 measurement mode %q（应为 shadow 或 enforce）", s)
	}
}
