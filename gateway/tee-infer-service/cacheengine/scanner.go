package cacheengine

import (
	"errors"
	"time"
)

// ErrClassifierUnavailable 分类器不可用哨兵错误。
var ErrClassifierUnavailable = errors.New("cache: classifier unavailable")

// FastScanner 读时快审接口（§7.2）。
// err 非空 = 分类器不可用（fail-closed）。
type FastScanner interface {
	Scan(text string) (ScanVerdict, error)
}

// stubScanner 桩实现（默认）：始终返回 ErrClassifierUnavailable → fail-closed。
// 生产环境应注入真正的 L1 分类器（outputguard 的 AC 自动机）。
type stubScanner struct{}

func (s *stubScanner) Scan(text string) (ScanVerdict, error) {
	return ScanVerdict{}, ErrClassifierUnavailable
}

// readFastCheck 读时快审实现（§7.2，唯一实现入口）。
// 返回 (allow, action, verdict)。
// - allow=false 且 action="block" → 直接拒答
// - allow=false 且 action="treat_as_miss" → 当作未命中
// - allow=true → 通过
func (e *engine) readFastCheck(entry *Entry, guardVer string) (bool, string, ScanVerdict) {
	if !e.cfg.Guard.ReadFastCheck {
		return true, "", ScanVerdict{Allow: true}
	}

	// 版本不一致 → 当作未命中（词库更新后旧缓存不被复用）
	if entry.GuardVer != guardVer {
		e.stats.observeReadFastCheck("version_mismatch")
		return false, "treat_as_miss", ScanVerdict{Allow: false, Reason: "version_mismatch"}
	}

	// 负向条目不做快审
	if entry.Kind == KindNegative {
		return true, "", ScanVerdict{Allow: true}
	}

	// 调用扫描器（§9.1 #10：快审耗时直方图）
	start := time.Now()
	v, err := e.scanner.Scan(entry.Text)
	e.stats.observeExtraDuration("read_fast_check", time.Since(start))
	if err != nil {
		// 分类器不可用 → fail-closed（当作未命中，同时记错误）
		e.stats.observeReadFastCheck("error")
		return false, "treat_as_miss", ScanVerdict{Allow: false, Reason: "scanner_error"}
	}

	if !v.Allow {
		action := e.cfg.Guard.ReadFastCheckAction
		if action == "" {
			action = "treat_as_miss"
		}
		e.stats.observeReadFastCheck("block")
		return false, action, v
	}

	return true, "", v
}
