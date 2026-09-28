// S4-4：租户处置状态机公共定义（所有构建均包含）。
// 提供 dispositionChecker 接口 + 空实现（OSS/私有化版本永远放行）。
package main

import "errors"

var (
	errBadDispositionState = errors.New("disposition state 非法（支持 warning|throttled|suspended|terminated）")
	errEmptyTenant         = errors.New("tenant 不能为空")
)

// dispositionChecker 处置检查接口（推理入口调用）。
// saas 构建由 tenantDispositionStore 实现；
// OSS/私有化构建由 nilDisposition 实现（永远放行）。
type dispositionChecker interface {
	Check(tenant string) (allowed bool, reason string)
}

// nilDisposition 空实现（默认值：永远放行，零成本。
type nilDisposition struct{}

func (nilDisposition) Check(string) (bool, string) { return true, "" }
