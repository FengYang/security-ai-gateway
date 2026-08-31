package secagg

import (
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Category 协议错误分类，供监控告警分级、重试策略与审计分流使用。
type Category int

const (
	// CategoryUnknown 未识别错误（人工排查）。
	CategoryUnknown Category = iota
	// CategoryConfig 配置/参数错误（不可重试，须修复配置）。
	CategoryConfig
	// CategoryProtocol 协议违规/恶意行为（不可重试，安全告警）。
	CategoryProtocol
	// CategoryCrypto 密码学操作失败（不可重试，检查密钥材料）。
	CategoryCrypto
	// CategoryNetwork 网络/传输错误（可重试）。
	CategoryNetwork
	// CategoryInsufficient 在线参与方不足（可重试，等待更多参与方）。
	CategoryInsufficient
)

func (c Category) String() string {
	switch c {
	case CategoryConfig:
		return "config"
	case CategoryProtocol:
		return "protocol"
	case CategoryCrypto:
		return "crypto"
	case CategoryNetwork:
		return "network"
	case CategoryInsufficient:
		return "insufficient"
	case CategoryUnknown:
		return "unknown"
	}
	return "unknown"
}

// Classify 将错误映射到分类。优先匹配哨兵错误（errors.Is），
// 其次匹配 gRPC 状态码，最后按错误文案启发式归类。
func Classify(err error) Category {
	if err == nil {
		return CategoryUnknown
	}
	switch {
	case errors.Is(err, ErrInsufficientParties):
		return CategoryInsufficient
	case errors.Is(err, ErrSignatureVerification),
		errors.Is(err, ErrCommitmentMismatch):
		return CategoryProtocol
	case errors.Is(err, ErrInvalidInput):
		return CategoryConfig
	}
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled, codes.Aborted:
			return CategoryNetwork
		case codes.InvalidArgument, codes.FailedPrecondition, codes.OutOfRange:
			return CategoryConfig
		}
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "连接"), strings.Contains(msg, "eof"),
		strings.Contains(msg, "handshake"), strings.Contains(msg, "certificate"),
		strings.Contains(msg, "证书"), strings.Contains(msg, "超时"):
		return CategoryNetwork
	case strings.Contains(msg, "解密"), strings.Contains(msg, "重构"),
		strings.Contains(msg, "密钥"), strings.Contains(msg, "份额") && !strings.Contains(msg, "不足"):
		return CategoryCrypto
	case strings.Contains(msg, "签名"), strings.Contains(msg, "承诺"),
		strings.Contains(msg, "冒充"), strings.Contains(msg, "伪造"):
		return CategoryProtocol
	}
	return CategoryUnknown
}
