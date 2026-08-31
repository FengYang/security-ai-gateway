// Package secagg 实现对齐 Bonawitz et al. CCS 2017 的安全聚合协议
// （OTP-Mask：成对掩码 + 自掩码双掩码 + Shamir 秘密共享 + 掉线恢复）。
//
// 实现范围（v1.0 GA 就绪）：
// - 阶段：AdvertiseKeys → ShareSeeds → MaskedInput → ConsistencyCheck → Unmask（Round 0/1/2/3/4）
// - 安全模型：恶意敌手（签名通告 + 种子承诺校验 + 身份绑定 + 会话重放防护）
// - 传输：内存同步模型 + gRPC 远程模型（PartyDriver 依赖倒置）
// - 变体说明：论文对"用户 ECDH 私钥"做秘密共享以恢复扰动；本实现改为
// 对"每对用户共享的扰动种子"做秘密共享（种子 = SHA-256(ECDH 共享密钥)，
// 泄露种子不泄露私钥，安全性质等价且实现可行）。
package secagg

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
)

// DefaultModulus 量化域 R = 2^32（对齐论文"R ≥ 2³² 时精度损失可忽略"）。
const DefaultModulus = 1 << 32

// MinParties 最小参与方数量。
const MinParties = 3

// SessionIDLen 会话 ID 字节长度（128 位随机性）。
const SessionIDLen = 16

// Round 协议阶段（论文 Round 编号）。
type Round int

const (
	Round0Advertise Round = iota
	Round1ShareSeeds
	Round2MaskedInput
	Round3Consistency
	Round4Unmask
)

func (r Round) String() string {
	switch r {
	case Round0Advertise:
		return "Round0Advertise"
	case Round1ShareSeeds:
		return "Round1ShareSeeds"
	case Round2MaskedInput:
		return "Round2MaskedInput"
	case Round3Consistency:
		return "Round3Consistency"
	case Round4Unmask:
		return "Round4Unmask"
	}
	return fmt.Sprintf("Round(%d)", int(r))
}

// Config 描述一次安全聚合会话的参数。
type Config struct {
	// NumParties 参与方数量 n。
	NumParties int
	// Threshold 秘密共享阈值 t（须满足 t > n/2，论文掉线容忍与安全权衡）。
	Threshold int
	// Modulus 量化域 R（输入与聚合和的取值空间 [0, R)）。
	Modulus uint64
	// Dimension 输入向量维度 k。
	Dimension int
	// SessionID 会话唯一标识，用于重放防护与签名绑定。
	// 由聚合服务器生成并分发，所有签名与承诺均绑定到此 ID。
	SessionID []byte
	// TrustedSignKeys 可信身份公钥表（ID → Ed25519 公钥）。
	// 聚合服务器用此表校验各参与方的通告签名；为空时降级为半诚实模型
	// （不校验签名，仅校验身份一致性）。
	TrustedSignKeys map[int]ed25519.PublicKey
}

// Validate 校验配置参数（非法输入显式报错）。
func (c Config) Validate() error {
	if c.NumParties < MinParties {
		return fmt.Errorf("secagg: 参与方数量 %d 小于最小值 %d", c.NumParties, MinParties)
	}
	if c.Threshold <= c.NumParties/2 {
		return fmt.Errorf("secagg: 阈值 t=%d 必须 > n/2=%d", c.Threshold, c.NumParties/2)
	}
	if c.Threshold > c.NumParties {
		return fmt.Errorf("secagg: 阈值 t=%d 超过参与方数量 %d", c.Threshold, c.NumParties)
	}
	if c.Modulus < 2 {
		return fmt.Errorf("secagg: 模数 R=%d 必须 ≥ 2", c.Modulus)
	}
	if c.Dimension < 1 {
		return fmt.Errorf("secagg: 维度 %d 必须 ≥ 1", c.Dimension)
	}
	if c.TrustedSignKeys != nil {
		for id, pk := range c.TrustedSignKeys {
			if id < 0 || id >= c.NumParties {
				return fmt.Errorf("secagg: 可信密钥表 ID %d 越界", id)
			}
			if len(pk) != ed25519.PublicKeySize {
				return fmt.Errorf("secagg: 可信密钥表 ID %d 公钥长度非法", id)
			}
		}
	}
	return nil
}

// ErrInsufficientParties 掉线比例超过容忍上限时返回的安全中止错误。
var ErrInsufficientParties = errors.New("secagg: 在线参与方不足阈值，协议安全中止")

// ErrInvalidInput 非法输入（空参与方、向量越界等）。
var ErrInvalidInput = errors.New("secagg: 非法输入")

// ErrSignatureVerification 签名校验失败（身份伪造或消息篡改）。
var ErrSignatureVerification = errors.New("secagg: 通告签名验证失败")

// ErrCommitmentMismatch 种子承诺不匹配（恶意份额或重构错误）。
var ErrCommitmentMismatch = errors.New("secagg: 种子承诺校验失败")

// Result 聚合输出。
type Result struct {
	// Sum 为在线用户输入之和（模 R），维度为 k。
	Sum []uint64
	// OnlineIDs 最终参与聚合的用户 ID（按升序）。
	OnlineIDs []int
	// Rounds 实际执行的轮次。
	Rounds int
}

// PartyInput 参与方输入（x_u ∈ [0, R)^k）。
type PartyInput struct {
	ID int
	X  []uint64
}

// Validate 校验输入向量范围。
func (in PartyInput) Validate(mod uint64) error {
	if in.ID < 0 {
		return fmt.Errorf("secagg: 参与方 ID %d 非法", in.ID)
	}
	for i, v := range in.X {
		if v >= mod {
			return fmt.Errorf("secagg: 参与方 %d 输入分量 %d 越界 %d >= %d", in.ID, i, v, mod)
		}
	}
	return nil
}

// ctxKey 上下文内部类型（避免键冲突）。
type ctxKey int

const partyCtxKey ctxKey = 1

// withContext 预留：v0.1 同步驱动暂不消费 ctx，接口签名保留以便扩展。
var _ = context.Background
