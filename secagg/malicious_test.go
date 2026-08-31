package secagg

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"

	"security-ai-gateway/secagg/shares"
)

// V-01 恶意份额检测：某参与方在 unmask 时篡改在线者 b 份额，
// 重构结果与种子承诺不匹配 → 返回 ErrCommitmentMismatch（安全中止）。
func TestMaliciousShareCommitmentMismatch(t *testing.T) {
	cfg := testConfig(4, 3, 8)
	cfg.SessionID = make([]byte, SessionIDLen)
	rand.Read(cfg.SessionID)
	values := make([][]uint64, 4)
	for i := range values {
		values[i] = randVector(cfg.Modulus, 8)
	}
	parties, trusted := newSignedParties(cfg, values)
	cfg.TrustedSignKeys = trusted

	// party 0 充当恶意方：篡改 party 1 的自掩码份额
	drivers := make([]PartyDriver, 4)
	for i, p := range parties {
		if i == 0 {
			drivers[i] = &maliciousParty{party: p, tamperVictim: 1}
		} else {
			drivers[i] = p
		}
	}

	agg, err := NewAggregator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = agg.Run(drivers)
	if err == nil {
		t.Fatal("篡改份额应导致协议中止")
	}
	if !errors.Is(err, ErrCommitmentMismatch) {
		t.Fatalf("应返回 ErrCommitmentMismatch，got: %v", err)
	}
}

// V-02 承诺校验不适用场景：半诚实模式（无 TrustedSignKeys）下
// 篡改份额会导致重构出错误掩码，最终结果与正确值不一致（检测为结果差异，
// 协议不保证检测——恶意敌手模式才提供承诺校验）。
func TestCommitmentVerificationRequiresMaliciousMode(t *testing.T) {
	cfg := testConfig(4, 3, 8)
	values := make([][]uint64, 4)
	for i := range values {
		values[i] = randVector(cfg.Modulus, 8)
	}
	parties := newParties(cfg, values)
	drivers := make([]PartyDriver, 4)
	for i, p := range parties {
		if i == 0 {
			drivers[i] = &maliciousParty{party: p, tamperVictim: 1}
		} else {
			drivers[i] = p
		}
	}

	agg, _ := NewAggregator(cfg)
	res, err := agg.Run(drivers)
	if err != nil {
		t.Fatal(err)
	}
	// 半诚实模式无承诺校验：篡改产生错误结果，但协议不报错（预期行为）
	want := sumVectors(values, cfg.Modulus)
	diff := false
	for i := range want {
		if res.Sum[i] != want[i] {
			diff = true
		}
	}
	if !diff {
		t.Fatal("篡改 b 份额后结果应偏离正确和（证明篡改生效）")
	}
}

// maliciousParty 在 unmask 阶段篡改 victim 的 b 份额（Y 值 +1 mod p）。
type maliciousParty struct {
	*party
	tamperVictim int // 被篡改自掩码份额的在线者 ID
}

func (m *maliciousParty) unmask(ctx context.Context, online map[int]bool) (unmaskMsg, error) {
	msg, err := m.party.unmask(ctx, online)
	if err != nil {
		return msg, err
	}
	raw, ok := msg.SelfMaskShares[m.tamperVictim]
	if !ok {
		return msg, nil
	}
	part, err := decodePart(raw)
	if err != nil {
		return msg, err
	}
	// 篡改份额值：Y = Y + 1 mod p（保持合法份额格式，仅数值改变）
	part.Y = new(big.Int).Add(part.Y, big.NewInt(1))
	part.Y.Mod(part.Y, shares.FieldPrime())
	tampered, err := encodePart(part)
	if err != nil {
		return msg, err
	}
	msg.SelfMaskShares[m.tamperVictim] = tampered
	return msg, nil
}
