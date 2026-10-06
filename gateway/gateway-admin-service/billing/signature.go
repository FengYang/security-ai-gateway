package billing

import (
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// ---------- 账单签名（T7b，§7.2） ----------

// BillSigner 账单签名器（HMAC-SHA256）。
type BillSigner interface {
	// Sign 生成签名（"hmac-sha256:<hex>"）。
	Sign(b *Bill) string
	// Verify 验签（恒定时间比较；支持密钥轮换的旧密钥）。
	Verify(b *Bill) bool
}

// billSigner HMAC-SHA256 签名器实现（支持双密钥并存轮换，B-7.2-1）。
type billSigner struct {
	current []byte
	old     [][]byte // 轮换期旧密钥（仅用于验签）
}

// NewBillSigner 构造签名器。key 为当前密钥；oldKeys 为轮换期保留的旧密钥。
func NewBillSigner(key []byte, oldKeys ...[]byte) BillSigner {
	return &billSigner{current: key, old: oldKeys}
}

// canonicalBill 账单规范序列化（签名域；金额以"分"十进制，明细按 model_key 升序）。
// 覆盖：ID/TenantID/Kind/Period/Total/Currency/LedgerHead/AuditHead + 明细行。
func canonicalBill(b *Bill) []byte {
	var sb strings.Builder
	items := append([]BillItem(nil), b.Items...)
	sort.Slice(items, func(i, j int) bool { return items[i].ModelKey < items[j].ModelKey })
	fmt.Fprintf(&sb, "%s|%s|%s|%s|%d|%s|%s|%s",
		b.ID, b.TenantID, b.Kind, b.Period, int64(b.Total), b.Currency, b.LedgerHead, b.AuditHead)
	for _, it := range items {
		fmt.Fprintf(&sb, "|%s:%d:%d:%d", it.ModelKey, it.StandardTokens, it.TokensIn, int64(it.Amount))
	}
	return []byte(sb.String())
}

// signWith 生成签名（`hmac-sha256:` / `hmac-sm3:` 前缀自述算法，P0-4 §5.4.3 组⑬）。
func signWith(key []byte, b *Bill) string {
	alg := hmacAlgTag()
	mac := macByAlg(alg, key, canonicalBill(b))
	return alg + ":" + hex.EncodeToString(mac)
}

// verifyWith 按**候选签名自身的前缀**分派复算（双读：旧 `hmac-sha256:` 账单在 sm 档仍可验；
// 无前缀/未知前缀按 SHA-256，B-5.4-1 fail-safe）。
func verifyWith(candidate string, key []byte, b *Bill) bool {
	prefix, _, found := strings.Cut(candidate, ":")
	if !found {
		prefix = "" // 无前缀的历史数据 → 按 SHA-256 解析
	}
	mac := macByAlg(prefix, key, canonicalBill(b))
	return hmac.Equal([]byte(prefix+":"+hex.EncodeToString(mac)), []byte(candidate))
}

func (s *billSigner) Sign(b *Bill) string {
	return signWith(s.current, b)
}

func (s *billSigner) Verify(b *Bill) bool {
	if b == nil || b.Sig == "" {
		return false
	}
	// 当前密钥
	if verifyWith(b.Sig, s.current, b) {
		return true
	}
	// 轮换期旧密钥（B-7.2-1）
	for _, k := range s.old {
		if verifyWith(b.Sig, k, b) {
			return true
		}
	}
	return false
}

// ---------- 计费 ↔ 审计双向关联（T7b，§7.3） ----------

// AuditAnchorProvider 审计链锚定校验提供者（tee-infer 审计链前缀匹配）。
type AuditAnchorProvider interface {
	// AuditAnchorExists 判断给定审计链尾哈希是否存在于审计链（前缀匹配）。
	AuditAnchorExists(head string) bool
	// AuditHead 返回当前审计链尾哈希（用于账单生成时锚定）。
	AuditHead() (string, error)
}

// VerifyBillingChain 端到端关联校验（账单 → 账本链 → 审计链）。
// 失败不阻断已出账（只标记 + 告警，A-31）。
func (s *BillingService) VerifyBillingChain(b *Bill) error {
	if b == nil {
		return fmt.Errorf("billing: verify assoc: bill is nil")
	}
	// 1. 账单锚定的账本链尾必须与当前账本可复现（重放 period 内条目 → 链尾 = b.LedgerHead）
	if b.LedgerHead != "" && !s.store.Ledger().ReproduceHead(b.TenantID, b.Period, b.LedgerHead) {
		return ErrLedgerAnchorMismatch
	}
	// 2. 账单锚定的审计链尾必须出现在 tee-infer 审计链上
	if b.AuditHead != "" && s.auditAnchor != nil && !s.auditAnchor.AuditAnchorExists(b.AuditHead) {
		return ErrAuditAnchorMissing
	}
	return nil
}
