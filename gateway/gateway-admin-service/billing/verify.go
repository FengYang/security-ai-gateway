// verify.go — P0-3 Token 计费体系：数据完整性校验接线（S-6 链校验 / S-10 关联校验）。
//
// 对应设计：§7.1.2（账本哈希链校验）、§7.3（计费↔审计关联）、§6.16（后台调度器
// 总表 S-6/S-10，★ A-31：为 `VerifyBillingChain` 补调用点）。
//
// 两个任务均为**纯读 + 事后审计性质**：S-6 断裂即停出账（fail-closed），
// S-10 不符仅标记账单状态 + 记账指标（**不阻断已出账**）。
package billing

import "log"

// ---------- 账单锚定（§7.3：账单→账本链须"重放可复现"） ----------

// periodTailHash 返回某租户某周期（日/月）内最后一条账本条目的 EntryHash。
//
// 账单以该值作 ledger_head 锚定，使 VerifyBillingChain 的 ReproduceHead 可复现
// （§7.3：账单→账本链为"强"关联）。**不可**用全局链尾——账本为全局单链，全局链尾
// 属于最后写入的租户，其余租户重放自身周期条目时必然对不上。
// 周期内无条目 → 返回 ""（空账单不锚定，关联校验自动跳过）。
func (s *BillingService) periodTailHash(tenant, from, to string) string {
	entries, err := s.store.Ledger().Range(LedgerQuery{TenantID: tenant, DayFrom: from, DayTo: to})
	if err != nil || len(entries) == 0 {
		return ""
	}
	return entries[len(entries)-1].EntryHash
}

// ---------- S-6 链校验（§7.1.2 / §6.16） ----------

// VerifyLedgerChain 全量校验账本哈希链（seq 连续 + prev 链接 + 哈希自洽）。
//
// 返回首个断链 Seq（-1 = 完好）；`err != nil` 时**不改变**链断裂标志（保留上次结果）。
// 断裂 → `chain_broken=1` 并停出账（fail-closed，§6.15/§7.1）；本方法是**指标 #4 的
// 唯一生产者**（§9.1.1）。
func (s *BillingService) VerifyLedgerChain() (int64, error) {
	brokenAt, err := s.store.Ledger().Verify()
	if err != nil {
		return -1, err
	}
	SetChainBroken(brokenAt >= 0)
	if brokenAt >= 0 {
		log.Printf("[billing] S-6 账本链断裂：seq=%d（停止出账，fail-closed）", brokenAt)
	}
	return brokenAt, nil
}

// ---------- S-10 关联校验（§7.3 / §6.16，★ A-31/A-34） ----------

// VerifyAssocRecent 对 `period >= fromPeriod` 的账单逐张执行关联校验（S-10 巡检）。
//
// 不符 → 标记账单 `assoc_mismatch` + 记指标 #22（**不阻断已出账**，事后审计性质）。
// fromPeriod 为空 = 全量。返回 (巡检数, 不符数, error)。
func (s *BillingService) VerifyAssocRecent(fromPeriod string) (checked, failed int, err error) {
	bills, err := s.store.Bills().List(BillQuery{From: fromPeriod})
	if err != nil {
		return 0, 0, err
	}
	for _, b := range bills {
		if b.Status == BillStatusVoid || b.Status == BillStatusAssocMismatch {
			continue // 已作废/已标记：不重复巡检
		}
		checked++
		if verr := s.VerifyBillingChain(b); verr != nil {
			failed++
			IncAssocVerify("fail") // 指标 #22（A-34）
			log.Printf("[billing] S-10 关联校验不符 bill=%s: %v", b.ID, verr)
			if uerr := s.store.Bills().UpdateStatus(b.ID, BillStatusAssocMismatch); uerr != nil {
				log.Printf("[billing] S-10 标记 assoc_mismatch 失败 bill=%s: %v", b.ID, uerr)
			}
			continue
		}
		IncAssocVerify("pass")
	}
	return checked, failed, nil
}

// verifyAssocAfterClose 出账后即时关联校验（S-10）。失败**不返回错误、不阻断出账**，
// 仅标记 `assoc_mismatch` + 记指标 #22 + 日志（§7.3/A-34）。
func (s *BillingService) verifyAssocAfterClose(b *Bill) {
	if b == nil {
		return
	}
	if err := s.VerifyBillingChain(b); err != nil {
		IncAssocVerify("fail")
		log.Printf("[billing] S-10 出账后关联校验不符 bill=%s: %v", b.ID, err)
		if uerr := s.store.Bills().UpdateStatus(b.ID, BillStatusAssocMismatch); uerr != nil {
			log.Printf("[billing] S-10 标记 assoc_mismatch 失败 bill=%s: %v", b.ID, uerr)
		}
		return
	}
	IncAssocVerify("pass")
}
