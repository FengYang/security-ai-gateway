package billing

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// ---------- 账本条目（T3/T7，§4.1.1 / §5.1） ----------

// LedgerEntry 账本条目（追加式；金额列不得 UPDATE/DELETE，§7.5）。
//
// ★ A-32：新增 StdIn/StdOut（入账时按当日价格表版本算好的标准 token）
// 与 PriceVer（系数版本追溯）。月累计标准 token = SUM(StdIn)/SUM(StdOut)，
// 热更新下恒成立（可加性充要条件）。
//
// ★ A-42：TokensIn/TokensOut 一律为净量（剔除 retry；与审计链净量三元组一致
// = M1 零容差基准）；retry 另列 RetryToks。
type LedgerEntry struct {
	Seq       uint64 `json:"seq"`         // 单调递增序号（链序）
	TenantID  string `json:"tenant"`
	ModelKey  string `json:"model_key"`   // "engine_type/model"（空侧省略斜杠）
	Day       string `json:"day"`         // UTC+8 自然日 "2006-01-02"
	TokensIn  int64  `json:"tokens_in"`   // 输入 token 净量（剔除 retry）
	TokensOut int64  `json:"tokens_out"`  // 输出 token 净量
	Requests  int64  `json:"requests"`
	RetryToks int64  `json:"retry_toks"`  // 重试 token（平台成本，不计用户；M9）
	StdIn     int64  `json:"std_in"`      // 标准输入 token（入账时锁定）
	StdOut    int64  `json:"std_out"`     // 标准输出 token
	Source    string `json:"source"`      // pull | push | manual
	PriceVer  string `json:"price_ver"`   // 入账时价格表版本（系数追溯依据）
	EventKey  string `json:"event_key"`   // 幂等键（去重）
	PrevHash  string `json:"prev_hash"`   // 前序 EntryHash
	EntryHash string `json:"entry_hash"`  // 本条哈希（不进自身，§7.1.2）
	// HashAlg P0-4 §5.4.3 B-5.4-1：本条账目哈希算法自述（**证据字段，不进自身哈希**）。
	// 缺省 "" = SHA-256（R-13）；"sm3" = SM3；未知值 → 校验失败（不得静默回退）。
	HashAlg   string `json:"hash_alg,omitempty"`
	CreatedAt int64  `json:"created_at"` // UTC 纳秒
}

// LedgerHead 链尾摘要（供锚定/对账/L2）。
type LedgerHead struct {
	Seq       uint64 `json:"seq"`
	EntryHash string `json:"entry_hash"`
	UpdatedAt int64  `json:"updated_at"`
}

// LedgerQuery 只读查询条件。
type LedgerQuery struct {
	TenantID string // "" = 全部
	DayFrom  string // 闭区间起点 ""=最早
	DayTo    string // 闭区间终点 ""=最新
	Limit    int    // 0 = 不限
}

// ComputeEntryHash 计算账本条目哈希（★ A-40：std_in/std_out/price_ver 必须入链，
// 否则计价依据可被就地篡改而 Verify() 检不出 → 违 INV-2）。
//
// 使用长度前缀编码消除字段拼接歧义（与 tee-infer 审计链 hash() 同风格）。
// 字段顺序必须冻结（链一致性的基础），变更=破坏性升级（§7.6）。
//
// **算法分派（P0-4 §5.4.3 B-5.4-1）**：由条目自述 `HashAlg` 决定——`""` 恒 SHA-256、`"sm3"` 恒 SM3
// （两 provider 固定，与进程 profile 解耦 ⇒ 迁移后旧条目仍可复算）。未知值返回错误。
func ComputeEntryHash(e LedgerEntry) (string, error) {
	var buf bytes.Buffer
	writeLP := func(s string) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(s)))
		buf.Write(l[:])
		buf.WriteString(s)
	}
	// 冻结顺序：seq → tenant → model_key → day → tokens_in → tokens_out →
	// requests → retry_toks → std_in → std_out → source → price_ver → event_key → prev_hash
	writeLP(fmt.Sprint(e.Seq))
	writeLP(e.TenantID)
	writeLP(e.ModelKey)
	writeLP(e.Day)
	writeLP(fmt.Sprint(e.TokensIn))
	writeLP(fmt.Sprint(e.TokensOut))
	writeLP(fmt.Sprint(e.Requests))
	writeLP(fmt.Sprint(e.RetryToks))
	writeLP(fmt.Sprint(e.StdIn))
	writeLP(fmt.Sprint(e.StdOut))
	writeLP(e.Source)
	writeLP(e.PriceVer)
	writeLP(e.EventKey)
	writeLP(e.PrevHash)
	prov := hashProvSHA256
	switch e.HashAlg {
	case "":
	case "sm3":
		prov = hashProvSM3
	default:
		return "", fmt.Errorf("billing: 未知 hash_alg %q（B-5.4-1：校验失败，不得回退 SHA-256）", e.HashAlg)
	}
	return hex.EncodeToString(prov.Hash(buf.Bytes())), nil
}
