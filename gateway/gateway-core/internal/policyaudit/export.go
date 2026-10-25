// P2-4 T-4.2：策略变更审计链的**只读导出**与**独立重算校验**。
//
// 设计口径：
//   - 只读：Export 只读取链快照，**不落 WORM、不触发锚定、不改 lastHex**，
//     保证 WORM 语义不被导出污染（导出是可任意次重复的观测操作）；
//   - 同构：NDJSON 每行 = json.Marshal(Event)，与 WORM 文件行格式逐字节一致，
//     tee 侧（gateway/tee-infer-service/audit_export.go）同口径，供 T-4.1 聚合侧统一处理；
//   - 可验证：VerifyExport/VerifyExportFrom 对导出内容**独立重算**哈希链，
//     等价于外部 audit-verify 的复核口径——单测据此证明"导出 → 重算 → 与链 Verify 结论一致"。
package policyaudit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
)

// ExportResult 只读导出结果（NDJSON + 链尾/锚点元信息）。
type ExportResult struct {
	// NDJSON 每行一条事件（与 WORM 行序列化一致），空链 = 空字节。
	NDJSON []byte
	// Lines 与 NDJSON 等价的行切片（供 HTTP 逐行写出，避免重复拆分）。
	Lines []string
	// Events 本次导出事件数。
	Events int
	// Total 链总长度（不受 limit 影响）。
	Total int
	// PrevHash 导出区间首条事件的前链哈希（全量导出 = ""，截断导出 = 区间前一条的哈希）。
	// 用途：对截断导出独立重算时作为起始 prev（见 VerifyExportFrom）。
	PrevHash string
	// TailHash 链尾哈希（本次导出末条事件哈希；空链 = ""）。
	TailHash string
	// Truncated 是否因 limit 截断。
	Truncated bool
}

// Export 以只读方式导出链快照（limit <= 0 = 全量，受调用方上限保护）。
//
// 截断语义：保留**最近** limit 条（与 List 一致），故 TailHash 恒为链尾哈希；
// 截断导出的 PrevHash 非 ""，独立重算须以 VerifyExportFrom(nd, PrevHash) 起始。
func (c *Chain) Export(limit int) (ExportResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	total := len(c.events)
	start := 0
	if limit > 0 && total > limit {
		start = total - limit
	}
	sel := c.events[start:]
	// 导出字节与链状态解耦：先算哈希再序列化，任一事件哈希不可算（R-12 未知算法）
	// 即返回错误，绝不回退为"跳过"（导出不可验证比不导出更危险）。
	prev := ""
	if start > 0 {
		h, err := c.events[start-1].hashWithErr()
		if err != nil {
			return ExportResult{}, fmt.Errorf("policyaudit: 导出区间前驱事件哈希不可算: %w", err)
		}
		prev = h
	}
	tail := ""
	if len(sel) > 0 {
		h, err := sel[len(sel)-1].hashWithErr()
		if err != nil {
			return ExportResult{}, fmt.Errorf("policyaudit: 链尾事件哈希不可算: %w", err)
		}
		tail = h
	}

	var buf bytes.Buffer
	lines := make([]string, 0, len(sel))
	for i := range sel {
		b, err := json.Marshal(sel[i])
		if err != nil {
			return ExportResult{}, fmt.Errorf("policyaudit: 事件序列化失败: %w", err)
		}
		lines = append(lines, string(b))
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return ExportResult{
		NDJSON:    buf.Bytes(),
		Lines:     lines,
		Events:    len(sel),
		Total:     total,
		PrevHash:  prev,
		TailHash:  tail,
		Truncated: start > 0,
	}, nil
}

// VerifyExport 对导出内容独立重算哈希链（起始 prev = ""，即全量导出口径）。
//
// 返回值：(链是否自洽, 已校验事件数, 错误)。错误仅指"无法完成重算"
// （JSON 解析失败 / 未知 hash_alg），链断裂属正常判定结果（ok=false, err=nil）。
func VerifyExport(ndjson []byte) (bool, int, error) {
	return VerifyExportFrom(ndjson, "")
}

// VerifyExportFrom 同 VerifyExport，但指定起始 prev（用于**截断导出**的重算：
// 起始 prev 取自 ExportResult.PrevHash）。
//
// ⚠️ 截断导出只能证明"区间内自洽"，不能单独证明与创世块的衔接——
// 全链衔接由链尾哈希与锚点（TailHash / Anchor）比对完成。
func VerifyExportFrom(ndjson []byte, prev string) (bool, int, error) {
	scanner := bufio.NewScanner(bytes.NewReader(ndjson))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	n := 0
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return false, n, fmt.Errorf("policyaudit: 导出第 %d 行解析失败: %w", n+1, err)
		}
		if e.PrevHash != prev {
			return false, n, nil
		}
		h, err := e.hashWithErr()
		if err != nil {
			return false, n, fmt.Errorf("policyaudit: 导出第 %d 行哈希算法非法: %w", n+1, err)
		}
		prev = h
		n++
	}
	if err := scanner.Err(); err != nil {
		return false, n, fmt.Errorf("policyaudit: 导出内容读取失败: %w", err)
	}
	return true, n, nil
}
