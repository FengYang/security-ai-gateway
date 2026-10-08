package billing

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strconv"
)

// ---------- 账单导出（T5，§4.3.2 / P0 仅 CSV） ----------

// ExportCSV 把账单导出为 CSV 字节流（UTF-8 BOM 前缀，便于 Excel 打开）。
// 返回内容 + MIME 类型。
func ExportCSV(b *Bill) ([]byte, string, error) {
	if b == nil {
		return nil, "", fmt.Errorf("billing: export: bill is nil")
	}
	var buf bytes.Buffer
	buf.WriteString("\xEF\xBB\xBF") // UTF-8 BOM

	w := csv.NewWriter(&buf)
	// 表头
	header := []string{
		"tenant", "bill_id", "kind", "period", "model_key",
		"standard_tokens", "tokens_in", "tokens_out", "retry_toks",
		"amount_fen", "currency", "price_version", "status", "generated_at",
	}
	if err := w.Write(header); err != nil {
		return nil, "", fmt.Errorf("billing: export header: %w", err)
	}
	// 明细行（无明细时输出一行汇总）
	if len(b.Items) == 0 {
		row := []string{
			csvSafe(b.TenantID), csvSafe(b.ID), csvSafe(b.Kind), csvSafe(b.Period), "",
			"0", "0", "0", "0",
			strconv.FormatInt(int64(b.Total), 10), csvSafe(b.Currency), csvSafe(b.PriceVersion),
			csvSafe(b.Status), strconv.FormatInt(b.GeneratedAt, 10),
		}
		if err := w.Write(row); err != nil {
			return nil, "", fmt.Errorf("billing: export row: %w", err)
		}
	} else {
		for _, it := range b.Items {
			row := []string{
				csvSafe(b.TenantID), csvSafe(b.ID), csvSafe(b.Kind), csvSafe(b.Period), csvSafe(it.ModelKey),
				strconv.FormatInt(it.StandardTokens, 10),
				strconv.FormatInt(it.TokensIn, 10),
				strconv.FormatInt(it.TokensOut, 10),
				strconv.FormatInt(it.RetryToks, 10),
				strconv.FormatInt(int64(it.Amount), 10),
				csvSafe(b.Currency), csvSafe(b.PriceVersion), csvSafe(b.Status),
				strconv.FormatInt(b.GeneratedAt, 10),
			}
			if err := w.Write(row); err != nil {
				return nil, "", fmt.Errorf("billing: export row: %w", err)
			}
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, "", fmt.Errorf("billing: export flush: %w", err)
	}
	return buf.Bytes(), "text/csv; charset=utf-8", nil
}

// csvSafe 防 CSV 公式注入（★ SEC-002）：以 `= + - @` 或制表/回车开头的文本单元格，
// 在表格软件（Excel 等）中可能被当作公式执行；前置单引号 `'` 使其降级为纯文本。
// 空串与普通文本原样返回（对既有导出内容零影响）。
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}
