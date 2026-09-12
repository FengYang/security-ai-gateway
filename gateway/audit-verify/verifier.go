package auditverify

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Result 链校验结论。
type Result struct {
	Schema      string `json:"schema"`
	Events      int    `json:"events"`
	OK          bool   `json:"ok"`
	BreakIndex  int    `json:"break_index"` // 首个断裂位置（0 基）；OK 时为 -1
	BreakReason string `json:"break_reason,omitempty"`
	LastHash    string `json:"last_hash"`

	AnchorChecked bool   `json:"anchor_checked"`
	AnchorOK      bool   `json:"anchor_ok"`
	AnchorDetail  string `json:"anchor_detail,omitempty"`
}

// AnchorRecord 锚定记录（两端格式一致：{timestamp, events, chain_hash}）。
type AnchorRecord struct {
	Timestamp int64  `json:"timestamp"`
	Events    int    `json:"events"`
	ChainHash string `json:"chain_hash"`
}

// VerifyReader 逐行解析链文件/导出 NDJSON 并重算哈希链。
//
// 链校验规则（与两端 load() 一致）：第 i 条事件的 prev_hash 必须等于第 i-1 条的重算哈希；
// 创世事件 prev_hash 必须为空串。任何历史行被篡改都会在此暴露。
func VerifyReader(r io.Reader, schema Schema) (*Result, error) {
	res := &Result{Schema: schema.Name, BreakIndex: -1}
	prefix, err := scanChain(r, schema)
	if err != nil {
		return nil, err
	}
	res.Events = len(prefix) - 1
	if res.Events > 0 {
		res.LastHash = prefix[len(prefix)-1]
	}
	res.OK = true
	return res, nil
}

// scanChain 逐行重算并校验链，返回前缀哈希数组 prefix[i]=前 i 条事件的链尾哈希；
// 若发现断裂，以 error 形式返回（含位置与原因）。
func scanChain(r io.Reader, schema Schema) ([]string, error) {
	prefix := []string{""}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	lineNo := 0
	events := 0
	for sc.Scan() {
		lineNo++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		event, err := decodeEvent(line)
		if err != nil {
			return nil, fmt.Errorf("第 %d 行 JSON 解析失败: %w", lineNo, err)
		}
		hash, err := schema.Hash(event)
		if err != nil {
			return nil, fmt.Errorf("第 %d 行哈希重算失败: %w", lineNo, err)
		}
		prev, _ := event["prev_hash"].(string)
		expectPrev := prefix[len(prefix)-1]
		if prev != expectPrev {
			// 返回**已成功校验的前缀**（断裂点之前的链），供报告"断前已校验 N 条"。
			return prefix, &ChainBreakError{
				Index:    events,
				FileLine: lineNo,
				Got:      prev,
				Want:     expectPrev,
			}
		}
		prefix = append(prefix, hash)
		events++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("读取链内容失败: %w", err)
	}
	return prefix, nil
}

// ChainBreakError 链断裂（用于把位置/原因带出给 CLI 与测试断言）。
type ChainBreakError struct {
	Index    int    // 0 基事件序号
	FileLine int    // 文件行号（1 基）
	Got      string // 该行声明的 prev_hash
	Want     string // 期望的 prev_hash（= 上一条重算哈希）
}

func (e *ChainBreakError) Error() string {
	return fmt.Sprintf("哈希链断裂：第 %d 条事件（文件第 %d 行）prev_hash=%q，期望 %q（该行或之前某行被篡改）",
		e.Index+1, e.FileLine, e.Got, e.Want)
}

// VerifyFile 校验链文件 + 可选锚点文件（CLI 主入口）。
//
// 链断裂与锚点不一致都不作为 error 返回，而是落在 Result 里（CLI 据此给不同退出码）；
// error 仅表示输入不可用（打不开、JSON 坏）。
func VerifyFile(chainPath, anchorPath string, schema Schema) (*Result, error) {
	prefix, err := prefixHashesOfFile(chainPath, schema)
	brokenErr, isBreak := err.(*ChainBreakError)
	if err != nil && !isBreak {
		return nil, err
	}
	res := &Result{
		Schema:     schema.Name,
		Events:     len(prefix) - 1,
		BreakIndex: -1,
		OK:         true,
	}
	if res.Events > 0 {
		res.LastHash = prefix[len(prefix)-1]
	}
	if isBreak {
		res.OK = false
		res.BreakIndex = brokenErr.Index
		res.BreakReason = brokenErr.Error()
	}
	if anchorPath == "" {
		return res, nil
	}
	records, err := readAnchorRecords(anchorPath)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		// 空锚点文件是**正常情况**（每 8192 条才锚定一次），此时无信息可判定截断，
		// 既不能判失败也不能宣称通过——如实标注"未执行比对"。
		res.AnchorChecked = false
		res.AnchorDetail = "锚点文件为空（尚未达到锚定间隔 8192 条），无法判定截断"
		return res, nil
	}
	ok, detail := CheckAnchor(records, prefix)
	res.AnchorChecked = true
	res.AnchorOK = ok
	res.AnchorDetail = detail
	return res, nil
}

func decodeEvent(line []byte) (map[string]any, error) {
	// UseNumber：保留数值字面量，避免纳秒时间戳经 float64 失真。
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	var event map[string]any
	if err := dec.Decode(&event); err != nil {
		return nil, err
	}
	return event, nil
}

func prefixHashesOfFile(path string, schema Schema) ([]string, error) {
	f, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return scanChain(f, schema)
}

func readAnchorRecords(path string) ([]AnchorRecord, error) {
	f, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []AnchorRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec AnchorRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("锚点记录解析失败: %w", err)
		}
		out = append(out, rec)
	}
	return out, sc.Err()
}

func openFile(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败 %s: %w", path, err)
	}
	return f, nil
}

// CheckAnchor 用锚点记录校验链是否被**截断**（链内部自洽但尾部被删的场景）。
//
// 判定：锚点声明的 (events, chain_hash) 必须是链的前缀匹配——
// prefixHashes[rec.Events] == rec.ChainHash。任一锚点记录不满足：
//   - rec.Events > len(chain)：锚点声明的事件数多于当前链 → 尾部被删（截断）；
//   - 哈希不等：该位置内容被改。
//
// 返回 (是否全部通过, 明细)。
func CheckAnchor(records []AnchorRecord, prefixHashes []string) (bool, string) {
	if len(records) == 0 {
		return false, "锚点文件为空，无法判定截断"
	}
	chainLen := len(prefixHashes) - 1
	for i, rec := range records {
		if rec.Events > chainLen {
			return false, fmt.Sprintf(
				"锚点记录 #%d（%d 条/链尾 %s）超出当前链长度 %d 条 —— 尾部事件被删除（截断）",
				i+1, rec.Events, shortHash(rec.ChainHash), chainLen)
		}
		if got := prefixHashes[rec.Events]; got != rec.ChainHash {
			return false, fmt.Sprintf(
				"锚点记录 #%d（%d 条）链尾哈希不符：锚点 %s，实际 %s —— 该位置内容被改",
				i+1, rec.Events, shortHash(rec.ChainHash), shortHash(got))
		}
	}
	return true, fmt.Sprintf("锚点 %d 条记录全部前缀匹配（链长 %d）", len(records), chainLen)
}

func shortHash(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	return h
}
