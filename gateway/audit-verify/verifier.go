package auditverify

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// Result 链校验结论。
type Result struct {
	Schema      string `json:"schema"`
	Events      int    `json:"events"` // 已校验事件数（窗口模式下 = 窗口内条数）
	OK          bool   `json:"ok"`
	BreakIndex  int    `json:"break_index"` // 首个断裂位置（**绝对** 0 基索引）；OK 时为 -1
	BreakReason string `json:"break_reason,omitempty"`
	LastHash    string `json:"last_hash"` // 已校验部分的链尾哈希（窗口模式下 = 窗口尾）

	AnchorChecked bool   `json:"anchor_checked"`
	AnchorOK      bool   `json:"anchor_ok"`
	AnchorDetail  string `json:"anchor_detail,omitempty"`

	// TST 离线 imprint 一致性校验：令牌 imprint 必须等于 SHA256(锚点 chain_hash)。
	// 令牌签名验签需 TSA 根证书/密钥，属外部条件（不在此判定）。
	TSTChecked bool   `json:"tst_checked"`
	TSTOK      bool   `json:"tst_ok"`
	TSTDetail  string `json:"tst_detail,omitempty"`

	// 验证范围（窗口抽样）
	Scoped          bool   `json:"scoped"`
	ScopeFrom       string `json:"scope_from,omitempty"` // RFC3339（含）
	ScopeTo         string `json:"scope_to,omitempty"`   // RFC3339（含）；空 = 未设上限
	ScopeFirstIndex int    `json:"scope_first_index"`    // 窗口首条事件绝对索引；窗口为空 = -1
	ScopeLastIndex  int    `json:"scope_last_index"`
	SkipBefore      int    `json:"skip_before"`  // 窗口之前跳过（未校验）的事件数
	RemainAfter     int    `json:"remain_after"` // 窗口之后未读事件数；-1 = 已提前停止读取故未知
	EntryHash       string `json:"entry_hash,omitempty"`
	EntryHashSource string `json:"entry_hash_source,omitempty"` // genesis / external / recomputed
}

// Options 验证范围（零值 = 全链验证，行为与既有实现一致）。
//
// 窗口抽样来自哈希链的固有约束：链上不存在"事件自身哈希"字段，只有 prev_hash，
// 因此要断言窗口首条事件合法，必须知道它应有的 prev_hash（= 窗口入口哈希 EntryHash）。
//   - 提供 EntryHash：跳过窗口前缀（只解析时间戳、不重算），校验成本 ∝ 窗口条数，
//     且入口哈希来自链外，属**真正独立**的抽样验证；
//   - 未提供：必须先重算到窗口起点才能得到入口哈希，此时报告 EntryHashSource=recomputed
//     （口径如实标注，不宣称独立锚定）。
type Options struct {
	From      time.Time // 窗口起点（含）；零值 = 创世
	To        time.Time // 窗口终点（含）；零值 = 链尾
	EntryHash string    // 窗口首条事件应有的 prev_hash；须与 From 同用
}

// windowed 是否启用窗口抽样。
func (o Options) windowed() bool { return !o.From.IsZero() || !o.To.IsZero() }

// validate 校验选项自洽性（调用方传参边界）。
func (o Options) validate() error {
	if !o.From.IsZero() && !o.To.IsZero() && o.From.After(o.To) {
		return fmt.Errorf("时间窗口非法：-from（%s）晚于 -to（%s）",
			o.From.Format(time.RFC3339Nano), o.To.Format(time.RFC3339Nano))
	}
	if o.EntryHash != "" && o.From.IsZero() {
		return errors.New("入口哈希（-from-hash）须与窗口起点（-from）同用")
	}
	return nil
}

// AnchorRecord 锚定记录（{timestamp, events, chain_hash}，与两端锚点文件格式一致）。
// TST 为可选字段：tee 侧锚点在启用 TSA 时会携带（本包只做 imprint 一致性校验）。
type AnchorRecord struct {
	Timestamp int64     `json:"timestamp"`
	Events    int       `json:"events"`
	ChainHash string    `json:"chain_hash"`
	TST       *TSTToken `json:"tst,omitempty"`
}

// TSTToken RFC 3161 风格时间戳令牌（字段与 tee-infer-service/tsa.go 的 TST 对齐：
// 字段名/含义任一端改动须同步本结构，否则 imprint 校验会误报）。
type TSTToken struct {
	Version        int    `json:"version"`
	Algorithm      string `json:"algorithm"`
	TimestampNS    int64  `json:"timestamp_ns"`
	MessageImprint string `json:"message_imprint"` // hex(Hash(chain_hash))，算法随 TST.algorithm 分派——本包校验此项
	Signature      string `json:"signature"`       // TSA 签名（验签需 TSA 密钥，属外部条件）
	TSAPublicKey   string `json:"tsa_public_key"`
	Source         string `json:"source"`
}

// VerifyReader 逐行解析链文件/导出 NDJSON 并重算哈希链（全链模式）。
//
// 链校验规则（与两端 load() 一致）：第 i 条事件的 prev_hash 必须等于第 i-1 条的重算哈希；
// 创世事件 prev_hash 必须为空串。任何历史行被篡改都会在此暴露。
func VerifyReader(r io.Reader, schema Schema) (*Result, error) {
	out, err := scanChain(r, schema, Options{})
	if err != nil {
		return nil, err
	}
	return resultFromScan(out, schema, Options{}), nil
}

// VerifyFile 校验链文件 + 可选锚点文件（CLI 主入口）。
//
// 链断裂、锚点不一致、TST imprint 不一致都不作为 error 返回，而是落在 Result 里
// （CLI 据此给不同退出码）；error 仅表示输入不可用（打不开、JSON 坏、选项非法）。
func VerifyFile(chainPath, anchorPath string, schema Schema, opt Options) (*Result, error) {
	if err := opt.validate(); err != nil {
		return nil, err
	}
	f, err := openFile(chainPath)
	if err != nil {
		return nil, err
	}
	out, err := scanChain(f, schema, opt)
	_ = f.Close()
	brokenErr, isBreak := err.(*ChainBreakError)
	if err != nil && !isBreak {
		return nil, err
	}
	res := resultFromScan(out, schema, opt)
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
	} else {
		checked, ok, detail := checkAnchor(records, out)
		res.AnchorChecked, res.AnchorOK, res.AnchorDetail = checked, ok, detail
	}
	res.TSTChecked, res.TSTOK, res.TSTDetail = checkTST(records)
	return res, nil
}

// scanOutcome 扫描结果（内部结构：既要支撑结果视图，也要支撑锚点按绝对位置比对）。
type scanOutcome struct {
	prefix       []string // prefix[i] = 已校验的前 i 条事件的链尾哈希；prefix[0] 为 prefixBase 位置的入口哈希
	prefixBase   int      // prefix[0] 对应的**绝对**事件数（外部入口哈希模式 = 窗口起点，其余 = 0）
	events       int      // 窗口内（全链模式 = 全链）已校验事件数
	firstIndex   int      // 窗口首条事件绝对索引；无窗口事件 = -1
	lastIndex    int      // 窗口尾条事件绝对索引；无窗口事件 = -1
	skipBefore   int      // 窗口之前未校验的事件数
	scannedToEnd bool     // 是否读到文件尾（-to 生效时提前停止 → false，此后无法判定截断）
}

// scanChain 逐行扫描并重算链。
//
// 窗口抽样（Options）语义：
//   - 无 Options：从创世校验全链（行为与引入窗口前完全一致）；
//   - 有 -from/-to：窗口 = 时间戳闭区间；窗口内事件做完整链接校验；
//   - 窗口前事件：EntryHash 已给出则**跳过**（不重算，成本 ∝ 窗口条数），
//     否则必须重算以得到窗口入口哈希（同时顺带校验了前缀）；
//   - 窗口后事件：在读到时停止（scannedToEnd=false，报告如实标注"无法判定截断"）。
//
// 时间戳单调假设：链按追加序写入、时间戳取 time.Now()，故窗口内事件一旦出现
// ts > -to 即可停止读取。若发生系统时钟回拨导致乱序，超出窗口的事件会被提前截断，
// 报告以 remain_after=-1 标注"已提前停止读取"作为提示。
func scanChain(r io.Reader, schema Schema, opt Options) (*scanOutcome, error) {
	fromSet, toSet := !opt.From.IsZero(), !opt.To.IsZero()
	windowed := fromSet || toSet
	// 外部入口哈希：可跳过窗口前缀；此时 prefix[0] 即入口哈希本身。
	externalEntry := windowed && fromSet && opt.EntryHash != ""

	// prefix[0] = prefixBase 位置的入口哈希（全链模式 = 创世空串），其后每校验一条追加其重算哈希。
	out := &scanOutcome{prefix: []string{""}, firstIndex: -1, lastIndex: -1, scannedToEnd: true}
	// running = 下一条事件的 prev_hash 期望值。
	running := ""
	inside := !fromSet // 未设下限 → 第 0 条起即入窗
	if externalEntry {
		inside = false
		out.prefix = []string{opt.EntryHash} // 入口哈希即窗口前缀起点（不重算前缀）
		running = opt.EntryHash
	}
	var fromNano, toNano int64
	if fromSet {
		fromNano = opt.From.UnixNano()
	}
	if toSet {
		toNano = opt.To.UnixNano()
	}
	// breakOn 区分"链断裂"（带着部分结果返回，供报告定位）与"输入不可用"（返回 nil）。
	breakOn := func(err error) (*scanOutcome, error) {
		if _, isBreak := err.(*ChainBreakError); isBreak {
			return out, err
		}
		return nil, err
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	lineNo := 0
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
		// 时间戳仅在窗口模式需要（全链模式不解析 → 与既有行为零差异）。
		var ts int64
		if windowed {
			ts, err = eventTimestamp(event)
			if err != nil {
				return nil, fmt.Errorf("第 %d 行时间戳不可用（窗口模式必需）: %w", lineNo, err)
			}
		}
		if !inside {
			if ts < fromNano {
				if externalEntry {
					// 入口哈希由链外提供：窗口前缀无需重算（抽样成本 ∝ 窗口条数）。
					out.skipBefore++
					continue
				}
				// 未提供入口哈希：必须重算前缀以得到窗口入口哈希（顺带校验了前缀链）。
				h, aerr := applyEvent(event, schema, &running, out.prefixBase+len(out.prefix)-1, lineNo)
				if aerr != nil {
					return breakOn(aerr)
				}
				out.prefix = append(out.prefix, h)
				out.skipBefore++
				continue
			}
			inside = true
			if externalEntry {
				out.prefixBase = out.skipBefore
			}
		}
		absIndex := out.prefixBase + len(out.prefix) - 1
		if toSet && ts > toNano {
			out.scannedToEnd = false
			break
		}
		firstChecked := out.events == 0
		h, aerr := applyEvent(event, schema, &running, absIndex, lineNo)
		if aerr != nil {
			// 外部入口模式下窗口首条不符即"入口哈希不符"——抽样验证的核心断言。
			if be, ok := aerr.(*ChainBreakError); ok && externalEntry && firstChecked {
				be.EntryMismatch = true
			}
			return breakOn(aerr)
		}
		if out.firstIndex < 0 {
			out.firstIndex = absIndex
		}
		out.lastIndex = absIndex
		out.prefix = append(out.prefix, h)
		out.events++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("读取链内容失败: %w", err)
	}
	return out, nil
}

// applyEvent 校验本条事件的 prev_hash 链接并重算哈希（返回重算哈希）。
// `hash_alg` 非法（R-12）→ 以 ChainBreakError 形式返回（**验证失败**，非"输入不可用"）。
func applyEvent(event map[string]any, schema Schema, running *string, absIndex, lineNo int) (string, error) {
	prev, _ := event["prev_hash"].(string)
	if prev != *running {
		return "", &ChainBreakError{
			Index:    absIndex,
			FileLine: lineNo,
			Got:      prev,
			Want:     *running,
		}
	}
	h, err := schema.Hash(event)
	if err != nil {
		return "", &ChainBreakError{
			Index:    absIndex,
			FileLine: lineNo,
			Reason:   err.Error(),
		}
	}
	*running = h
	return h, nil
}

// eventTimestamp 取事件时间戳（UTC 纳秒）。
func eventTimestamp(event map[string]any) (int64, error) {
	raw, ok := event["timestamp"]
	if !ok || raw == nil {
		return 0, errors.New("缺少 timestamp 字段")
	}
	num, ok := raw.(json.Number)
	if !ok {
		return 0, fmt.Errorf("timestamp 类型不支持：%T（应为 JSON 数值）", raw)
	}
	ts, err := num.Int64()
	if err != nil {
		return 0, fmt.Errorf("timestamp 非法：%s", num.String())
	}
	return ts, nil
}

// resultFromScan 由扫描结果组装对外视图。
func resultFromScan(out *scanOutcome, schema Schema, opt Options) *Result {
	res := &Result{
		Schema:          schema.Name,
		Events:          out.events,
		BreakIndex:      -1,
		OK:              true,
		Scoped:          opt.windowed(),
		SkipBefore:      out.skipBefore,
		RemainAfter:     -1,
		ScopeFirstIndex: out.firstIndex,
		ScopeLastIndex:  out.lastIndex,
	}
	if out.events > 0 {
		res.LastHash = out.prefix[len(out.prefix)-1]
	}
	if out.scannedToEnd {
		res.RemainAfter = 0
	}
	if !opt.windowed() {
		return res
	}
	switch {
	case opt.From.IsZero():
		res.EntryHashSource = "genesis" // 窗口自创世始：入口即创世空串
	case opt.EntryHash != "":
		res.EntryHashSource = "external"
		res.EntryHash = opt.EntryHash
	default:
		res.EntryHashSource = "recomputed"
		// 前缀已逐条重算，窗口入口哈希 = 第 skipBefore 条事件之后的链尾哈希。
		if out.skipBefore < len(out.prefix) {
			res.EntryHash = out.prefix[out.skipBefore]
		}
	}
	if !opt.From.IsZero() {
		res.ScopeFrom = opt.From.Format(time.RFC3339Nano)
	}
	if !opt.To.IsZero() {
		res.ScopeTo = opt.To.Format(time.RFC3339Nano)
	}
	return res
}

// ChainBreakError 链断裂（用于把位置/原因带出给 CLI 与测试断言）。
type ChainBreakError struct {
	Index         int    // 0 基**绝对**事件序号
	FileLine      int    // 文件行号（1 基）
	Got           string // 该行声明的 prev_hash
	Want          string // 期望的 prev_hash（= 上一条重算哈希）
	EntryMismatch bool   // 窗口首条事件不符入口哈希（抽样验证断言失败）
	Reason        string // 非链接原因的验证失败（如 R-12 未知 hash_alg）
}

func (e *ChainBreakError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("哈希重算失败：第 %d 条事件（文件第 %d 行）：%s", e.Index+1, e.FileLine, e.Reason)
	}
	if e.EntryMismatch {
		return fmt.Sprintf("窗口起点哈希不符：第 %d 条事件（文件第 %d 行）prev_hash=%s，外部入口哈希为 %s（-from-hash 与链不一致）",
			e.Index+1, e.FileLine, shortHash(e.Got), shortHash(e.Want))
	}
	return fmt.Sprintf("哈希链断裂：第 %d 条事件（文件第 %d 行）prev_hash=%q，期望 %q（该行或之前某行被篡改）",
		e.Index+1, e.FileLine, e.Got, e.Want)
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

// checkAnchor 用锚点记录校验链是否被**截断**（链内部自洽但尾部被删的场景）。
//
// 判定：锚点声明的 (events, chain_hash) 必须是已校验前缀的匹配——
// prefix[rec.Events-prefixBase] == rec.ChainHash。按绝对位置分为三类：
//   - 落在已校验区间：比对哈希（不符 → 内容被改）；
//   - 超出已校验区间且已读到文件尾：锚点声明的事件数多于当前链 → 尾部被删（截断）；
//   - 超出已校验区间但**未读到文件尾**（窗口抽样提前停止）：无法判定，
//     如实标注"超出验证范围"而**不误报截断**；同理早于窗口起点的锚点标注"窗口之前"。
//
// 返回 (是否执行了比对, 是否通过, 明细)。
func checkAnchor(records []AnchorRecord, out *scanOutcome) (bool, bool, string) {
	verifiedFrom := out.prefixBase
	verifiedTo := out.prefixBase + len(out.prefix) - 1
	compared, before, beyond := 0, 0, 0
	for i, rec := range records {
		if rec.Events < verifiedFrom {
			before++
			continue
		}
		if rec.Events > verifiedTo {
			if out.scannedToEnd {
				return true, false, fmt.Sprintf(
					"锚点记录 #%d（%d 条/链尾 %s）超出当前链长度 %d 条 —— 尾部事件被删除（截断）",
					i+1, rec.Events, shortHash(rec.ChainHash), verifiedTo)
			}
			beyond++
			continue
		}
		got := out.prefix[rec.Events-verifiedFrom]
		if got != rec.ChainHash {
			return true, false, fmt.Sprintf(
				"锚点记录 #%d（%d 条）链尾哈希不符：锚点 %s，实际 %s —— 该位置内容被改",
				i+1, rec.Events, shortHash(rec.ChainHash), shortHash(got))
		}
		compared++
	}
	if compared == 0 {
		if before > 0 && beyond == 0 {
			return false, false, fmt.Sprintf("锚点 %d 条均早于验证窗口起点（第 %d 条）——窗口之外，未参与判定（无法判定截断）",
				before, verifiedFrom+1)
		}
		return false, false, fmt.Sprintf("锚点 %d 条均超出验证窗口（无法判定截断；已校验区间为第 %d–%d 条）",
			before+beyond, verifiedFrom+1, verifiedTo)
	}
	detail := fmt.Sprintf("锚点比对通过 %d 条（已校验区间第 %d–%d 条）", compared, verifiedFrom+1, verifiedTo)
	if before+beyond > 0 {
		detail += fmt.Sprintf("；另有 %d 条落在验证范围之外，未参与判定", before+beyond)
	}
	return true, true, detail
}

// checkTST 离线校验锚点记录携带的 TST imprint 一致性：
// tst.message_imprint 必须等于 hex(SHA256(chain_hash))（与 tee 侧 anchorNow 的
// imprint = sha256(chain_hash) 同构）。可检出"锚点记录被换成另一条自洽内容但令牌未同步换"。
// 令牌签名验签需 TSA 根证书/密钥，属外部条件，不在本函数判定。
func checkTST(records []AnchorRecord) (bool, bool, string) {
	withTST, okCount := 0, 0
	for i, rec := range records {
		if rec.TST == nil {
			continue
		}
		withTST++
		// imprint 算法按令牌自述 `algorithm` 分派（§5.2.2 判定口径：**仅** `=="sm3"` 判 SM3；
		// 空/其它值一律按 SHA-256，fail-safe 防伪造字段绕过）。
		prov := hashProvSHA256
		if rec.TST.Algorithm == "sm3" {
			prov = hashProvSM3
		}
		want := hex.EncodeToString(prov.Hash([]byte(rec.ChainHash)))
		if rec.TST.MessageImprint != want {
			return true, false, fmt.Sprintf(
				"锚点记录 #%d 的 TST imprint 与 chain_hash 不符：令牌 %s，应为 %s —— 锚点记录被替换（令牌未同步更新）",
				i+1, shortHash(rec.TST.MessageImprint), shortHash(want))
		}
		okCount++
	}
	if withTST == 0 {
		return false, false, "锚点记录未携带 TST（未启用 TSA 或为旧格式）——无法校验锚定时间可信性"
	}
	return true, true, fmt.Sprintf("TST imprint 一致性校验通过 %d 条（令牌签名验签需 TSA 根证书，属外部条件）", okCount)
}

func openFile(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败 %s: %w", path, err)
	}
	return f, nil
}

func shortHash(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	return h
}
