// audit-verify —— 审计链独立验证 CLI（Phase 2 门禁 #4）。
//
// 与运行中的服务完全独立：只读链文件 / 导出 NDJSON（可选锚点文件），自行重算哈希链。
//
// 用法：
//
//	audit-verify -file <chain.jsonl> [-anchor <anchor.jsonl>] [-schema admin|tee] [-json]
//	             [-from <时间>] [-to <时间>] [-from-hash <64位hex>]
//	             [-report <report.json>] [-emit-anchor <anchor.jsonl>] [-anchor-time <时间>]
//
// 时间格式：RFC3339（2026-09-11T10:00:00+08:00）或 Unix 秒/毫秒/微秒/纳秒（按位数判定，
// 10/13/16/19 位），可直接粘贴链内纳秒时间戳。
//
// 窗口抽样（-from/-to）：哈希链不含"事件自身哈希"，故窗口首条事件要成立必须知道它应有的
// prev_hash（入口哈希）。给出 -from-hash 时跳过窗口前缀（成本 ∝ 窗口条数，入口来自链外，
// 属独立抽样）；未给出时先重算到窗口起点，报告标注 entry_hash_source=recomputed。
//
// 退出码：0 = 通过；1 = 哈希链断裂 / 窗口入口哈希不符；2 = 锚点不一致（含 TST imprint）；
// 3 = 输入或输出错误（打不开、JSON 坏、参数非法、报告/锚点写失败）。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	auditverify "security-ai-gateway/gateway/audit-verify"
)

func main() {
	file := flag.String("file", "", "链文件或导出 NDJSON（必填）")
	anchor := flag.String("anchor", "", "锚点文件（可选；提供后可判定截断）")
	schemaName := flag.String("schema", "admin", "链类型：admin（管理面）| tee（数据面）")
	asJSON := flag.Bool("json", false, "以 JSON 输出结论（便于流水线消费）")
	from := flag.String("from", "", "窗口起点（时间；含）")
	to := flag.String("to", "", "窗口终点（时间；含）")
	fromHash := flag.String("from-hash", "", "窗口入口哈希（窗口首条事件应有的 prev_hash；需与 -from 同用）")
	report := flag.String("report", "", "验证报告输出路径（JSON）")
	emitAnchor := flag.String("emit-anchor", "", "把本次验证结果追加为一条锚点记录（jsonl）")
	anchorTime := flag.String("anchor-time", "", "锚点记录时间戳（时间；缺省取 -to，否则当前时间）")
	flag.Parse()

	if *file == "" {
		fmt.Fprintln(os.Stderr, "错误：缺少 -file 参数")
		flag.Usage()
		os.Exit(3)
	}
	schema, err := auditverify.SchemaFor(*schemaName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误：", err)
		os.Exit(3)
	}
	opt, err := buildOptions(*from, *to, *fromHash)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误：", err)
		os.Exit(3)
	}
	res, err := auditverify.VerifyFile(*file, *anchor, schema, opt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误：", err)
		os.Exit(3)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		printText(res)
	}

	if *report != "" {
		rep, err := auditverify.NewReport(*file, res)
		if err != nil {
			fmt.Fprintln(os.Stderr, "错误：", err)
			os.Exit(3)
		}
		if err := auditverify.WriteReport(*report, rep); err != nil {
			fmt.Fprintln(os.Stderr, "错误：", err)
			os.Exit(3)
		}
		fmt.Printf("验证报告      : 已写入 %s\n", *report)
	}
	if *emitAnchor != "" {
		ts, err := anchorTimestamp(*anchorTime, opt.To)
		if err != nil {
			fmt.Fprintln(os.Stderr, "错误：", err)
			os.Exit(3)
		}
		rec, err := auditverify.AnchorRecordFrom(res, ts)
		if err != nil {
			fmt.Fprintln(os.Stderr, "错误：", err)
			os.Exit(3)
		}
		if err := auditverify.EmitAnchor(*emitAnchor, rec); err != nil {
			fmt.Fprintln(os.Stderr, "错误：", err)
			os.Exit(3)
		}
		fmt.Printf("锚点记录      : 已写入 %s（events=%d）\n", *emitAnchor, rec.Events)
	}

	switch {
	case !res.OK:
		os.Exit(1)
	case res.AnchorChecked && !res.AnchorOK:
		os.Exit(2)
	case res.TSTChecked && !res.TSTOK:
		os.Exit(2)
	}
}

// buildOptions 解析窗口参数（时间支持 RFC3339 或 Unix 秒）。
func buildOptions(fromArg, toArg, fromHash string) (auditverify.Options, error) {
	var opt auditverify.Options
	var err error
	if opt.From, err = parseTimeArg(fromArg); err != nil {
		return opt, fmt.Errorf("-from %w", err)
	}
	if opt.To, err = parseTimeArg(toArg); err != nil {
		return opt, fmt.Errorf("-to %w", err)
	}
	opt.EntryHash = fromHash
	return opt, nil
}

// anchorTimestamp 解析锚点时间戳（缺省取窗口终点，再缺省取当前时间）。
func anchorTimestamp(arg string, to time.Time) (int64, error) {
	if arg == "" {
		if !to.IsZero() {
			return to.UnixNano(), nil
		}
		return time.Now().UnixNano(), nil
	}
	t, err := parseTimeArg(arg)
	if err != nil {
		return 0, fmt.Errorf("-anchor-time %w", err)
	}
	return t.UnixNano(), nil
}

// parseTimeArg 解析时间参数：RFC3339，或按位数判定的 Unix 秒/毫秒/微秒/纳秒。
// 链内 timestamp 为纳秒（19 位），故必须支持直接粘贴链内时间戳；
// 位数无法识别时**报错而非猜测**——静默把纳秒当秒会得到完全错误的窗口。
func parseTimeArg(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		switch len(strings.TrimLeft(s, "+")) {
		case 10:
			return time.Unix(n, 0), nil
		case 13:
			return time.UnixMilli(n), nil
		case 16:
			return time.UnixMicro(n), nil
		case 19:
			return time.Unix(0, n), nil
		}
		return time.Time{}, fmt.Errorf("数字时间 %q 位数不支持（10=秒/13=毫秒/16=微秒/19=纳秒，或改用 RFC3339）", s)
	}
	return time.Time{}, fmt.Errorf("时间格式非法 %q（支持 RFC3339 或 Unix 秒/毫秒/微秒/纳秒）", s)
}

func printText(res *auditverify.Result) {
	fmt.Printf("链类型        : %s\n", res.Schema)
	fmt.Printf("已校验事件数  : %d\n", res.Events)
	fmt.Printf("链尾哈希      : %s\n", res.LastHash)
	if res.OK {
		fmt.Println("哈希链        : 完整（未发现篡改）")
	} else {
		fmt.Printf("哈希链        : 断裂 —— %s\n", res.BreakReason)
	}
	if res.Scoped {
		fmt.Printf("验证范围      : %s\n", scopeText(res))
		if res.EntryHash != "" {
			fmt.Printf("窗口入口哈希  : %s（来源：%s）\n", shortHash(res.EntryHash), res.EntryHashSource)
		} else {
			fmt.Printf("窗口入口哈希  : %s（来源：%s）\n", "（创世空串）", res.EntryHashSource)
		}
	}
	switch {
	case !res.AnchorChecked && res.AnchorDetail != "":
		fmt.Printf("锚点比对      : 未执行 —— %s\n", res.AnchorDetail)
	case res.AnchorChecked && res.AnchorOK:
		fmt.Printf("锚点比对      : 通过 —— %s\n", res.AnchorDetail)
	case res.AnchorChecked:
		fmt.Printf("锚点比对      : 失败 —— %s\n", res.AnchorDetail)
	default:
		fmt.Println("锚点比对      : 未执行（未提供 -anchor；无法判定截断）")
	}
	switch {
	case res.TSTChecked && res.TSTOK:
		fmt.Printf("TST imprint   : 通过 —— %s\n", res.TSTDetail)
	case res.TSTChecked:
		fmt.Printf("TST imprint   : 失败 —— %s\n", res.TSTDetail)
	default:
		fmt.Printf("TST imprint   : 未执行 —— %s\n", res.TSTDetail)
	}
}

// scopeText 窗口摘要（绝对位置便于与锚点 events 对齐）。
func scopeText(res *auditverify.Result) string {
	from, to := res.ScopeFrom, res.ScopeTo
	if from == "" {
		from = "创世"
	}
	if to == "" {
		to = "链尾"
	}
	if res.Events == 0 {
		return fmt.Sprintf("%s ~ %s（窗口内无事件）", from, to)
	}
	remain := "已读到文件尾"
	if res.RemainAfter < 0 {
		remain = "已提前停止读取"
	}
	return fmt.Sprintf("%s ~ %s（窗口 %d 条，绝对第 %d–%d 条；窗口前跳过 %d 条；%s）",
		from, to, res.Events, res.ScopeFirstIndex+1, res.ScopeLastIndex+1, res.SkipBefore, remain)
}

func shortHash(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	return h
}
