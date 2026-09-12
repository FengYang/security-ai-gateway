// audit-verify —— 审计链独立验证 CLI（Phase 2 门禁 #4）。
//
// 与运行中的服务完全独立：只读链文件 / 导出 NDJSON（可选锚点文件），自行重算哈希链。
//
// 用法：
//
//	audit-verify -file <chain.jsonl> [-anchor <anchor.jsonl>] [-schema admin|tee] [-json]
//
// 退出码：0 = 通过；1 = 哈希链断裂（篡改）；2 = 锚点不一致（截断/内容被改）；3 = 输入错误。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	auditverify "security-ai-gateway/gateway/audit-verify"
)

func main() {
	file := flag.String("file", "", "链文件或导出 NDJSON（必填）")
	anchor := flag.String("anchor", "", "锚点文件（可选；提供后可判定截断）")
	schemaName := flag.String("schema", "admin", "链类型：admin（管理面）| tee（数据面）")
	asJSON := flag.Bool("json", false, "以 JSON 输出结论（便于流水线消费）")
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
	res, err := auditverify.VerifyFile(*file, *anchor, schema)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误：", err)
		os.Exit(3)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		fmt.Printf("链类型        : %s\n", res.Schema)
		fmt.Printf("已校验事件数  : %d\n", res.Events)
		fmt.Printf("链尾哈希      : %s\n", res.LastHash)
		if res.OK {
			fmt.Println("哈希链        : 完整（未发现篡改）")
		} else {
			fmt.Printf("哈希链        : 断裂 —— %s\n", res.BreakReason)
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
	}

	switch {
	case !res.OK:
		os.Exit(1)
	case res.AnchorChecked && !res.AnchorOK:
		os.Exit(2)
	}
}
