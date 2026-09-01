// tokenizer.go — 计量口径可插拔（GF.2.4，决策点 D-3=B）。
//
// 现状：配额/计量用"字符数/4"估算（estimateTokens）。D-3 结论 = 保持估算口径，
// 真机 tokenizer 就绪后校准（偏差 <5%）。本文件把计量口径抽为接口，
// 作为真机 tokenizer 的正式接入点——替换实现即完成校准，不改动调用方。
//
// 安全约束：计量口径只影响配额/计费，不影响段① 加密链与 fail-closed 语义；
// 接入真机 tokenizer 时须保证与阿里计费对账口径一致（见 GA-计费接口设计.md）。
package main

// Tokenizer 计量 token 计数接口。
type Tokenizer interface {
	// Count 返回 text 的 token 数（计量/配额统一口径）。
	Count(text string) int
}

// charDiv4Tokenizer 字符/4 估算口径（D-3=B 过渡实现）。
// 局限（记录于 GA-AI网关能力补齐方案 D-3）：中文每字≈1 token，估算偏差 3-4 倍；
// 真机 tokenizer 接入前保持此口径并在接入点预留（研发计划 GF.2.4）。
type charDiv4Tokenizer struct{}

// Count 字符/4 估算（与既有 estimateTokens 完全一致，向后兼容）。
func (charDiv4Tokenizer) Count(text string) int {
	return estimateTokens(text)
}

// countTokens 计量入口：tokenizer 未注入（nil，测试/缺省）时回退字符/4，
// 生产注入真机 tokenizer 后自动切换为精确口径。
func (s *teeServer) countTokens(text string) int {
	if s.tokenizer != nil {
		return s.tokenizer.Count(text)
	}
	return estimateTokens(text)
}
