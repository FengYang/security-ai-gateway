package route2step

// ---- batch 行序（设计 §7.1.1 / D16 联合裁定：line-major，非待定项）----
//
// batch 承载 arity × T 行：arity 来自 StepSpec 的输入行数（residual_add 为 2，
// 其余为 1），T 为位置数。布局**必须为 line-major**（设计 §7.1.1 已裁定）：
//
//	batch[ line*T + pos ]   // 第 line 条输入行、第 pos 个位置
//
// 客户端 cmd/route2-client/main.go 的 batchLayout="line-major" 与本常量必须同款；
// 二者不一致时 residual_add 会把「不同位置的行」加在一起——不报错、数值全错
// （与 §2.5.1 规则 4 同族静默失败）。false ⇒ line-major（见下方两个函数），true ⇒ 交错式。
const BatchRowOrderPosMajor = false // false ⇒ line-major（batch[line*T+pos]），与客户端/设计稿一致

// BatchRowIndex 位置 j、行类 r 在 batch 中的下标。
func BatchRowIndex(arity, nPos, posIdx, rowIdx int) int {
	if BatchRowOrderPosMajor {
		return posIdx*arity + rowIdx
	}
	return rowIdx*nPos + posIdx
}

// BatchRowKind batch 下标 idx 所属的行类（形状校验用）。
func BatchRowKind(arity, nPos, idx int) int {
	if arity <= 0 {
		return 0
	}
	if BatchRowOrderPosMajor {
		return idx % arity
	}
	if nPos <= 0 {
		return 0
	}
	return idx / nPos
}
