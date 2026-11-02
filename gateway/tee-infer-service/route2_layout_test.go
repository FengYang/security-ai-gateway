// route2_layout_test.go - 锁定 batch 行布局为 line-major（§7.1.1 / D16），Bug 1 的核心不变量。
//
// 设计稿与客户端 cmd/route2-client/main.go（batchLayout="line-major"）均裁定 batch 采用
// line-major：batch[line*T + pos]。若服务端误用交错式 pos-major（pos*arity+row），扇入步
// residual_add 会把「不同位置的行」相加——不报错、日志全绿、数值全错（与 §2.5.1 规则 4 同族
// 静默失败）。本测试以最小代价把这一不变量钉死，任何把 batchRowOrderPosMajor 翻回 true
// 或改写这两个函数的提交都会立即红。
package main

import "testing"

func TestBatchRowLayoutIsLineMajor(t *testing.T) {
	const arity, nPos = 2, 3

	// line-major：batch[row*nPos + pos]
	if got, want := batchRowIndex(arity, nPos, 1, 0), 0*nPos+1; got != want {
		t.Fatalf("batchRowIndex(arity=2,nPos=3,pos=1,row=0)=%d want line-major=%d（pos-major 会是 %d）",
			got, want, 1*arity+0)
	}
	if got, want := batchRowIndex(arity, nPos, 1, 1), 1*nPos+1; got != want {
		t.Fatalf("batchRowIndex(arity=2,nPos=3,pos=1,row=1)=%d want line-major=%d（pos-major 会是 %d）",
			got, want, 1*arity+1)
	}
	// 段归属（逐段行宽校验用）：第 line 段的行索引落在 [line*nPos, (line+1)*nPos)
	if got, want := batchRowKind(arity, nPos, 1), 1/nPos; got != want { // =0（第 0 段）
		t.Fatalf("batchRowKind(arity=2,nPos=3,idx=1)=%d want 0（属第 0 段）", got)
	}
	if got, want := batchRowKind(arity, nPos, 4), 4/nPos; got != want { // =1（第 1 段）
		t.Fatalf("batchRowKind(arity=2,nPos=3,idx=4)=%d want 1（属第 1 段）", got)
	}
}
