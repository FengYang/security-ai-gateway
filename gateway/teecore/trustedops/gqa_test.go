package trustedops

import (
	"reflect"
	"testing"
)

// TestExpandGQAIdentity MHA（kvHeads==heads）应为恒等变换：零拷贝返回原切片。
func TestExpandGQAIdentity(t *testing.T) {
	rows := [][]float64{{1, 2, 3, 4}, {5, 6, 7, 8}}
	got, err := ExpandGQA(rows, 2, 2, 2)
	if err != nil {
		t.Fatalf("MHA 下 ExpandGQA 不应报错: %v", err)
	}
	if &got[0] == &rows[0] && &got[1] == &rows[1] {
		// 期望零拷贝：同一底层切片
	} else {
		t.Errorf("MHA 下 ExpandGQA 应零拷贝返回原切片")
	}
	if !reflect.DeepEqual(got, rows) {
		t.Errorf("MHA 下 ExpandGQA 应逐位相等: got=%v want=%v", got, rows)
	}
}

// TestExpandGQABasic GQA kvHeads=2/heads=4/headDim=2：
// 输入 KV 行 [a0,a1, b0,b1]（2 个 KV 头），扩展后应为
// [a0,a1, a0,a1, b0,b1, b0,b1]（qh0,qh1→kvh0；qh2,qh3→kvh1）。
func TestExpandGQABasic(t *testing.T) {
	rows := [][]float64{
		{1, 2, 3, 4}, // 第 0 个位置：KV 头0=[1,2], KV 头1=[3,4]
		{5, 6, 7, 8}, // 第 1 个位置
	}
	want := [][]float64{
		{1, 2, 1, 2, 3, 4, 3, 4},
		{5, 6, 5, 6, 7, 8, 7, 8},
	}
	got, err := ExpandGQA(rows, 2, 4, 2)
	if err != nil {
		t.Fatalf("ExpandGQA 报错: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExpandGQA 结果不符: got=%v want=%v", got, want)
	}
	// 验证每行长度 == heads*headDim
	for i, r := range got {
		if len(r) != 8 {
			t.Errorf("第 %d 行长度 %d != 8(heads*headDim)", i, len(r))
		}
	}
}

// TestExpandGQAErrors 非法参数必须 fail-closed。
func TestExpandGQAErrors(t *testing.T) {
	// heads 不能被 kvHeads 整除
	if _, err := ExpandGQA([][]float64{{1, 2, 3}}, 2, 3, 1); err == nil {
		t.Error("heads%kvHeads!=0 应报错")
	}
	// 行长度错配
	if _, err := ExpandGQA([][]float64{{1, 2, 3}}, 2, 4, 2); err == nil {
		t.Error("KV 行长度 != kvHeads*headDim 应报错")
	}
	// 负参数
	if _, err := ExpandGQA([][]float64{{1, 2}}, -1, 2, 1); err == nil {
		t.Error("kvHeads<0 应报错")
	}
}
