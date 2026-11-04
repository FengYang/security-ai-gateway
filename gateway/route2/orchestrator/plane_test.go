// plane_test.go - 编排平面的**契约边界**断言（方案 §3 安全不变量 / §0.6 两条插件平面）
//
// 方案原文：orchestrator 处理明文 Embedding / OTP / LMHead / argmax，须运行于可信网关侧①；
// 与 route2step 的纯掩码步契约**不得合并**。本文件用反射把这份职责分工钉在单测里：
// 谁能碰明文词表（Encode/Decode/Embed/LMHead）是一张显式清单，改动即红。
package orchestrator

import (
	"reflect"
	"sort"
	"testing"
)

// TestModelAdapterOwnsPlaintextVocabulary 断言编排平面对适配器的契约**显式**包含词表进出。
//
// 为什么值得单独断言：一旦有人图省事把 Encode/Decode/LMHead 从契约里挪走（例如塞进
// route2step 的掩码步里做"顺手 argmax"），两条平面的边界就被抹掉——而这类改动编译照过、
// 数值"看起来对"，只在安全评审里才暴露。故用方法集清单把它变成编译期外的硬断言。
func TestModelAdapterOwnsPlaintextVocabulary(t *testing.T) {
	got := methodNames(reflect.TypeOf((*ModelAdapter)(nil)).Elem())
	want := []string{
		"BackendStep", "Decode", "Dim", "Embed", "EmbedRows", "Encode", "LMHead",
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ModelAdapter 方法集变化：\n got=%v\nwant=%v\n"+
			"（新增/删除方法须同步本清单与方案 §8.1 术语表；明文词表职责不得外移）", got, want)
	}
}

// methodNames 返回接口的方法名（升序）。
func methodNames(it reflect.Type) []string {
	out := make([]string, 0, it.NumMethod())
	for i := 0; i < it.NumMethod(); i++ {
		out = append(out, it.Method(i).Name)
	}
	sort.Strings(out)
	return out
}
