// plane_test.go - 明文引擎平面的**契约边界**断言（方案 §0.6 / D7：两条平面不得合并）
//
// 方案裁定：`model.Engine`（明文生成，vLLM/C-MaaS）与 `route2step.MaskedStepBackend`
// （掩码单步）分属两条正交平面，**不得合并**。vLLM 的落点就是本平面的 `RemoteEngine`。
//
// 本文件把"不得合并"变成可执行断言：Engine 的方法集必须恰为明文生成所需的两个方法；
// 一旦有人把掩码步（Step/Unmask/Remask）挂到明文引擎上，或把 Generate 挪进掩码平面，
// 下面的清单立即不匹配 ⇒ 单测红。与 gateway/route2step/backend_test.go 的
// TestMaskedStepPlaneIsMaskedOnly 互为镜像。
package model

import (
	"reflect"
	"sort"
	"testing"
)

// TestEnginePlaneIsPlaintextOnly 断言明文引擎契约只含明文生成方法。
func TestEnginePlaneIsPlaintextOnly(t *testing.T) {
	it := reflect.TypeOf((*Engine)(nil)).Elem()

	got := make([]string, 0, it.NumMethod())
	for i := 0; i < it.NumMethod(); i++ {
		got = append(got, it.Method(i).Name)
	}
	sort.Strings(got)
	want := []string{"Generate", "Predict"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Engine 方法集变化：\n got=%v\nwant=%v\n"+
			"（§0.6/D7：掩码步不得并入明文引擎平面；掩码步见 route2step.MaskedStepBackend）",
			got, want)
	}

	// Generate 必须是明文 text 载荷契约：入参为 GenerateRequest（内含 OpenAI 兼容 messages）。
	gen, ok := it.MethodByName("Generate")
	if !ok {
		t.Fatal("Engine 缺少 Generate")
	}
	ft := gen.Type
	if ft.NumIn() != 2 || ft.In(0) != reflect.TypeOf(GenerateRequest{}) {
		t.Fatalf("Generate 第 1 个入参必须是 GenerateRequest（明文 text 载荷），got %v", ft)
	}
	// GenerateRequest 必须真带明文消息：Content 字段是 string。
	msgT, ok := reflect.TypeOf(GenerateRequest{}).FieldByName("Messages")
	if !ok || msgT.Type.Kind() != reflect.Slice {
		t.Fatal("GenerateRequest.Messages 必须存在且为切片")
	}
	cm := msgT.Type.Elem()
	if f, ok := cm.FieldByName("Content"); !ok || f.Type.Kind() != reflect.String {
		t.Fatal("ChatMessage.Content 必须是 string（明文平面特征）；掩码平面不得复用本结构")
	}
}
