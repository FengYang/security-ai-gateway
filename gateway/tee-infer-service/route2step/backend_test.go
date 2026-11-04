// backend_test.go - 掩码后端平面的**契约边界**断言（方案 §3 安全不变量）
//
// 方案原文：`route2step` 仅持掩码态张量、在 TEE 内做 unmask→非线性→remask，
// 不接触明文词表/logits；该不变量须作为断言写入单测，防止编排逻辑被误部署到不可信域。
package route2step

import (
	"reflect"
	"testing"

	"security-ai-gateway/gateway/teecore/route2plan"
)

// TestMaskedStepPlaneIsMaskedOnly 断言 MaskedStepBackend 的签名只吞吐掩码态数据。
//
// 入参只有 *StepContext，出参只有 ([][]uint64, int, *StepError)。任何人都无法经此
// 契约把「明文文本 / token id / 明文 logits」带进带出——这正是掩码平面与编排平面
// （orchestrator.ModelAdapter，见其 plane_test.go）不得合并的结构性保证。
func TestMaskedStepPlaneIsMaskedOnly(t *testing.T) {
	it := reflect.TypeOf((*MaskedStepBackend)(nil)).Elem()
	mt, ok := it.MethodByName("Step")
	if !ok {
		t.Fatal("MaskedStepBackend 缺少 Step 方法")
	}
	ft := mt.Type // 接口方法类型不含接收者

	if ft.NumIn() != 1 || ft.In(0) != reflect.TypeOf((*StepContext)(nil)) {
		t.Fatalf("Step 入参必须恰为 (*StepContext)，got %v", ft)
	}
	if ft.NumOut() != 3 {
		t.Fatalf("Step 必须返回 3 个值，got %d（%v）", ft.NumOut(), ft)
	}
	if want := reflect.TypeOf([][]uint64(nil)); ft.Out(0) != want {
		t.Fatalf("Step 第 1 个返回值必须是 %v（掩码态张量），got %v", want, ft.Out(0))
	}
	if want := reflect.TypeOf(int(0)); ft.Out(1) != want {
		t.Fatalf("Step 第 2 个返回值必须是 token 下标 %v，got %v", want, ft.Out(1))
	}
	if want := reflect.TypeOf((*StepError)(nil)); ft.Out(2) != want {
		t.Fatalf("Step 第 3 个返回值必须是 %v，got %v", want, ft.Out(2))
	}
}

// TestStepContextHasNoPlaintextChannel 断言上下文里没有明文直通字段。
//
// 具体禁止：`string`（明文文本）、元素为有符号整型的切片（`[]int`/`[]int64` 等 token id）。
// `[]byte`（Seed）与 `[][]uint64`（Batch）不受限——前者是密钥种子、后者是掩码态。
// 目的不是"洁癖"，而是挡住最省事的越界写法：给上下文加个 `Text string` 直接在里面编码。
func TestStepContextHasNoPlaintextChannel(t *testing.T) {
	ct := reflect.TypeOf(StepContext{})
	for i := 0; i < ct.NumField(); i++ {
		f := ct.Field(i)
		if f.Type.Kind() == reflect.String {
			t.Fatalf("StepContext.%s 是 string：明文文本不得进入掩码平面", f.Name)
		}
		if f.Type.Kind() == reflect.Slice && isSignedInt(f.Type.Elem().Kind()) {
			t.Fatalf("StepContext.%s 是 %v：token id 序列不得进入掩码平面", f.Name, f.Type)
		}
	}
}

// isSignedInt 判断是否是有符号整型（token id 的特征；uint64 掩码态不算）。
func isSignedInt(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return true
	}
	return false
}

// TestExecStepStandaloneRejectsBadShape 验「本包可独立单测」：不经宿主 HTTP，
// 直接驱动 ExecStep，形状不符时按 400 + shape_mismatch 审计码 fail-closed。
//
// 这是包级可复用性的最小证据（方案 §4 阶段5a：route2step 在主仓可直接编译/单测）。
func TestExecStepStandaloneRejectsBadShape(t *testing.T) {
	ctx := &StepContext{
		// arity=2（residual_add 形状）：InSrc 两行，Batch 却只有 1 行 ⇒ len(Batch)%arity != 0
		Spec:  route2plan.StepSpec{InSrc: []int{route2plan.SrcInject, route2plan.SrcInject}},
		Batch: [][]uint64{{1, 2, 3}},
	}
	res, tok, err := ExecStep(ctx)
	if err == nil {
		t.Fatalf("形状不符应报错，got res=%v tok=%d", res, tok)
	}
	if err.Status != 400 || err.Audit != AuditRecomputeShapeMismatch {
		t.Fatalf("应 400/%s，got %d/%s（%s）", AuditRecomputeShapeMismatch, err.Status, err.Audit, err.Msg)
	}
}
