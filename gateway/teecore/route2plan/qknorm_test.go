package route2plan

import "testing"

// TestQKNormPlanFolded QK-norm 是「折叠进既有 KV 追加 / attention 步」的结构，
// 不新增 plan 步（保持掩码域不变量与 8/10 步布局不变）。故开启 QKNorm 后 plan
// 结构必须与关闭时逐位相同（仅 step_exec 运行时行为不同）。（T3 验收）
func TestQKNormPlanFolded(t *testing.T) {
	base := DemoTinyConfig() // FFNType 默认 "" → GELU
	normed := DemoTinyConfig()
	normed.QKNorm = true

	pBase, err := Build(base)
	if err != nil {
		t.Fatal(err)
	}
	pNorm, err := Build(normed)
	if err != nil {
		t.Fatal(err)
	}
	if len(pBase) != len(pNorm) {
		t.Fatalf("QKNorm 不应改变 plan 长度: base=%d norm=%d", len(pBase), len(pNorm))
	}
	// 逐字段一致（QKNorm 仅影响 step_exec 运行时，不改变 plan 真值源）
	for i := range pBase {
		if pBase[i].Op != pNorm[i].Op {
			t.Fatalf("step#%d op 因 QKNorm 发生变化: %q vs %q", i, pBase[i].Op, pNorm[i].Op)
		}
		if pBase[i].Coord != pNorm[i].Coord {
			t.Fatalf("step#%d 坐标因 QKNorm 发生变化", i)
		}
	}
	if err := pNorm.Validate(); err != nil {
		t.Fatalf("QKNorm plan 自校验失败: %v", err)
	}
}

// TestQKNormTensorKeysValid 断言 q_norm/k_norm 是合法归一化张量 key
// （已登记进 normTensorSet，route2demo.Affine 可据此派生 gamma）。
func TestQKNormTensorKeysValid(t *testing.T) {
	for _, tk := range []TensorKey{
		{Block: 0, Tensor: TensorQNorm},
		{Block: 2, Tensor: TensorKNorm},
		{Block: DemoTiny.Blocks - 1, Tensor: TensorKNorm},
	} {
		if !tk.IsNorm() {
			t.Fatalf("%s 应被识别为 norm 张量", tk.String())
		}
		if err := tk.Validate(); err != nil {
			t.Fatalf("%s 应合法: %v", tk.String(), err)
		}
	}
	// 负 block 必须非法（TensorKey.Validate 仅做 cfg 无关的键合法性检查；
	// 越界 block 的语义检查由 route2demo.QKNormParams 在加载期执行）。
	bad := TensorKey{Block: -1, Tensor: TensorQNorm}
	if err := bad.Validate(); err == nil {
		t.Fatal("负 block 的 QK-norm key 应被 Validate 拒绝")
	}
}
