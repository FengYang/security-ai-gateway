// state_machine_model_test.go - resolveModel 的模型解析契约（T4）
//
// 只测**不需真实权重**的路径与 fail-closed 语义；真实 0.6B 权重的加载/数值正确性
// 由端到端 golden 对拍覆盖（T5）。这些断言存在的意义：模型解析一旦"悄悄回落 demo"
// 或"未知 id 也放行"，客户端会以为自己换了模型而实际没换，且没有任何一层报错。
package main

import (
	"os"
	"strings"
	"testing"

	"github.com/FengYang/masked-infer/plan"
)

// TestResolveModelDemo demo 模型必须可用，且配置的 ModelID 与常量源一致。
func TestResolveModelDemo(t *testing.T) {
	cfg, w, err := resolveModel(route2plan.DemoModelID)
	if err != nil {
		t.Fatalf("demo 模型应可解析: %v", err)
	}
	if w == nil {
		t.Fatal("demo 权重不可为 nil")
	}
	if cfg.ModelID != route2plan.DemoModelID {
		t.Errorf("cfg.ModelID = %q, want %q", cfg.ModelID, route2plan.DemoModelID)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("demo 配置应自洽可校验: %v", err)
	}
	// 权重必须与 cfg 同源：ExecStep 依赖 ModelWeights.Config() 与 StepContext.Cfg 一致。
	if got := w.Config().ModelID; got != route2plan.DemoModelID {
		t.Errorf("weights.Config().ModelID = %q, want %q（两处配置分叉会让掩码域/维度错配）",
			got, route2plan.DemoModelID)
	}
}

// TestResolveModelUnknownRejected 未知 model_id 一律拒绝，绝不回落默认配置。
func TestResolveModelUnknownRejected(t *testing.T) {
	for _, id := range []string{"", "gpt-4", "qwen3-7b", "Qwen3-0.6b"} {
		if _, _, err := resolveModel(id); err == nil {
			t.Errorf("未知 model_id %q 应被拒绝，却被接受（回落会让客户端以为换了模型）", id)
		}
	}
}

// TestResolveModelRealQwenRequiresEnv 未配置安装期参数时必须 fail-closed，
// 且错误信息须点明该参数名（运维才知该填什么）。
func TestResolveModelRealQwenRequiresEnv(t *testing.T) {
	t.Setenv(envRealQwenWeights, "")
	_, _, err := resolveModel(realQwenModelID)
	if err == nil {
		t.Fatal("未配置 " + envRealQwenWeights + " 时应 fail-closed")
	}
	if !strings.Contains(err.Error(), envRealQwenWeights) {
		t.Errorf("错误信息应点明参数名 %s，实际: %v", envRealQwenWeights, err)
	}
}

// TestResolveModelRealQwenMissingFile 路径配了但文件不可读时同样 fail-closed，
// 不得静默跳过或回落 demo。
func TestResolveModelRealQwenMissingFile(t *testing.T) {
	t.Setenv(envRealQwenWeights, os.TempDir()+"/definitely-not-a-weights-file.safetensors")
	if _, _, err := resolveModel(realQwenModelID); err == nil {
		t.Fatal("权重文件不存在时应 fail-closed")
	}
}
