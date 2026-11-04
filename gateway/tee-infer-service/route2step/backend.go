package route2step

// MaskedStepBackend 掩码单步后端契约：输入/输出均为掩码态张量（[][]uint64），
// 在 TEE 内做「Unmask → 算子 → Remask」。
//
// 它与明文生成引擎 model.Engine（Generate 文本/token，vLLM/cmaas 实现）分属两条
// 正交插件平面，**不得合并**：本平面不生成文本、不碰明文 token。
type MaskedStepBackend interface {
	Step(ctx *StepContext) ([][]uint64, int, *StepError)
}

// StepFunc 把普通函数适配为 MaskedStepBackend。
type StepFunc func(ctx *StepContext) ([][]uint64, int, *StepError)

func (f StepFunc) Step(ctx *StepContext) ([][]uint64, int, *StepError) { return f(ctx) }

// 编译期断言：ExecStep 满足默认掩码步后端契约。
var _ MaskedStepBackend = StepFunc(ExecStep)
