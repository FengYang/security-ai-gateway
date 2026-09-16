// 输出侧内容审查配置（P-* 参数组，技术方案 §5；§3.2 文件清单 outputguard_config.go）。
//
// OG-4 先落 D 组「缓冲与资源」中与缓冲器直接相关的参数（P-UNIT、P-MAX-UNIT-RUNES、
// P-FIRST-UNIT-MAX-RUNES、P-MAX-BUFFER-BYTES、P-WINDOW-MARGIN 及派生的 P-WINDOW-CHARS）；
// OG-8 在此基础上扩展启动 flag、运行时覆盖、/config 快照与持久化，并接入 D8 变更流程。
// 全局在飞上限（P-MAX-INFLIGHT-BYTES）与句数上限（P-MAX-SLOTS）随 enforcing/级联（M4）落地。
//
// 两条纪律：
//   - 「未配置」用哨兵 paramUnset(-1) 表达——OG-8 的 flag 解析器把"未提供"映射为 -1，
//     "显式提供 0"保持 0。否则无法区分二者，而 §5.4 明确「显式 0」属非法（启动失败）。
//   - resolve 只派生（不报错）、validate 只校验（不派生），职责分离——
//     防止"非法值被兜底逻辑悄悄改成合法值"，使「非法＝启动失败」不被掩蔽（§5.4 兜底列）。
package main

import "fmt"

// paramUnset 未配置哨兵（见文件头约定）。
const paramUnset = -1

// M1 缓冲默认值（T5 标定前的保守取值；取值回填不改类型/接口，§5 约定）。
const (
	defaultMaxUnitRunes   = 500     // P-MAX-UNIT-RUNES 保守默认
	defaultMaxBufferBytes = 1 << 20 // P-MAX-BUFFER-BYTES 每请求默认 1MiB
	firstUnitRatio        = 0.4     // P-FIRST-UNIT-MAX-RUNES 派生比例（§5.4）
	windowMarginRatio     = 1.5     // P-WINDOW-MARGIN 保守默认（≥ 词库最长词 × 1.5，§5.4）
)

// outputGuardParams D 组缓冲参数（原始值 + 派生值）。
type outputGuardParams struct {
	Unit              string // P-UNIT：sentence｜fixed-window
	MaxUnitRunes      int    // P-MAX-UNIT-RUNES（判定单元 rune 上限）
	FirstUnitMaxRunes int    // P-FIRST-UNIT-MAX-RUNES（首句强切阈值，≤ MaxUnitRunes）
	MaxBufferBytes    int    // P-MAX-BUFFER-BYTES（每请求缓冲字节上限）
	WindowMargin      int    // P-WINDOW-MARGIN（滑窗余量 rune 数；0 非法）
	MaxKeywordRunes   int    // 词库最长命中长度（P-WINDOW-CHARS 派生输入；OG-9 后取词库实测值）
	WindowRunes       int    // P-WINDOW-CHARS（派生只读：MaxKeywordRunes + WindowMargin）
}

// defaultOutputGuardParams 返回未配置态（全哨兵）的 D 组参数。
func defaultOutputGuardParams() outputGuardParams {
	return outputGuardParams{
		Unit:              unitSentence,
		MaxUnitRunes:      paramUnset,
		FirstUnitMaxRunes: paramUnset,
		MaxBufferBytes:    paramUnset,
		WindowMargin:      paramUnset,
	}
}

// resolveOutputGuardParams 填入缺省并派生 P-WINDOW-CHARS / P-FIRST-UNIT-MAX-RUNES（§5.4）。
// 只做派生，不做合法性判断：0/负值一律按"未配置"处理（保证零值结构体也能安全构造），
// "显式 0 非法"由 validateOutputGuardParams 对**原始值**拦截（启动期先 validate 再 resolve）。
func resolveOutputGuardParams(p outputGuardParams) outputGuardParams {
	if p.Unit == "" {
		p.Unit = unitSentence
	}
	if p.MaxUnitRunes <= 0 {
		p.MaxUnitRunes = defaultMaxUnitRunes
	}
	// §5.4：未配置＝0.4 派生；大于 P-MAX-UNIT-RUNES＝非法，按 0.4 比例自动取。
	if p.FirstUnitMaxRunes <= 0 || p.FirstUnitMaxRunes > p.MaxUnitRunes {
		p.FirstUnitMaxRunes = int(float64(p.MaxUnitRunes)*firstUnitRatio + 0.5)
		if p.FirstUnitMaxRunes < 1 {
			p.FirstUnitMaxRunes = 1
		}
	}
	if p.MaxBufferBytes <= 0 {
		p.MaxBufferBytes = defaultMaxBufferBytes
	}
	// §5.4：未配置＝保守默认（≥ 词库最长词 × 1.5），下限 1。
	if p.WindowMargin <= 0 {
		p.WindowMargin = int(float64(p.MaxKeywordRunes)*windowMarginRatio + 0.5)
		if p.WindowMargin < 1 {
			p.WindowMargin = 1
		}
	}
	p.WindowRunes = p.MaxKeywordRunes + p.WindowMargin
	return p
}

// validateOutputGuardParams 校验原始参数；非法即返回错误（调用方 fail-closed 拒绝启动）。
// 显式 0 一律非法（§5.4）；未配置须留 paramUnset，不得填 0。
func validateOutputGuardParams(p outputGuardParams) error {
	switch p.Unit {
	case "", unitSentence, unitFixedWindow:
	default:
		return fmt.Errorf("P-UNIT=%q 非法（取值：sentence|fixed-window）", p.Unit)
	}
	if err := validatePositiveRunes("P-MAX-UNIT-RUNES", p.MaxUnitRunes); err != nil {
		return err
	}
	if err := validatePositiveRunes("P-MAX-BUFFER-BYTES", p.MaxBufferBytes); err != nil {
		return err
	}
	if err := validatePositiveRunes("P-WINDOW-MARGIN", p.WindowMargin); err != nil {
		return err
	}
	if p.MaxKeywordRunes < 0 {
		return fmt.Errorf("P-WINDOW-CHARS 派生输入（词库最长命中长度）=%d 非法（不得为负）", p.MaxKeywordRunes)
	}
	return nil
}

// validatePositiveRunes 校验 int 参数：paramUnset＝未配置（放行）；0 或负＝非法。
func validatePositiveRunes(name string, v int) error {
	if v == paramUnset {
		return nil
	}
	if v <= 0 {
		return fmt.Errorf("%s=%d 非法（不得为 0/负数；未配置请留 %d）", name, v, paramUnset)
	}
	return nil
}

// outputGuardConfig 审查管线构造配置（§2.3 I1 `outputguard.New(cfg)`）。
type outputGuardConfig struct {
	Mode          string            // P-MODE：off｜shadow（enforcing 属 M4）
	PolicyVersion string            // 策略版本（manifest.policy_version；M1 未接词库，用 defaultPolicyVersion）
	Params        outputGuardParams // D 组缓冲参数（允许传未 resolve 值，构造时会 resolve）
}

// ---- OG-8：运行时配置请求 / 持久化记录（与 guardrailConfigRequest 同构）----

// outputGuardConfigRequest POST /config/output-guard 请求体（OG-8 运行时覆盖）。
// 仅允许切换 mode（off｜shadow）；enforcing 属 M4，此处拒绝（安全闸门不开放）。
// 治理链在 gateway-admin-service（D8 高敏变更 submitter≠reviewer 复核通过后执行），
// 本端点只做"配置生效 + 持久化 + 落 tee-infer 审计链"。
type outputGuardConfigRequest struct {
	Mode string `json:"mode"`
}

// outputGuardConfigRecord 持久化记录（JSON 单行，写 0600；与 guardrailConfigRecord 同构）。
// 启动时读取恢复运行时覆盖（文件缺失/解析失败/取值非法 → 沿用启动参数，不阻断启动）。
type outputGuardConfigRecord struct {
	Mode      string `json:"mode"`
	Actor     string `json:"actor"`
	RequestID string `json:"request_id"`
	UpdatedAt int64  `json:"updated_at"` // UTC 纳秒
}
