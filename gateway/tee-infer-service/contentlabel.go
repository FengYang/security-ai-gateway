// B1 强标标识（GB 45438-2025）配置与注入器（合规达标最小集；技术方案 B1 节）。
//
// 判据落法：显式标识文字须同时含"人工智能"+"生成"（GB 45438-2025 5.1 b)），置于文本
// 起始/末尾（同 5.1 d)）→ 流首（head）+ 流尾（tail）双标 + 每 N 内容帧可重复（repeat）。
// 注：分片/卡片截取/转发"标识不丢失"**非标准明文要求**（未检索到标准原文），
// 系我方**风险缓释**目标（head＋tail 双锚点），不得作为"满足标准"的主张依据。
//
// 两条纪律（照抄 outputguard_config.go 文件头）：
//   - resolve 只派生（不报错）、validate 只校验（不派生），职责分离——
//     防止"非法值被兜底逻辑悄悄改成合法值"，使「非法＝启动失败」不被掩蔽。
//   - 校验 fail-closed：启用时文案必须同时含"人工智能"与"生成"子串，
//     否则启动失败 / POST 400（不合规文案不得静默生效）。
//
// 设计要点（与 OG 的差异）：
//   - 标识非拦截语义：运行时热切换 on/off 双向可切（无 enforcing 式单向闸门）；
//   - 标识帧**不计费**：不进 emittedBuilder / agg（tokens_out 与 filtered_tokens 口径不变），
//     经 emitLabel（count=false）发射，不旁路 writeChunk（seq 唯一分配点，帧序天然连续）；
//   - 终止帧恒带 label{position:"tail"}——尾标帧因截断丢失时终止帧兜底隐式标识；
//   - genErr error 分支不注入 tail（error 终止在插件侧整流 fail-closed，明文不出，标识无意义）。
package main

import (
	"fmt"
	"strings"
)

// B1：强标标识开关取值（-content-label）。
const (
	contentLabelOff = "off" // 缺省：完全不注入，行为与现网逐字节一致
	contentLabelOn  = "on"  // 流首/流尾双标 + 按间隔重复
)

// B1：标识位置（chunkLabelMeta.Position；终止帧固定 tail）。
const (
	labelPositionHead   = "head"
	labelPositionRepeat = "repeat"
	labelPositionTail   = "tail"
)

// B1：默认值（flag 缺省与 resolve 兜底同源）。
const (
	defaultContentLabelText = "内容由人工智能生成"
	defaultContentLabelStd  = "GB45438-2025"
	// maxContentLabelRepeat 重复间隔上限（0=仅首尾，∈[0,1000]）。
	maxContentLabelRepeat = 1000
)

// contentLabelConfig 强标标识生效配置（原始值 + resolve 后生效值）。
type contentLabelConfig struct {
	Enabled bool   // 开关（off 时其余字段不参与发射，但仍参与 repeat 范围校验）
	Text    string // 标识文案（启用时必须同时含"人工智能"与"生成"）
	Repeat  int    // 每 N 个内容帧插一次 repeat 标识（0=仅首尾）
	Std     string // 标准号（默认 GB45438-2025；chunkLabelMeta.Std 与审计同源）
	// 标识溯源要素：生成合成服务提供者要素（客户主体编码/名称；空 = 不输出该字段）。
	// **硬约束**：该字段属"溯源要素"，不得据此宣称"已满足 GB 45438-2025 6.1 文件元数据隐式标识"。
	Producer string
}

// defaultContentLabelConfig 返回未配置态（Enabled=false，文案/标准留空待 resolve 兜底）。
func defaultContentLabelConfig() contentLabelConfig {
	return contentLabelConfig{}
}

// resolveContentLabelConfig 填入缺省文案与标准号（resolve 只派生，不校验合法性）。
func resolveContentLabelConfig(c contentLabelConfig) contentLabelConfig {
	if c.Text == "" {
		c.Text = defaultContentLabelText
	}
	if c.Std == "" {
		c.Std = defaultContentLabelStd
	}
	return c
}

// validateContentLabelConfig 校验标识配置；非法即返回错误（启动期 / POST 均 fail-closed）。
// 文案子串仅在启用时校验（off 态文案不参与发射）；repeat 范围常校（捕获显式 typo）。
func validateContentLabelConfig(c contentLabelConfig) error {
	if c.Repeat < 0 || c.Repeat > maxContentLabelRepeat {
		return fmt.Errorf("content-label-repeat=%d 非法（取值 ∈[0,%d]；0=仅首尾）", c.Repeat, maxContentLabelRepeat)
	}
	if !c.Enabled {
		return nil
	}
	if !strings.Contains(c.Text, "人工智能") || !strings.Contains(c.Text, "生成") {
		return fmt.Errorf("content-label-text=%q 不合规（GB 45438-2025：显式标识须同时含「人工智能」与「生成」子串）", c.Text)
	}
	return nil
}

// ---- 运行时配置请求 / 持久化记录（与 outputGuardConfigRequest/Record 同构）----

// contentLabelConfigRequest POST /config/content-label 请求体（B1 运行时热切换）。
// 字段全可选（指针语义）：提供的字段覆盖当前生效值，未提供的保持现状——
// 与 outputGuardConfigRequest 的"整单覆盖"不同：标识非拦截语义，允许细粒度调整。
type contentLabelConfigRequest struct {
	Enabled *bool   `json:"enabled"`
	Text    *string `json:"text"`
	Repeat  *int    `json:"repeat"`
}

// contentLabelConfigRecord 持久化记录（JSON 单行，写 0600；与 outputGuardConfigRecord 同构）。
// 启动时读取恢复运行时覆盖（文件缺失/解析失败/取值非法 → 沿用启动参数，不阻断启动；
// 与 OG-8 不同：on/off 双向均可恢复——标识非拦截语义，无 enforcing 式单向闸门）。
type contentLabelConfigRecord struct {
	Enabled   bool   `json:"enabled"`
	Text      string `json:"text"`
	Repeat    int    `json:"repeat"`
	Std       string `json:"std"`
	Actor     string `json:"actor"`
	RequestID string `json:"request_id"`
	UpdatedAt int64  `json:"updated_at"` // UTC 纳秒
}

// contentLabelSnapshot 强标标识只读快照（GET /config 的 ContentLabel 字段）。
type contentLabelSnapshot struct {
	Enabled  bool   `json:"enabled"`
	Source   string `json:"source"` // startup | runtime
	Text     string `json:"text"`
	Repeat   int    `json:"repeat"`
	Std      string `json:"std"`
	Producer string `json:"producer"` // 标识溯源要素：生成合成服务提供者要素（空 = 未配置）
}

// ---- 注入器 ----

// contentLabeler 单请求标识注入器（流首/流尾/间隔重复三态）。
// cfg 为已 resolve 的生效配置；emit 为发射回调（内部即 emitLabel：不计费、带 label meta）。
type contentLabeler struct {
	cfg           contentLabelConfig
	emit          func(text string, meta *chunkLabelMeta) error
	contentFrames int    // 已下发内容帧计数（repeat 间隔基准）
	contentID     string // 标识溯源要素：内容制作编号（本请求 request_id，由调用点注入）
}

// newContentLabeler 构造注入器；cfg 为 nil 或 Enabled=false 时返回 nil（调用方统一判空）。
func newContentLabeler(cfg *contentLabelConfig, emit func(text string, meta *chunkLabelMeta) error) *contentLabeler {
	if cfg == nil || !cfg.Enabled || emit == nil {
		return nil
	}
	return &contentLabeler{cfg: *cfg, emit: emit}
}

// meta 构造本请求标识 meta（Std 与配置同源；标识溯源要素随标识帧携带溯源要素）。
func (l *contentLabeler) meta(position string) *chunkLabelMeta {
	if l == nil {
		return nil
	}
	return &chunkLabelMeta{
		Std:       l.cfg.Std,
		Position:  position,
		Synthetic: true, // 本形态输出即 AI 生成合成内容（标识生效时恒 true）
		Producer:  l.cfg.Producer,
		ContentID: l.contentID,
	}
}

// emitHead 流首标识（eng.Generate 之前调用；首帧 seq=1）。
func (l *contentLabeler) emitHead() error {
	if l == nil {
		return nil
	}
	return l.emit(l.cfg.Text, l.meta(labelPositionHead))
}

// afterContent 每个内容帧下发后调用：计数并按 repeat 间隔插重复标识帧。
// finish!=""（终止帧）或空 delta 不计数（与 emittedBuilder 口径一致）。
func (l *contentLabeler) afterContent(delta, finish string) error {
	if l == nil || l.cfg.Repeat <= 0 || finish != "" || delta == "" {
		return nil
	}
	l.contentFrames++
	if l.contentFrames%l.cfg.Repeat != 0 {
		return nil
	}
	return l.emit(l.cfg.Text, l.meta(labelPositionRepeat))
}

// emitTail 流尾标识（og.Finish 之后、stopChunk 构造之前调用）。
func (l *contentLabeler) emitTail() error {
	if l == nil {
		return nil
	}
	return l.emit(l.cfg.Text, l.meta(labelPositionTail))
}

// tailMeta 终止帧兜底 meta（恒带 position=tail；尾标帧因截断丢失时终止帧兜底隐式标识）。
// genErr error 分支不使用（error 终止在插件侧整流 fail-closed，明文不出，标识无意义）。
func (l *contentLabeler) tailMeta() *chunkLabelMeta {
	if l == nil {
		return nil
	}
	return l.meta(labelPositionTail)
}
