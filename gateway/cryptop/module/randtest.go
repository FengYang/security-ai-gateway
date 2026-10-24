package cryptopmodule

import (
	"errors"
	"fmt"
	"io"

	"github.com/Trisia/randomness"
	"github.com/Trisia/randomness/detect"
)

// 本文件实现 R-S3-12（GM2-03）随机数质量启动自检。
//
// 标准依据（2026-10-24 逐条核实）：
//   - GB/T 32915-2016《信息安全技术 二元序列随机性检测方法》/ GM/T 0005-2021
//     《随机性检测规范》：15 项检测方法，显著性水平 α=0.01（库常量 randomness.Alpha）。
//   - GM/T 0062-2018《密码产品随机数检测要求》：E 类产品随机数发生器的
//     出厂/上电/周期/单次四阶段检测（上电检测 = 15 项 × 20 组 × 10^6 bit，
//     组间另做均匀性判定 AlphaT=0.0001）。
//   - GM/T 0078-2020《密码模块安全技术要求》：物理随机源序列每 20000 bit 执行
//     单比特频数/扑克/游程总数检测（模块内连续检测口径）。
//
// ⚠️ 标准号订正（登记 U-S3-10）：设计文档 R-S3-12 原文为"GM/T 0050 启动测试"，
// 经核实 GM/T 0050-2016 是《密码设备管理 设备管理技术规范》（国家密码管理局
// 2016 年第 31 号公告发布），与随机性检测无关；GM/T 0005-2012 已被
// GM/T 0005-2021 替代。本实现按现行有效的 GB/T 32915-2016 检测方法 +
// GM/T 0062-2018 上电检测语义 + GM/T 0078-2020 的 20000 bit 规模落地，
// 标准号订正与参数档位选择待 S4-a 测评机构回写确认（U-S3-10）。

// ErrRandSelfCheckFailed 随机数质量启动自检未通过（R-S3-12）。
// fail-closed：不合格随机数不得进入上层使用路径。
var ErrRandSelfCheckFailed = errors.New("module: 随机数质量启动自检未通过（R-S3-12）")

// randQuickCheckBits quick 档样本规模：20000 bit（GM/T 0078-2020 连续检测口径）。
const randQuickCheckBits = 20000

// RandCheckProfile 随机数自检档位。
type RandCheckProfile int

const (
	// RandCheckQuick 20000 bit 三项检测（单比特频数/扑克 m=4/游程总数），
	// 启动自检默认档；开销约 2500 字节随机数，毫秒级。
	RandCheckQuick RandCheckProfile = iota
	// RandCheckPowerOn GM/T 0062-2018 E 类产品上电检测全量
	// （15 项 × 20 组 × 10^6 bit ≈ 2.5MB 随机数），用于 S3-a 厂商到货验收
	// 与密评留档；启动路径不启用。
	RandCheckPowerOn
)

// String 档位名称（留档/日志）。
func (p RandCheckProfile) String() string {
	switch p {
	case RandCheckQuick:
		return "quick(20000bit/3项)"
	case RandCheckPowerOn:
		return "power-on(GM/T 0062-2018 15项x20组x10^6bit)"
	default:
		return fmt.Sprintf("unknown(%d)", int(p))
	}
}

// RandCheckItem 单项检测结果（P-value 与判定）。
type RandCheckItem struct {
	Name string
	P    float64
	Pass bool
}

// RandCheckReport 自检报告，R-S3-12 留档要素：样本量、显著水平、逐项 P-value、结论。
type RandCheckReport struct {
	Profile RandCheckProfile
	Bits    int
	Alpha   float64
	Items   []RandCheckItem
	Passed  bool
	// Detail 失败摘要（失败项名与 P-value），通过时为空。
	Detail string
}

// String 人类可读摘要（日志/留档）。
func (r *RandCheckReport) String() string {
	if r == nil {
		return "<nil>"
	}
	verdict := "PASS"
	if !r.Passed {
		verdict = "FAIL"
	}
	s := fmt.Sprintf("rand-self-check profile=%s bits=%d alpha=%g verdict=%s",
		r.Profile, r.Bits, r.Alpha, verdict)
	for _, it := range r.Items {
		mark := "pass"
		if !it.Pass {
			mark = "FAIL"
		}
		s += fmt.Sprintf(" | %s P=%.6g %s", it.Name, it.P, mark)
	}
	if r.Detail != "" {
		s += " | detail=" + r.Detail
	}
	return s
}

// RunRandSelfCheck 从 reader 读取随机样本执行启动自检（R-S3-12）。
//
// 语义：reader 提供被测熵源输出（生产为模块 C_GenerateRandom 输出）；
// 返回的 error 仅表示检测过程本身失败（读样本失败/档位非法），
// 检测完成但结论不通过时 error 为 nil、report.Passed=false。
func RunRandSelfCheck(reader io.Reader, profile RandCheckProfile) (*RandCheckReport, error) {
	switch profile {
	case RandCheckQuick:
		return runQuickRandCheck(reader)
	case RandCheckPowerOn:
		return runPowerOnRandCheck(reader)
	default:
		return nil, fmt.Errorf("module: 未知随机数自检档位 %d", int(profile))
	}
}

// runQuickRandCheck 20000 bit 三项检测（GB/T 32915-2016 方法 + GM/T 0078-2020 规模）。
func runQuickRandCheck(reader io.Reader) (*RandCheckReport, error) {
	buf := make([]byte, randQuickCheckBits/8)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return nil, fmt.Errorf("module: 随机数自检样本读取失败（需 %d 字节）: %w", len(buf), err)
	}
	seq := randomness.NewBitSeqFromBytes(buf)

	// 三项检测各返回 (P, Q)，取 P-value 判定（GB/T 32915-2016：P ≥ α 通过）。
	pMono, _ := randomness.MonoBitFrequencyTestBitSeq(seq)
	pPoker, _ := randomness.PokerTestBitSeq(seq, 4)
	pRuns, _ := randomness.RunsTestBitSeq(seq)
	items := []RandCheckItem{
		randItem("单比特频数检测", pMono),
		randItem("扑克检测(m=4)", pPoker),
		randItem("游程总数检测", pRuns),
	}

	rep := &RandCheckReport{
		Profile: RandCheckQuick,
		Bits:    randQuickCheckBits,
		Alpha:   randomness.Alpha,
		Items:   items,
	}
	for _, it := range items {
		if !it.Pass {
			rep.Passed = false
			rep.Detail += fmt.Sprintf("%s(P=%.6g<alpha=%.3g); ", it.Name, it.P, randomness.Alpha)
		}
	}
	if rep.Detail == "" {
		rep.Passed = true
	}
	return rep, nil
}

// randItem 用库判定（Pass = P ≥ Alpha）组装单项结果。
func randItem(name string, p float64) RandCheckItem {
	return RandCheckItem{Name: name, P: p, Pass: p >= randomness.Alpha}
}

// runPowerOnRandCheck GM/T 0062-2018 E 类上电检测（委托 randomness/detect，
// v1.6.0 实现 15 项 × 20 组 × 10^6 bit + 组通过率 + 分布均匀性双重判定）。
//
// 注意库的错误语义：组通过率/均匀性不达标与 io 读取失败都经 (bool, error)
// 返回，前者 error 消息形如"检测项 n/20"（结论失败，含明细），后者为
// io.EOF/ErrUnexpectedEOF 类（过程失败）。此处按此区分：结论失败记入
// report（Passed=false、Detail 带明细），过程失败才返回 error。
//
// 明细留档：该档只给失败摘要；逐项完整明细由 S3-a 厂商到货验收时用库的
// rddetector 工具产出报告（登记于已知限制）。
func runPowerOnRandCheck(reader io.Reader) (*RandCheckReport, error) {
	ok, err := detect.PowerOnDetect(reader)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("module: 上电检测样本读取失败: %w", err)
		}
		return &RandCheckReport{
			Profile: RandCheckPowerOn,
			Alpha:   randomness.AlphaT,
			Passed:  false,
			Detail:  fmt.Sprintf("上电检测未通过: %v", err),
		}, nil
	}
	return &RandCheckReport{
		Profile: RandCheckPowerOn,
		Alpha:   randomness.AlphaT,
		Passed:  ok,
	}, nil
}

// RandHealthStatus 随机数健康状态（附录 B 指标 cryptop_module_rand_health，
// 1=通过/0=失败；另增 -1=尚未自检的内部态）。
//
// 常量顺序即零值安全性：RandHealthUnknown=0 使 &PKCS11Backend{} 零值构造
// 落在"尚未自检"而非误判"已失败"。
type RandHealthStatus int

const (
	// RandHealthUnknown 尚未执行自检（零值）。
	RandHealthUnknown RandHealthStatus = iota
	// RandHealthPassed 自检通过（指标值 1）。
	RandHealthPassed
	// RandHealthFailed 自检未通过（指标值 0；fail-closed）。
	RandHealthFailed
)

// Int 指标值（附录 B：gauge，1=通过/0=失败；未检返回 -1 供上层区分）。
func (s RandHealthStatus) Int() int {
	switch s {
	case RandHealthPassed:
		return 1
	case RandHealthFailed:
		return 0
	default:
		return -1
	}
}
