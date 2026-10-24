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
	// Attempts 实际尝试次数（quick 档重试机制；1 = 一次通过）。
	Attempts int
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
	if r.Attempts > 1 {
		s += fmt.Sprintf(" attempts=%d", r.Attempts)
	}
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

// randQuickCheckAttempts quick 档最大尝试次数（1 次首检 + 2 次复检）。
//
// 依据（2026-10-24 实测，.248 SoftHSM）：单样本统计检测有固有误拒率——
// 每项 α=0.01，三项合计约 2.5%（实测 200 次误拒 5 次：mono=2/poker=2/
// runs=1，与统计预期吻合，熵源无异常）。若启动门禁只检一次，健康模块
// 每次进程启动有约 2.5% 概率被误拒而无法启动（可用性缺陷）。
// 对策（行业惯例，SP 800-90B 连续检测的重复确认思想）：首检失败后重新
// 采样复检，仅当连续 randQuickCheckAttempts 次均不通过才判失败——坏熵源
// 每次必败（fail-closed 不放松），健康熵源误拒率降至约 (0.025)^3 ≈ 1.6e-5。
const randQuickCheckAttempts = 3

// randPowerOnAttempts power-on 档最大尝试次数（1 次首检 + 2 次复检）。
//
// 依据：库 PowerOnDetect 判据为每项 ≥ Threshold(20)=19 组通过（组内
// α=0.01）+ Q 值分布均匀性（AlphaT=0.0001）。按二项分布，健康熵源每项
// P(≤18/20)≈1.7%，15 项合计误拒率约 20%（2026-10-24 实测复现：重叠子
// 序列检测 18/20）。该档用于 S3-a 到货验收/密评留档，误拒会把合格设备
// 判废，故同样采用复检对策；坏熵源每次必败，fail-closed 不放松。
const randPowerOnAttempts = 3

// runQuickRandCheck 20000 bit 三项检测（GB/T 32915-2016 方法 + GM/T 0078-2020
// 规模），带误拒率对策重试（见 randQuickCheckAttempts）。
func runQuickRandCheck(reader io.Reader) (*RandCheckReport, error) {
	var last *RandCheckReport
	var firstDetail string
	attempted := 0
	for attempt := 1; attempt <= randQuickCheckAttempts; attempt++ {
		rep, err := runQuickRandCheckOnce(reader)
		if err != nil {
			if attempt > 1 {
				break // 复检取样失败（如有限 reader 耗尽）：首检结论即最终结论
			}
			return nil, err // 首检取样失败：过程错误（非结论失败）
		}
		attempted = attempt
		rep.Attempts = attempt
		if rep.Passed {
			return rep, nil
		}
		if attempt == 1 {
			firstDetail = rep.Detail
		}
		last = rep
	}
	// 首检失败且复检无法救回：fail-closed。
	if attempted < randQuickCheckAttempts {
		last.Detail = fmt.Sprintf("复检取样失败（reader 耗尽），以首检失败结论为准: %s", last.Detail)
	} else {
		last.Detail = fmt.Sprintf("连续 %d 次尝试均未通过（首次: %s；末次: %s）",
			attempted, firstDetail, last.Detail)
	}
	return last, nil
}

// runQuickRandCheckOnce 单次 20000 bit 三项检测。
func runQuickRandCheckOnce(reader io.Reader) (*RandCheckReport, error) {
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
// v1.6.0 实现 15 项 × 20 组 × 10^6 bit + 组通过率 ≥19/20 + 分布均匀性双重
// 判定），带误拒率对策重试（见 randPowerOnAttempts）。
func runPowerOnRandCheck(reader io.Reader) (*RandCheckReport, error) {
	var last *RandCheckReport
	var firstDetail string
	attempted := 0
	for attempt := 1; attempt <= randPowerOnAttempts; attempt++ {
		rep, err := runPowerOnRandCheckOnce(reader)
		if err != nil {
			if attempt > 1 {
				break // 复检取样失败：首检结论即最终结论
			}
			return nil, err
		}
		attempted = attempt
		rep.Attempts = attempt
		if rep.Passed {
			return rep, nil
		}
		if attempt == 1 {
			firstDetail = rep.Detail
		}
		last = rep
	}
	if attempted < randPowerOnAttempts {
		last.Detail = fmt.Sprintf("复检取样失败（reader 耗尽），以首检失败结论为准: %s", last.Detail)
	} else {
		last.Detail = fmt.Sprintf("连续 %d 次尝试均未通过（首次: %s；末次: %s）",
			attempted, firstDetail, last.Detail)
	}
	return last, nil
}

// runPowerOnRandCheckOnce 单次上电检测。
//
// 注意库的错误语义：组通过率/均匀性不达标与 io 读取失败都经 (bool, error)
// 返回，前者 error 消息形如"检测项 n/20"（结论失败，含明细），后者为
// io.EOF/ErrUnexpectedEOF 类（过程失败）。此处按此区分：结论失败记入
// report（Passed=false、Detail 带明细），过程失败才返回 error。
//
// 明细留档：该档只给失败摘要；逐项完整明细由 S3-a 厂商到货验收时用库的
// rddetector 工具产出报告（登记于已知限制）。
func runPowerOnRandCheckOnce(reader io.Reader) (*RandCheckReport, error) {
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
