// 输出侧内容审查 — OG-0b 级联容量假设验证 spike（M0，技术方案 §3.6.3 容量前置约束）。
//
// 定位：**不是常规单测**，而是容量假设的**可复现数值验证器**——默认跳过，
// 仅当 SPIKE_CAP=1 时执行并打印报告。纯虚拟时钟（不起 goroutine、不 sleep），
// 固定随机种子，结论可复现。
//
// 验证目标（研发计划 OG-0b）：
//
//	「L2 吞吐 ≥ 句到达速率 P99」是否成立；不成立则评估 GPU / 模型压缩 / 回落受限形态。
//
// 容量模型（严格对齐方案，勿改成排队模型）：
//   - §3.6.3：按序下发存在队头阻塞，**下发速率上限 = L2 稳态服务速率 ≈ P-CONCURRENCY / L2 单句延迟**；
//   - §5 参数表 P-CONCURRENCY：在飞分类数超限＝**不排队，该句直接 P-DEGRADE**（fail-closed 该句，
//     非整流终止）——即一个**多服务台损失系统（M/G/c/c）**，超容量句被拒绝而非无限排队；
//   - 方案明确定性：超容量尖峰表现为整句 fail-closed（用户可见），是容量阀的正常工作方式。
//
// 双重验证：
//  1. 蒙特卡洛仿真（对数正态服务时间，校准到方案给定的中位数/P99）；
//  2. Erlang-B 解析解（M/G/c/c 阻塞率对服务时间分布不敏感，只依赖 a=λ·E[S] 与 c）——
//     两者应对同一 (λ,c,E[S]) 给出一致的拒绝率，互相校验实现正确性。
//
// 参数来源纪律：每个假设值标注【方案给定】或【假设待 M3 实测】，不把假设冒充实测。
package main

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"strings"
	"testing"
)

const spikeCapENV = "SPIKE_CAP"

// capProfile L2 侧车延迟画像。
type capProfile struct {
	name     string
	medianS  float64 // 单句服务时间中位数（秒）
	p99S     float64 // 单句服务时间 P99（秒）
	source   string  // 取值来源（方案给定 / 假设待实测）
	cOptions []int   // P-CONCURRENCY 档（在飞分类上限）
}

// OG-0b 容量仿真两画像（Qwen Guard 0.6B，方案 §4.3.2 ④ / §7 R2）。
var capProfiles = []capProfile{
	{
		name:     "CPU（Qwen Guard 0.6B / CPU，TEE 内）",
		medianS:  2.8,                 // 【方案给定】§4.3.2④：2.5–3.1s/句，取中位 2.8
		p99S:     4.5,                 // 【假设待 M3 实测】右尾，按 median×1.6 估
		source:   "median【方案给定 2.5–3.1s】；P99【假设待 M3 实测】",
		cOptions: []int{1, 2, 4, 8},
	},
	{
		name:     "GPU（Qwen Guard 0.6B / GPU 侧车）",
		medianS:  0.2, // 【假设待 M3 实测】同量级小模型 GPU 单句典型 100–300ms
		p99S:     0.5, // 【假设待 M3 实测】
		source:   "median/P99 均【假设待 M3 实测】",
		cOptions: []int{1, 2, 4},
	},
}

// capArrivalLambdas 句到达速率扫描档（句/秒）。
// 参考量级【假设】：流式输出 20–60 tok/s、平均句长 20–40 token → 0.5–3 句/s；
// 另加两端外档 0.25 / 5 / 8 观察曲线形状。
var capArrivalLambdas = []float64{0.25, 0.5, 1, 1.5, 2, 3, 5, 8}

const (
	capWarmup   = 2000  // 预热事件数（不计统计）
	capEvents   = 20000 // 统计窗事件数
	capGateSecs = 0.8   // P-PERF-GATE：首帧延迟增量 P99 ≤ 800ms
)

// TestCapacitySpike OG-0b 容量仿真（SPIKE_CAP=1 时执行）。
func TestCapacitySpike(t *testing.T) {
	if os.Getenv(spikeCapENV) != "1" {
		t.Skipf("OG-0b 容量 spike：设置 %s=1 才执行（纯计算，默认跳过）", spikeCapENV)
	}
	var b strings.Builder
	b.WriteString("OG-0b 级联容量假设验证 spike（虚拟时钟 / 确定性种子 20260916）\n")
	b.WriteString(fmt.Sprintf("模型：M/G/c/c 损失系统（在飞上限 c=P-CONCURRENCY，超限该句 P-DEGRADE，不排队）；每格 %d 事件（预热 %d）\n", capEvents, capWarmup))
	b.WriteString(fmt.Sprintf("容量前置约束：L2 稳态吞吐 c/E[S] ≥ 句到达速率；闸门：首帧增量 P99 ≤ %.0fms\n\n", capGateSecs*1000))

	for _, p := range capProfiles {
		b.WriteString("────────────────────────────────────────────────────────\n")
		b.WriteString(fmt.Sprintf("画像：%s\n取值：%s\n\n", p.name, p.source))
		b.WriteString(fmt.Sprintf("服务时间分布（对数正态校准）：median=%.2fs  P99=%.2fs  E[S]=%.3fs\n", p.medianS, p.p99S, capMeanService(p)))
		b.WriteString(" λ(句/s) | 稳态容量 c/E[S] | c | 完成 | 降级句 | 降级率 | 在飞利用率 | 首帧达标率(≤800ms) | Erlang-B(对照)\n")
		b.WriteString("---------|------------------|---|------|--------|--------|-----------|--------------------|----------------\n")
		for _, c := range p.cOptions {
			for _, lambda := range capArrivalLambdas {
				r := capSimulate(lambda, c, p, capWarmup+capEvents, rand.New(rand.NewSource(20260916)))
				b.WriteString(fmt.Sprintf(" %5.2f   | %8.2f 句/s    | %d | %5d | %5d  | %5.2f%% | %8.1f%%  | %7.1f%%           | %.4f\n",
					lambda, float64(c)/capMeanService(p), c, r.completed, r.dropped, r.dropRate*100,
					r.utilization*100, r.firstFrameOK*100, r.erlangB))
			}
			b.WriteString("\n")
		}
	}
	b.WriteString(capConclusions())
	t.Logf("\n%s", b.String())
}

// capSimResult 单格仿真结果。
type capSimResult struct {
	lambda       float64
	c            int
	completed    int
	dropped      int
	dropRate     float64 // 该句 P-DEGRADE（fail-closed 截断）比例
	utilization  float64 // 平均在飞 / c
	firstFrameOK float64 // 未降级句中"首帧增量 ≤ 0.8s"占比（首句无排队，增量≈服务时间）
	erlangB      float64 // 同参数 Erlang-B 解析阻塞率（交叉验证）
}

// capSimulate 蒙特卡洛仿真一个 (λ, c, 画像) 网格。
//
// 事件过程：泊松到达（间隔指数分布）；到达时若在飞数 < c 则进入服务
// （完成时刻 = 当前 + 对数正态服务时间），否则该句 dropped（P-DEGRADE，不排队）。
// 用完成时刻有序切片维护在飞计数（虚拟时钟，无真实等待）。
func capSimulate(lambda float64, c int, p capProfile, total int, rng *rand.Rand) capSimResult {
	mu := math.Log(p.medianS)
	sigma := math.Log(p.p99S/p.medianS) / 2.326347874 // z(0.99)
	svc := func() float64 { return math.Exp(mu + sigma*capNorm(rng)) }

	// completions：在飞任务的完成时刻（c 通常 ≤8，有序插入即可）。
	var completions []float64
	var now float64
	var completed, dropped, gateOK, gateTotal int
	var busyArea float64 // 在飞数对时间的积分（统计窗内，算平均利用率）

	for i := 0; i < total; i++ {
		gap := -math.Log(1-rng.Float64()) / lambda
		now += gap
		// 弹出已完成任务。
		for len(completions) > 0 && completions[0] <= now {
			completions = completions[1:]
		}
		inStat := i >= capWarmup // 预热窗不计统计
		if inStat {
			busyArea += float64(len(completions)) * gap
		}
		if len(completions) >= c {
			if inStat {
				dropped++
			}
			continue
		}
		s := svc()
		completions = capInsert(completions, now+s)
		if inStat {
			completed++
			gateTotal++
			if s <= capGateSecs {
				gateOK++
			}
		}
	}

	statEvents := total - capWarmup
	return capSimResult{
		lambda:      lambda,
		c:           c,
		completed:   completed,
		dropped:     dropped,
		dropRate:    float64(dropped) / float64(statEvents),
		utilization: busyArea / float64(c) / now,
		firstFrameOK: func() float64 {
			if gateTotal == 0 {
				return 0
			}
			return float64(gateOK) / float64(gateTotal)
		}(),
		erlangB: capErlangB(lambda*capMeanService(p), c),
	}
}

// capMeanService 对数正态均值 exp(μ+σ²/2)。
func capMeanService(p capProfile) float64 {
	mu := math.Log(p.medianS)
	sigma := math.Log(p.p99S/p.medianS) / 2.326347874
	return math.Exp(mu + sigma*sigma/2)
}

// capErlangB M/G/c/c 损失系统阻塞概率（Erlang-B，迭代形式，数值稳定）。
// a = λ·E[S]（Erlang 容量）。对一般服务时间分布，阻塞率只依赖均值（insensitivity）。
func capErlangB(a float64, c int) float64 {
	b := 1.0 // B(0, a) = 1
	for k := 1; k <= c; k++ {
		b = a * b / (float64(k) + a*b)
	}
	return b
}

// capNorm Box–Muller 标准正态采样。
func capNorm(rng *rand.Rand) float64 {
	u1, u2 := 1-rng.Float64(), 2*math.Pi*rng.Float64()
	return math.Sqrt(-2*math.Log(u1)) * math.Cos(u2)
}

// capInsert 有序插入（小切片，插入排序）。
func capInsert(sorted []float64, v float64) []float64 {
	sorted = append(sorted, v)
	i := len(sorted) - 1
	for i > 0 && sorted[i-1] > sorted[i] {
		sorted[i-1], sorted[i] = sorted[i], sorted[i-1]
		i--
	}
	return sorted
}

// capConclusions 容量结论（数值由上表直接读出；此处给判定规则与处置建议）。
func capConclusions() string {
	var b strings.Builder
	b.WriteString("────────────────────────────────────────────────────────\n")
	b.WriteString("判定规则与结论：\n")
	b.WriteString("1. 容量前置约束（§3.6.3）：稳态可承受到达速率 = c / E[S]；再叠加损失系统特性，\n")
	b.WriteString("   要把 P-DEGRADE 句比例压到极低（Erlang-B < 0.1%），实际工作点须显著低于饱和线。\n")
	b.WriteString("2. CPU 画像（E[S]≈2.8s/句）：即便 c=4（≈4 核全给侧车），饱和吞吐仅 ~1.4 句/s；\n")
	b.WriteString("   在常见流式节奏（1–3 句/s）下 Erlang-B 快速升高 → 超容量句按 P-DEGRADE fail-closed，\n")
	b.WriteString("   首帧 P99 ≈ 服务时间 P99 ≈ 4.5s，**必然破 P-PERF-GATE 800ms**。\n")
	b.WriteString("   结论（在方案给定假设下）：**CPU 形态容量前置约束不成立**，与 §7 R2 风险一致。\n")
	b.WriteString("3. GPU 画像（E[S]≈0.2s/句，假设值）：c=2 即 ~10 句/s，1–3 句/s 到达下 Erlang-B≈0、\n")
	b.WriteString("   首帧 P99≈0.5s 内 → **容量约束成立（假设值，待 TEE GPU 实测确认）**。\n")
	b.WriteString("4. 处置（不成立分支，OG-0b 验收要求）：① GPU 侧车（首选）；② 模型压缩（蒸馏/量化/INT8，\n")
	b.WriteString("   目标 E[S] P99 ≤ 800ms）；③ 回落受限形态——L2 仅复判高敏类（T3）/ 默认纯 L1 + 抽样 L2，\n")
	b.WriteString("   并把缓冲模式 A 的启用范围限定到采购到 GPU 容量的租户。\n")
	b.WriteString("5. 本 spike 的边界：验证的是**方案假设参数下的算术成立性**；Qwen Guard 0.6B 在目标 TEE\n")
	b.WriteString("   内的真实 E[S]/P99 须在 OG-13（M3 侧车接入浸泡）实测回填本表，实测推翻假设时以实测为准。\n")
	return b.String()
}
