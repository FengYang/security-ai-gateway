package main

// ttft_report.go — P1-6 M2：数据面 TTFT 采集与上报（固定桶计数 + 首 token 采样 + 上报体/待确认队列）。
//
// 范围（如实，随 M2 原子滚动补全）：
//   - M2.2（本原子）：固定 11 桶计数（§3.4；逐边界对齐 tee-infer-service/metrics.go ttftBuckets）；
//   - M2.1：首 token 采样钩子（解密回调 + delta.content 判定，R2-04/R2-05）；
//   - M2.3：上报体构造 + VM ID + batch_id（TT2-08）；
//   - M2.4：待确认队列（冻结/确认清零/上限丢弃，R2-06）；
//   - M2.5：周期上报 tick（复用 wrapper.RegisterTickFunc 范式）。
//
// 本文件不含路由决策/权函数（TT2-19 解耦）；指标注册见 metrics.go（M5）。

// TTFTBucketCount TTFT 上报桶数（§3.4：11 桶；+Inf 为隐式兜底桶，不计入上报数组）。
const TTFTBucketCount = 11

// ttftBucketUpperBoundsMs 桶上界（毫秒，严格升序；§3.4）。
//
// 口径对齐（M2.2 验收）：逐边界等于 gateway/tee-infer-service/metrics.go 的 ttftBuckets
// （秒制 {0.01,0.025,0.05,0.1,0.25,0.5,1,2,5,10,30} × 1000）。两侧共同锁定同一字面量基线
// （ttft_report_test.go 断言），任一侧改动必须双侧同改，保证桶边界一致、口径可比。
var ttftBucketUpperBoundsMs = [TTFTBucketCount]int64{
	10, 25, 50, 100, 250, 500, 1000, 2000, 5000, 10000, 30000,
}

// ttftBucketCounts 固定桶计数（O(端点数×桶数)；观测零分配）。
type ttftBucketCounts struct {
	counts [TTFTBucketCount]uint64
}

// observe 计入一次 TTFT 样本（毫秒；负值防御归 0；超末桶上界归末桶，§3.4）。
func (c *ttftBucketCounts) observe(ms int64) {
	c.counts[ttftBucketIndex(ms)]++
}

// total 返回桶计数总和（当前周期样本数）。
func (c *ttftBucketCounts) total() uint64 {
	var n uint64
	for _, v := range c.counts {
		n += v
	}
	return n
}

// ttftBucketIndex 返回毫秒值所属桶（首个上界 ≥ ms 的桶；> 30000ms 归末桶，§3.4）。
func ttftBucketIndex(ms int64) int {
	if ms < 0 {
		ms = 0
	}
	for i, ub := range ttftBucketUpperBoundsMs {
		if ms <= ub {
			return i
		}
	}
	return TTFTBucketCount - 1
}
