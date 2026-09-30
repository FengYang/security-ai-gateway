package routeengine

import (
	"testing"
)

// ============================================================
// EWMA 单元测试（方案 §6.2.7 测试清单节选）
// ============================================================

// 新创建的 EWMA：rate=0，无效
func TestEWMA_New(t *testing.T) {
	e := NewEWMARate(0.1, 10, 60)
	if e.GetRate() != 0 {
		t.Fatalf("初始失败率应为 0，got %.4f", e.GetRate())
	}
	if e.Valid() {
		t.Fatalf("初始状态应无效")
	}
}

// 全成功：失败率趋近于 0
func TestEWMA_AllSuccess(t *testing.T) {
	e := NewEWMARate(0.2, 5, 0) // 无衰减
	for i := 0; i < 20; i++ {
		e.Record(true, int64(i*1000))
	}
	if e.GetRate() > 0.01 {
		t.Fatalf("全成功后失败率应接近 0，got %.4f", e.GetRate())
	}
	if !e.Valid() {
		t.Fatalf("20 个样本后应有效")
	}
}

// 全失败：失败率趋近于 1
func TestEWMA_AllFail(t *testing.T) {
	e := NewEWMARate(0.2, 5, 0)
	for i := 0; i < 20; i++ {
		e.Record(false, int64(i*1000))
	}
	if e.GetRate() < 0.95 {
		t.Fatalf("全失败后失败率应接近 1，got %.4f", e.GetRate())
	}
}

// α 越小收敛越慢：α=0.05 比 α=0.3 在相同失败次数下 rate 更低
func TestEWMA_AlphaAffectsConvergence(t *testing.T) {
	eSlow := NewEWMARate(0.05, 1, 0)
	eFast := NewEWMARate(0.3, 1, 0)
	for i := 0; i < 10; i++ {
		eSlow.Record(false, int64(i*1000))
		eFast.Record(false, int64(i*1000))
	}
	if eSlow.GetRate() >= eFast.GetRate() {
		t.Fatalf("α 小的应收敛更慢，slow=%.4f fast=%.4f", eSlow.GetRate(), eFast.GetRate())
	}
}

// 最小样本数：未达标时 Valid()=false
func TestEWMA_MinSamples(t *testing.T) {
	e := NewEWMARate(0.1, 10, 0)
	for i := 0; i < 5; i++ {
		e.Record(false, int64(i*1000))
	}
	if e.Valid() {
		t.Fatalf("5 个样本不应达到 minSamples=10")
	}
	if e.GetSampleCount() != 5 {
		t.Fatalf("样本数应为 5，got %d", e.GetSampleCount())
	}
	for i := 0; i < 5; i++ {
		e.Record(false, int64((i+5)*1000))
	}
	if !e.Valid() {
		t.Fatalf("10 个样本后应有效")
	}
}

// 时间衰减：超过半衰期后失败率和样本数衰减
func TestEWMA_Decay(t *testing.T) {
	e := NewEWMARate(0.2, 1, 1) // 半衰期 1 秒
	// 先积累一些失败
	for i := 0; i < 20; i++ {
		e.Record(false, int64(i*100)) // 每 100ms 一次
	}
	rateBefore := e.GetRate()
	countBefore := e.GetSampleCount()
	if rateBefore < 0.9 {
		t.Fatalf("积累后失败率应较高，got %.4f", rateBefore)
	}

	// 等待 2 个半衰期（2 秒 = 2000ms）
	// Record 会自动触发 decay
	e.Record(true, 20*100+2000) // 在最后一次基础上 +2000ms

	rateAfter := e.GetRate()
	countAfter := e.GetSampleCount()
	if rateAfter >= rateBefore {
		t.Fatalf("衰减后失败率应降低，before=%.4f after=%.4f", rateBefore, rateAfter)
	}
	if countAfter >= countBefore {
		t.Fatalf("衰减后样本数应减少，before=%d after=%d", countBefore, countAfter)
	}
}

// 时间衰减不足一个半衰期：不衰减
func TestEWMA_NoDecayWithinHalfLife(t *testing.T) {
	e := NewEWMARate(0.2, 1, 60) // 半衰期 60 秒
	for i := 0; i < 10; i++ {
		e.Record(false, int64(i*1000))
	}
	rateBefore := e.GetRate()
	// 30 秒后（<60s 半衰期）
	e.Record(false, 30*1000)
	rateAfter := e.GetRate()
	// 不应有衰减导致的 rate 下降（新的失败样本反而会升高 rate）
	if rateAfter < rateBefore {
		t.Fatalf("不足半衰期不应衰减，before=%.4f after=%.4f", rateBefore, rateAfter)
	}
}

// Reset：重置后 rate=0，样本数=0
func TestEWMA_Reset(t *testing.T) {
	e := NewEWMARate(0.2, 5, 0)
	for i := 0; i < 20; i++ {
		e.Record(false, int64(i*1000))
	}
	if e.GetRate() < 0.9 {
		t.Fatalf("积累后失败率应较高")
	}
	e.Reset()
	if e.GetRate() != 0 {
		t.Fatalf("Reset 后 rate 应为 0，got %.4f", e.GetRate())
	}
	if e.GetSampleCount() != 0 {
		t.Fatalf("Reset 后样本数应为 0，got %d", e.GetSampleCount())
	}
	if e.Valid() {
		t.Fatalf("Reset 后应无效")
	}
}

// ============================================================
// 动态权重调整测试（方案 §6.2.3）
// ============================================================

// 统计无效（样本不足）：不调整
func TestAdjustWeight_InvalidStat(t *testing.T) {
	newW, changed := AdjustWeight(0.6, 0.8, false, WeightAdjustConfig{
		BaseWeight:       0.6,
		MinWeight:        0.05,
		AdjustStep:       0.1,
		FailureThreshold: 0.5,
		RecoveryRatio:    0.5,
	})
	if changed {
		t.Fatalf("统计无效不应调整")
	}
	if newW != 0.6 {
		t.Fatalf("权重应不变，got %.4f", newW)
	}
}

// 失败率超阈值：降权
func TestAdjustWeight_Down(t *testing.T) {
	newW, changed := AdjustWeight(0.6, 0.7, true, WeightAdjustConfig{
		BaseWeight:       0.6,
		MinWeight:        0.05,
		AdjustStep:       0.1,
		FailureThreshold: 0.5,
		RecoveryRatio:    0.5,
	})
	if !changed {
		t.Fatalf("失败率超阈值应降权")
	}
	if newW != 0.5 {
		t.Fatalf("应降权到 0.5，got %.4f", newW)
	}
}

// 失败率低于恢复阈值：升权
func TestAdjustWeight_Up(t *testing.T) {
	newW, changed := AdjustWeight(0.3, 0.1, true, WeightAdjustConfig{
		BaseWeight:       0.6,
		MinWeight:        0.05,
		AdjustStep:       0.1,
		FailureThreshold: 0.5,
		RecoveryRatio:    0.5, // 恢复阈值 = 0.5 * 0.5 = 0.25
	})
	if !changed {
		t.Fatalf("失败率低于恢复阈值应升权")
	}
	if newW != 0.4 {
		t.Fatalf("应升权到 0.4，got %.4f", newW)
	}
}

// 中间区间：不调整（迟滞效应）
func TestAdjustWeight_Hysteresis(t *testing.T) {
	newW, changed := AdjustWeight(0.5, 0.3, true, WeightAdjustConfig{
		BaseWeight:       0.6,
		MinWeight:        0.05,
		AdjustStep:       0.1,
		FailureThreshold: 0.5,  // 降权阈值
		RecoveryRatio:    0.5,  // 恢复阈值 = 0.25
	})
	if changed {
		t.Fatalf("中间区间(0.25 < rate < 0.5)不应调整")
	}
	if newW != 0.5 {
		t.Fatalf("权重应不变，got %.4f", newW)
	}
}

// 降权到最小权重后不再降
func TestAdjustWeight_MinFloor(t *testing.T) {
	cfg := WeightAdjustConfig{
		BaseWeight:       0.5,
		MinWeight:        0.05,
		AdjustStep:       0.1,
		FailureThreshold: 0.5,
		RecoveryRatio:    0.5,
	}
	w := 0.5
	// 连续降权
	for i := 0; i < 10; i++ {
		newW, _ := AdjustWeight(w, 0.8, true, cfg)
		w = newW
	}
	if w < 0.05 {
		t.Fatalf("权重不应低于 MinWeight，got %.4f", w)
	}
	if w != 0.05 {
		t.Fatalf("权重应稳定在 MinWeight，got %.4f", w)
	}
}

// 升权到基础权重后不再升
func TestAdjustWeight_BaseCeil(t *testing.T) {
	cfg := WeightAdjustConfig{
		BaseWeight:       0.6,
		MinWeight:        0.05,
		AdjustStep:       0.1,
		FailureThreshold: 0.5,
		RecoveryRatio:    0.5,
	}
	w := 0.1
	// 连续升权
	for i := 0; i < 10; i++ {
		newW, _ := AdjustWeight(w, 0.01, true, cfg)
		w = newW
	}
	if w > 0.6 {
		t.Fatalf("权重不应超过 BaseWeight，got %.4f", w)
	}
	if w != 0.6 {
		t.Fatalf("权重应稳定在 BaseWeight，got %.4f", w)
	}
}

// ============================================================
// 权重归一化测试
// ============================================================

// 正常归一化：权重之和 = 1
func TestNormalizeWeights(t *testing.T) {
	eps := []*EndpointState{
		{Name: "a", Weight: 0.6},
		{Name: "b", Weight: 0.4},
	}
	// 先让权重非归一化，模拟调整后
	eps[0].Weight = 0.5
	eps[1].Weight = 0.3
	NormalizeWeights(eps)
	var sum float64
	for _, ep := range eps {
		sum += ep.Weight
	}
	if abs(sum-1.0) > 1e-9 {
		t.Fatalf("归一化后权重和应为 1，got %.10f", sum)
	}
	// 比例应保持：a/b = 0.5/0.3 ≈ 1.667
	ratio := eps[0].Weight / eps[1].Weight
	if abs(ratio-0.5/0.3) > 1e-9 {
		t.Fatalf("归一化后比例应保持，got %.4f", ratio)
	}
}

// 所有权重为 0：不 panic，不修改
func TestNormalizeWeights_AllZero(t *testing.T) {
	eps := []*EndpointState{
		{Name: "a", Weight: 0},
		{Name: "b", Weight: 0},
	}
	NormalizeWeights(eps) // 不应 panic
	for _, ep := range eps {
		if ep.Weight != 0 {
			t.Fatalf("全零权重归一化后应仍为 0")
		}
	}
}

// 空切片：不 panic
func TestNormalizeWeights_Empty(t *testing.T) {
	NormalizeWeights(nil)
	NormalizeWeights([]*EndpointState{})
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
