// Package routeengine — P1-6 TTFT 严格性能择优：统计结构与延迟配置（M1.1）。
//
// 设计依据：《GA-AI网关能力补齐方案--P1--TTFT严格性能择优.md》v1.5
//
//	§4.1 M1.1：TTFTStat + LatencyConfig（纯数据结构，无 Mode，模式由 Strategy 决定）
//	§6.1：latency 段字段表（JSON 标签逐字段一致；默认值/范围见字段注释）
//	§6.3：stats 下发条目字段（p50_ms / p95_ms / samples / valid / updated_at / cache）
//
// 边界（对齐本体附录 B 职责划分）：本文件仅定义数据结构与参数归一化，
// 不含采样、上报、网络调用；读路径无锁、值语义（C-3）。
package routeengine

// ============================================================
// TTFT 统计结构（写入 EndpointState.TTFT）
// ============================================================

// TTFTStat 端点首 token 延迟（TTFT）统计快照（值语义、读路径无锁）。
//
// 由数据面周期拉取（M2.6，ttftfetch.go）自控制面 `GET /routes/ttft/stats`（§6.3）
// 取得并写入 `EndpointState.TTFT`；选路时仅作只读使用，不就地改写（C-3）。
// JSON 标签与 §6.3 stats 条目逐字段一致。
type TTFTStat struct {
	P50Ms     int64  `json:"p50_ms"`     // P50 分位（毫秒）
	P95Ms     int64  `json:"p95_ms"`     // P95 分位（毫秒；默认参考分位，见 LatencyConfig.Quantile）
	Samples   int64  `json:"samples"`    // 窗口内样本数
	Valid     bool   `json:"valid"`      // 统计是否有效（样本充足且未过期，D-8）
	UpdatedAt int64  `json:"updated_at"` // 统计更新时间（Unix 秒）
	Cache     string `json:"cache"`      // cache 分层标识："hit"/"miss"（D-10；契约未落地前恒 "miss"）
}

// ============================================================
// 延迟配置（路由表 latency 段，§6.1）
// ============================================================

// LatencyConfig 延迟择优参数（自路由表 `latency` 段解析，M4.5）。
//
// 设计要点（§6.1）：
//   - **无 Mode 字段**：选路模式由 `Config.Strategy` 唯一决定
//     （latency-aware / latency-fastest / hybrid）；
//   - 缺省值：window_sec=300 / quantile=p95 / gamma=1.0 / min_weight=0.05 /
//     explore_ratio=0.05 / min_samples=20 / stale_sec=75 / cache_partition=true /
//     max_ttft_ms=30000；
//   - `gamma=0` 与 `explore_ratio=0` 均为**合法显式取值**（§3.5 关键性质：
//     γ=0 且 explore_ratio=1 退化为均匀随机），故缺省填充必须在 schema 解析层
//     **按字段存在性**完成（M4.5）；本层 normalized() 只做越界钳制，
//     不把合法 0 值改写为缺省；
//   - `cache_partition` 的缺省 true 同样由 M4.5 依 JSON 字段存在性填充
//     （Go 零值为 false，本层无法区分「显式 false」与「未提供」）。
type LatencyConfig struct {
	WindowSec      int     `json:"window_sec"`      // 滑窗长度（秒），默认 300，范围 60–3600（分片数 N=ceil(window_sec/25)，§3.3）
	Quantile       string  `json:"quantile"`        // 参考延迟分位："p50"/"p95"，默认 "p95"
	Gamma          float64 `json:"gamma"`           // 倒数幂指数 γ，默认 1.0，范围 0–5（D-3）
	MinWeight      float64 `json:"min_weight"`      // 归一化前相对权重下界，默认 0.05，范围 0–0.5（D-4）
	ExploreRatio   float64 `json:"explore_ratio"`   // 探索概率，默认 0.05，范围 0–1（D-4）
	MinSamples     int     `json:"min_samples"`     // 样本不足判无效，默认 20，≥1（D-8）
	StaleSec       int     `json:"stale_sec"`       // 统计过期阈值（秒），默认 75，≥25 且 ≥2×上报周期（D-8）
	CachePartition bool    `json:"cache_partition"` // 按 cache 分层统计，默认 true（D-10）
	MaxTTFTMs      int64   `json:"max_ttft_ms"`     // 采样上限（毫秒），默认 30000，≥1000（超时按上限归桶，抑制离群）
}

// 越界钳制的安全缺省（对齐 §6.1 默认值列与范围约束）。
const (
	defaultLatencyWindowSec    = 300
	minLatencyWindowSec        = 60
	maxLatencyWindowSec        = 3600
	defaultLatencyQuantile     = "p95"
	defaultLatencyGamma        = 1.0
	maxLatencyGamma            = 5.0
	defaultLatencyMinWeight    = 0.05
	maxLatencyMinWeight        = 0.5
	defaultLatencyExploreRatio = 0.05
	defaultLatencyMinSamples   = 20
	defaultLatencyStaleSec     = 75
	minLatencyStaleSec         = 25
	defaultLatencyMaxTTFTMs    = 30000
	minLatencyMaxTTFTMs        = 1000
)

// normalized 返回越界字段被钳制回安全缺省后的副本（不修改接收者）。
//
// 语义边界：仅处理**越界**值；合法显式值（含 gamma=0 / explore_ratio=0 /
// min_weight=0 / quantile="p50"）原样保留。字段**缺省填充**（未提供时取默认）
// 由 schema 解析层按存在性完成（M4.5），不在本层处理。
func (c LatencyConfig) normalized() LatencyConfig {
	if c.WindowSec < minLatencyWindowSec || c.WindowSec > maxLatencyWindowSec {
		c.WindowSec = defaultLatencyWindowSec
	}
	if c.Quantile != "p50" && c.Quantile != "p95" {
		c.Quantile = defaultLatencyQuantile
	}
	if c.Gamma < 0 || c.Gamma > maxLatencyGamma {
		c.Gamma = defaultLatencyGamma
	}
	if c.MinWeight < 0 || c.MinWeight > maxLatencyMinWeight {
		c.MinWeight = defaultLatencyMinWeight
	}
	if c.ExploreRatio < 0 || c.ExploreRatio > 1 {
		c.ExploreRatio = defaultLatencyExploreRatio
	}
	if c.MinSamples < 1 {
		c.MinSamples = defaultLatencyMinSamples
	}
	if c.StaleSec < minLatencyStaleSec {
		c.StaleSec = defaultLatencyStaleSec
	}
	if c.MaxTTFTMs < minLatencyMaxTTFTMs {
		c.MaxTTFTMs = defaultLatencyMaxTTFTMs
	}
	return c
}
