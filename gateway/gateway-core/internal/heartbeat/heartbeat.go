// Package heartbeat 实现 gateway-core 侧的「集群心跳上报」（P2-4 T-3.4 / T-2.6 消费侧）。
//
// 口径来源：《GA-AI 网关能力补齐方案 · P2-4 多集群管理》§6.2（L270）与评审处置记录 C6(7)：
//
//	插件拉取 /routes 的请求头 X-Config-Version（当前生效版本）
//	  → core 缓存「最近上报版本 + 时间」
//	  → core 心跳上报 applied_config_version 给管理面
//
// 管理面契约（§6.1 表）：
//
//	POST /v1/adminext/clusters/{id}/heartbeat
//	Header: X-Cluster-Credential: <集群身份凭证>   （T-2.3；凭证缺失/过期 → 拒绝）
//	Body:   {"applied_config_version": "<最近上报的版本>"}
//
// 语义要点：
//   - **未上报（unknown）时上报空串**：管理面按「空 = 不覆盖既有值」处理，
//     首次上报时该项保持为空 ⇒ sync-status 标记 unknown 并告警（禁止默认收敛）。
//   - **core 不做收敛判定**：期望 vs 实际的比较属管理面 sync-status（T-3.3）。
//   - **上报失败不阻断 core**：心跳丢失由管理面状态机降级为 degraded/unreachable
//     并告警（R-1 自治前提：数据面不因控制面心跳失败而停摆）。
package heartbeat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// DefaultInterval 心跳上报周期（默认 30s，与 §6.1 状态机默认定量一致）。
const DefaultInterval = 30 * time.Second

// DefaultTimeout 单次上报超时（控制面内网调用，取保守值）。
const DefaultTimeout = 5 * time.Second

// maxResponseBytes 响应体读取上限（防响应体耗尽内存）。
const maxResponseBytes = 64 << 10

// Config 心跳上报配置。
type Config struct {
	// Endpoint 管理面心跳端点**完整 URL**
	// （如 http://gateway-admin-service:8080/v1/adminext/clusters/cluster-a/heartbeat）。
	Endpoint string
	// ClusterID 集群 ID（写入 URL 与日志；凭证与集群绑定）。
	ClusterID string
	// Credential 集群身份凭证明文（T-2.3 签发；仅在内存与请求头中使用，不落盘不打印）。
	Credential string
	// Interval 上报周期（≤0 ⇒ DefaultInterval）。
	Interval time.Duration
	// Timeout 单次请求超时（≤0 ⇒ DefaultTimeout）。
	Timeout time.Duration
	// HTTPClient 可注入的客户端（测试用；nil ⇒ 按 Timeout 新建）。
	HTTPClient *http.Client
	// Logger 日志器（nil ⇒ log.Default()）。
	Logger *log.Logger
}

// Reporter 心跳上报器。
type Reporter struct {
	cfg    Config
	client *http.Client
	logger *log.Logger
}

// NewReporter 构造心跳上报器并校验配置（缺端点/集群 ID/凭证 ⇒ 返回错误，
// 由调用方决定 fail-closed 拒启动还是降级为不上报）。
func NewReporter(cfg Config) (*Reporter, error) {
	cfg.Endpoint = strings.TrimSpace(cfg.Endpoint)
	cfg.ClusterID = strings.TrimSpace(cfg.ClusterID)
	cfg.Credential = strings.TrimSpace(cfg.Credential)
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("heartbeat: 心跳端点为空")
	}
	if !strings.HasPrefix(cfg.Endpoint, "http://") && !strings.HasPrefix(cfg.Endpoint, "https://") {
		return nil, fmt.Errorf("heartbeat: 心跳端点须为 http/https: %q", cfg.Endpoint)
	}
	if cfg.ClusterID == "" {
		return nil, fmt.Errorf("heartbeat: 集群 ID 为空")
	}
	if cfg.Credential == "" {
		return nil, fmt.Errorf("heartbeat: 集群身份凭证为空（心跳须携带集群凭证）")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	return &Reporter{cfg: cfg, client: client, logger: logger}, nil
}

// Interval 返回生效的上报周期。
func (r *Reporter) Interval() time.Duration { return r.cfg.Interval }

// ReportOnce 执行一次心跳上报。version 为空串表示「未上报（unknown）」。
// 返回错误由调用方决定重试/告警；本函数不 panic、不修改任何状态。
func (r *Reporter) ReportOnce(ctx context.Context, version string) error {
	body, err := json.Marshal(map[string]string{"applied_config_version": version})
	if err != nil {
		return fmt.Errorf("heartbeat: 请求体序列化失败: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("heartbeat: 构造请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// 集群身份凭证（T-2.3）：与 RBAC 叠加，缺失/过期/不匹配 → 管理面拒绝。
	req.Header.Set("X-Cluster-Credential", r.cfg.Credential)

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("heartbeat: 上报失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	// 读取并丢弃少量响应体（便于连接复用），限制读取上限。
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("heartbeat: 上报被拒: HTTP %d", resp.StatusCode)
	}
	return nil
}

// Run 周期上报直到 ctx 取消。versionFn 返回当前 applied 版本（空串 = unknown）。
//
// 单次失败只记日志并继续下一轮（不退出、不阻断 core）：心跳丢失由管理面状态机
// 降级为 degraded/unreachable 并告警。
func (r *Reporter) Run(ctx context.Context, versionFn func() string) {
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()
	for {
		version := ""
		if versionFn != nil {
			version = versionFn()
		}
		if err := r.ReportOnce(ctx, version); err != nil {
			r.logger.Printf("[heartbeat] 集群 %s 心跳上报失败（管理面将按状态机降级并告警）: %v",
				r.cfg.ClusterID, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
