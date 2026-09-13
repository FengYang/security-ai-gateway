package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"security-ai-gateway/gateway/gateway-core/internal/ratelimit"
)

// TeeQuotaApplier 把配额更新下发 tee-infer（抽成接口便于测试注入 stub）。
type TeeQuotaApplier interface {
	ApplyQuota(ctx context.Context, updates []ratelimit.QuotaUpdate) error
}

// httpTeeQuotaApplier 基于 tee-infer 既有接口 `POST /usage/quota`（管理头 X-Admin-Token）。
type httpTeeQuotaApplier struct {
	baseURL string
	token   string
	client  *http.Client
}

// NewHTTPTeeQuotaApplier 构造下发器；teeURL 为空返回 nil（= 未配置，不做 TEE 下发）。
func NewHTTPTeeQuotaApplier(teeURL, token string) TeeQuotaApplier {
	if strings.TrimSpace(teeURL) == "" {
		return nil
	}
	return &httpTeeQuotaApplier{
		baseURL: strings.TrimRight(teeURL, "/"),
		token:   token,
		client:  &http.Client{Timeout: 5 * time.Second},
	}
}

// ApplyQuota 逐条下发；任一条失败立即返回错误。
//
// 失败语义（设计 v1.1 §4/§6）：**不发送任何"清除配额"指令**，即 tee-infer 保留现有配额继续生效；
// 调用方把失败如实回报（策略表已落库，仅 TEE 侧未更新）。
func (a *httpTeeQuotaApplier) ApplyQuota(ctx context.Context, updates []ratelimit.QuotaUpdate) error {
	for _, u := range updates {
		body, err := json.Marshal(u)
		if err != nil {
			return fmt.Errorf("tee: 配额编码失败: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/usage/quota", bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("tee: 构造请求失败: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if a.token != "" {
			req.Header.Set("X-Admin-Token", a.token)
		}
		resp, err := a.client.Do(req)
		if err != nil {
			return fmt.Errorf("tee: 下发失败（tee-infer 保留现有配额）: %w", err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("tee: 下发被拒 status=%d（tee-infer 保留现有配额）", resp.StatusCode)
		}
	}
	return nil
}
