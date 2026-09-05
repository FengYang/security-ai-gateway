// billing.go - 计费扩展（GA-计费接口设计 v2 评审落地）
//
// P0-4：/usage from/to 增量查询——按审计事件时间戳聚合（免疫进程重启丢失，
// 自带模型维度）；计量唯一真源 = tee-infer 审计链（Higress 只见密文无法计量）。
// P1-1：Webhook 推送端——HMAC-SHA256 签名 + 指数退避重试 + event_id 幂等。
// 推拉互补契约：拉取为主、推送为辅、推送可丢可补（推送失败由 from/to 拉取兜底）。
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ---------- P0-4：from/to 增量查询 ----------

// parseBillingTime 解析计费时间参数：RFC 3339（推荐，UTC）或 Unix 秒。
// 空 = 缺省（from → 0，即最早事件；to → 当前时刻）。返回 Unix 纳秒
// （与审计事件 timestamp 同单位、同时钟源）。
func parseBillingTime(v string, def int64) (int64, bool) {
	if v == "" {
		return def, true
	}
	if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
		return sec * int64(time.Second), true
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UnixNano(), true
	}
	return 0, false
}

// billingIncrement 增量聚合结果（单租户，含模型维度）。
type billingIncrement struct {
	TokensIn  int                    `json:"tokens_in"`
	TokensOut int                    `json:"tokens_out"`
	Requests  int                    `json:"requests"`
	ByModel   map[string]*modelUsage `json:"by_model"`
}

// aggregateUsage 按审计事件聚合 [from, to) 计量增量（左闭右开，UTC）。
// 只统计计费事件（action=infer：含 ok 与部分计费的 engine_error）；deny 不计费。
// 事件时间戳取自审计链 append 时刻（TEE 内时钟，不可由客户端篡改）。
func aggregateUsage(events []AuditEvent, from, to int64) map[string]*billingIncrement {
	out := map[string]*billingIncrement{}
	for _, e := range events {
		if e.Action != "infer" || e.Timestamp < from || e.Timestamp >= to {
			continue
		}
		inc := out[e.TenantID]
		if inc == nil {
			inc = &billingIncrement{ByModel: map[string]*modelUsage{}}
			out[e.TenantID] = inc
		}
		inc.TokensIn += e.TokensIn
		inc.TokensOut += e.TokensOut
		inc.Requests++
		key := modelDimensionKey(e.EngineType, e.Model)
		mu := inc.ByModel[key]
		if mu == nil {
			mu = &modelUsage{}
			inc.ByModel[key] = mu
		}
		mu.TokensIn += e.TokensIn
		mu.TokensOut += e.TokensOut
		mu.Requests++
	}
	return out
}

// modelDimensionKey 模型维度聚合键："engine_type/model"（空侧省略斜杠）。
func modelDimensionKey(engineType, model string) string {
	switch {
	case engineType != "" && model != "":
		return engineType + "/" + model
	case engineType != "":
		return engineType
	default:
		return model
	}
}

// ---------- P1-1：Webhook 推送端 ----------

// billingWebhook 计费事件推送器。未配置（url 为空）→ newBillingWebhook 返回
// nil，notify 为 no-op（调用点无需判空：nil 接收者方法安全返回）。
type billingWebhook struct {
	url       string
	secret    string          // HMAC-SHA256 签名密钥（空 = 不签名，仅内网明文模式）
	client    *http.Client    // 推送 HTTP 客户端（短超时，不拖垮推理主链）
	mu        sync.Mutex      // 保护 sent
	sent      map[string]bool // event_id 进程内幂等去重
	retryWait time.Duration   // 重试退避基数（测试可调小）
}

// newBillingWebhook 构造推送器；url 为空返回 nil（推送关闭，拉取为主）。
func newBillingWebhook(url, secret string) *billingWebhook {
	if url == "" {
		return nil
	}
	return &billingWebhook{
		url:       url,
		secret:    secret,
		client:    &http.Client{Timeout: 5 * time.Second},
		sent:      make(map[string]bool),
		retryWait: 200 * time.Millisecond,
	}
}

// billingEventPayload 推送事件（event_id 与审计事件对齐，幂等键）。
type billingEventPayload struct {
	EventID    string `json:"event_id"`
	TenantID   string `json:"tenant"`
	RequestID  string `json:"request_id"`
	EngineType string `json:"engine_type,omitempty"`
	Model      string `json:"model,omitempty"`
	TokensIn   int    `json:"tokens_in"`
	TokensOut  int    `json:"tokens_out"`
	Result     string `json:"result"` // ok / engine_error（部分计费）
	TS         string `json:"ts"`     // RFC 3339 UTC（与审计 timestamp 同源）
}

// webhookMaxAttempts 推送重试上限（指数退避：base * 2^n）。
const webhookMaxAttempts = 3

// notify 推送单笔计费事件：HMAC-SHA256 签名（X-Signature: sha256=<hex>）+
// 指数退避重试 + event_id 幂等（已推送过不再推）。推送失败仅告警日志，
// 绝不影响推理主链与审计链（拉取兜底，见 GA-计费接口设计 v2 §2.3）。
func (b *billingWebhook) notify(ev AuditEvent) {
	if b == nil || ev.Action != "infer" {
		return
	}
	b.mu.Lock()
	if b.sent[ev.EventID] {
		b.mu.Unlock()
		return
	}
	// 标记在先（进程内去重）：失败不重入队列，由计费侧拉取兜底
	b.sent[ev.EventID] = true
	b.mu.Unlock()

	payload := billingEventPayload{
		EventID:    ev.EventID,
		TenantID:   ev.TenantID,
		RequestID:  ev.RequestID,
		EngineType: ev.EngineType,
		Model:      ev.Model,
		TokensIn:   ev.TokensIn,
		TokensOut:  ev.TokensOut,
		Result:     ev.Result,
		TS:         time.Unix(0, ev.Timestamp).UTC().Format(time.RFC3339Nano),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[billing] 事件编码失败: %v", err)
		return
	}
	var sig string
	if b.secret != "" {
		mac := hmac.New(sha256.New, []byte(b.secret))
		mac.Write(body)
		sig = "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}
	var lastErr error
	for attempt := 0; attempt < webhookMaxAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(b.retryWait * time.Duration(1<<(attempt-1)))
		}
		req, rerr := http.NewRequest(http.MethodPost, b.url, bytes.NewReader(body))
		if rerr != nil {
			lastErr = rerr
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if sig != "" {
			req.Header.Set("X-Signature", sig)
		}
		resp, derr := b.client.Do(req)
		if derr != nil {
			lastErr = derr
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return
		}
		lastErr = fmt.Errorf("billing webhook HTTP %d", resp.StatusCode)
	}
	log.Printf("[billing] Webhook 推送失败（event_id=%s，计费侧拉取兜底）: %v",
		payload.EventID, lastErr)
}
