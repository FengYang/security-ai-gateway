// Package model — GF.4.3 语义分类器的侧车（sidecar）契约与 HTTP 实现。
//
// 定位：Guardrail 的提示词注入/越狱检测从"关键词规则"升级为"语义分类器"时，
// 分类器**不放进 tee-infer 进程内**（模型权重与运行时体积/许可/TEE 度量面都不适合），
// 而是以本地/受控侧车形式提供，经 HTTP 调用。本文件是该接入点的唯一契约实现：
// 运行时（guardrail）与评测跑道（guardrail_eval_test.go）共用同一请求/响应结构，
// 避免"评测口径与运行口径漂移"。
//
// 契约（v1）：
//
//	POST <url>                                  sidecar
//	Content-Type: application/json
//	Authorization: Bearer <key>                 （仅当配置了 key）
//	{"text": "<待分类文本>"}
//	→ 200 {"blocked": bool, "category": "...", "match": "...", "resources": {...}}
//
// 语义：
//   - blocked=true → 命中，category 为空时按 "prompt_injection" 处理（Guardrail 既有类别名）；
//   - blocked=false → 未命中；
//   - resources 为**可选**字段（候选侧资源占用，仅供评测跑道采集）；
//   - 非 200 / 超时 / 网络错误 / JSON 非法 → 视为**不可用**，走降级路径（见下）。
//
// 降级策略（安全取舍，须与"Guardrail 不可降级"边界区分）：分类器不可用时
// **回退到关键词规则分类器**（fallback），并以 onResult("degraded") 上报指标；
// 即：可用性不因侧车故障而中断，但语义检出能力会回落到关键词基线（该水位由
// 基准集量化：公开集语义越狱检出 ~12%），必须可观测、可告警。
// fallback 为 nil 时按 fail-closed 处理：返回命中并标注 classifier_unavailable
// （宁可拒绝，不可静默放行）——生产接线必须传入规则分类器作为 fallback。
package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ClassifyRequest 侧车请求体。
type ClassifyRequest struct {
	Text string `json:"text"`
}

// ClassifyResponse 侧车响应体（resources 可选，评测跑道消费）。
type ClassifyResponse struct {
	Blocked   bool           `json:"blocked"`
	Category  string         `json:"category,omitempty"`
	Match     string         `json:"match,omitempty"`
	Resources map[string]any `json:"resources,omitempty"`
}

// GuardClassifierBackendHTTP 侧车后端标识（/config 快照与指标标签用）。
const GuardClassifierBackendHTTP = "http-sidecar"

// GuardClassifierBackendKeyword 关键词规则后端标识（默认，无侧车）。
const GuardClassifierBackendKeyword = "keyword"

// errClassifierUnavailable 侧车不可用（内部错误，不外泄响应体）。
var errClassifierUnavailable = errors.New("guard classifier unavailable")

// HTTPClassifier 经 HTTP 调用外部语义分类器的 Classifier 实现。
type HTTPClassifier struct {
	url      string
	key      string
	client   *http.Client
	fallback Classifier // 不可用时回退（通常为关键词规则分类器）
	onResult func(result string)
}

// NewHTTPClassifier 构造侧车分类器。
//
// timeout <= 0 时取 2s（分类器在请求路径上，超时必须有限且小）。
// onResult 收到 "ok"（侧车正常应答）或 "degraded"（不可用并已回退）；可为 nil。
func NewHTTPClassifier(url, key string, timeout time.Duration, fallback Classifier, onResult func(result string)) *HTTPClassifier {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &HTTPClassifier{
		url:      url,
		key:      key,
		client:   &http.Client{Timeout: timeout},
		fallback: fallback,
		onResult: onResult,
	}
}

// Classify 实现 Classifier：命中返回 (类别, 片段)，未命中返回空类别。
func (c *HTTPClassifier) Classify(text string) (string, string) {
	resp, err := c.ClassifyWithResources(text)
	if err != nil {
		c.report("degraded")
		if c.fallback != nil {
			return c.fallback.Classify(text)
		}
		// 无回退实现：fail-closed（不放行），并如实标注原因。
		return "prompt_injection", "classifier_unavailable"
	}
	c.report("ok")
	if !resp.Blocked {
		return "", ""
	}
	cat := resp.Category
	if cat == "" {
		cat = "prompt_injection"
	}
	return cat, resp.Match
}

// ClassifyWithResources 调用侧车并返回原始响应（评测跑道用：需 resources 与原始错误）。
// error 非 nil 表示侧车不可用（调用方按降级处理，不得视为"未命中"）。
func (c *HTTPClassifier) ClassifyWithResources(text string) (ClassifyResponse, error) {
	body, err := json.Marshal(ClassifyRequest{Text: text})
	if err != nil {
		return ClassifyResponse{}, fmt.Errorf("%w: 请求序列化失败: %v", errClassifierUnavailable, err)
	}
	req, err := http.NewRequest(http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return ClassifyResponse{}, fmt.Errorf("%w: 构造请求失败: %v", errClassifierUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.key != "" {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return ClassifyResponse{}, fmt.Errorf("%w: %v", errClassifierUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return ClassifyResponse{}, fmt.Errorf("%w: HTTP %d", errClassifierUnavailable, resp.StatusCode)
	}
	var out ClassifyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return ClassifyResponse{}, fmt.Errorf("%w: 响应解析失败: %v", errClassifierUnavailable, err)
	}
	return out, nil
}

// Backend 后端标识（写入 /config 快照，避免"prompt_classifier=true"含义不明）。
func (c *HTTPClassifier) Backend() string { return GuardClassifierBackendHTTP }

func (c *HTTPClassifier) report(result string) {
	if c.onResult != nil {
		c.onResult(result)
	}
}
