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
//   - 非 200 / 超时 / 网络错误 / JSON 非法 → 视为**不可用**，按 fail-closed 处置（见下）。
//
// 不可用语义（2026-09-26）：侧车不可用时**不回退关键词规则、不放行**，
// 而是按 fail-closed 返回命中并标注类别 classifier_unavailable
// （宁可拒绝，不可静默放行；审计按该类别记账，避免把"不可用"误记为"注入命中"），
// 同时以 onResult("degraded", reason) 上报，reason ∈ unreachable|timeout|http_status|bad_response
// （供指标与告警归因）。可用性由侧车健康探活 + readiness 保障（见 guardrail_probe.go），
// 不以"回退关键词、静默降级"换取可用性。
package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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

// GuardCategoryClassifierUnavailable fail-closed 类别：侧车不可用（**非真实命中**）。
// 独立类别用于审计与指标区分"不可用"与"语义命中"，避免拒答原因失真。
const GuardCategoryClassifierUnavailable = "classifier_unavailable"

// 侧车不可用原因（指标/告警标签，便于归因与告警分级）。
const (
	GuardFailReasonUnreachable = "unreachable"  // 连接失败 / DNS 失败 / 连接拒绝
	GuardFailReasonTimeout     = "timeout"      // 调用超时
	GuardFailReasonHTTPStatus  = "http_status"  // 非 200 应答
	GuardFailReasonBadResponse = "bad_response" // 响应非法（请求构造失败 / JSON 解析失败）
)

// errClassifierUnavailable 侧车不可用（内部错误，不外泄响应体）。
var errClassifierUnavailable = errors.New("guard classifier unavailable")

// HTTPClassifier 经 HTTP 调用外部语义分类器的 Classifier 实现。
type HTTPClassifier struct {
	url      string
	key      string
	client   *http.Client
	onResult func(result, reason string)
}

// NewHTTPClassifier 构造侧车分类器。
//
// timeout <= 0 时取 2s（分类器在请求路径上，超时必须有限且小）。
// onResult 收到 "ok"（侧车正常应答，reason 为空）或 "degraded"（不可用，已按 fail-closed 拒答，
// reason 为归因）；可为 nil。
func NewHTTPClassifier(url, key string, timeout time.Duration, onResult func(result, reason string)) *HTTPClassifier {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &HTTPClassifier{
		url:      url,
		key:      key,
		client:   &http.Client{Timeout: timeout},
		onResult: onResult,
	}
}

// Classify 实现 Classifier：命中返回 (类别, 片段)，未命中返回空类别。
//
// 侧车不可用时按 fail-closed 返回 (classifier_unavailable, classifier_unavailable)——
// 调用方据此拒答（不回退关键词重判，不静默放行）。
func (c *HTTPClassifier) Classify(text string) (string, string) {
	resp, reason, err := c.classify(text)
	if err != nil {
		c.report("degraded", reason)
		return GuardCategoryClassifierUnavailable, GuardCategoryClassifierUnavailable
	}
	c.report("ok", "")
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
	resp, _, err := c.classify(text)
	return resp, err
}

// classify 调用侧车；error 非 nil 表示不可用，reason 为归因（指标/告警标签）。
func (c *HTTPClassifier) classify(text string) (ClassifyResponse, string, error) {
	body, err := json.Marshal(ClassifyRequest{Text: text})
	if err != nil {
		return ClassifyResponse{}, GuardFailReasonBadResponse, fmt.Errorf("%w: 请求序列化失败: %v", errClassifierUnavailable, err)
	}
	req, err := http.NewRequest(http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return ClassifyResponse{}, GuardFailReasonBadResponse, fmt.Errorf("%w: 构造请求失败: %v", errClassifierUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.key != "" {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return ClassifyResponse{}, guardFailReasonOf(err), fmt.Errorf("%w: %v", errClassifierUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return ClassifyResponse{}, GuardFailReasonHTTPStatus, fmt.Errorf("%w: HTTP %d", errClassifierUnavailable, resp.StatusCode)
	}
	var out ClassifyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return ClassifyResponse{}, GuardFailReasonBadResponse, fmt.Errorf("%w: 响应解析失败: %v", errClassifierUnavailable, err)
	}
	return out, "", nil
}

// guardFailReasonOf 传输层失败归因：超时单列，其余（连接拒绝/DNS/重置）归 unreachable。
func guardFailReasonOf(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return GuardFailReasonTimeout
	}
	return GuardFailReasonUnreachable
}

// Backend 后端标识（写入 /config 快照，避免"prompt_classifier=true"含义不明）。
func (c *HTTPClassifier) Backend() string { return GuardClassifierBackendHTTP }

func (c *HTTPClassifier) report(result, reason string) {
	if c.onResult != nil {
		c.onResult(result, reason)
	}
}
