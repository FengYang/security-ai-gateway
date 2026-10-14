package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

var errMissingToken = errors.New("AUDIT_REPORT_TOKEN 不得为空（不得回落管理令牌，A3-11）")

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envIntOr(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
}

// maxBatchBytes 单批请求体上限：略大于服务端 1<<20（1MB）读取上限，提前在本地拒绝，
// 避免无谓的上游往返。
const maxBatchBytes = 1 << 20

type relay struct {
	cfg    config
	client *http.Client

	// 计数（Prometheus 文本格式暴露；与 A3-14「丢弃可观测」同精神）
	batchesIn   atomic.Int64
	forwarded   atomic.Int64
	dropped     atomic.Int64 // 4xx：契约非法，重试无意义
	failed      atomic.Int64 // 重试耗尽仍失败（5xx/网络）
	itemsIn     atomic.Int64
	lastStatus  atomic.Int64
	lastErrUnix atomic.Int64
}

func newRelay(cfg config) *relay {
	return &relay{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

// normalize 把 Fluent Bit 的批次载荷整形为 /audit/report 契约结构 {"reports":[...]}。
//
// 接受三种输入（Fluent Bit 输出形态随 output 配置而异）：
//  1. 已为 {"reports":[...]} → 原样返回（幂等）；
//  2. JSON 数组 [{...},{...}] → 包裹为 {"reports":[...]}；
//  3. NDJSON（每行一个对象）→ 聚合成 {"reports":[...]}。
//
// ⚠️ 只做**结构整形**，不做字段改写：字段语义与租户解析由 Lua 过滤器（audit_replay.lua）
// 与服务端（D-18 两层解析）负责，签名器不介入业务判定。
func normalize(raw []byte) ([]byte, int, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, 0, errors.New("空批次")
	}
	switch trimmed[0] {
	case '{':
		// 先按「已是契约结构」解析；失败（例如 Fluent Bit 以 NDJSON 逐行输出多个对象）
		// 再回退到 NDJSON 聚合，避免把多行对象误判为非法对象载荷。
		var probe struct {
			Reports []json.RawMessage `json:"reports"`
		}
		if err := json.Unmarshal(trimmed, &probe); err == nil {
			if probe.Reports == nil {
				return nil, 0, errors.New("对象载荷缺 reports 字段")
			}
			out, err := json.Marshal(map[string]any{"reports": probe.Reports})
			return out, len(probe.Reports), err
		}
		return parseNDJSON(trimmed)
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, 0, fmt.Errorf("数组载荷解析失败: %w", err)
		}
		out, err := json.Marshal(map[string]any{"reports": arr})
		return out, len(arr), err
	default:
		return parseNDJSON(trimmed)
	}
}

// parseNDJSON 把「每行一个 JSON 对象」的载荷聚合为契约结构。
func parseNDJSON(trimmed []byte) ([]byte, int, error) {
	var items []json.RawMessage
	for _, line := range bytes.Split(trimmed, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if !json.Valid(line) {
			return nil, 0, errors.New("NDJSON 存在非法行")
		}
		items = append(items, json.RawMessage(line))
	}
	if len(items) == 0 {
		return nil, 0, errors.New("NDJSON 无有效行")
	}
	out, err := json.Marshal(map[string]any{"reports": items})
	return out, len(items), err
}

// sign 计算 X-Audit-Report-Sig = hex(HMAC-SHA256(token, 原始 body))。
// 与 tee-infer 侧 audit_traffic.go 的算法**逐字节一致**（对最终 body 签名，非对中间结构）。
func (r *relay) sign(body []byte) string {
	mac := hmac.New(sha256.New, []byte(r.cfg.Token))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// forward 投递单个批次。返回最终状态码与错误。
//
// 重试策略：仅 **5xx / 网络错误**重试（指数退避）；**4xx 不重试**——
// 4xx 由服务端整批校验产生（契约非法），重试只会得到同样结果（D-13 整批语义）。
func (r *relay) forward(body []byte) (int, error) {
	sig := r.sign(body)
	var lastStatus int
	var lastErr error
	for attempt := 0; attempt <= r.cfg.MaxRetry; attempt++ {
		if attempt > 0 {
			time.Sleep(r.cfg.Backoff * time.Duration(1<<(attempt-1)))
		}
		req, err := http.NewRequest(http.MethodPost, r.cfg.Endpoint, bytes.NewReader(body))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Admin-Token", r.cfg.Token)
		req.Header.Set("X-Audit-Report-Sig", sig)

		resp, err := r.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		lastStatus = resp.StatusCode
		r.lastStatus.Store(int64(resp.StatusCode))
		if resp.StatusCode < 500 {
			return resp.StatusCode, nil
		}
		lastErr = fmt.Errorf("上游 %d", resp.StatusCode)
	}
	if lastErr != nil {
		r.lastErrUnix.Store(time.Now().Unix())
	}
	return lastStatus, lastErr
}

// handleBatch Fluent Bit → 本签名器的唯一写入端点。
func (r *relay) handleBatch(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "仅支持 POST", http.StatusMethodNotAllowed)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(req.Body, maxBatchBytes+1))
	if err != nil {
		http.Error(w, "读取批次失败", http.StatusBadRequest)
		return
	}
	if len(raw) > maxBatchBytes {
		r.dropped.Add(1)
		http.Error(w, "批次超过 1MB 上限", http.StatusRequestEntityTooLarge)
		return
	}
	r.batchesIn.Add(1)

	body, n, err := normalize(raw)
	if err != nil {
		r.dropped.Add(1)
		// 不回显原始载荷（防敏感内容回传）
		http.Error(w, "批次整形失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	if n == 0 {
		r.dropped.Add(1)
		http.Error(w, "批次为空", http.StatusBadRequest)
		return
	}
	r.itemsIn.Add(int64(n))

	status, err := r.forward(body)
	if err != nil {
		r.failed.Add(1)
		http.Error(w, "上游投递失败（已重试，丢弃并计数，不补链）", http.StatusBadGateway)
		return
	}
	if status >= 400 {
		r.dropped.Add(1)
		http.Error(w, fmt.Sprintf("上游拒绝 status=%d（不重试，丢弃并计数）", status), http.StatusBadGateway)
		return
	}
	r.forwarded.Add(1)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":%d,"items":%d}`, status, n)
}

func (r *relay) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, "ok\n")
}

// handleMetrics 最小 Prometheus 文本指标（供 A3-14 丢弃率告警抓取）。
func (r *relay) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "# HELP audit_sign_relay_batches_total 接收批次数\n# TYPE audit_sign_relay_batches_total counter\naudit_sign_relay_batches_total %d\n", r.batchesIn.Load())
	fmt.Fprintf(w, "# HELP audit_sign_relay_items_total 接收记录条数\n# TYPE audit_sign_relay_items_total counter\naudit_sign_relay_items_total %d\n", r.itemsIn.Load())
	fmt.Fprintf(w, "# HELP audit_sign_relay_forwarded_total 成功投递批次数\n# TYPE audit_sign_relay_forwarded_total counter\naudit_sign_relay_forwarded_total %d\n", r.forwarded.Load())
	fmt.Fprintf(w, "# HELP audit_sign_relay_dropped_total 丢弃批次数（4xx/整形失败，重试无意义）\n# TYPE audit_sign_relay_dropped_total counter\naudit_sign_relay_dropped_total %d\n", r.dropped.Load())
	fmt.Fprintf(w, "# HELP audit_sign_relay_failed_total 重试耗尽批次（5xx/网络，不可补链）\n# TYPE audit_sign_relay_failed_total counter\naudit_sign_relay_failed_total %d\n", r.failed.Load())
	fmt.Fprintf(w, "# HELP audit_sign_relay_upstream_last_status 上游最近状态码\n# TYPE audit_sign_relay_upstream_last_status gauge\naudit_sign_relay_upstream_last_status %d\n", r.lastStatus.Load())
	fmt.Fprintf(w, "# HELP audit_sign_relay_last_error_unix 最近错误时间戳（Unix 秒）\n# TYPE audit_sign_relay_last_error_unix gauge\naudit_sign_relay_last_error_unix %d\n", r.lastErrUnix.Load())
}
