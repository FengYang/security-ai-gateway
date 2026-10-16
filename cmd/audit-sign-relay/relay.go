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
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var errMissingToken = errors.New("AUDIT_REPORT_TOKEN 不得为空（不得回落管理令牌，A3-11）")

// sentinelTenant 回灌侧无服务端可解析身份时的哨兵租户（D-18）。
const sentinelTenant = "_unauthenticated"

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

func envBoolOr(k string, def bool) bool {
	v := strings.ToLower(os.Getenv(k))
	switch v {
	case "1", "true", "on", "yes":
		return true
	case "0", "false", "off", "no":
		return false
	}
	return def
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
	skipped     atomic.Int64 // TRANSFORM 模式下被判定为非拒绝类而跳过的条数
	lastStatus  atomic.Int64
	lastErrUnix atomic.Int64

	// 租户映射表（TRANSFORM 模式；consumer → tenant_id，D-18 A 层解析依据）
	mapOnce sync.Once
	mapErr  error
	cTenant map[string]string
}

func newRelay(cfg config) *relay {
	return &relay{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

// parseRecords 把 Fluent Bit 的批次载荷解析为**记录列表**。
//
// 接受三种输入（Fluent Bit 输出形态随 output 配置而异）：
//  1. 已为 {"reports":[...]} → 取 reports 数组（幂等）；
//  2. JSON 数组 [{...},{...}] → 数组本身；
//  3. NDJSON（每行一个对象）→ 逐行解析；
//  4. **单个 JSON 对象** → 视为 1 条记录（Fluent Bit 单条批次的实测形态）。
func parseRecords(raw []byte) ([]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("空批次")
	}
	switch trimmed[0] {
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, fmt.Errorf("数组载荷解析失败: %w", err)
		}
		return arr, nil
	case '{':
		var probe struct {
			Reports []json.RawMessage `json:"reports"`
		}
		if err := json.Unmarshal(trimmed, &probe); err == nil && probe.Reports != nil {
			return probe.Reports, nil
		}
		if json.Valid(trimmed) {
			return []json.RawMessage{json.RawMessage(trimmed)}, nil
		}
		// 多个对象逐行排列（NDJSON 以 '{' 开头）时整体解析必然失败 ⇒ 回退逐行解析。
		return parseNDJSON(trimmed)
	default:
		return parseNDJSON(trimmed)
	}
}

// parseNDJSON 把「每行一个 JSON 对象」的载荷解析为记录列表。
func parseNDJSON(trimmed []byte) ([]json.RawMessage, error) {
	var items []json.RawMessage
	for _, line := range bytes.Split(trimmed, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if !json.Valid(line) {
			return nil, errors.New("NDJSON 存在非法行")
		}
		items = append(items, json.RawMessage(line))
	}
	if len(items) == 0 {
		return nil, errors.New("NDJSON 无有效行")
	}
	return items, nil
}

// marshalReports 把记录列表序列化为 /audit/report 契约结构 {"reports":[...]}。
func marshalReports(items []json.RawMessage) ([]byte, error) {
	return json.Marshal(map[string]any{"reports": items})
}

// ── TRANSFORM：访问日志 → 契约记录（2026-10-14 联调下沉） ──────────────────────
//
// Fluent Bit 的 Lua 过滤器**不允许替换 record**（会报 invalid table returned），
// 故整形逻辑下沉到本签名器；且只取白名单字段，不把 ai_log 等可能含请求原文的
// 字段带入上报链路（对齐 V-2「链上/导出无原文」）。

func mapResult(code, details string) (string, bool) {
	switch code {
	case "429":
		return "rate_limited", true
	case "401":
		return "auth_failed", true
	case "403":
		// 403 有两个语义与归属均不同的子类（2026-10-14 实测）：
		//   Unauthorized_consumer（consumer 不在 allow）→ 可归真实租户；
		//   ip_not_allowed（IP 封禁）                    → 哨兵租户。
		if strings.Contains(details, "Unauthorized_consumer") {
			return "consumer_unauthorized", true
		}
		return "ip_blocked", true
	}
	return "", false
}

// loadTenantMap 懒加载 consumer → tenant_id 映射表（D-18 A 层解析依据）。
func (r *relay) loadTenantMap() map[string]string {
	r.mapOnce.Do(func() {
		path := r.cfg.MapPath
		if path == "" {
			r.mapErr = errors.New("MAP_PATH 未配置")
			return
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			r.mapErr = err
			return
		}
		m := map[string]string{}
		if err := json.Unmarshal(raw, &m); err != nil {
			r.mapErr = err
			log.Printf("[tenant-map] 解析失败 path=%s err=%v", path, err)
			return
		}
		r.cTenant = m
		log.Printf("[tenant-map] 已加载 %d 条映射 path=%s", len(m), path)
	})
	return r.cTenant
}

// resolveTenant 按 D-18 两层解析租户。
//
//	A 层：X-Mse-Consumer 可得（实测仅 403 授权拒绝子类）⇒ 映射表解析为真实租户；
//	B 层：缺失或为 Envoy 字面量 "-" ⇒ 哨兵租户 _unauthenticated。
func (r *relay) resolveTenant(consumer string) (string, string) {
	if consumer != "" && consumer != "-" {
		if m := r.loadTenantMap(); m != nil {
			if t, ok := m[consumer]; ok && t != "" {
				return t, "consumer_map"
			}
		}
	}
	return sentinelTenant, "unauthenticated"
}

func strOf(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatInt(int64(t), 10)
	default:
		return fmt.Sprint(t)
	}
}

func intOf(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(t)
		return n
	}
	return 0
}

// parseTimeNS 解析访问日志的 start_time（RFC3339）；失败则回退当前时刻
// （须落在服务端 5 分钟时间窗内，否则整批 400）。
func parseTimeNS(v any) int64 {
	s := strOf(v)
	if s != "" {
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			if t, err := time.Parse(layout, s); err == nil {
				return t.UnixNano()
			}
		}
	}
	return time.Now().UnixNano()
}

// transform 把一条 Higress 访问日志记录整形为 /audit/report 的 report 项。
// 返回 nil 表示非数据面拒绝类（跳过，不回灌）。
func (r *relay) transform(rec map[string]any) map[string]any {
	code := strOf(rec["response_code"])
	details := strOf(rec["response_code_details"])
	result, ok := mapResult(code, details)
	if !ok {
		return nil
	}
	consumer := strOf(rec["x_mse_consumer"])
	tenant, resolution := r.resolveTenant(consumer)
	// 诊断日志：仅在「拿到非空 consumer」时打印，便于联调定位映射是否命中（不打印请求内容）。
	if consumer != "" && consumer != "-" {
		log.Printf("[tenant-map] 403 授权拒绝 consumer=%q -> tenant=%q resolution=%q", consumer, tenant, resolution)
	}
	return map[string]any{
		"request_id":           strOf(rec["request_id"]),
		"tenant_id":            tenant,
		"path":                 strOf(rec["path"]),
		"path_mode":            "plain",
		"http_status":          intOf(rec["response_code"]),
		"result":               result,
		"dur_ms":               intOf(rec["duration"]),
		"timestamp_ns":         parseTimeNS(rec["start_time"]),
		"tenant_id_resolution": resolution, // 证据字段（D-18；服务端据此复核解析来源）
	}
}

// ── 签名与投递 ──────────────────────────────────────────────────────────────

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

	items, err := parseRecords(raw)
	if err != nil {
		r.dropped.Add(1)
		// 不回显原始载荷（防敏感内容回传）
		http.Error(w, "批次解析失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	r.itemsIn.Add(int64(len(items)))

	// TRANSFORM 模式：访问日志 → 契约记录（跳过非拒绝类）
	if r.cfg.Transform {
		out := make([]json.RawMessage, 0, len(items))
		for _, it := range items {
			var rec map[string]any
			if err := json.Unmarshal(it, &rec); err != nil {
				r.dropped.Add(1)
				http.Error(w, "记录解析失败", http.StatusBadRequest)
				return
			}
			ti := r.transform(rec)
			if ti == nil {
				r.skipped.Add(1)
				continue
			}
			b, err := json.Marshal(ti)
			if err != nil {
				r.dropped.Add(1)
				http.Error(w, "记录序列化失败", http.StatusBadRequest)
				return
			}
			out = append(out, b)
		}
		items = out
		if len(items) == 0 {
			// 整批无拒绝类：视为成功（Fluent Bit 不应重试），不计丢弃
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"status":200,"items":0,"skipped":true}`)
			return
		}
	}

	body, err := marshalReports(items)
	if err != nil {
		r.dropped.Add(1)
		http.Error(w, "批次序列化失败", http.StatusBadRequest)
		return
	}

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
	fmt.Fprintf(w, `{"status":%d,"items":%d}`, status, len(items))
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
	fmt.Fprintf(w, "# HELP audit_sign_relay_dropped_total 丢弃批次数（4xx/解析失败，重试无意义）\n# TYPE audit_sign_relay_dropped_total counter\naudit_sign_relay_dropped_total %d\n", r.dropped.Load())
	fmt.Fprintf(w, "# HELP audit_sign_relay_failed_total 重试耗尽批次（5xx/网络，不可补链）\n# TYPE audit_sign_relay_failed_total counter\naudit_sign_relay_failed_total %d\n", r.failed.Load())
	fmt.Fprintf(w, "# HELP audit_sign_relay_skipped_total TRANSFORM 模式下跳过的非拒绝类记录\n# TYPE audit_sign_relay_skipped_total counter\naudit_sign_relay_skipped_total %d\n", r.skipped.Load())
	fmt.Fprintf(w, "# HELP audit_sign_relay_upstream_last_status 上游最近状态码\n# TYPE audit_sign_relay_upstream_last_status gauge\naudit_sign_relay_upstream_last_status %d\n", r.lastStatus.Load())
	fmt.Fprintf(w, "# HELP audit_sign_relay_last_error_unix 最近错误时间戳（Unix 秒）\n# TYPE audit_sign_relay_last_error_unix gauge\naudit_sign_relay_last_error_unix %d\n", r.lastErrUnix.Load())
}
