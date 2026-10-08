// Package main — Tempo 查询响应解析（P1-2 §7.7）。
//
// Tempo HTTP API：
//
//	GET /api/search?tags=...&limit=...   → {"traces":[{"traceID":"...", ...}]}
//	GET /api/traces/{traceID}            → OTLP-JSON 风格 {batches|resourceSpans:[...]}
//
// 解析对键名/类型保持宽容（scopeSpans 与 instrumentationLibrarySpans 均接受；
// 时间戳与属性值兼容字符串/数字两种编码），避免因 Tempo 版本差异导致排障不可用。
// 仅保留 §6.2 白名单属性（traceAllowedAttrs），其余一律丢弃。
package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// flexUint64 兼容 JSON 数字与字符串两种 uint64 编码（OTLP-JSON 用字符串）。
type flexUint64 uint64

func (f *flexUint64) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		// 容忍浮点表示（部分编码器将纳秒写成浮点）
		fv, ferr := strconv.ParseFloat(s, 64)
		if ferr != nil {
			return err
		}
		v = uint64(fv)
	}
	*f = flexUint64(v)
	return nil
}

// tempoKV OTLP-JSON 属性键值对（value 子字段兼容字符串/数字/布尔）。
type tempoKV struct {
	Key   string `json:"key"`
	Value struct {
		StringValue json.RawMessage `json:"stringValue"`
		IntValue    json.RawMessage `json:"intValue"`
		BoolValue   json.RawMessage `json:"boolValue"`
		DoubleValue json.RawMessage `json:"doubleValue"`
	} `json:"value"`
}

// coerce 将 OTLP-JSON 属性值转为 Go 原生值（尽力而为；无法判定返回字符串形式）。
func (kv tempoKV) coerce() any {
	for _, raw := range []json.RawMessage{kv.Value.StringValue, kv.Value.IntValue, kv.Value.DoubleValue, kv.Value.BoolValue} {
		if len(raw) == 0 {
			continue
		}
		s := strings.Trim(string(raw), `"`)
		if s == "" || s == "null" {
			continue
		}
		if b, err := strconv.ParseBool(s); err == nil {
			return b
		}
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return i
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			if f == float64(int64(f)) {
				return int64(f)
			}
			return f
		}
		return s
	}
	return nil
}

// tempoSpan OTLP-JSON span。
type tempoSpan struct {
	Name              string     `json:"name"`
	StartTimeUnixNano flexUint64 `json:"startTimeUnixNano"`
	EndTimeUnixNano   flexUint64 `json:"endTimeUnixNano"`
	Attributes        []tempoKV  `json:"attributes"`
}

// tempoScopeSpans 兼容 scopeSpans（新）与 instrumentationLibrarySpans（旧）。
type tempoScopeSpans struct {
	Spans []tempoSpan `json:"spans"`
}

// tempoBatch 一个 Resource-span 批次。
type tempoBatch struct {
	ScopeSpans []tempoScopeSpans `json:"scopeSpans"`
	ILSpans    []tempoScopeSpans `json:"instrumentationLibrarySpans"`
}

// tempoTrace 顶层 trace 容器（兼容 batches / resourceSpans）。
type tempoTrace struct {
	Batches       []tempoBatch `json:"batches"`
	ResourceSpans []tempoBatch `json:"resourceSpans"`
}

// allSpans 展平所有 span。
func (t *tempoTrace) allSpans() []tempoSpan {
	var out []tempoSpan
	collect := func(batches []tempoBatch) {
		for _, b := range batches {
			for _, ss := range b.ScopeSpans {
				out = append(out, ss.Spans...)
			}
			for _, ss := range b.ILSpans {
				out = append(out, ss.Spans...)
			}
		}
	}
	collect(t.Batches)
	collect(t.ResourceSpans)
	return out
}

// views 生成响应视图（起点相对最早 span；属性按白名单裁剪）。
func (t *tempoTrace) views() []traceSpanView {
	raw := t.allSpans()
	if len(raw) == 0 {
		return []traceSpanView{}
	}
	// 最早起点作为时间基准
	var base uint64
	for i, s := range raw {
		if i == 0 || uint64(s.StartTimeUnixNano) < base {
			base = uint64(s.StartTimeUnixNano)
		}
	}
	out := make([]traceSpanView, 0, len(raw))
	for _, s := range raw {
		start := uint64(s.StartTimeUnixNano)
		end := uint64(s.EndTimeUnixNano)
		if start < base {
			start = base
		}
		attrs := make(map[string]any, len(s.Attributes))
		for _, kv := range s.Attributes {
			if _, ok := traceAllowedAttrs[kv.Key]; !ok {
				continue
			}
			attrs[kv.Key] = kv.coerce()
		}
		startMs := float64(start-base) / 1e6
		durMs := 0.0
		if end >= start {
			durMs = float64(end-start) / 1e6
		}
		out = append(out, traceSpanView{Name: s.Name, StartMs: startMs, DurMs: durMs, Attrs: attrs})
	}
	return out
}

// tenantID 从 span 属性提取租户（首个非空 tenant.id）。
func (t *tempoTrace) tenantID() string {
	for _, s := range t.allSpans() {
		for _, kv := range s.Attributes {
			if kv.Key == "tenant.id" {
				if v, ok := kv.coerce().(string); ok {
					return v
				}
			}
		}
	}
	return ""
}

// parseTempoTrace 解析 Tempo /api/traces 响应体。
func parseTempoTrace(body []byte) (*tempoTrace, error) {
	var t tempoTrace
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, fmt.Errorf("tempo: trace 解析失败: %w", err)
	}
	return &t, nil
}
