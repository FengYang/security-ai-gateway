package main

import (
	"strings"
	"unicode/utf8"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func extractJSONText(body []byte, path string) (string, bool) {
	result := gjson.GetBytes(body, path)
	if !result.Exists() {
		return "", false
	}
	return result.String(), true
}

// labelJSONTextAtPath 在 JSON 指定路径的字符串**首尾各插入一次**标识文案（head＋tail 双锚点）。
//
// 用途：**非流式整包**响应（明文路径 `onHttpResponseBody`）。整包只有一段文本、无法像流式那样分帧注入，
// 故按与流式一致的"双锚点"纪律在正文首尾各带一次标识（对齐 GB 45438-2025 5.1 d) 与 S4-3 分片保留策略）。
//
// 返回：改写后的 body 与"是否发生改写"。路径不存在、文本为空、label 为空、或已注入过（幂等）时返回
// (原 body, false)，调用方**不得**据此替换响应体。
func labelJSONTextAtPath(body []byte, path, label string) ([]byte, bool) {
	if label == "" {
		return body, false
	}
	text, ok := extractJSONText(body, path)
	if !ok || text == "" {
		return body, false
	}
	if strings.HasPrefix(text, label) && strings.HasSuffix(text, label) {
		return body, false // 幂等：已带双锚点，不重复注入
	}
	labelled := label + "\n" + text + "\n" + label
	out, err := sjson.SetBytes(body, path, labelled)
	if err != nil {
		return body, false
	}
	return out, true
}

func splitCompleteSSE(data string, endStream bool) (string, string) {
	if endStream {
		return data, ""
	}
	lfEnd := strings.LastIndex(data, "\n\n")
	crlfEnd := strings.LastIndex(data, "\r\n\r\n")
	switch {
	case lfEnd == -1 && crlfEnd == -1:
		return "", data
	case crlfEnd > lfEnd:
		return data[:crlfEnd+4], data[crlfEnd+4:]
	default:
		return data[:lfEnd+2], data[lfEnd+2:]
	}
}

func extractSSEDataPayloads(data string) []string {
	normalized := strings.ReplaceAll(data, "\r\n", "\n")
	blocks := strings.Split(normalized, "\n\n")
	payloads := make([]string, 0, len(blocks))
	for _, block := range blocks {
		if strings.TrimSpace(block) == "" {
			continue
		}
		var lines []string
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "data:") {
				lines = append(lines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			}
		}
		if len(lines) > 0 {
			payloads = append(payloads, strings.Join(lines, "\n"))
		}
	}
	return payloads
}

func isDonePayload(payload string) bool {
	return strings.TrimSpace(payload) == "[DONE]"
}

func charCount(value string) int {
	return utf8.RuneCountInString(value)
}

func exceedsByteLimit(currentBytes int, additionalBytes int, limit uint32) bool {
	return uint64(currentBytes)+uint64(additionalBytes) > uint64(limit)
}
