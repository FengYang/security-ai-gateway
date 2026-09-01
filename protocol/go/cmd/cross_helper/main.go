// Package main — 协议交叉测试辅助程序（仅供 cross_test.py 调用）。
//
// 用法：
//
//	go run ./protocol/go/cmd/cross_helper decode request <hex>
//	go run ./protocol/go/cmd/cross_helper decode response <hex>
//	go run ./protocol/go/cmd/cross_helper encode request <json> <k_sig_hex>
//	go run ./protocol/go/cmd/cross_helper envelope_seal <k_enc_hex> <session_id> <endpoint> <direction> <counter> <plaintext_hex>
//	go run ./protocol/go/cmd/cross_helper envelope_open <k_enc_hex> <session_id> <endpoint> <direction> <envelope_hex>
//	go run ./protocol/go/cmd/cross_helper window_run <counters_csv>
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"security-ai-gateway/protocol/go"
)

func die(format string, args ...any) {
	fmt.Fprintln(os.Stderr, fmt.Sprintf(format, args...))
	os.Exit(1)
}

func main() {
	if len(os.Args) < 3 {
		die("用法: cross_helper <op> <args...>（decode/encode 带子命令，envelope_*/window_run 直接带参）")
	}
	op, kind := os.Args[1], os.Args[2]
	switch op {
	case "decode":
		data, err := hex.DecodeString(os.Args[3])
		if err != nil {
			die("hex 解码失败: %v", err)
		}
		if kind == "request" {
			req, err := protocol.DecodeRequest(data)
			if err != nil {
				die("DecodeRequest: %v", err)
			}
			vectors := make([][]uint64, len(req.CipherVectors))
			for i, v := range req.CipherVectors {
				vectors[i] = v.Data
			}
			out, _ := json.Marshal(map[string]any{
				"request_id": req.RequestID, "timestamp_ns": req.TimestampNS,
				"model": req.Model, "max_new_tokens": req.MaxNewTokens,
				"nonce": hex.EncodeToString(req.Nonce),
				"cipher_vectors": vectors, "cipher_text": hex.EncodeToString(req.CipherText),
				"signature": hex.EncodeToString(req.Signature),
				"engine_type": req.EngineType, "attest_type": req.AttestType,
				"text_payload": hex.EncodeToString(req.TextPayload), "stream": req.Stream,
			})
			fmt.Println(string(out))
		} else {
			resp, err := protocol.DecodeResponse(data)
			if err != nil {
				die("DecodeResponse: %v", err)
			}
			out, _ := json.Marshal(map[string]any{
				"request_id": resp.RequestID, "timestamp_ns": resp.TimestampNS,
				"status": resp.Status, "cipher_output": resp.CipherOutput.Data,
				"tokens_generated": resp.TokensGenerated, "signature": hex.EncodeToString(resp.Signature),
			})
			fmt.Println(string(out))
		}
	case "encode":
		kSig, err := hex.DecodeString(os.Args[4])
		if err != nil {
			die("k_sig hex 解码失败: %v", err)
		}
		var f map[string]any
		if err := json.Unmarshal([]byte(os.Args[3]), &f); err != nil {
			die("字段 JSON 解析失败: %v", err)
		}
		if kind == "request" {
			req := &protocol.InferenceRequest{
				RequestID:   f["request_id"].(string),
				TimestampNS: int64(f["timestamp_ns"].(float64)),
				Model:       f["model"].(string),
				MaxNewTokens: uint32(f["max_new_tokens"].(float64)),
			}
			req.Nonce, _ = hex.DecodeString(f["nonce"].(string))
			for _, v := range f["cipher_vectors"].([]any) {
				var vec protocol.CipherVector
				for _, x := range v.([]any) {
					vec.Data = append(vec.Data, uint64(x.(float64)))
				}
				req.CipherVectors = append(req.CipherVectors, vec)
			}
			if ct, ok := f["cipher_text"].(string); ok && ct != "" {
				req.CipherText, _ = hex.DecodeString(ct)
			}
			// 协议扩展字段（可选）
			if et, ok := f["engine_type"].(string); ok {
				req.EngineType = et
			}
			if at, ok := f["attest_type"].(string); ok {
				req.AttestType = at
			}
			// P2/P5：text 载荷（hex）+ 流式标志
			if tp, ok := f["text_payload"].(string); ok && tp != "" {
				req.TextPayload, _ = hex.DecodeString(tp)
			}
			if st, ok := f["stream"].(bool); ok {
				req.Stream = st
			}
			protocol.SignRequest(kSig, req)
			data, err := protocol.EncodeRequest(req)
			if err != nil {
				die("EncodeRequest: %v", err)
			}
			fmt.Println(hex.EncodeToString(data))
		} else {
			die("encode response 暂未实现（使用 Python 侧构造）")
		}
	case "envelope_seal":
		// os.Args: prog envelope_seal k_enc session endpoint direction counter plaintext
		if len(os.Args) != 8 {
			die("用法: cross_helper envelope_seal <k_enc_hex> <session_id> <endpoint> <direction> <counter> <plaintext_hex>")
		}
		kEnc, err := hex.DecodeString(os.Args[2])
		if err != nil {
			die("k_enc hex 解码失败: %v", err)
		}
		dir, err := strconv.Atoi(os.Args[5])
		if err != nil {
			die("direction 解析失败: %v", err)
		}
		counter, err := strconv.ParseUint(os.Args[6], 10, 64)
		if err != nil {
			die("counter 解析失败: %v", err)
		}
		pt, err := hex.DecodeString(os.Args[7])
		if err != nil {
			die("plaintext hex 解码失败: %v", err)
		}
		wire, err := protocol.SealEnvelope(kEnc, os.Args[3], os.Args[4], protocol.Direction(dir), counter, pt)
		if err != nil {
			die("SealEnvelope: %v", err)
		}
		fmt.Println(hex.EncodeToString(wire))
	case "envelope_open":
		// os.Args: prog envelope_open k_enc session endpoint direction envelope
		if len(os.Args) != 7 {
			die("用法: cross_helper envelope_open <k_enc_hex> <session_id> <endpoint> <direction> <envelope_hex>")
		}
		kEnc, err := hex.DecodeString(os.Args[2])
		if err != nil {
			die("k_enc hex 解码失败: %v", err)
		}
		dir, err := strconv.Atoi(os.Args[5])
		if err != nil {
			die("direction 解析失败: %v", err)
		}
		wire, err := hex.DecodeString(os.Args[6])
		if err != nil {
			die("envelope hex 解码失败: %v", err)
		}
		pt, counter, err := protocol.OpenEnvelope(kEnc, os.Args[3], os.Args[4], protocol.Direction(dir), wire)
		if err != nil {
			die("OpenEnvelope: %v", err)
		}
		out, _ := json.Marshal(map[string]any{
			"plaintext": hex.EncodeToString(pt), "counter": counter,
		})
		fmt.Println(string(out))
	case "window_run":
		// os.Args: prog window_run counters_csv；逐个喂入计数器，输出接受/拒绝决策序列（与 Python 比对）
		if len(os.Args) != 3 {
			die("用法: cross_helper window_run <counters_csv>")
		}
		var decisions []map[string]any
		var w protocol.CounterWindow
		for _, part := range strings.Split(os.Args[2], ",") {
			c, err := strconv.ParseUint(strings.TrimSpace(part), 10, 64)
			if err != nil {
				die("counter 解析失败 %q: %v", part, err)
			}
			decisions = append(decisions, map[string]any{
				"counter": c, "ok": w.Check(c) == nil,
			})
		}
		out, _ := json.Marshal(decisions)
		fmt.Println(string(out))
	case "time":
		fmt.Println(time.Now().UnixNano())
	default:
		die("未知操作: %s", op)
	}
	_ = strconv.Itoa
}
