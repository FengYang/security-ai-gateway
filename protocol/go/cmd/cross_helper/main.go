// Package main — 协议交叉测试辅助程序（仅供 cross_test.py 调用）。
//
// 用法：
//
//	go run ./protocol/go/cmd/cross_helper decode request <hex>
//	go run ./protocol/go/cmd/cross_helper decode response <hex>
//	go run ./protocol/go/cmd/cross_helper encode request <json> <k_sig_hex>
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"security-ai-gateway/protocol/go"
)

func die(format string, args ...any) {
	fmt.Fprintln(os.Stderr, fmt.Sprintf(format, args...))
	os.Exit(1)
}

func main() {
	if len(os.Args) < 4 {
		die("用法: cross_helper <encode|decode> <request|response> <arg> [k_sig_hex]")
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
			protocol.SignRequest(kSig, req)
			data, err := protocol.EncodeRequest(req)
			if err != nil {
				die("EncodeRequest: %v", err)
			}
			fmt.Println(hex.EncodeToString(data))
		} else {
			die("encode response 暂未实现（使用 Python 侧构造）")
		}
	case "time":
		fmt.Println(time.Now().UnixNano())
	default:
		die("未知操作: %s", op)
	}
	_ = strconv.Itoa
}
