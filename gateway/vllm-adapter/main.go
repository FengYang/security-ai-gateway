// Package main — vLLM 密态对接适配器（M12，）
//
// 运行于 TEE 内明文域，向 tee-infer 暴露统一明文推理接口：
//
//	POST /generate  {"vectors":[[...]],"text":""} -> {"tokens":[...]}
//	GET  /health    -> {"status":"ok","engine":"mock"}
//
// 明文边界：本服务位于 TEE 可信域内，接收明文向量/文本，返回 token IDs；
// tee-infer 经 -engine-url 指向本服务即可切换引擎（本地模拟 → 适配器）。
//
// 引擎接入：
// - mock（本实现）：复用明文引擎平面的确定性演示引擎（gateway/modelengine.Demo），
// 结果与 tee-infer 本地引擎完全一致，用于本地无 GPU 环境验证"换引擎不改变密态链路行为"。
// - 真实 vLLM：由同目录 vllm_adapter.py（Python 标准库，无第三方依赖）
// 提供 /generate 实现（内部调用 vLLM.LLM.generate）；部署于 GPU 环境时
// 二者端口一致即可平滑替换，tee-infer 侧无需改动。
//
// 依赖方向（方案 §8.2④）：本适配器**只依赖 gateway/modelengine**，不得 import 宿主
// gateway/tee-infer-service/*；越界由 gateway/archtest 的边界门禁机器拦截。
//
// 运行：go run ./gateway/vllm-adapter [-listen :19190]
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"time"

	"security-ai-gateway/gateway/modelengine"
)

// generateRequest / generateResponse TEE 内部明文推理接口。
// 与宿主 model.RemoteEngine 的 /generate 报文**协议**对齐（仅协议一致，无类型依赖）。
type generateRequest struct {
	Vectors [][]float64 `json:"vectors,omitempty"`
	Text    string      `json:"text,omitempty"`
}

type generateResponse struct {
	Tokens []uint64 `json:"tokens"`
}

// mockEngine 确定性演示引擎：直接复用明文引擎平面的 Demo（与 tee-infer 本地引擎同一实现），
// 保证本地验证"换引擎不改变密态链路行为"。
//
// 【依赖方向】本适配器是独立进程，**只依赖 gateway/modelengine**（明文引擎平面契约 +
// 演示引擎），不 import 宿主 gateway/tee-infer-service/model（方案 §8.2④：vLLM 侧治理）。
// 该约束由 gateway/archtest 的依赖方向门禁机器校验（adapters-no-host-model）。
type mockEngine struct {
	m *modelengine.Demo
}

func (e *mockEngine) Generate(vectors [][]float64) []uint64 {
	out := make([]uint64, len(vectors))
	for i, v := range vectors {
		out[i] = uint64(e.m.Predict(v))
	}
	return out
}

func main() {
	listen := flag.String("listen", ":19190", "监听地址")
	flag.Parse()

	eng := &mockEngine{m: modelengine.NewDemo()}

	mux := http.NewServeMux()
	mux.HandleFunc("/generate", func(w http.ResponseWriter, r *http.Request) {
		var req generateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		vectors := req.Vectors
		if len(vectors) == 0 && req.Text != "" {
			// 文本入口占位（真实场景由 vLLM tokenizer 直接处理文本；mock 以零向量示意）
			vectors = [][]float64{{0, 0, 0, 0, 0, 0, 0, 0}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(generateResponse{Tokens: eng.Generate(vectors)})
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","engine":"mock"}`))
	})

	log.Printf("vllm-adapter 就绪: %s engine=mock（真实 vLLM 用 vllm_adapter.py）", *listen)
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("服务退出: %v", err)
	}
}
