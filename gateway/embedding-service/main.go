// Package main — embedding-service（M4 里程碑 + G2-1 修正：tiktoken 集成）
//
// 职责：文本 → token IDs → 词嵌入向量（明文；可信区域随场景，见《GA-产品场景与可信区域矩阵》）。
// 位置：网关侧独立服务（Sidecar），Wasm 插件经本地 HTTP 调用。
//
// 实现说明（诚实标注）：
// - Tokenizer：tiktoken-go（cl100k_base，与 OpenAI 模型一致，内嵌词表无网络依赖）；
// 分词结果与 OpenAI token 数对齐（G2-2 验证）。
// - Embedding：确定性伪向量（SHA-256(token_id) 派生，元素 < R=2^32），
// 仅用于打通"文本 → 向量 → 密文"协议链路；真实模型权重接入待实现。
//
// API：
// POST /embed  {"text": "..."}  ->  {"tokens": [...], "vectors": [[...]]}
//
// 运行：go run ./gateway/embedding-service  （默认 :18080）
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/pkoukk/tiktoken-go"
)

// maskModulus 向量值域模数（与 otpmask-plugin / secagg 对齐 R=2^32）。
const maskModulus uint64 = 1 << 32

// defaultDim 默认嵌入维度。
const defaultDim = 8

// tokenizer 全局 tokenizer（cl100k_base，与 OpenAI 模型一致）。
var tokenizer *tiktoken.Tiktoken

func init() {
	tkm, err := tiktoken.GetEncoding("cl100k_base")
	if err != nil {
		// 词表加载失败属致命错误（内嵌词表不应失败）
		panic(fmt.Sprintf("加载 cl100k_base 词表失败: %v", err))
	}
	tokenizer = tkm
}

// embedRequest 请求体：待嵌入文本。
type embedRequest struct {
	Text string `json:"text"`
}

// embedResponse 响应体：token IDs 与嵌入向量。
type embedResponse struct {
	Tokens  []uint32  `json:"tokens"`
	Vectors [][]uint64 `json:"vectors"`
}

// tokenize 使用 tiktoken-go（cl100k_base）分词，与 OpenAI token 数一致。
func tokenize(text string) []uint32 {
	ids := tokenizer.Encode(text, nil, nil)
	tokens := make([]uint32, len(ids))
	for i, id := range ids {
		tokens[i] = uint32(id)
	}
	return tokens
}

// embedToken 由 token id 派生确定性伪向量（MVP：SHA-256 哈希 → [0, R)）。
// 真实模型权重（如 BGE/LLaMA embedding 表）替换见后续。
func embedToken(id uint32, dim int) []uint64 {
	seed := make([]byte, 4)
	binary.BigEndian.PutUint32(seed, id)
	vec := make([]uint64, dim)
	for i := 0; i < dim; i++ {
		h := sha256.Sum256(append(seed, byte(i)))
		// 取哈希前 8 字节 → [0, R)
		vec[i] = binary.BigEndian.Uint64(h[:8]) % maskModulus
	}
	return vec
}

// metrics 全局指标。
var metrics = newEmbedMetrics()

func handleEmbed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req embedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("bad json: %v", err), http.StatusBadRequest)
		return
	}
	if req.Text == "" {
		http.Error(w, "empty text", http.StatusBadRequest)
		return
	}

	tokens := tokenize(req.Text)
	vectors := make([][]uint64, len(tokens))
	for i, t := range tokens {
		vectors[i] = embedToken(t, defaultDim)
	}
	metrics.inc(int64(len(tokens)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(embedResponse{Tokens: tokens, Vectors: vectors})
	log.Printf("[embedding-service] text=%d chars -> %d tokens (cl100k_base), dim=%d", len(req.Text), len(tokens), defaultDim)
}

// handleMetrics Prometheus 指标端点：GET /metrics。
func handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	metrics.render(w)
}

func main() {
	addr := flag.String("listen", ":18080", "监听地址")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/embed", handleEmbed)
	mux.HandleFunc("/metrics", handleMetrics)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("embedding-service 就绪: %s（MVP: 字符级分词 + 伪向量）", *addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("服务退出: %v", err)
	}
}
