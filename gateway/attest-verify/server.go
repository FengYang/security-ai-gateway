package attestverify

// localhost 验证服务（D2）：wasm 插件 / 网关组件经 http://127.0.0.1:<port>/verify
// 提交 quote 与握手绑定材料，sidecar 返回度量列表或拒绝原因（fail-closed）。
//
// 安全注意：本服务仅绑定回环地址（127.0.0.1），不暴露集群网络；
// 真实部署可再加共享令牌头（-token）防同机其他进程滥用。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"
)

// VerifyRequest /verify 请求体。
type VerifyRequest struct {
	Quote      []byte `json:"quote"`       // 证明载荷（原始 JSON 或 hex(JSON)）
	ReportData []byte `json:"report_data"` // 期望绑定材料 H(nonce‖server_pub)（可空 = 不校验）
}

// VerifyResponse /verify 响应体。
type VerifyResponse struct {
	OK           bool     `json:"ok"`
	Measurements []string `json:"measurements,omitempty"`
	Error        string   `json:"error,omitempty"`
}

// Server localhost 验证服务。
type Server struct {
	verifier AttestationVerifier
	token    string // 可选共享令牌（X-Verify-Token）
	addr     string
}

// NewServer 构造验证服务；verifier 为验证器实现（第三方可换）。
func NewServer(verifier AttestationVerifier, token, addr string) *Server {
	if addr == "" {
		addr = "127.0.0.1:19191"
	}
	return &Server{verifier: verifier, token: token, addr: addr}
}

// Handler 返回 HTTP handler（供 httptest 与主服务复用）。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/verify", s.handleVerify)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// ListenAndServe 启动回环服务（阻塞）。
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("attestverify: 监听 %s 失败: %w", s.addr, err)
	}
	log.Printf("attestverify: sidecar 就绪 %s（回环绑定）", s.addr)
	return http.Serve(ln, s.Handler())
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.token != "" && r.Header.Get("X-Verify-Token") != s.token {
		http.Error(w, "验证令牌无效", http.StatusUnauthorized)
		return
	}
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	measurements, err := s.verifier.VerifyQuote(req.Quote, req.ReportData)
	resp := VerifyResponse{OK: err == nil, Measurements: measurements}
	if err != nil {
		resp.Error = err.Error()
		w.WriteHeader(http.StatusForbidden) // 验证失败 → 403（fail-closed 语义）
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
	log.Printf("attestverify: verify %s ok=%v %s", r.RemoteAddr, resp.OK,
		func() string {
			if err != nil {
				return err.Error()
			}
			return fmt.Sprintf("measurements=%v", measurements)
		}())
}

// VerifyViaHTTP 客户端便捷函数：调用回环 sidecar 验证 quote。
// token 为共享验证令牌（空 = 服务端未启用令牌校验时）。
func VerifyViaHTTP(addr string, token string, quote, reportData []byte, timeout time.Duration) (*VerifyResponse, error) {
	body, _ := json.Marshal(VerifyRequest{Quote: quote, ReportData: reportData})
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/verify", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("attestverify: 构造请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Verify-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("attestverify: 调用 sidecar 失败: %w", err)
	}
	defer resp.Body.Close()
	var vr VerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&vr); err != nil {
		return nil, fmt.Errorf("attestverify: 解析响应失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK || !vr.OK {
		return &vr, fmt.Errorf("attestverify: 验证拒绝: %s", orEmpty(vr.Error))
	}
	return &vr, nil
}

// orEmpty 空串回退（响应展示）。
func orEmpty(s string) string {
	if s == "" {
		return "（无原因）"
	}
	return s
}
