// relay.go — OHTTP 最小中继（relay，M8-1；技术方案 §5.5 判据 4）。
//
// 语义：中继只转发密文**不解开**（OHTTP 核心隐私语义）——请求方向转发 message/ohttp-req
// 至 target（解密方），响应方向原样回传 message/ohttp-resp。附带最小重放防护：
// 同一密文请求摘要（sha256）在时间窗内重复出现 → 409 拒绝。
//
// 安装期参数：OHTTP_RELAY_ENABLED·false·env·未填=不启用 relay（装配侧按值决定是否挂载）；
// OHTTP_RELAY_TARGET·空·env·未填且启用 → 构造拒（fail-closed）；OHTTP_RELAY_MAX_BODY·
// 1048576·env·未填=默认 1MiB；OHTTP_RELAY_WINDOW·10m·env·未填=默认值（重放窗口）。
package ohttp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RelayConfig relay 安装期配置。
type RelayConfig struct {
	TargetURL   string        // OHTTP_RELAY_TARGET（解密方端点）
	MaxBody     int64         // OHTTP_RELAY_MAX_BODY（默认 1MiB）
	ReplayWin   time.Duration // 重放窗口（默认 10m）
	ForwardWait time.Duration // 上游超时（默认 30s）
}

// RelayConfigFromEnv 从安装期参数装配。
func RelayConfigFromEnv() (RelayConfig, error) {
	cfg := RelayConfig{
		TargetURL:   strings.TrimSpace(os.Getenv("OHTTP_RELAY_TARGET")),
		MaxBody:     1 << 20,
		ReplayWin:   10 * time.Minute,
		ForwardWait: 30 * time.Second,
	}
	if v := os.Getenv("OHTTP_RELAY_MAX_BODY"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			cfg.MaxBody = n
		}
	}
	if v := os.Getenv("OHTTP_RELAY_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.ReplayWin = d
		}
	}
	if cfg.TargetURL == "" {
		return cfg, errRelayTargetMissing
	}
	u, err := url.Parse(cfg.TargetURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return cfg, errRelayTargetInvalid
	}
	return cfg, nil
}

var (
	errRelayTargetMissing = &relayError{"OHTTP_RELAY_TARGET 未配置（fail-closed）"}
	errRelayTargetInvalid = &relayError{"OHTTP_RELAY_TARGET 非法（须 http/https URL）"}
)

type relayError struct{ msg string }

func (e *relayError) Error() string { return "ohttp-relay: " + e.msg }

// RelayHandler OHTTP 中继 HTTP 处理器。
type RelayHandler struct {
	cfg    RelayConfig
	client *http.Client

	mu      sync.Mutex
	seen    map[string]time.Time // 请求密文 sha256 摘要 → 首见时间
	maxSeen int
}

// NewRelayHandler 构造（target 非法 fail-closed 返回错误）。
func NewRelayHandler(cfg RelayConfig) (*RelayHandler, error) {
	if _, err := RelayConfigFromEnv(); cfg.TargetURL == "" {
		_ = err // 配置以参数为准；env 校验仅供装配方参考
	}
	u, err := url.Parse(cfg.TargetURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errRelayTargetInvalid
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = 1 << 20
	}
	if cfg.ReplayWin <= 0 {
		cfg.ReplayWin = 10 * time.Minute
	}
	if cfg.ForwardWait <= 0 {
		cfg.ForwardWait = 30 * time.Second
	}
	return &RelayHandler{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.ForwardWait,
			// 中继不解密：禁用自动重定向（OHTTP 语义，密文不应被重定向链扩散）。
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		seen:    make(map[string]time.Time),
		maxSeen: 4096,
	}, nil
}

// ServeHTTP 处理 message/ohttp-req → 转发 → 回传 message/ohttp-resp。
func (h *RelayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "ohttp-relay: 仅接受 POST", http.StatusMethodNotAllowed)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "message/ohttp-req") {
		http.Error(w, "ohttp-relay: Content-Type 须为 message/ohttp-req", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, h.cfg.MaxBody+1))
	if err != nil {
		http.Error(w, "ohttp-relay: 读取请求体失败", http.StatusBadRequest)
		return
	}
	if int64(len(body)) > h.cfg.MaxBody {
		http.Error(w, "ohttp-relay: 请求体超限", http.StatusRequestEntityTooLarge)
		return
	}

	// 重放防护（最小实现）：摘要 → 时间窗。
	sum := sha256.Sum256(body)
	key := hex.EncodeToString(sum[:])
	if h.checkReplay(key) {
		http.Error(w, "ohttp-relay: 疑似重放（时间窗内重复密文）", http.StatusConflict)
		return
	}

	up, err := http.NewRequestWithContext(r.Context(), http.MethodPost, h.cfg.TargetURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "ohttp-relay: 构造上游请求失败", http.StatusInternalServerError)
		return
	}
	up.Header.Set("Content-Type", "message/ohttp-req")
	up.ContentLength = int64(len(body))

	resp, err := h.client.Do(up)
	if err != nil {
		http.Error(w, "ohttp-relay: 上游不可达", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, h.cfg.MaxBody+1))
	if err != nil || int64(len(respBody)) > h.cfg.MaxBody {
		http.Error(w, "ohttp-relay: 上游响应超限", http.StatusBadGateway)
		return
	}
	// 上游（解密方）返回非 200（含其封装失败语义）时原样透传状态与体，由客户端侧处置。
	w.Header().Set("Content-Type", "message/ohttp-resp")
	w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

// checkReplay 重放检查：窗口内重复 → true。惰性清理过期项；满容量整体重置（最小实现）。
func (h *RelayHandler) checkReplay(key string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	for k, t := range h.seen {
		if now.Sub(t) > h.cfg.ReplayWin {
			delete(h.seen, k)
		}
	}
	if _, dup := h.seen[key]; dup {
		return true
	}
	if len(h.seen) >= h.maxSeen {
		h.seen = make(map[string]time.Time)
	}
	h.seen[key] = now
	return false
}
