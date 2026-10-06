// recompute.go - 路线2的非线性补算服务
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"security-ai-gateway/cipher/mask"
	"security-ai-gateway/gateway/teecore"
	"security-ai-gateway/gateway/teecore/maskedinfer"
)

type recomputeRequest struct {
	RequestID   string     `json:"request_id"`
	Layer       int        `json:"layer"`
	Op          string     `json:"op"`
	Batch       [][]uint64 `json:"batch"`
	MaskVersion int        `json:"mask_version"`
	Gamma       []float64  `json:"gamma,omitempty"`
	Beta        []float64  `json:"beta,omitempty"`
	Signature   string     `json:"signature"`
}

// recomputeBatchLimit 单请求 batch 上限（vLLM 连续批处理对齐，防超长请求）
const recomputeBatchLimit = 4096

type recomputeResponse struct {
	RequestID string     `json:"request_id"`
	Result    [][]uint64 `json:"result"`
	MaskNext  string     `json:"mask_next"`
	Signature string     `json:"signature"`
}

// recomputeState 每会话的补算层序状态
type recomputeState struct {
	mu         sync.Mutex
	lastLayer  int
	hasHistory bool
}

type recomputeStates struct {
	mu   sync.Mutex
	byID map[string]*recomputeState
}

func newRecomputeStates() *recomputeStates {
	return &recomputeStates{byID: make(map[string]*recomputeState)}
}

// state 获取或创建会话的补算状态
func (rs *recomputeStates) state(sessionID string) *recomputeState {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	st, ok := rs.byID[sessionID]
	if !ok {
		st = &recomputeState{}
		rs.byID[sessionID] = st
	}
	return st
}

// checkLayerOrder 校验层序连续
func (st *recomputeState) checkLayerOrder(layer int) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.hasHistory && layer != st.lastLayer+1 {
		return fmt.Errorf("recompute: 层序乱序（期望 %d, 收到 %d）", st.lastLayer+1, layer)
	}
	st.lastLayer = layer
	st.hasHistory = true
	return nil
}

// maskNext 计算 mask_next 指纹（MAC 下沉 Provider；intl=HMAC-SHA256 逐字节等价现役）。
func maskNext(sessionKey []byte, layer int, requestID string) string {
	sum := cryptoProvider.HMAC(sessionKey, []byte(fmt.Sprintf("%d|%s", layer+1, requestID)))
	return hex.EncodeToString(sum)
}

// LayerWeightProvider 层权重提供器
type LayerWeightProvider interface {
	LayerWeight(layer int) (*maskedinfer.QuantizedMatrix, error)
}

// mockWeightProvider 测试用 mock 权重
type mockWeightProvider struct {
	dim int
}

func NewMockWeightProvider(dim int) *mockWeightProvider {
	return &mockWeightProvider{dim: dim}
}

// LayerWeight mock：基于层号哈希生成确定性权重
func (p *mockWeightProvider) LayerWeight(layer int) (*maskedinfer.QuantizedMatrix, error) {
	weights := make([][]float64, p.dim)
	for i := range weights {
		weights[i] = make([]float64, p.dim)
		for j := range weights[i] {
			h := sha256.Sum256([]byte(fmt.Sprintf("layer-%d-%d-%d", layer, i, j)))
			weights[i][j] = (float64(int16(h[0])|int16(h[1])<<8)/32768.0)*0.5 - 0.25
		}
	}
	m, err := maskedinfer.NewQuantizedMatrix(weights, 8)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// handleRecompute /v1/recompute
func (s *teeServer) handleRecompute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess := s.sessionByID(r)
	if sess == nil {
		http.Error(w, "未证明会话（B4：recompute 需有效证明会话）", http.StatusUnauthorized)
		return
	}
	var req recomputeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("bad json: %v", err), http.StatusBadRequest)
		return
	}
	// 签名校验
	if !verifyRecomputeSig(sess.K_sig, &req) {
		http.Error(w, "recompute 签名无效", http.StatusUnauthorized)
		return
	}
	// batch 上限（连续批处理对齐）
	if len(req.Batch) == 0 || len(req.Batch) > recomputeBatchLimit {
		http.Error(w, fmt.Sprintf("batch 长度 %d 超限（1..%d）", len(req.Batch), recomputeBatchLimit), http.StatusBadRequest)
		return
	}
	// 遥测：补算调用计数
	s.metrics.incRecompute(req.Op, 0)
	t0 := time.Now()
	// 层序校验
	st := s.recomputeStates.state(sess.ID)
	if err := st.checkLayerOrder(req.Layer); err != nil {
		s.denyAndAudit(tenantOf(r), req.RequestID, "recompute_layer_mismatch", "")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 派生层掩码流
	seed, serr := s.sessionSeed(r)
	if serr != nil {
		http.Error(w, "会话密钥缺失: "+serr.Error(), http.StatusInternalServerError)
		return
	}
	defer wipe(seed)
	layerDomain := fmt.Sprintf("otpmask/layer/%d/v1", req.Layer)
	stream, err := newLayerStream(seed, maskModulus, []byte(layerDomain))
	if err != nil {
		http.Error(w, fmt.Sprintf("掩码流派生失败: %v", err), http.StatusInternalServerError)
		return
	}
	nextStream, err := newLayerStream(seed, maskModulus, []byte(fmt.Sprintf("otpmask/layer/%d/v1", req.Layer+1)))
	if err != nil {
		http.Error(w, fmt.Sprintf("下一层掩码流派生失败: %v", err), http.StatusInternalServerError)
		return
	}

	// 掩码像 + 脱掩码 -> 非线性 -> 重掩码
	result := make([][]uint64, len(req.Batch))
	dim := len(req.Batch[0])
	weights, err := s.weightProvider.LayerWeight(req.Layer)
	if err != nil {
		http.Error(w, fmt.Sprintf("权重加载失败: %v", err), http.StatusInternalServerError)
		return
	}
	// 掩码 r_l 和掩码像 W_l·r_l
	rMask := make([]uint64, dim)
	for i := range rMask {
		rMask[i] = stream.Next() % maskModulus
	}
	maskImage, err := weights.MaskImage(rMask)
	if err != nil {
		http.Error(w, fmt.Sprintf("掩码像计算失败: %v", err), http.StatusInternalServerError)
		return
	}
	for b, yCipher := range req.Batch {
		// 脱掩码
		y, err := maskedinfer.Unmask(yCipher, maskImage)
		if err != nil {
			http.Error(w, fmt.Sprintf("脱掩码失败: %v", err), http.StatusInternalServerError)
			return
		}
		// 符号还原 + 浮点化
		signed := maskedinfer.SignedVector(y)
		yFloat := make([]float64, len(signed))
		for i, v := range signed {
			yFloat[i] = float64(v) / 1e6
		}
		// 非线性
		switch req.Op {
		case "gelu":
			for i := range yFloat {
				yFloat[i] = teecore.GELU(yFloat[i])
			}
		case "softmax":
			yFloat = teecore.Softmax(yFloat)
		case "layernorm":
			yFloat = teecore.LayerNorm(yFloat, req.Gamma, req.Beta, 1e-5)
		case "rmsnorm":
			// vLLM RMSNorm（无均值减法）；Gamma 为权重，Beta 不使用
			yFloat = teecore.RMSNorm(yFloat, req.Gamma, 1e-6)
		case "argmax":
			// 方案 C 采样确认（P4）：TEE 内 ArgMax 决定 token，不再重掩码
			tokenIdx := teecore.ArgMax(yFloat)
			result[b] = []uint64{uint64(tokenIdx)}
			continue
		default:
			http.Error(w, fmt.Sprintf("未知算子 %q（gelu|softmax|layernorm|rmsnorm|argmax）", req.Op), http.StatusBadRequest)
			return
		}
		// 定点化 + 重掩码
		fY := maskedinfer.FloatToMaskDomain(yFloat)
		rNext := make([]uint64, dim)
		for i := range rNext {
			rNext[i] = nextStream.Next() % maskModulus
		}
		remasked, err := maskedinfer.Remask(fY, rNext)
		if err != nil {
			http.Error(w, fmt.Sprintf("重掩码失败: %v", err), http.StatusInternalServerError)
			return
		}
		result[b] = remasked
	}

	resp := &recomputeResponse{
		RequestID: req.RequestID,
		Result:    result,
		MaskNext:  maskNext(sess.K_sig, req.Layer, req.RequestID),
	}
	resp.Signature = signRecompute(sess.K_sig, resp)
	// 遥测：补算耗时（毫秒累计）
	s.metrics.incRecompute(req.Op, time.Since(t0).Milliseconds())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
	log.Printf("[tee] recompute session=%s layer=%d op=%s batch=%d mask_next=%s...",
		sess.ID[:8], req.Layer, req.Op, len(req.Batch), resp.MaskNext[:8])
}

// sessionSeed 取会话请求密钥（经 cryptop.Provider.KDF；intl=HKDF-SHA256 逐字节等价）。
// seed 长度**随 PRG 而非 profile**（§5.3.2 选择表）：hmac-sha256 → 32；sm4 → p.SymmetricKeySize()。
func (s *teeServer) sessionSeed(r *http.Request) ([]byte, error) {
	sess := s.sessionByID(r)
	if sess == nil || len(sess.K_enc) == 0 {
		return nil, errors.New("会话密钥缺失")
	}
	seedLen := 32
	if cryptoMaskPRG == "sm4" {
		seedLen = cryptoProvider.SymmetricKeySize()
	}
	seed, err := cryptoProvider.KDF(sess.K_enc, nil, []byte("otpmask/recompute-seed/v1"), seedLen)
	if err != nil {
		return nil, fmt.Errorf("掩码 seed 派生失败: %w", err)
	}
	return seed, nil
}

// newLayerStream 按 `mask_prg` 选构造器（P0-4 §5.3.2 选择表，唯一选择点）：
//   - `hmac-sha256`（intl 默认）→ `NewStreamDomain`（hmacPRG，profile 无关，逐字节等价现役实现）；
//   - `sm4` → `NewStreamWithProvider`（SM4-CTR，key 长度须 = SymmetricKeySize，由 seed 长度保证）；
//   - `bridge` → sm 档迁移桥接，层掩码无请求头可依，按 profile 目标态取 `sm4`。
func newLayerStream(seed []byte, modulus uint64, domain []byte) (*mask.Stream, error) {
	if cryptoMaskPRG == "sm4" || cryptoMaskPRG == "bridge" {
		return mask.NewStreamWithProvider(cryptoProvider, seed, domain, modulus)
	}
	return mask.NewStreamDomain(seed, modulus, domain)
}

func verifyRecomputeSig(kSig []byte, req *recomputeRequest) bool {
	got, err := hex.DecodeString(req.Signature)
	if err != nil {
		return false
	}
	canonical := recomputeCanonical(req)
	want := cryptoProvider.HMAC(kSig, canonical)
	return hmac.Equal(got, want)
}

func recomputeCanonical(req *recomputeRequest) []byte {
	var buf []byte
	buf = append(buf, []byte(fmt.Sprintf("%s|%d|%s|%d", req.RequestID, req.Layer, req.Op, req.MaskVersion))...)
	batchJSON, _ := json.Marshal(req.Batch)
	buf = append(buf, batchJSON...)
	return cryptoProvider.Hash(buf)
}

func signRecompute(kSig []byte, resp *recomputeResponse) string {
	var buf []byte
	buf = append(buf, []byte(resp.RequestID)...)
	buf = append(buf, []byte(resp.MaskNext)...)
	resultJSON, _ := json.Marshal(resp.Result)
	buf = append(buf, resultJSON...)
	sum := cryptoProvider.HMAC(kSig, cryptoProvider.Hash(buf))
	return hex.EncodeToString(sum)
}

func toFloat64(v []uint64) []float64 {
	out := make([]float64, len(v))
	for i, x := range v {
		out[i] = float64(x)
	}
	return out
}

var errNoWeights = errors.New("recompute: 权重提供器未初始化")
