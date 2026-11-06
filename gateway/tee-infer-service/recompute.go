// recompute.go - 路线2的非线性补算服务（proto=2：传输 + 鉴权 + 委派）
//
// 【本文件的职责边界】只做三件事：传输解析、版本门禁、会话鉴权；随后**一律委派**
// 给 state_machine.go（状态推进）与 step_exec.go（步执行）。
//
// 【为什么不再在这里做数值】proto=1 时代本文件把「层序校验 + 掩码流 + 算子 + 重掩码」
// 全写在 handler 里，导致：① 掩码域归属写反（旧 168/175 行用下一层的域给本层输出
// 重掩码）无任何结构性约束；② st.mu 临界区里混着 http.Error 与审计，构成锁序反转
// （§6.3 / §10 R7）。现在 handler 只负责「把请求安全地交给状态机」，数值与状态一律下沉。
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/FengYang/masked-infer/core"
	"github.com/FengYang/masked-infer/demo"
	"github.com/FengYang/masked-infer/masklite"
	"github.com/FengYang/masked-infer/plan"
	"security-ai-gateway/cipher/mask"
)

// recomputeBatchLimit 单请求 batch 上限（vLLM 连续批处理对齐，防超长请求）
const recomputeBatchLimit = 4096

// LayerWeightProvider 层权重提供器（proto=1 遗留，仅 mock/旧测试使用）。
//
// D15：保留不删，新代码一律走 route2demo.ModelWeights（按 TensorKey 取张量）。
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

// LayerWeight mock：基于层号哈希生成确定性权重。
// 算法已抽取到 route2demo（客户端编排器 cmd/route2-client 共享同一实现，
// 保证双方对同一 (layer,dim) 得到逐位一致的权重，无需经线路传输）。
func (p *mockWeightProvider) LayerWeight(layer int) (*maskedinfer.QuantizedMatrix, error) {
	return route2demo.LayerWeights(layer, p.dim)
}

// handleRecompute /v1/recompute（proto=2）
func (s *teeServer) handleRecompute(w http.ResponseWriter, r *http.Request) {
	// T3a：注入请求路径证据元数据（path/path_mode）。
	r = r.WithContext(withAuditReqMeta(r.Context(), r.URL.Path, auditPathMode(r.URL.Path)))
	if r.Method != http.MethodPost {
		recordExemptExit("handleRecompute", "method_not_allowed")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess := s.sessionByID(r)
	if sess == nil {
		s.auditDenyExitReq(r, tenantOf(r), "", "recompute_no_session", "", http.StatusUnauthorized)
		http.Error(w, "未证明会话（B4：recompute 需有效证明会话）", http.StatusUnauthorized)
		return
	}
	var req recomputeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.auditDenyExitReq(r, tenantOf(r), "", "recompute_bad_json", "", http.StatusBadRequest)
		http.Error(w, fmt.Sprintf("bad json: %v", err), http.StatusBadRequest)
		return
	}
	// ---- 版本门禁（硬切换，§2.5.2 方案 B）----
	// proto≠2 或缺 coord ⇒ 独立审计码，绝不混用 recompute_layer_mismatch：
	// 旧客户端的 layer 语义已变（MLP 第 L 层 ≠ Transformer 第 b 块第 s 步），
	// 静默兼容的危险态是「层序校验通过但权重/掩码彻底错配」——日志全绿、数值全错。
	if req.Proto != protoV2 || req.Coord == "" {
		s.auditDenyExitReq(r, tenantOf(r), req.RequestID, auditRecomputeProtoV1Unsupported,
			"", http.StatusBadRequest)
		http.Error(w, "proto=1 已不受支持：需 proto=2 且携带 coord（旧客户端请升级）",
			http.StatusBadRequest)
		return
	}
	// 签名校验（canonical v2：coord/seq/model_id 均进签名）
	if !verifyRecomputeSig(sess.K_sig, &req) {
		s.auditDenyExitReq(r, tenantOf(r), req.RequestID, "recompute_bad_signature",
			"", http.StatusUnauthorized)
		http.Error(w, "recompute 签名无效", http.StatusUnauthorized)
		return
	}
	// 带外 op：kv_reset（D10：不新增路由，走同一端点；不参与 plan 步序）
	if req.Op == route2plan.OpKVReset {
		s.handleKVReset(w, r, sess, &req)
		return
	}
	// batch 上限（连续批处理对齐）
	if len(req.Batch) == 0 || len(req.Batch) > recomputeBatchLimit {
		s.auditDenyExitReq(r, tenantOf(r), req.RequestID, "recompute_batch_invalid",
			"", http.StatusBadRequest)
		http.Error(w, fmt.Sprintf("batch 长度 %d 超限（1..%d）", len(req.Batch), recomputeBatchLimit),
			http.StatusBadRequest)
		return
	}
	// 掩码 seed：必须在取 st.mu **之前**派生（sessionSeed 内部取 s.mu，
	// 若反过来在 st.mu 内调用就构成 s.mu 反向取锁 ⇒ 死锁，§6.3）。
	seed, serr := s.sessionSeed(r)
	if serr != nil {
		s.auditDenyExitReq(r, tenantOf(r), req.RequestID, "recompute_no_session_key",
			"", http.StatusInternalServerError)
		http.Error(w, "会话密钥缺失: "+serr.Error(), http.StatusInternalServerError)
		return
	}
	defer wipe(seed)

	t0 := time.Now()
	// ---- 临界区：状态推进校验 + 步执行（无 IO / 无审计 / 无遥测）----
	st := s.recomputeStates.state(sess.ID)
	out := st.runStep(&req, seed)
	elapsed := time.Since(t0).Milliseconds()

	// ---- 以下全部在 st.mu 之外 ----
	if out.err != nil {
		s.metrics.incRecompute(req.Op, elapsed)
		s.auditDenyExitReq(r, tenantOf(r), req.RequestID, out.err.auditCode, "", out.err.httpStatus)
		http.Error(w, out.err.msg, out.err.httpStatus)
		return
	}
	nextCoord := out.nextCoord
	maskNext := nextCoordFingerprint(sess.K_sig, nextCoord, req.RequestID)
	resp := &recomputeResponse{
		RequestID: req.RequestID,
		Seq:       out.seq,
		Result:    out.result,
		Token:     out.token,
		NextCoord: nextCoord,
		MaskNext:  maskNext,
	}
	resp.Signature = signRecompute(sess.K_sig, resp)
	s.metrics.incRecompute(req.Op, elapsed)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
	log.Printf("[tee] recompute session=%s seq=%d op=%s rows=%d next=%s",
		sess.ID[:8], out.seq, req.Op, len(req.Batch), maskCoordBrief(nextCoord))
}

// maskCoordBrief 日志用的坐标摘要（避免把完整 wire 打进日志）。
func maskCoordBrief(coord string) string {
	if len(coord) <= 12 {
		return coord
	}
	return coord[:12] + "..."
}

// handleKVReset 带外 op kv_reset（§7.4.2 规程 R-RECOVER ①）。
//
// 语义：KV 逐元素清零后复用、pos 归零、turn 归零、stage 回到 prefill。
// 注意**不**重建会话与不清空 model_id —— 那是重新 attest 的事（规程 ②）。
func (s *teeServer) handleKVReset(w http.ResponseWriter, r *http.Request, sess *teeSession, req *recomputeRequest) {
	st := s.recomputeStates.state(sess.ID)
	modelID, cfg, initialized := st.resetSession(req.RequestID)
	nextCoord := ""
	if initialized {
		// 出锁后重建首步坐标（BuildTurn 是纯函数，纯计算不持锁）。
		if plan, err := route2plan.BuildTurn(cfg, route2plan.StagePrefill, 0); err == nil && len(plan) > 0 {
			nextCoord = plan[0].Coord.Wire()
		}
	}
	resp := &recomputeResponse{
		RequestID: req.RequestID,
		Seq:       0,
		Token:     -1,
		Result:    make([][]uint64, 0),
		NextCoord: nextCoord,
		MaskNext:  nextCoordFingerprint(sess.K_sig, nextCoord, req.RequestID),
	}
	resp.Signature = signRecompute(sess.K_sig, resp)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
	log.Printf("[tee] kv_reset session=%s model=%s", sess.ID[:8], modelID)
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
func newLayerStream(seed []byte, modulus uint64, domain []byte) (masklite.MaskStream, error) {
	if cryptoMaskPRG == "sm4" || cryptoMaskPRG == "bridge" {
		return mask.NewStreamWithProvider(cryptoProvider, seed, domain, modulus)
	}
	return mask.NewStreamDomain(seed, modulus, domain)
}

func toFloat64(v []uint64) []float64 {
	out := make([]float64, len(v))
	for i, x := range v {
		out[i] = float64(x)
	}
	return out
}

var errNoWeights = errors.New("recompute: 权重提供器未初始化")
