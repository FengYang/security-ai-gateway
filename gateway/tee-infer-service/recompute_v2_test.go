// recompute_v2_test.go - proto=2 状态机的验收用例（T03）
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/FengYang/masked-infer/core"
	"github.com/FengYang/masked-infer/demo"
	"github.com/FengYang/masked-infer/plan"
	"security-ai-gateway/gateway/tee-infer-service/route2step"
)

// route2MaskModulus 路线2 掩码模 R（M1 接线，技术方案 §7.7 定案）的测试侧别名。
//
// 权威定义已随步执行下沉到 route2step.Route2MaskModulus；宿主生产代码不再引用本名，
// 仅测试用它独立重算掩码流，以断言「客户端/服务端同模」（任一环节退回 Mod32 垫片即红）。
const route2MaskModulus = route2step.Route2MaskModulus

// ---- 测试台：驱动 step 机的最小客户端（含"不可信加速器"模拟）----

type v2Harness struct {
	t         *testing.T
	srv       *teeServer
	ts        *httptest.Server
	sessionID string
	kSig      []byte
	cfg       route2plan.ModelConfig
	weights   route2demo.ModelWeights
	plan      route2plan.Plan
	pos       int
	nextCoord string
	seed      []byte
	// injected 客户端注入行（block 0 的残差直通复用同一条掩码行）
	injected [][]uint64
}

func newV2Harness(t *testing.T) *v2Harness {
	t.Helper()
	srv, ts := newM9Server(t)
	sessionID, ksig, _ := setupTestSession(t, ts)
	cfg := route2plan.DemoTinyConfig()
	weights, err := route2demo.NewWeights(cfg)
	if err != nil {
		t.Fatalf("NewWeights: %v", err)
	}
	plan, err := route2plan.Build(cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	seedReq, _ := http.NewRequest("GET", "/", nil)
	seedReq.Header.Set("X-Session-ID", sessionID)
	seed, err := srv.sessionSeed(seedReq)
	if err != nil {
		t.Fatalf("sessionSeed: %v", err)
	}
	h := &v2Harness{
		t: t, srv: srv, ts: ts, sessionID: sessionID, kSig: ksig,
		cfg: cfg, weights: weights, plan: plan, pos: 0,
		nextCoord: plan[0].Coord.Wire(), seed: seed,
	}
	t.Cleanup(func() { wipe(seed) })
	return h
}

// state 取服务端侧状态（仅用于断言内部不变式）。
func (h *v2Harness) state() *recomputeState {
	return h.srv.recomputeStates.state(h.sessionID)
}

// mkReq 构造一个 proto=2 请求（不签名）。
func (h *v2Harness) mkReq(op string, seq int, coord string, batch [][]uint64) *recomputeRequest {
	return &recomputeRequest{
		Proto:     protoV2,
		RequestID: "v2-seq-" + itoa(seq) + "-" + op,
		ModelID:   route2plan.DemoModelID,
		Coord:     coord,
		Seq:       seq,
		Op:        op,
		NRows:     len(batch),
		Batch:     batch,
	}
}

// sign 就地签名（与 buildRecomputeReq 同款：HMAC-SHA256(K_sig, canonicalV2)）。
func (h *v2Harness) sign(req *recomputeRequest) {
	canonical := recomputeCanonicalV2(req)
	mac := hmac.New(sha256.New, h.KsigOrZero())
	mac.Write(canonical)
	req.Signature = hex.EncodeToString(mac.Sum(nil))
}

func (h *v2Harness) KsigOrZero() []byte { return h.kSig }

// post 发送已签名请求，返回原始响应与解析后的响应体。
func (h *v2Harness) post(req *recomputeRequest) (*http.Response, *recomputeResponse) {
	h.t.Helper()
	h.sign(req)
	body, _ := json.Marshal(req)
	hr, _ := http.NewRequest("POST", h.ts.URL+"/v1/recompute", bytes.NewReader(body))
	hr.Header.Set("X-Session-ID", h.sessionID)
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		h.t.Fatalf("recompute 请求: %v", err)
	}
	var rc recomputeResponse
	_ = json.NewDecoder(resp.Body).Decode(&rc)
	resp.Body.Close()
	return resp, &rc
}

// postRaw 发送「已签名但**不再重签**」的请求。
// 用于篡改后验签类用例：若经 post()，会就地重签导致篡改被覆盖，无法触发验签失败。
func (h *v2Harness) postRaw(req *recomputeRequest) (*http.Response, *recomputeResponse) {
	h.t.Helper()
	body, _ := json.Marshal(req)
	hr, _ := http.NewRequest("POST", h.ts.URL+"/v1/recompute", bytes.NewReader(body))
	hr.Header.Set("X-Session-ID", h.sessionID)
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		h.t.Fatalf("recompute 请求: %v", err)
	}
	var rc recomputeResponse
	_ = json.NewDecoder(resp.Body).Decode(&rc)
	resp.Body.Close()
	return resp, &rc
}

// step 按当前 pos 发一步，断言 200，并推进测试台的 pos / nextCoord。
func (h *v2Harness) step(batch [][]uint64) *recomputeResponse {
	h.t.Helper()
	spec, err := h.plan.At(h.pos)
	if err != nil {
		h.t.Fatalf("plan.At(%d): %v", h.pos, err)
	}
	req := h.mkReq(spec.Op, h.pos, h.nextCoord, batch)
	resp, rc := h.post(req)
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("seq=%d op=%s 应 200, got %d (body=%+v)", h.pos, spec.Op, resp.StatusCode, rc)
	}
	if rc.Seq != h.pos {
		h.t.Fatalf("响应 seq=%d want=%d", rc.Seq, h.pos)
	}
	h.pos++
	h.nextCoord = rc.NextCoord
	return rc
}

// offload 模拟不可信加速器的密态线性：y = W·V + b (mod R)。
func (h *v2Harness) offload(key route2plan.TensorKey, rows [][]uint64) [][]uint64 {
	h.t.Helper()
	m, err := h.weights.Matrix(key)
	if err != nil {
		h.t.Fatalf("Matrix(%s): %v", key.String(), err)
	}
	out, err := m.CipherLinear(rows)
	if err != nil {
		h.t.Fatalf("CipherLinear(%s): %v", key.String(), err)
	}
	return out
}

// inject 客户端注入：V = ToMaskDomain(x) + ρ_inj(Stage,Turn) （跨域①的唯一形态）。
func (h *v2Harness) inject(x []float64) []uint64 {
	h.t.Helper()
	return h.injectRows([][]float64{x})[0]
}

// injectRows 客户端注入的多行版本：同一源域的掩码流**逐步推进**（每行取一段），
// 与服务端逐行 nextMaskVec 的消费次序一致——行 j 的 ρ = 流第 j 段。
// 若误用 inject() 逐行独立取流的首段，多行会共用同一 ρ，服务端脱掩码即错位
// （不报错、数值全错）。
func (h *v2Harness) injectRows(xs [][]float64) [][]uint64 {
	h.t.Helper()
	m, err := h.weights.Matrix(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnQ})
	if err != nil {
		h.t.Fatalf("基准矩阵: %v", err)
	}
	domain, err := h.plan.SrcMaskDomain(0, 0)
	if err != nil {
		h.t.Fatalf("SrcMaskDomain(0,0): %v", err)
	}
	stream, err := newLayerStream(h.seed, route2MaskModulus, []byte(domain))
	if err != nil {
		h.t.Fatalf("注入掩码流: %v", err)
	}
	out := make([][]uint64, len(xs))
	for j, x := range xs {
		rho := make([]uint64, len(x))
		for i := range rho {
			rho[i] = stream.Next() % route2MaskModulus
		}
		xMask := m.ToMaskDomain(x)
		row := make([]uint64, len(x))
		for i := range row {
			row[i] = xMask[i] + rho[i] // uint64 自然回绕 = mod 2^64（Mod64）
		}
		out[j] = row
	}
	return out
}

// itoa 小工具（避免为每个调用点引 strconv）。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// srcRho 取 plan 第 seq 步第 row 行源域掩码流的首 n 个分量。
// 单位置步即完整消费段；多位置步只取首段（批量用例请用 injectRows 的推进式取法）。
func (h *v2Harness) srcRho(seq, row, n int) []uint64 {
	h.t.Helper()
	domain, err := h.plan.SrcMaskDomain(seq, row)
	if err != nil {
		h.t.Fatalf("SrcMaskDomain(%d,%d): %v", seq, row, err)
	}
	stream, err := newLayerStream(h.seed, route2MaskModulus, []byte(domain))
	if err != nil {
		h.t.Fatalf("掩码流派生(域=%s): %v", domain, err)
	}
	out := make([]uint64, n)
	for i := range out {
		out[i] = stream.Next() % route2MaskModulus
	}
	return out
}

// outRho 取 plan 第 seq 步产出域掩码流的首 n 个分量（服务端重掩码用的 ρ_out；
// 与 step_exec.go 的 outStream 派生同款）。
func (h *v2Harness) outRho(seq, n int) []uint64 {
	h.t.Helper()
	spec, err := h.plan.At(seq)
	if err != nil {
		h.t.Fatalf("plan.At(%d): %v", seq, err)
	}
	stream, err := newLayerStream(h.seed, route2MaskModulus, []byte(spec.MaskDomain()))
	if err != nil {
		h.t.Fatalf("输出掩码流派生(域=%s): %v", spec.MaskDomain(), err)
	}
	out := make([]uint64, n)
	for i := range out {
		out[i] = stream.Next() % route2MaskModulus
	}
	return out
}

// maskForStep 构造 plan 第 seq 步第 row 行的密态输入：
// V = ToMaskDomain(x) + ρ_src(seq,row)（uint64 自然回绕 = mod 2^64）。
// ToMaskDomain 的定点标度取服务端 refMatrix（block0 AttnQ）同款 InputScale——
// 该标度是全局常量，与具体权重矩阵无关。
func (h *v2Harness) maskForStep(seq, row int, x []float64) []uint64 {
	h.t.Helper()
	ref, err := h.weights.Matrix(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnQ})
	if err != nil {
		h.t.Fatalf("基准矩阵: %v", err)
	}
	rho := h.srcRho(seq, row, len(x))
	xMask := ref.ToMaskDomain(x)
	out := make([]uint64, len(x))
	for i := range out {
		out[i] = xMask[i] + rho[i]
	}
	return out
}

// ---- 版本门禁 ----

func TestProtoV2Gate(t *testing.T) {
	h := newV2Harness(t)
	// proto=1（缺 proto / coord）⇒ 400 + 独立审计码
	old := &recomputeRequest{RequestID: "v1-1", Op: "gelu", Batch: [][]uint64{{1, 2, 3, 4}}, MaskVersion: 0, Layer: 0}
	resp, _ := h.post(old)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("proto=1 应 400, got %d", resp.StatusCode)
	}
	// 缺 coord 但有 proto=2 ⇒ 同样 400（不落进 layer_mismatch）
	noCoord := h.mkReq(route2plan.OpRMSNorm, 0, "", [][]uint64{{1, 2}})
	resp2, _ := h.post(noCoord)
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺 coord 应 400, got %d", resp2.StatusCode)
	}
	// 审计码必须独立可区分（不与 recompute_layer_mismatch 混用）
	if auditRecomputeProtoV1Unsupported == "recompute_layer_mismatch" {
		t.Fatal("proto v1 审计码不得复用 layer_mismatch")
	}
}

// ---- canonical v2 与签名 ----

func TestCanonicalV2CoversCoordSeqModelID(t *testing.T) {
	h := newV2Harness(t)
	base := h.mkReq(route2plan.OpRMSNorm, 0, h.nextCoord, [][]uint64{{1, 2, 3, 4}})
	c0 := recomputeCanonicalV2(base)

	alt := *base
	// 注意：不能改 stage/turn 段造差异——plan[0] 是 prefill(Stage=1)/turn=0/block=0，
	// "v2|1|000000|0000|00|0|00" 恰是其真实 Wire，改了等于没改（该用例曾因此永败）。
	// 改 block 段（0000→0001）才是真差异。
	alt.Coord = "v2|1|000000|0001|00|0|00"
	if bytes.Equal(recomputeCanonicalV2(&alt), c0) {
		t.Fatal("coord 未进 canonical（可重绑定步骤）")
	}
	alt = *base
	alt.Seq = 7
	if bytes.Equal(recomputeCanonicalV2(&alt), c0) {
		t.Fatal("seq 未进 canonical（可重绑定轮次）")
	}
	alt = *base
	alt.ModelID = "other-model"
	if bytes.Equal(recomputeCanonicalV2(&alt), c0) {
		t.Fatal("model_id 未进 canonical（可重绑定模型/权重/模数）")
	}
	alt = *base
	alt.NRows = 99
	if bytes.Equal(recomputeCanonicalV2(&alt), c0) {
		t.Fatal("n_rows 未进 canonical")
	}
	alt = *base
	alt.Batch = [][]uint64{{9, 9, 9, 9}}
	if bytes.Equal(recomputeCanonicalV2(&alt), c0) {
		t.Fatal("batch 未进 canonical")
	}
}

func TestV2TamperedModelIDFailsSignature(t *testing.T) {
	h := newV2Harness(t)
	req := h.mkReq(route2plan.OpRMSNorm, 0, h.nextCoord, [][]uint64{{1, 2, 3, 4}})
	h.sign(req)          // 用 DemoModelID 签
	req.ModelID = "evil" // 传输途中改 model_id（下面用 postRaw，不再重签）
	resp, _ := h.postRaw(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("改 model_id 后应验签失败 401, got %d", resp.StatusCode)
	}
}

func TestV2ShapeMismatch(t *testing.T) {
	h := newV2Harness(t)
	req := h.mkReq(route2plan.OpRMSNorm, 0, h.nextCoord, [][]uint64{{1, 2, 3, 4}})
	req.NRows = 2 // 与 len(batch)=1 不符
	resp, _ := h.post(req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("n_rows≠len(batch) 应 400, got %d", resp.StatusCode)
	}
}

// ---- 步序 / 重放 ----

func TestV2CoordMismatchRejected(t *testing.T) {
	h := newV2Harness(t)
	req := h.mkReq(route2plan.OpRMSNorm, 0, "v2|1|000000|0003|00|0|00", [][]uint64{{1, 2, 3, 4}})
	resp, _ := h.post(req)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("coord 与 plan[0] 不符应 409, got %d", resp.StatusCode)
	}
}

func TestV2SeqReplayRejected(t *testing.T) {
	h := newV2Harness(t)
	x := make([]float64, h.cfg.Dim)
	for i := range x {
		x[i] = (float64(i) - float64(h.cfg.Dim)/2) * 0.05
	}
	v := h.inject(x)
	h.injected = [][]uint64{v}
	h.step([][]uint64{v}) // seq 0 成功，pos 推进到 1

	// (1) 同 request_id 重放 ⇒ 409 replay
	req := h.mkReq(route2plan.OpRMSNorm, 0, h.plan[0].Coord.Wire(), [][]uint64{v})
	resp, _ := h.post(req)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("同 request_id 重放应 409, got %d", resp.StatusCode)
	}
	// (2) 换 request_id 重试**同一个 seq** ⇒ 仍 409（§7.4.1 之 2：不得重复追加 KV）
	req2 := h.mkReq(route2plan.OpRMSNorm, 0, h.plan[0].Coord.Wire(), [][]uint64{v})
	req2.RequestID = "v2-seq-0-rmsnorm-retry"
	resp2, _ := h.post(req2)
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("换 request_id 重试同一步应 409, got %d", resp2.StatusCode)
	}
	// (3) 会话仍在（未被破坏）：seq=1 可正常推进
	if got := h.state().pos; got != 1 {
		t.Fatalf("服务端 pos=%d want=1", got)
	}
}

// ---- 端到端：block 0 的 0..6 步（含 kv_append 空返回 / gelu 权重通路）----

func TestV2Block0ChainAndKVAppendEmpty(t *testing.T) {
	h := newV2Harness(t)
	x := make([]float64, h.cfg.Dim)
	for i := range x {
		x[i] = (float64(i) - float64(h.cfg.Dim)/2) * 0.05
	}
	v0 := h.inject(x)

	// seq0 attn_norm
	vHN := h.step([][]uint64{v0})
	if len(vHN.Result) != 1 || len(vHN.Result[0]) != h.cfg.Dim {
		t.Fatalf("attn_norm 结果形状错误: %d x %d", len(vHN.Result), len(vHN.Result[0]))
	}
	// 加速器：QKV 投影
	q := h.offload(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnQ}, vHN.Result)
	k := h.offload(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnK}, vHN.Result)
	vv := h.offload(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnV}, vHN.Result)

	// seq1/seq2 kv_append_k/v：result 必须是**空**（§7.2）
	r1 := h.step(k)
	if len(r1.Result) != 0 {
		t.Fatalf("kv_append_k 应返回空 result, got %d 行", len(r1.Result))
	}
	r2 := h.step(vv)
	if len(r2.Result) != 0 {
		t.Fatalf("kv_append_v 应返回空 result, got %d 行", len(r2.Result))
	}
	// KV 已各追加 1 行
	st := h.state()
	rows, err := st.kv.Rows(0)
	if err != nil || rows != 1 {
		t.Fatalf("Rows(0)=(%d,%v) want=(1,nil)", rows, err)
	}

	// seq3 attention
	vAO := h.step(q)
	if len(vAO.Result) != 1 || len(vAO.Result[0]) != h.cfg.Dim {
		t.Fatalf("attention 结果形状错误: %d x %d", len(vAO.Result), len(vAO.Result[0]))
	}
	// 加速器：O 投影
	ao := h.offload(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnO}, vAO.Result)

	// seq4 attn_residual：两行扇入（Ao 经 Wo，h 为注入直通 ⇒ 掩码不同，逐行脱掩码）
	vH2 := h.step([][]uint64{ao[0], v0})
	if len(vH2.Result) != 1 || len(vH2.Result[0]) != h.cfg.Dim {
		t.Fatalf("attn_residual 结果形状错误: %d x %d", len(vH2.Result), len(vH2.Result[0]))
	}
	// seq5 ffn_norm
	vHN2 := h.step(vH2.Result)
	// 加速器：up 投影
	up := h.offload(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorFFNUp}, vHN2.Result)
	// seq6 ffn_up（gelu，走完整权重通路）
	vF1 := h.step(up)
	if len(vF1.Result) != 1 || len(vF1.Result[0]) != h.cfg.FFNDim {
		t.Fatalf("ffn_up 结果形状错误: %d x %d（want 1 x %d）",
			len(vF1.Result), len(vF1.Result[0]), h.cfg.FFNDim)
	}
}

// ---- prefill 批量：kv_append_k/v 各携 T 行（K-run / V-run；修复前真机 HTTP 500）----

// TestV2BatchPrefillKVRun 复现并钉住批量 prefill 的 KV 通路：一个 kv_append_k 步携带
// T 行 K 连续到达、随后 kv_append_v 步携 T 行 V 连续配对（plan step-major 的真实形态）。
// 旧 KVCache「逐行严格交替」语义下该序列在第 2 行 K 即报 ErrKVNotPaired（HTTP 500：
// "kv_append_k / kv_append_v 未成对"），导致 -prompt-len >1 的 prefill 整体不可用。
func TestV2BatchPrefillKVRun(t *testing.T) {
	h := newV2Harness(t)
	const T = 4

	xs := make([][]float64, T)
	for j := range xs {
		xs[j] = make([]float64, h.cfg.Dim)
		for i := range xs[j] {
			xs[j][i] = (float64(i) - float64(h.cfg.Dim)/2) * 0.05 * float64(j+1)
		}
	}
	batch := h.injectRows(xs)

	// seq0 attn_norm：T 行批量（掩码流按行推进，injectRows 已对齐服务端消费次序）
	vHN := h.step(batch)
	if len(vHN.Result) != T || len(vHN.Result[0]) != h.cfg.Dim {
		t.Fatalf("attn_norm 批量结果形状错误: %d x %d（want %d x %d）",
			len(vHN.Result), len(vHN.Result[0]), T, h.cfg.Dim)
	}

	// 加速器：K/V 投影（每行独立 CipherLinear）
	k := h.offload(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnK}, vHN.Result)
	vv := h.offload(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnV}, vHN.Result)
	if len(k) != T || len(vv) != T {
		t.Fatalf("K/V 投影行数 k=%d v=%d want=%d", len(k), len(vv), T)
	}

	// seq1/seq2 kv_append_k/v：各携 T 行（修复点：K-run / V-run 配对）
	r1 := h.step(k)
	if len(r1.Result) != 0 {
		t.Fatalf("kv_append_k 应返回空 result, got %d 行", len(r1.Result))
	}
	r2 := h.step(vv)
	if len(r2.Result) != 0 {
		t.Fatalf("kv_append_v 应返回空 result, got %d 行", len(r2.Result))
	}
	st := h.state()
	if rows, err := st.kv.Rows(0); err != nil || rows != T {
		t.Fatalf("Rows(0)=(%d,%v) want=(%d,nil)", rows, err, T)
	}
	if got := st.kv.Tokens(); got != T {
		t.Fatalf("Tokens=%d want=%d", got, T)
	}

	// seq3 attention：T 行批量（每行对其历史 [0..pos] 做因果注意力）
	q := h.offload(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnQ}, vHN.Result)
	vAO := h.step(q)
	if len(vAO.Result) != T || len(vAO.Result[0]) != h.cfg.Dim {
		t.Fatalf("attention 批量结果形状错误: %d x %d（want %d x %d）",
			len(vAO.Result), len(vAO.Result[0]), T, h.cfg.Dim)
	}
}

// ---- argmax 走 token 字段 ----

func TestV2ArgMaxUsesTokenField(t *testing.T) {
	h := newV2Harness(t)
	// 直接把状态推到本轮末步（argmax）：pos = len(plan)-1
	st := h.state()
	st.mu.Lock()
	if err := st.initLocked(route2plan.DemoModelID); err != nil {
		st.mu.Unlock()
		t.Fatalf("initLocked: %v", err)
	}
	if err := st.ensurePlanLocked(); err != nil {
		st.mu.Unlock()
		t.Fatalf("ensurePlanLocked: %v", err)
	}
	st.pos = len(st.plan) - 1
	st.mu.Unlock()

	spec := h.plan[len(h.plan)-1]
	if spec.Op != route2plan.OpArgMax {
		t.Fatalf("plan 末步应为 argmax, got %s", spec.Op)
	}
	// 构造 logits 掩码行：V = Wlm·(xMask + ρ_lnfinal)
	lm := route2plan.TensorKey{Block: h.cfg.Blocks, Tensor: route2plan.TensorLMHead}
	x := make([]float64, h.cfg.Dim)
	for i := range x {
		x[i] = 0.01 * float64(i+1)
	}
	ref, _ := h.weights.Matrix(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnQ})
	domain, err := h.plan.SrcMaskDomain(len(h.plan)-1, 0)
	if err != nil {
		t.Fatalf("SrcMaskDomain: %v", err)
	}
	stream, err := newLayerStream(h.seed, route2MaskModulus, []byte(domain))
	if err != nil {
		t.Fatalf("流: %v", err)
	}
	rho := make([]uint64, h.cfg.Dim)
	for i := range rho {
		rho[i] = stream.Next() % route2MaskModulus
	}
	xMask := ref.ToMaskDomain(x)
	in := make([]uint64, h.cfg.Dim)
	for i := range in {
		in[i] = xMask[i] + rho[i]
	}
	logits := h.offload(lm, [][]uint64{in})

	req := h.mkReq(route2plan.OpArgMax, len(h.plan)-1, spec.Coord.Wire(), logits)
	resp, rc := h.post(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("argmax 应 200, got %d", resp.StatusCode)
	}
	if rc.Token < 0 {
		t.Fatal("argmax 必须走 token 字段（不得挤在 result 里）")
	}
	if len(rc.Result) != 0 {
		t.Fatalf("argmax 的 result 应为空, got %d 行", len(rc.Result))
	}
	if rc.Token < 0 || rc.Token >= h.cfg.Vocab {
		t.Fatalf("token=%d 越界（Vocab=%d）", rc.Token, h.cfg.Vocab)
	}
	// 末步之后 next_coord 应为下一轮首步（decode turn=1）
	if rc.NextCoord == "" {
		t.Fatal("末步的 next_coord 应为下一轮首步坐标，不得为空")
	}
}

// ---- kv_reset ----

func TestV2KVResetClearsState(t *testing.T) {
	h := newV2Harness(t)
	x := make([]float64, h.cfg.Dim)
	for i := range x {
		x[i] = 0.02 * float64(i+1)
	}
	v0 := h.inject(x)
	h.step([][]uint64{v0})                                                                            // seq0
	h.step(h.offload(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnK}, [][]uint64{v0})) // seq1 K
	st := h.state()
	if n, _ := st.kv.Rows(0); n != 0 {
		t.Fatalf("kv_append_k 后 Rows(0)=%d want 0（V 未配对，半行不计数）", n)
	}
	req := h.mkReq(route2plan.OpKVReset, 0, h.nextCoord, nil)
	req.NRows = 0
	resp, _ := h.post(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("kv_reset 应 200, got %d", resp.StatusCode)
	}
	st.mu.Lock()
	pos, turn, stage := st.pos, st.turn, st.stage
	st.mu.Unlock()
	if pos != 0 || turn != 0 || stage != route2plan.StagePrefill {
		t.Fatalf("kv_reset 后 pos=%d turn=%d stage=%d want 0/0/prefill", pos, turn, uint8(stage))
	}
}

// ---- 会话清扫：KV 必须被逐元素清零并释放 ----

func TestV2SessionEvictReleasesKV(t *testing.T) {
	h := newV2Harness(t)
	x := make([]float64, h.cfg.Dim)
	for i := range x {
		x[i] = 0.03 * float64(i+1)
	}
	v0 := h.inject(x)
	vHN := h.step([][]uint64{v0})
	k := h.offload(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnK}, vHN.Result)
	vv := h.offload(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnV}, vHN.Result)
	h.step(k)
	h.step(vv)

	st := h.state()
	st.mu.Lock()
	kv := st.kv
	st.mu.Unlock()
	// 前置：清扫前 KV 确有内容（否则下面的 fail-closed 断言会被空 cache 蒙对）。
	if n, err := kv.Rows(0); err != nil || n == 0 {
		t.Fatalf("清扫前 KV 应有内容: rows=%d err=%v", n, err)
	}

	h.srv.recomputeStates.evict(h.sessionID)

	// (1) 清扫确实走了 Release 语义（而非只从 map 摘除）：读操作必须 fail-closed。
	//     「逐元素清零」由 route2step 包内的 TestKVCacheReleaseZeroesElementsAndFailClosed
	//     直接断言（行内存只有包内可见），本处不跨包窥探内部字段。
	if _, err := kv.ReadK(0); !errors.Is(err, route2step.ErrKVCacheReleased) {
		t.Fatalf("evict 后 ReadK 应报 ErrKVCacheReleased, got %v", err)
	}
	// (2) 已从 map 摘除，再次取到的是全新状态（KV 为 nil）
	if _, ok := h.srv.recomputeStates.byID[h.sessionID]; ok {
		t.Fatal("evict 后 recomputeStates 仍持有该会话")
	}
	// (3) 释放后的 KV 再调用写操作必须 fail-closed
	if err := kv.AppendK(0, make([]float64, h.cfg.AttnDim())); !errors.Is(err, route2step.ErrKVCacheReleased) {
		t.Fatalf("释放后 AppendK 应报 ErrKVCacheReleased, got %v", err)
	}
}

// ---- 掩码域归属：产出步 own 自己的域（写反只会"数值全错但全绿"）----

func TestV2OutputMaskDomainIsOwnStep(t *testing.T) {
	h := newV2Harness(t)
	spec := h.plan[0]
	want := spec.Coord.MaskDomain()
	if want != spec.MaskDomain() {
		t.Fatal("StepSpec.MaskDomain() 必须等于其自身坐标的域（产出步 own）")
	}
	// 与「下一层的域」必须不同（旧实现的错误约定）
	next := h.plan[1]
	if want == next.MaskDomain() {
		t.Fatal("相邻两步的掩码域不得相同（一步一掩码，绝不重用）")
	}
}

// ---- 并发：-race 下多会话并行推进 ----

func TestV2ConcurrentSessions(t *testing.T) {
	srv, ts := newM9Server(t)
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			sessionID, ksig, _ := setupTestSession(t, ts)
			cfg := route2plan.DemoTinyConfig()
			plan, _ := route2plan.Build(cfg)
			seedReq, _ := http.NewRequest("GET", "/", nil)
			seedReq.Header.Set("X-Session-ID", sessionID)
			seed, err := srv.sessionSeed(seedReq)
			if err != nil {
				done <- err
				return
			}
			defer wipe(seed)
			h := &v2Harness{t: t, srv: srv, ts: ts, sessionID: sessionID, kSig: ksig,
				cfg: cfg, plan: plan, nextCoord: plan[0].Coord.Wire(), seed: seed}
			w, werr := route2demo.NewWeights(cfg)
			if werr != nil {
				done <- werr
				return
			}
			h.weights = w
			x := make([]float64, cfg.Dim)
			for j := range x {
				x[j] = 0.01 * float64(j+i+1)
			}
			v := h.inject(x)
			req := h.mkReq(plan[0].Op, 0, plan[0].Coord.Wire(), [][]uint64{v})
			h.sign(req)
			body, _ := json.Marshal(req)
			hr, _ := http.NewRequest("POST", ts.URL+"/v1/recompute", bytes.NewReader(body))
			hr.Header.Set("X-Session-ID", sessionID)
			resp, err := http.DefaultClient.Do(hr)
			if err != nil {
				done <- err
				return
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				done <- errHTTPStatus{resp.StatusCode}
				return
			}
			done <- nil
		}(i)
	}
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatalf("并发会话 %d 失败: %v", i, err)
		}
	}
}

type errHTTPStatus struct{ code int }

func (e errHTTPStatus) Error() string { return "HTTP " + itoa(e.code) }

// ---- 量化矩阵必须是 Mod64（M1 接线未退化）----

func TestV2WeightsAreMod64(t *testing.T) {
	h := newV2Harness(t)
	m, err := h.weights.Matrix(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnQ})
	if err != nil {
		t.Fatalf("Matrix: %v", err)
	}
	if m.ModBits != maskedinfer.Mod64 {
		t.Fatalf("权重应为 Mod64, got %v", m.ModBits)
	}
}
