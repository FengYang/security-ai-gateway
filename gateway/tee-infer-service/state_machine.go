// state_machine.go - 路线2 proto=2 的服务端状态机（plan 驱动的 step 机）
//
// 【本文件是服务端权威】位置 pos / 轮次 turn / KV 长度一律服务端自持，客户端只能
// 请求 `plan[pos]`，且提交的 `coord` 必须与 `plan[pos].Coord` **逐字段相等**。
//
// 【锁序硬约束】teeServer.mu → recomputeStates.mu → recomputeState.mu → KVCache.mu。
// 本文件禁止反向取锁：runStep 内不回调 teeServer 的任何方法（含 sessionByID /
// sessionSeed / audit / metrics），seed 与 K_sig 一律由调用方在取 st.mu 之前备好传入。
//
// 【临界区纪律】st.mu 临界区内只做「状态推进校验 + 步执行」；所有 http.Error /
// 审计 / 遥测 / json.Encode 必须在释放 st.mu 之后由 handler 执行（否则与审计模块
// 内部的 session-map 取锁构成反转，见设计 §6.3 / §10 R7-R11）。
package main

import (
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"security-ai-gateway/gateway/teecore/route2demo"
	"security-ai-gateway/gateway/teecore/route2plan"
)

// protoV2 协议版本门禁常量。硬切换（设计 §2.5.2 方案 B）：proto≠2 一律拒绝。
const protoV2 = 2

// ---- 审计码（§7.3；新增码独立命名，不与既有 recompute_layer_mismatch 混淆）----
const (
	auditRecomputeProtoV1Unsupported = "recompute_proto_v1_unsupported"
	auditRecomputeModelMismatch      = "recompute_model_mismatch"
	auditRecomputeShapeMismatch      = "recompute_shape_mismatch"
	auditRecomputeUnknownOp          = "recompute_unknown_op"
	auditRecomputeStepOutOfOrder     = "recompute_step_out_of_order"
	auditRecomputeStageMismatch      = "recompute_stage_mismatch"
	auditRecomputeReplay             = "recompute_replay"
	auditKVCacheFull                 = "kv_cache_full"
	auditRecomputeStreamFailed       = "recompute_stream_failed"
	auditRecomputeWeightLoadFailed   = "recompute_weight_load_failed"
	auditRecomputeMaskImageFailed    = "recompute_mask_image_failed"
	auditRecomputeUnmaskFailed       = "recompute_unmask_failed"
	auditRecomputeRemaskFailed       = "recompute_remask_failed"
	auditRecomputeNormFailed         = "recompute_norm_failed"
	auditRecomputeAttentionFailed    = "recompute_attention_failed"
	auditRecomputePlanBuildFailed    = "recompute_plan_build_failed"
	auditRecomputeKVFailed           = "recompute_kv_failed"
)

// recomputeRequest proto=2 请求（设计 §7.1）。
//
// `layer` 与 `mask_version` **保留字段但一律不再信任**：proto=1 的层序语义已废
// （MLP 第 L 层 ≠ Transformer 第 b 块第 s 步），任何基于它们的判定都会把"老客户端
// 层序校验通过但权重/掩码彻底错配"这种最坏失败模式放过去。
type recomputeRequest struct {
	Proto       int        `json:"proto"`
	RequestID   string     `json:"request_id"`
	ModelID     string     `json:"model_id"`
	Coord       string     `json:"coord"`
	Seq         int        `json:"seq"`
	Op          string     `json:"op"`
	NRows       int        `json:"n_rows"`
	Batch       [][]uint64 `json:"batch"`
	MaskVersion int        `json:"mask_version"` // 保留，不参与任何判定
	Layer       int        `json:"layer,omitempty"` // 保留，不参与任何判定
	Gamma       []float64  `json:"gamma,omitempty"`
	Beta        []float64  `json:"beta,omitempty"`
	Signature   string     `json:"signature"`
}

// recomputeResponse proto=2 响应（设计 §7.2）。
type recomputeResponse struct {
	RequestID string     `json:"request_id"`
	Seq       int        `json:"seq"`
	Result    [][]uint64 `json:"result"`
	// Token 采样明文 token（G11 形态歧义修复）。字段恒存在：argmax 步骤为真实 token，
	// 非 argmax 步骤取哨兵 -1（§7.2.1：不得因"有时有 token 有时没有"产生可预测的段数差异）。
	// response signature 覆盖 request_id|next_coord|seq|token|result（§7.2.1 补齐）。
	Token     int        `json:"token"`
	NextCoord string     `json:"next_coord"`
	MaskNext  string     `json:"mask_next"`
	Signature string     `json:"signature"`
}

// stepError 一步的失败结果：**只描述如何向调用方交代**，不含任何 IO 动作。
// 由 handler 在释放 st.mu 之后按 (httpStatus, auditCode) 写 HTTP 与审计。
type stepError struct {
	httpStatus int
	auditCode  string
	msg        string
}

func (e *stepError) Error() string { return e.msg }

func newStepError(status int, audit, format string, args ...interface{}) *stepError {
	return &stepError{httpStatus: status, auditCode: audit, msg: fmt.Sprintf(format, args...)}
}

// stepOutcome 一步的执行结果（出锁后由 handler 消费）。
type stepOutcome struct {
	seq       int
	nextCoord string
	result    [][]uint64
	token     int // 非 argmax 步骤为哨兵 -1；argmax 覆盖为真实 token
	err       *stepError
}

// ---- 会话状态（设计 §2.4.4）----

// recomputeState 每会话的 step 机状态。
//
// 替换（而非并存）旧的 lastLayer/hasHistory：两套层序双轨会立刻产生"各自为政"的
// 分歧窗口。KV 与权重随会话共生共灭。
type recomputeState struct {
	mu sync.Mutex

	// ---- 冻结段（首次请求后不变）----
	modelID string
	cfg     route2plan.ModelConfig
	weights route2demo.ModelWeights
	kv      *KVCache

	// ---- 推进段 ----
	plan     route2plan.Plan
	stage    route2plan.Stage
	turn     uint32
	pos      int  // 下一个期望的 plan 下标
	turnBase int  // 本轮开始时的 KV 行数（位置基准，服务端自持）
	lastReqID string
	lastUse  time.Time
}

type recomputeStates struct {
	mu   sync.Mutex
	byID map[string]*recomputeState
}

func newRecomputeStates() *recomputeStates {
	return &recomputeStates{byID: make(map[string]*recomputeState)}
}

// state 获取或创建会话的 step 机状态（取 rs.mu，返回时已释放）。
func (rs *recomputeStates) state(sessionID string) *recomputeState {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	st, ok := rs.byID[sessionID]
	if !ok {
		st = &recomputeState{stage: route2plan.StagePrefill}
		rs.byID[sessionID] = st
	}
	return st
}

// evict 清扫会话：rs.mu → st.mu → kv.Release() → delete(rs.byID, id)。
//
// 挂点在 sessionCleanup（main.go），紧随 delete(s.sessions, id) 之后。
// 锁序与 §6.2 一致（s.mu 已在调用方持有）：s.mu → rs.mu → st.mu → kv.mu，无反转。
func (rs *recomputeStates) evict(sessionID string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	st, ok := rs.byID[sessionID]
	if !ok {
		return
	}
	st.mu.Lock()
	if st.kv != nil {
		st.kv.Release() // 逐元素清零 → 释放（安全性质，不是内存优化）
		st.kv = nil
	}
	st.plan = nil
	st.pos = 0
	st.turn = 0
	st.stage = route2plan.StagePrefill
	st.turnBase = 0
	st.lastReqID = ""
	st.mu.Unlock()
	delete(rs.byID, sessionID)
}

// ---- 模型解析 ----

// resolveModelConfig 把 model_id 解析为模型配置。
//
// 目前 demo 只认 route2plan.DemoModelID（唯一常量源）；未知 model_id 一律拒，
// 而不是回落到某个"默认配置"——回落会让客户端以为换了模型其实没换。
func resolveModelConfig(modelID string) (route2plan.ModelConfig, error) {
	if modelID == route2plan.DemoModelID {
		return route2plan.DemoTinyConfig(), nil
	}
	return route2plan.ModelConfig{}, fmt.Errorf("未知 model_id %q（当前仅支持 %q）",
		modelID, route2plan.DemoModelID)
}

// ---- canonical v2 与签名 ----

// recomputeCanonicalV2 签名规范串（设计 §2.5.3）：
//
//	proto|request_id|coord_wire|seq|model_id|op|n_rows + json(batch)   再 Hash
//
// coord/seq/model_id 进签名 ⇒ 攻击者不可重绑定步骤/轮次/模型（模型决定权重与模数，
// 属"意图"的一部分）。
func recomputeCanonicalV2(req *recomputeRequest) []byte {
	var buf []byte
	buf = append(buf, []byte(fmt.Sprintf("%d|%s|%s|%d|%s|%s|%d",
		req.Proto, req.RequestID, req.Coord, req.Seq, req.ModelID, req.Op, req.NRows))...)
	batchJSON, _ := json.Marshal(req.Batch)
	buf = append(buf, batchJSON...)
	return cryptoProvider.Hash(buf)
}

func verifyRecomputeSig(kSig []byte, req *recomputeRequest) bool {
	got, err := hex.DecodeString(req.Signature)
	if err != nil {
		return false
	}
	want := cryptoProvider.HMAC(kSig, recomputeCanonicalV2(req))
	return hmac.Equal(got, want)
}

// signRecompute 响应签名（§7.2.1：覆盖 request_id|next_coord|seq|token|result，再 Hash 后 HMAC）。
// token 在非 argmax 步骤恒为哨兵 -1（字段恒存在）；result 即使为空也参与运算（恒定形态，恒为 []）。
func signRecompute(kSig []byte, resp *recomputeResponse) string {
	var buf []byte
	buf = append(buf, []byte(fmt.Sprintf("%s|%s|%d|%d",
		resp.RequestID, resp.NextCoord, resp.Seq, resp.Token))...)
	resultJSON, _ := json.Marshal(resp.Result)
	buf = append(buf, resultJSON...)
	sum := cryptoProvider.HMAC(kSig, cryptoProvider.Hash(buf))
	return hex.EncodeToString(sum)
}

// nextCoordFingerprint mask_next 的新语义（§2.5.4）：下一步坐标的指纹
//
//	HMAC(K_sig, next_coord|request_id)
//
// 使客户端可校验服务端对"下一步做什么"的承诺。纯函数，不加锁。
func nextCoordFingerprint(kSig []byte, nextCoord, requestID string) string {
	sum := cryptoProvider.HMAC(kSig, []byte(nextCoord+"|"+requestID))
	return hex.EncodeToString(sum)
}

// ---- 状态推进 ----

// initLocked 首次请求时冻结 model_id / cfg / 权重 / KV。调用方须持 st.mu。
func (st *recomputeState) initLocked(modelID string) *stepError {
	if st.modelID != "" {
		if modelID != st.modelID {
			return newStepError(400, auditRecomputeModelMismatch,
				"model_id 与冻结值不符（冻结=%q 收到=%q）", st.modelID, modelID)
		}
		return nil
	}
	cfg, err := resolveModelConfig(modelID)
	if err != nil {
		return newStepError(400, auditRecomputeModelMismatch, "model_id 非法: %v", err)
	}
	weights, err := route2demo.NewWeights(cfg)
	if err != nil {
		return newStepError(500, auditRecomputeWeightLoadFailed, "权重提供者构造失败: %v", err)
	}
	kv, err := NewKVCache(cfg)
	if err != nil {
		return newStepError(500, auditRecomputeKVFailed, "KV cache 构造失败: %v", err)
	}
	st.modelID = modelID
	st.cfg = cfg
	st.weights = weights
	st.kv = kv
	st.stage = route2plan.StagePrefill
	st.turn = 0
	st.pos = 0
	st.plan = nil
	st.turnBase = 0
	return nil
}

// ensurePlanLocked 保证 plan 存在且 pos 落在范围内；必要时推进轮次并重建 plan。
// 调用方须持 st.mu。plan 由 (Stage,Turn) 纯函数重建（设计 §2.4.2：单份 plan 只表达一轮）。
func (st *recomputeState) ensurePlanLocked() *stepError {
	if st.plan != nil && st.pos < len(st.plan) {
		return nil
	}
	if st.plan != nil {
		// 上一轮走完：prefill → decode(turn=1)；decode → turn+1。
		if st.stage == route2plan.StagePrefill {
			st.stage = route2plan.StageDecode
			st.turn = 1
		} else {
			if st.turn >= route2plan.MaxTurn {
				return newStepError(409, auditRecomputeStepOutOfOrder,
					"turn=%d 已达定宽上限 %d，无法继续推进", st.turn, route2plan.MaxTurn)
			}
			st.turn++
		}
	}
	plan, err := route2plan.BuildTurn(st.cfg, st.stage, st.turn)
	if err != nil {
		return newStepError(500, auditRecomputePlanBuildFailed,
			"plan 重建失败(stage=%d turn=%d): %v", uint8(st.stage), st.turn, err)
	}
	st.plan = plan
	st.pos = 0
	st.turnBase = st.kv.Tokens() // 位置基准服务端自持，客户端不得提交
	return nil
}

// checkStepLocked 状态推进校验（不含任何 IO）。调用方须持 st.mu。
func (st *recomputeState) checkStepLocked(req *recomputeRequest) (route2plan.StepSpec, *stepError) {
	if err := st.initLocked(req.ModelID); err != nil {
		return route2plan.StepSpec{}, err
	}
	// 重放：同一会话内 request_id 重复一律拒（不限 seq，§7.4.1 服务端三条之 1）。
	if req.RequestID != "" && req.RequestID == st.lastReqID {
		return route2plan.StepSpec{}, newStepError(409, auditRecomputeReplay,
			"request_id %q 已出现过（重放）", req.RequestID)
	}
	// op 白名单（含带外 op kv_reset；kv_reset 不在此处处理，已在 handler 分流）。
	if !route2plan.ValidOp(req.Op) && req.Op != route2plan.OpKVReset {
		return route2plan.StepSpec{}, newStepError(400, auditRecomputeUnknownOp,
			"未知算子 %q", req.Op)
	}
	if err := st.ensurePlanLocked(); err != nil {
		return route2plan.StepSpec{}, err
	}
	// seq 必须等于服务端自持的 pos（跳步/重排/已推进 seq 的重来一律拒）。
	if req.Seq != st.pos {
		return route2plan.StepSpec{}, newStepError(409, auditRecomputeStepOutOfOrder,
			"seq=%d != 服务端 pos=%d（乱序或该 seq 已被推进过）", req.Seq, st.pos)
	}
	spec, err := st.plan.At(st.pos)
	if err != nil {
		return route2plan.StepSpec{}, newStepError(500, auditRecomputePlanBuildFailed,
			"plan[%d] 取步失败: %v", st.pos, err)
	}
	// coord 必须与 plan[pos].Coord **逐字段相等**（ParseWire 已做格式/取值域双校验）。
	coord, cerr := route2plan.ParseWire(req.Coord)
	if cerr != nil {
		return route2plan.StepSpec{}, newStepError(409, auditRecomputeStepOutOfOrder,
			"coord %q 非法: %v", req.Coord, cerr)
	}
	if coord != spec.Coord {
		// 阶段/轮次不符单独成码（§2.5.4），其余按 step_out_of_order。
		if coord.Stage != spec.Coord.Stage || coord.Turn != spec.Coord.Turn {
			return route2plan.StepSpec{}, newStepError(409, auditRecomputeStageMismatch,
				"coord 阶段/轮次不符（收到 stage=%d turn=%d，期望 stage=%d turn=%d）",
				uint8(coord.Stage), coord.Turn, uint8(spec.Coord.Stage), spec.Coord.Turn)
		}
		return route2plan.StepSpec{}, newStepError(409, auditRecomputeStepOutOfOrder,
			"coord %q != plan[%d].Coord %q", req.Coord, st.pos, spec.Coord.Wire())
	}
	if req.Op != spec.Op {
		return route2plan.StepSpec{}, newStepError(409, auditRecomputeStepOutOfOrder,
			"op %q != plan[%d].Op %q", req.Op, st.pos, spec.Op)
	}
	// 形状：n_rows 与 batch 行数必须相等（防 JSON 层歧义），且按 arity 对齐。
	if req.NRows != len(req.Batch) {
		return route2plan.StepSpec{}, newStepError(400, auditRecomputeShapeMismatch,
			"n_rows=%d != len(batch)=%d", req.NRows, len(req.Batch))
	}
	arity := len(spec.InSrc)
	if arity <= 0 || len(req.Batch) == 0 || len(req.Batch)%arity != 0 {
		return route2plan.StepSpec{}, newStepError(400, auditRecomputeShapeMismatch,
			"batch 行数 %d 不是 arity=%d 的整数倍", len(req.Batch), arity)
	}
	nPos := len(req.Batch) / arity
	for idx, row := range req.Batch {
		kind := batchRowKind(arity, nPos, idx)
		want := spec.InDim[kind]
		if len(row) != want {
			return route2plan.StepSpec{}, newStepError(400, auditRecomputeShapeMismatch,
				"batch[%d] 维度 %d != plan[%d].InDim[%d]=%d", idx, len(row), st.pos, kind, want)
		}
	}
	return spec, nil
}

// nextCoordLocked 本步之后的下一步坐标（纯函数，不加锁依赖）。调用方须持 st.mu。
// 已到本轮末步时返回**下一轮首步**的坐标，便于客户端连续推进；轮次越界返回空串。
func (st *recomputeState) nextCoordLocked() string {
	if st.pos < len(st.plan) {
		return st.plan[st.pos].Coord.Wire()
	}
	stage, turn := st.stage, st.turn
	if stage == route2plan.StagePrefill {
		stage, turn = route2plan.StageDecode, 1
	} else {
		if turn >= route2plan.MaxTurn {
			return ""
		}
		turn++
	}
	next, err := route2plan.BuildTurn(st.cfg, stage, turn)
	if err != nil || len(next) == 0 {
		return ""
	}
	return next[0].Coord.Wire()
}

// runStep 一次 recompute 步：状态推进校验 + 步执行，全程在 st.mu 内，
// **不做任何 IO / 审计 / 遥测**。返回 outcome 供 handler 出锁后写响应。
//
// 之所以把「执行」也放进临界区：seq 一旦推进就必须保证本步的 KV 写入已落地，
// 否则下一个 seq 的并发请求会让 K/V 交错追加（静默污染注意力分布，§7.4.1）。
func (st *recomputeState) runStep(req *recomputeRequest, seed []byte) stepOutcome {
	st.mu.Lock()
	defer st.mu.Unlock()

	spec, serr := st.checkStepLocked(req)
	if serr != nil {
		return stepOutcome{err: serr}
	}
	ctx := &stepContext{
		cfg:      st.cfg,
		weights:  st.weights,
		plan:     st.plan,
		seq:      st.pos,
		spec:     spec,
		stage:    st.stage,
		turn:     st.turn,
		turnBase: st.turnBase,
		kv:       st.kv,
		seed:     seed,
		batch:    req.Batch,
	}
	result, token, eerr := execStep(ctx)
	if eerr != nil {
		return stepOutcome{err: eerr}
	}
	// 推进：pos++ 且记录 request_id（重放判重键）。
	st.pos++
	st.lastReqID = req.RequestID
	st.lastUse = time.Now()
	return stepOutcome{seq: req.Seq, nextCoord: st.nextCoordLocked(), result: result, token: token}
}

// resetSession 带外 op kv_reset（设计 §7.4.2 ①）：KV 清零、pos 归零、turn 归零、
// stage 回到 prefill。调用方须**不**持 st.mu（本方法自取）。
func (st *recomputeState) resetSession(reqID string) (modelID string, cfg route2plan.ModelConfig, ok bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.kv != nil {
		st.kv.Reset() // 逐元素清零后复用（安全性质）
	}
	st.pos = 0
	st.turn = 0
	st.stage = route2plan.StagePrefill
	st.plan = nil
	st.turnBase = 0
	st.lastReqID = reqID
	st.lastUse = time.Now()
	return st.modelID, st.cfg, st.modelID != ""
}

// ---- batch 行序（设计 §7.1.1 / D16 联合裁定：line-major，非待定项）----
//
// batch 承载 arity × T 行：arity 来自 StepSpec 的输入行数（residual_add 为 2，
// 其余为 1），T 为位置数。布局**必须为 line-major**（设计 §7.1.1 已裁定）：
//
//	batch[ line*T + pos ]   // 第 line 条输入行、第 pos 个位置
//
// 客户端 cmd/route2-client/main.go 的 batchLayout="line-major" 与本常量必须同款；
// 二者不一致时 residual_add 会把「不同位置的行」加在一起——不报错、数值全错
// （与 §2.5.1 规则 4 同族静默失败）。false ⇒ line-major（见下方两个函数），true ⇒ 交错式。
const batchRowOrderPosMajor = false // false ⇒ line-major（batch[line*T+pos]），与客户端/设计稿一致

// batchRowIndex 位置 j、行类 r 在 batch 中的下标。
func batchRowIndex(arity, nPos, posIdx, rowIdx int) int {
	if batchRowOrderPosMajor {
		return posIdx*arity + rowIdx
	}
	return rowIdx*nPos + posIdx
}

// batchRowKind batch 下标 idx 所属的行类（形状校验用）。
func batchRowKind(arity, nPos, idx int) int {
	if arity <= 0 {
		return 0
	}
	if batchRowOrderPosMajor {
		return idx % arity
	}
	if nPos <= 0 {
		return 0
	}
	return idx / nPos
}
