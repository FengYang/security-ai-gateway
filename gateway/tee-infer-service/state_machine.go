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
	"os"
	"sync"
	"time"

	"github.com/FengYang/masked-infer/adapters/qwen"
	"github.com/FengYang/masked-infer/demo"
	"github.com/FengYang/masked-infer/plan"
	"security-ai-gateway/gateway/tee-infer-service/route2step"
)

// protoV2 协议版本门禁常量。硬切换（设计 §2.5.2 方案 B）：proto≠2 一律拒绝。
const protoV2 = 2

// ---- 审计码（§7.3；新增码独立命名，不与既有 recompute_layer_mismatch 混淆）----
const (
	auditRecomputeProtoV1Unsupported = "recompute_proto_v1_unsupported"
	auditRecomputeModelMismatch      = "recompute_model_mismatch"
	auditRecomputeStepOutOfOrder     = "recompute_step_out_of_order"
	auditRecomputeStageMismatch      = "recompute_stage_mismatch"
	auditRecomputePlanBuildFailed    = "recompute_plan_build_failed"

	// 以下审计码与 route2step 同源，别名到该包以保证单一事实来源（掩码单步在本包外）。
	// 只有宿主**自己**仍会产出的码才留别名；其余（stream/mask_image/unmask/remask/norm/
	// attention/kv_full 等）由 route2step 内部产生并经 StepError.Audit 原值透传，
	// 宿主不再引用，故不在此重复声明（避免死代码）。
	auditRecomputeShapeMismatch    = route2step.AuditRecomputeShapeMismatch
	auditRecomputeUnknownOp        = route2step.AuditRecomputeUnknownOp
	auditRecomputeReplay           = route2step.AuditRecomputeReplay
	auditRecomputeWeightLoadFailed = route2step.AuditRecomputeWeightLoadFailed
	auditRecomputeKVFailed         = route2step.AuditRecomputeKVFailed
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
	MaskVersion int        `json:"mask_version"`    // 保留，不参与任何判定
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
	Token     int    `json:"token"`
	NextCoord string `json:"next_coord"`
	MaskNext  string `json:"mask_next"`
	Signature string `json:"signature"`
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
	kv      *route2step.KVCache

	// ---- 推进段 ----
	plan      route2plan.Plan
	stage     route2plan.Stage
	turn      uint32
	pos       int // 下一个期望的 plan 下标
	turnBase  int // 本轮开始时的 KV 行数（位置基准，服务端自持）
	lastReqID string
	lastUse   time.Time
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

// realQwenModelID 真实 Qwen3 模型的 model_id（生产链路目标，T4 接入）。
const realQwenModelID = "qwen3-0.6b"

// envRealQwenWeights 真实 Qwen3 权重的 safetensors 路径的**安装期**配置键。
//
// 按登记口径铁律：客户/部署环境才能定的取值一律做成「安装期可配置参数」，
// 未设置即 fail-closed（绝不静默回落 demo），提示运维在部署时按现场填好路径。
const envRealQwenWeights = "REAL_QWEN_WEIGHTS_PATH"

// qwenCacheEntry 缓存项同时保存 cfg 与 weights。
//
// ⚠ 必须**成对**缓存：cfg.ModelID 是在 resolveModel 里按请求填入的（ToModelConfig 不知晓
// 部署侧 model_id），若只缓存 weights 再在命中时调用 w.Config()，拿到的 cfg 的 ModelID 为空，
// 会被 route2plan.Validate 以「ModelID 不可为空」fail-closed 拒绝——症状是**首个会话正常、
// 从第二个会话起真实模型全部失败**。
type qwenCacheEntry struct {
	cfg route2plan.ModelConfig
	w   route2demo.ModelWeights
}

// qwenCache 按「路径 + 文件身份」缓存已加载的真实 Qwen 权重（进程内多会话共享，
// 避免重复加载 0.6B）。
//
// 键里带 size/mtime 而非仅 path：权重文件被替换后（换模型/换精度/热更新）必须重新加载，
// 否则会静默沿用旧权重产出错误回答且无任何一层报错（§2.2 G6 同类风险）。
var (
	qwenCacheMu sync.Mutex
	qwenCache   = map[string]qwenCacheEntry{} // path|size|mtime -> entry
)

// qwenCacheKey 由权重路径与文件身份（大小 + mtime）构造缓存键。
func qwenCacheKey(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("真实权重路径不可读（%s）: %w", envRealQwenWeights, err)
	}
	return fmt.Sprintf("%s|%d|%d", path, st.Size(), st.ModTime().UnixNano()), nil
}

// resolveModel 把 model_id 解析为 (cfg, weights)。
//
//   - demo（route2plan.DemoModelID）：确定性玩具权重，零 I/O；
//   - 真实 Qwen3（realQwenModelID）：从环境变量 REAL_QWEN_WEIGHTS_PATH 指向的 safetensors
//     加载并量化（缓存），未配置即 fail-closed；
//   - 未知 model_id 一律拒，而非回落默认配置——回落会让客户端以为换了模型其实没换。
func resolveModel(modelID string) (route2plan.ModelConfig, route2demo.ModelWeights, error) {
	switch modelID {
	case route2plan.DemoModelID:
		cfg := route2plan.DemoTinyConfig()
		w, err := route2demo.NewWeights(cfg)
		if err != nil {
			return route2plan.ModelConfig{}, nil, err
		}
		return cfg, w, nil
	case realQwenModelID:
		path := os.Getenv(envRealQwenWeights)
		if path == "" {
			return route2plan.ModelConfig{}, nil, fmt.Errorf(
				"model_id=%q 需要真实权重，但未设置安装期参数 %s（缺失即 fail-closed）", modelID, envRealQwenWeights)
		}
		key, err := qwenCacheKey(path)
		if err != nil {
			return route2plan.ModelConfig{}, nil, err
		}
		// 注：加载在锁内完成（0.6B 首次加载可达数秒），换取「同进程只加载一次」的简单正确性；
		// 当前 model_id 白名单仅两项，不存在高并发加载多种大权重而被此锁放大的场景。
		qwenCacheMu.Lock()
		defer qwenCacheMu.Unlock()
		if cached, ok := qwenCache[key]; ok {
			return cached.cfg, cached.w, nil
		}
		w, err := qwen.LoadWeights(path, qwen.Qwen3_06B())
		if err != nil {
			return route2plan.ModelConfig{}, nil, fmt.Errorf("加载真实 Qwen3 权重失败: %w", err)
		}
		cfg := w.Config()
		// model_id 是 ModelConfig 的标识字段（参与权重派生 key 与 Validate），
		// 由 resolveModel 在此据请求填入；ToModelConfig 自身不知晓部署侧 model_id。
		cfg.ModelID = modelID
		qwenCache[key] = qwenCacheEntry{cfg: cfg, w: w}
		return cfg, w, nil
	default:
		return route2plan.ModelConfig{}, nil, fmt.Errorf("未知 model_id %q（当前支持 %q / %q）",
			modelID, route2plan.DemoModelID, realQwenModelID)
	}
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
	cfg, weights, err := resolveModel(modelID)
	if err != nil {
		return newStepError(400, auditRecomputeModelMismatch, "model_id 解析失败: %v", err)
	}
	kv, err := route2step.NewKVCache(cfg)
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
		kind := route2step.BatchRowKind(arity, nPos, idx)
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
	ctx := &route2step.StepContext{
		Cfg:       st.cfg,
		Weights:   st.weights,
		Plan:      st.plan,
		Seq:       st.pos,
		Spec:      spec,
		Stage:     st.stage,
		Turn:      st.turn,
		TurnBase:  st.turnBase,
		KV:        st.kv,
		Seed:      seed,
		Batch:     req.Batch,
		NewStream: newLayerStream,
	}
	result, token, eerr := route2step.ExecStep(ctx)
	if eerr != nil {
		// 跨包边界：route2step.StepError → 宿主 stepError（同值转写，审计码单一来源）。
		return stepOutcome{err: &stepError{httpStatus: eerr.Status, auditCode: eerr.Audit, msg: eerr.Msg}}
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

// batch 行布局（line-major）与行类判定已迁至 route2step.BatchRowIndex/BatchRowKind。
