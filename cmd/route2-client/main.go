// cmd/route2-client —— 路线2（掩码像推理）端到端客户端编排器。
//
// 两条路径并存：
//
//	① 旧 MLP 路径（-dim/-layers/-input，proto=v1 canonical）：保留既有语义，不做改动；
//	② plan 驱动路径（-model/-prompt-len/-gen，proto=2）：T04 新增，按 route2plan.Build(cfg)
//	   生成的 plan 逐步编排 prefill 与 decode，字段与 canonical 严格照设计 §7。
//
// ============================ plan 驱动路径的可信边界（必读） ============================
//
// 客户端只做三件事，且**只接触掩码态**：
//  1. 第 0 步注入：`V₀ = ToMaskDomain(嵌入) + ρ_inj(Stage,Turn)`（ρ 由会话密钥 + 坐标域派生）；
//  2. 线性搬运：按 `StepSpec.InWeight` 指定的权重，在不可信加速器（或 CPU 回退内核）上算
//     `W·V (mod R)`，产出的仍是掩码态，客户端自己**看不到任何明文激活**；
//  3. 把掩码态行送 `/v1/recompute`，由可信域做 `Unmask → Decode → 算子 → Remask`。
//
// 客户端**不得**提交任何解释性状态（`pos` / `mask_seed` / `cache_len` 一律服务端自持），
// 只能请求 `plan[pos]`（设计 §2.5.1 规则 3）。
//
// ============================ 恢复规程 R-RECOVER（§7.4.2，正常控制流） ============================
//
// 任一步遇到非 2xx 或网络错误时，**不得原地重试**（包括"换 request_id 重试同一步"）：
// 客户端无法区分"请求被丢弃（step 未执行）"与"请求被拒绝（step 已执行）"，
// 而前者的安全恢复路径恰好会把后者的 K/V **静默加倍**。既然不可区分，
// 唯一安全的选择就是无条件走"重置 + 从完整 prefill 重放"：
//
//	① op=kv_reset（同会话：KV 清零、pos 归零、turn 归零）⇒ 重新 prefill；
//	② 新建会话（重新 attest/ECDH/complete）⇒ 重新 prefill。
//
// 本文件把该分支实现为 `recoverOnce` 的正常控制流（不是 catch 里的补丁），
// 400 类调用方缺陷**不允许运行时恢复**，直接失败。
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/FengYang/masked-infer/core"
	"github.com/FengYang/masked-infer/demo"
	"github.com/FengYang/masked-infer/masklite"
	"github.com/FengYang/masked-infer/plan"
	"github.com/FengYang/masked-infer/ref"
	"security-ai-gateway/gateway/cryptop"
)

const (
	route2MaskModulus uint64 = ^uint64(0) // 2^64-1（与 recompute.go route2MaskModulus 一致）
	sessionInfo              = "otpmask/session/v1"
	sigInfo                  = "otpmask/kdf/sig/v1"
	encInfo                  = "otpmask/kdf/enc/v1"
	seedInfo                 = "otpmask/recompute-seed/v1"

	// protoV2 协议版本常量；服务端缺 coord 或 proto≠2 ⇒ recompute_proto_v1_unsupported。
	protoV2 = 2

	// maxRecovery R-RECOVER 的最大恢复次数（防止会话被反复重置而掩盖真正的缺陷）。
	maxRecovery = 2

	// maxRespBytes /v1/recompute 响应体的读取上限（8 MiB）。
	// 取 8 MiB 与 KV 字节硬顶同量级，既够用又能挡住畸形超大响应。
	maxRespBytes = 8 << 20
)

// batchLayout 扇入步（residual_add，len(InSrc)==2）的 batch 行布局。
//
// 【PROVISIONAL · 待裁定，见 T04 回报第 1 条】§7.1 写「行=位置维」、D16 写「batch 维度仅
// 承载位置」，但 §2.4.2/§3.2 要求扇入步一次送两条输入行，而 §7.3 又要求
// `n_rows == len(batch)` —— 三者在扇入步上无法同时成立。
// 本实现采用：**总行数 = 位置数 × 输入行数**，按「输入行优先（line-major）」排布：
//
//	rows[ line*nPos + pos ]
//
// 该决策**只落在这一个常量与 encodeBatch 一个函数里**，裁定变更时改一处即可。
const batchLayout = "line-major"

type proofWire struct {
	Nonce        string            `json:"nonce"`
	Platform     string            `json:"platform"`
	ReportData   string            `json:"report_data"`
	Measurements map[string]string `json:"measurements"`
	SigningKey   string            `json:"signing_key"`
	Signature    string            `json:"signature"`
}

type attestResp struct {
	Status    string    `json:"status"`
	Protocol  string    `json:"protocol"`
	SessionID string    `json:"session_id"`
	ServerPub string    `json:"server_pub"`
	Proof     proofWire `json:"proof"`
}

// ---------- proto=1（旧 MLP 路径）报文 ----------

type recomputeReq struct {
	RequestID   string     `json:"request_id"`
	Layer       int        `json:"layer"`
	Op          string     `json:"op"`
	Batch       [][]uint64 `json:"batch"`
	MaskVersion int        `json:"mask_version"`
	Signature   string     `json:"signature"`
}

type recomputeResp struct {
	RequestID string     `json:"request_id"`
	Result    [][]uint64 `json:"result"`
	MaskNext  string     `json:"mask_next"`
	Signature string     `json:"signature"`
}

// ---------- proto=2（plan 驱动路径）报文：字段名严格照设计 §7.1 / §7.2 ----------

type v2Request struct {
	RequestID string     `json:"request_id"`
	Proto     int        `json:"proto"`
	ModelID   string     `json:"model_id"`
	Coord     string     `json:"coord"`
	Seq       int        `json:"seq"`
	Op        string     `json:"op"`
	Batch     [][]uint64 `json:"batch"`
	NRows     int        `json:"n_rows"`
	// MaskVersion 旧字段，**保留但不再信任**：不参与任何判定（§7.1）。
	MaskVersion int `json:"mask_version"`
	// Gamma 仅 norm 类 op 携带（RMSNorm 无 beta，故不发送 beta）。
	Gamma []float64 `json:"gamma,omitempty"`
	// Beta 占位：设计 §7.1 列出该字段，但 vLLM RMSNorm 无 beta，恒不发送。
	Beta      []float64 `json:"beta,omitempty"`
	Signature string    `json:"signature"`
}

type v2Response struct {
	RequestID string     `json:"request_id"`
	Seq       int        `json:"seq"`
	Result    [][]uint64 `json:"result"`
	Token     int        `json:"token"`
	NextCoord string     `json:"next_coord"`
	MaskNext  string     `json:"mask_next"`
	Signature string     `json:"signature"`
}

type client struct {
	base      string
	http      *http.Client
	p         cryptop.Provider
	accelHint string // M5-2 请求级加速后端 hint（空=池默认；非法值由 masked-infer 拒绝并回退 CPU）
}

// session 一次 attest/ECDH/complete 之后得到的会话态。
type session struct {
	id        string
	ksig      []byte
	kenc      []byte
	seed      []byte
	serial    uint64 // 会话内 request_id 单调序号（判重键，绝不复用）
	sessionNo int    // 第几次建会话（仅用于日志）
}

func main() {
	server := flag.String("server", "http://127.0.0.1:19090", "tee-infer-service 基地址")
	dim := flag.Int("dim", route2demo.DefaultDim, "向量维度（旧 MLP 路径；须与服务端一致，默认 32）")
	layers := flag.Int("layers", 4, "层数：前 layers-1 层 gelu，末层 argmax（旧 MLP 路径）")
	input := flag.String("input", "", "输入向量（逗号分隔浮点）；空=确定性 ramp（旧 MLP 路径）")
	model := flag.String("model", route2plan.DemoModelID, "模型 ID（plan 驱动路径）")
	promptLen := flag.Int("prompt-len", 0, "prompt token 数；>0 时走 plan 驱动的 prefill/decode 路径")
	gen := flag.Int("gen", 0, "生成 token 数（配合 -prompt-len；<=0 视为 1）")
	selftest := flag.Bool("selftest", false, "本地直跑 route2ref 双基线（不连服务端）并打印对比报告")
	accelHint := flag.String("accel-hint", "", "M5-2 请求级加速后端 hint（须为 ACCEL_BACKEND_LIB 候选列表内的受信路径；空=池默认）")
	flag.Parse()

	p, err := cryptop.New(cryptop.ProfileIntl)
	if err != nil {
		log.Fatalf("[route2-client] 初始化 cryptop(intl) 失败: %v", err)
	}
	c := &client{base: strings.TrimRight(*server, "/"), http: &http.Client{Timeout: 30 * time.Second}, p: p, accelHint: strings.TrimSpace(*accelHint)}

	// --selftest：完全本地，直连 route2ref.Selftest，不发起任何网络请求。
	if *selftest {
		cfg, cerr := modelConfigByID(*model)
		if cerr != nil {
			log.Fatalf("[route2-client] selftest: %v", cerr)
		}
		n := *promptLen
		if n <= 0 {
			n = 8
		}
		toks := demoPrompt(cfg, n)
		rep, rerr := route2ref.Selftest(cfg, toks)
		if rerr != nil {
			log.Fatalf("[route2-client] selftest 失败: %v", rerr)
		}
		fmt.Printf("[route2-client] selftest: model=%s tokens=%d steps=%d logits=%d\n",
			cfg.ModelID, len(toks), rep.Steps, rep.Logits)
		fmt.Printf("[route2-client] selftest: atol=%g rtol=%g MaxAbsDiff=%.6g MaxRelDiff=%.4g top1一致=%d/%d\n",
			rep.Atol, rep.Rtol, rep.MaxAbsDiff, rep.MaxRelDiff, rep.Top1Agree, rep.Steps)
		fmt.Printf("[route2-client] selftest: 注 MaxRelDiff 是“占当期容差档的比例”，<=1 即通过当前档\n")
		return
	}

	// -prompt-len / -gen 任一被显式给出 ⇒ plan 驱动路径；否则沿用旧 MLP 路径（语义不变）。
	if *promptLen > 0 || *gen > 0 {
		cfg, cerr := modelConfigByID(*model)
		if cerr != nil {
			log.Fatalf("[route2-client] %v", cerr)
		}
		genN := *gen
		if genN <= 0 {
			genN = 1
		}
		tokens, terr := c.runV2(cfg, *promptLen, genN)
		if terr != nil {
			log.Fatalf("[route2-client] 失败: %v", terr)
		}
		fmt.Printf("[route2-client] 完成：model=%s prompt=%d generated=%d tokens=%v\n",
			cfg.ModelID, *promptLen, len(tokens), tokens)
		return
	}

	if *dim != route2demo.DefaultDim {
		log.Printf("[route2-client] 警告：dim=%d 与服务端默认 %d 可能不一致（服务端 MaskImage 维度校验将失败）", *dim, route2demo.DefaultDim)
	}
	token, err := c.run(*dim, *layers, *input)
	if err != nil {
		log.Fatalf("[route2-client] 失败: %v", err)
	}
	fmt.Printf("[route2-client] 完成：token=%d\n", token)
}

// ---------- plan 驱动路径（proto=2） ----------

// modelConfigByID 按 model_id 解析模型配置（唯一真值源在 route2plan.DemoTiny）。
// 未知 model 一律 error：模型决定权重/维度/模数，猜错会让"层序全绿但数值全错"。
func modelConfigByID(id string) (route2plan.ModelConfig, error) {
	switch id {
	case route2plan.DemoModelID:
		return route2plan.DemoTinyConfig(), nil
	default:
		return route2plan.ModelConfig{},
			fmt.Errorf("未知 -model %q（当前内置模型仅 %q）", id, route2plan.DemoModelID)
	}
}

// demoPrompt 确定性 prompt（与 route2ref 的测试同源）。
// 必须是确定性的：R-RECOVER 要从完整 prefill 重放，prompt 若带随机性就无法复现。
func demoPrompt(cfg route2plan.ModelConfig, n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = (i*7 + 3) % cfg.Vocab
	}
	return out
}

// stepFailure 一步的失败形态（§7.4.2 的分类落到类型上，避免用字符串判断）。
type stepFailure struct {
	Seq    int
	Op     string
	Coord  string
	Status int // HTTP 状态码；0 表示传输层失败（连接/超时/读响应）
	Body   string
	Cause  error // 传输层原始错误
}

func (f *stepFailure) Error() string {
	if f.Status == 0 {
		return fmt.Sprintf("step#%d(%s,coord=%s) 传输层失败: %v", f.Seq, f.Op, f.Coord, f.Cause)
	}
	return fmt.Sprintf("step#%d(%s,coord=%s) HTTP %d: %s", f.Seq, f.Op, f.Coord, f.Status, f.Body)
}

// recoverable 是否允许运行时恢复（§7.4.2 表）。
// 400（proto/model/shape/unknown_op）属调用方缺陷：**不允许运行时恢复**。
func (f *stepFailure) recoverable() bool {
	return f.Status != http.StatusBadRequest
}

// needsNewSession 是否只能走 ② 新建会话（401：会话过期或被清扫，kv_reset 也会被拒）。
func (f *stepFailure) needsNewSession() bool {
	return f.Status == http.StatusUnauthorized
}

// orchestrator plan 驱动的编排器（一次会话一份）。
type orchestrator struct {
	c    *client
	cfg  route2plan.ModelConfig
	sess *session
	mats map[route2plan.TensorKey]*maskedinfer.QuantizedMatrix
	ref  *maskedinfer.QuantizedMatrix // 定点化/重掩码的参照矩阵（只取 ModBits 与 InputScale）
}

func newOrchestrator(c *client, cfg route2plan.ModelConfig, sess *session) (*orchestrator, error) {
	ref, err := route2demo.TensorWeights(cfg, route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnQ})
	if err != nil {
		return nil, fmt.Errorf("加载参照权重失败: %w", err)
	}
	return &orchestrator{
		c:    c,
		cfg:  cfg,
		sess: sess,
		mats: make(map[route2plan.TensorKey]*maskedinfer.QuantizedMatrix),
		ref:  ref,
	}, nil
}

// matrix 取（缓存的）量化权重矩阵。
func (o *orchestrator) matrix(k route2plan.TensorKey) (*maskedinfer.QuantizedMatrix, error) {
	if m, ok := o.mats[k]; ok {
		return m, nil
	}
	m, err := route2demo.TensorWeights(o.cfg, k)
	if err != nil {
		return nil, err
	}
	o.mats[k] = m
	return m, nil
}

// rho 由会话 seed + 掩码域派生一步的掩码向量 r（与服务端 newLayerStream 同域同名同取模）。
// 注意：同一批的所有位置共用同一条 r —— 掩码像 MaskImage(W,r) 只需算一次，
// 服务端也是这么做的（recompute.go 现有实现即按"一步一条 r"处理整个 batch）。
func (o *orchestrator) rho(domain string, n int) ([]uint64, error) {
	st, err := masklite.NewStreamDomain(o.sess.seed, route2MaskModulus, []byte(domain))
	if err != nil {
		return nil, fmt.Errorf("派生掩码流(%s)失败: %w", domain, err)
	}
	r := make([]uint64, n)
	for i := range r {
		r[i] = st.Next() % route2MaskModulus
	}
	return r, nil
}

// injectRows 生成第 0 步注入行：V₀ = ToMaskDomain(嵌入) + ρ_inj(Stage,Turn) (mod R)。
// 嵌入表来自 route2demo（客户端注入与服务端 Gather 共用同一张表，见 route2plan.TensorTokEmb)。
//
// 【每行掩码必须按流顺序推进取段，不得全行共用首段】服务端对同一个源域流是
// 「逐步消费」的：batch 内第 j 行取流的第 j 段（step_exec.go 的 nextMaskVec 在
// 位置循环内推进）。prefill 批量（nPos>1）时若每行都取首段，第 1..nPos-1 行的
// 掩码与服务端错位，脱掩码得到垃圾明文——不报错、首 token 即错（真机实测
// prompt-len 4 出 [40 38]，纯浮点参照 [38 38]）。单行 decode（nPos=1）只取首段，
// 故该 bug 只在批量 prefill 暴露。
func (o *orchestrator) injectRows(plan route2plan.Plan, tokens []int) ([][]uint64, error) {
	emb, err := route2demo.Embedding(o.cfg, tokens)
	if err != nil {
		return nil, err
	}
	domain, err := route2plan.InjectDomain(plan.Stage(), plan.Turn())
	if err != nil {
		return nil, err
	}
	st, err := masklite.NewStreamDomain(o.sess.seed, route2MaskModulus, []byte(domain))
	if err != nil {
		return nil, fmt.Errorf("派生注入掩码流(%s)失败: %w", domain, err)
	}
	rows := make([][]uint64, len(emb))
	for i, e := range emb {
		if len(e) != o.cfg.Dim {
			return nil, fmt.Errorf("嵌入维度 %d != Dim %d", len(e), o.cfg.Dim)
		}
		r := make([]uint64, len(e))
		for j := range r {
			r[j] = st.Next() % route2MaskModulus // 行 i 取流第 i 段，与服务端逐行消费一致
		}
		rows[i], err = o.ref.Remask(o.ref.ToMaskDomain(e), r)
		if err != nil {
			return nil, fmt.Errorf("注入行重掩码失败: %w", err)
		}
	}
	return rows, nil
}

// encodeBatch 把若干条输入行（每条 nPos 行）按 batchLayout 摊平成一维 batch。
// 【唯一与布局约定耦合的函数】裁定变更时只需改这里（见 batchLayout 常量注释）。
func encodeBatch(lines [][][]uint64, nPos int) [][]uint64 {
	total := 0
	for _, l := range lines {
		total += len(l)
	}
	flat := make([][]uint64, 0, total)
	switch batchLayout {
	case "line-major":
		for _, l := range lines {
			flat = append(flat, l...)
		}
	default:
		// 交错式（保留实现，便于按裁定一键切换）
		for p := 0; p < nPos; p++ {
			for _, l := range lines {
				if p < len(l) {
					flat = append(flat, l[p])
				}
			}
		}
	}
	return flat
}

// buildBatch 构造某一步的请求 batch：逐条输入行取源 →（若 InWeight 指明）施加线性 → 摊平。
func (o *orchestrator) buildBatch(spec route2plan.StepSpec, injected [][]uint64, outs [][][]uint64) ([][]uint64, error) {
	nPos := len(injected)
	lines := make([][][]uint64, len(spec.InSrc))
	for lineIdx, src := range spec.InSrc {
		var srcRows [][]uint64
		if src == route2plan.SrcInject {
			srcRows = injected
		} else {
			if src < 0 || src >= len(outs) {
				return nil, fmt.Errorf("step#%d 行 %d 的 InSrc=%d 越界", spec.Seq, lineIdx, src)
			}
			srcRows = outs[src]
			if len(srcRows) == 0 {
				return nil, fmt.Errorf("step#%d 行 %d 的源 step#%d 无输出行（尚未执行？）", spec.Seq, lineIdx, src)
			}
		}
		if len(srcRows) != nPos {
			return nil, fmt.Errorf("step#%d 行 %d 的源行数 %d != 位置数 %d", spec.Seq, lineIdx, len(srcRows), nPos)
		}
		if !spec.InWeight[lineIdx].Applied {
			// 直通：源行原样送出，服务端按"掩码像不适用"处理（G12/R2）。
			if len(srcRows[0]) != spec.InDim[lineIdx] {
				return nil, fmt.Errorf("step#%d 行 %d 直通行维度 %d != InDim %d",
					spec.Seq, lineIdx, len(srcRows[0]), spec.InDim[lineIdx])
			}
			lines[lineIdx] = srcRows
			continue
		}
		w, err := o.matrix(spec.InWeight[lineIdx].Key)
		if err != nil {
			return nil, fmt.Errorf("step#%d 行 %d 加载权重 %s 失败: %w",
				spec.Seq, lineIdx, spec.InWeight[lineIdx].Key, err)
		}
		if w.Cols != len(srcRows[0]) {
			return nil, fmt.Errorf("step#%d 行 %d 的权重列数 %d != 源行维度 %d",
				spec.Seq, lineIdx, w.Cols, len(srcRows[0]))
		}
		if w.Rows != spec.InDim[lineIdx] {
			return nil, fmt.Errorf("step#%d 行 %d 的权重行数 %d != InDim %d",
				spec.Seq, lineIdx, w.Rows, spec.InDim[lineIdx])
		}
		// 线性搬运：W·V (mod R)。优先加速后端，不可用回退 CPU 128 位内核。
		prod, err := o.c.linearBatch(w, srcRows)
		if err != nil {
			return nil, fmt.Errorf("step#%d 行 %d 线性层: %w", spec.Seq, lineIdx, err)
		}
		lines[lineIdx] = prod
	}
	return encodeBatch(lines, nPos), nil
}

// normKeyFor 归一化步对应的 gamma 张量（RMSNorm 无 beta）。
func normKeyFor(spec route2plan.StepSpec, cfg route2plan.ModelConfig) (route2plan.TensorKey, bool) {
	switch spec.Coord.Step {
	case route2plan.StepAttnNorm:
		return route2plan.TensorKey{Block: int(spec.Coord.Block), Tensor: route2plan.TensorLNIn}, true
	case route2plan.StepFFNNorm:
		return route2plan.TensorKey{Block: int(spec.Coord.Block), Tensor: route2plan.TensorLNPost}, true
	case route2plan.StepFinalNorm:
		return route2plan.TensorKey{Block: cfg.Blocks, Tensor: route2plan.TensorLNFinal}, true
	default:
		return route2plan.TensorKey{}, false
	}
}

// newRequest 组装一个 proto=2 请求（**不发送**）。
// 抽出来是为了让单测能直接断言字段与 canonical，而不必起一个服务端。
func (o *orchestrator) newRequest(spec route2plan.StepSpec, batch [][]uint64) (*v2Request, error) {
	req := &v2Request{
		RequestID:   o.nextRequestID(),
		Proto:       protoV2,
		ModelID:     o.cfg.ModelID,
		Coord:       spec.Coord.Wire(),
		Seq:         spec.Seq,
		Op:          spec.Op,
		Batch:       batch,
		NRows:       len(batch), // §7.3：n_rows 必须等于 len(batch)，否则服务端判 shape_mismatch
		MaskVersion: 0,
	}
	if key, ok := normKeyFor(spec, o.cfg); ok {
		gamma, _, err := route2demo.NormParams(o.cfg, key)
		if err != nil {
			return nil, fmt.Errorf("step#%d 的 gamma 派生失败(%s): %w", spec.Seq, key, err)
		}
		req.Gamma = gamma
	}
	return req, nil
}

// sendStep 发一步并校验响应（回显、mask_next、signature）。失败统一返回 *stepFailure。
func (o *orchestrator) sendStep(spec route2plan.StepSpec, batch [][]uint64) (*v2Response, error) {
	req, err := o.newRequest(spec, batch)
	if err != nil {
		return nil, &stepFailure{Seq: spec.Seq, Op: spec.Op, Coord: spec.Coord.Wire(),
			Status: http.StatusBadRequest, Body: err.Error()}
	}
	resp, status, body, err := o.c.recomputeV2(o.sess.id, o.sess.ksig, req)
	if err != nil || status/100 != 2 {
		return nil, &stepFailure{Seq: spec.Seq, Op: spec.Op, Coord: req.Coord, Status: status, Body: body, Cause: err}
	}
	if resp.RequestID != req.RequestID {
		return nil, &stepFailure{Seq: spec.Seq, Op: spec.Op, Coord: req.Coord, Status: http.StatusBadRequest,
			Body: fmt.Sprintf("request_id 回显不一致: got %q want %q", resp.RequestID, req.RequestID)}
	}
	if resp.Seq != spec.Seq {
		return nil, &stepFailure{Seq: spec.Seq, Op: spec.Op, Coord: req.Coord, Status: http.StatusBadRequest,
			Body: fmt.Sprintf("seq 回显不一致: got %d want %d", resp.Seq, spec.Seq)}
	}
	if err := o.verifyMaskNext(resp, req.RequestID); err != nil {
		return nil, &stepFailure{Seq: spec.Seq, Op: spec.Op, Coord: req.Coord, Status: http.StatusBadRequest,
			Body: err.Error()}
	}
	if err := o.verifyRespSig(resp); err != nil {
		return nil, &stepFailure{Seq: spec.Seq, Op: spec.Op, Coord: req.Coord, Status: http.StatusBadRequest,
			Body: err.Error()}
	}
	return resp, nil
}

// verifyMaskNext 校验 mask_next == HMAC(K_sig, next_coord|request_id)（§7.2）。
// next_coord 为空表示终止（服务端承诺已结束），此时不校验。
func (o *orchestrator) verifyMaskNext(resp *v2Response, requestID string) error {
	if resp.NextCoord == "" {
		return nil
	}
	want := hex.EncodeToString(o.c.p.HMAC(o.sess.ksig, []byte(fmt.Sprintf("%s|%s", resp.NextCoord, requestID))))
	if !hmac.Equal([]byte(want), []byte(resp.MaskNext)) {
		return fmt.Errorf("mask_next 校验失败（服务端对“下一步做什么”的承诺被篡改？）: got %q want %q", resp.MaskNext, want)
	}
	return nil
}

// verifyRespSig 校验响应签名。
//
// 【§7.2 与既有实现的措辞差异】§7.2 写"覆盖 request_id+next_coord+result"，
// 而既有 signRecompute（recompute.go:350 附近）用的是 request_id+mask_next+result。
// 两者都是同一个 K_sig 下的密钥化 MAC、覆盖同一组字段，安全性等价；
// 这里**两种形态都接受，但都不匹配即报错**（fail-closed：不接受"签名缺失/无效"）。
// 已在 T04 回报中提请团队统一措辞。
// verifyRespSig 校验响应签名（§7.2.1：request_id|next_coord|seq|token|result，HMAC 于 K_sig）。
// 凡客户端当作真值消费的字段（含 token/seq）都必须被签名覆盖——否则链路可被篡改而不被发现：
// 被篡改的 token 会被当作下一轮输入追加进 KV，污染后续全部注意力。fail-closed：不匹配即拒绝。
func (o *orchestrator) verifyRespSig(resp *v2Response) error {
	if resp.Signature == "" {
		return fmt.Errorf("响应缺少 signature")
	}
	got, err := hex.DecodeString(resp.Signature)
	if err != nil {
		return fmt.Errorf("signature 非 hex: %w", err)
	}
	resultJSON, _ := json.Marshal(resp.Result)
	buf := []byte(fmt.Sprintf("%s|%s|%d|%d",
		resp.RequestID, resp.NextCoord, resp.Seq, resp.Token))
	buf = append(buf, resultJSON...)
	want := o.c.p.HMAC(o.sess.ksig, o.c.p.Hash(buf))
	if hmac.Equal(got, want) {
		return nil
	}
	return fmt.Errorf("响应 signature 校验失败（request_id|next_coord|seq|token|result 形态不匹配）")
}

// nextRequestID 生成会话内唯一 request_id（服务端按 request_id 判重，绝不复用）。
func (o *orchestrator) nextRequestID() string {
	o.sess.serial++
	return fmt.Sprintf("r2-s%d-%s-%d", o.sess.sessionNo, o.cfg.ModelID, o.sess.serial)
}

// checkResultShape 客户端侧行维度校验（fail-closed：早于服务端发现 shape_mismatch）。
func checkResultShape(spec route2plan.StepSpec, result [][]uint64, nPos int) error {
	if spec.OutDim == 0 {
		// kv_append_*：不产出张量（§7.2「为空内层数组」），接受 len==0 或全空行两种形态。
		for i, row := range result {
			if len(row) != 0 {
				return fmt.Errorf("step#%d(%s) 应返回空结果，第 %d 行却有 %d 个元素", spec.Seq, spec.Op, i, len(row))
			}
		}
		return nil
	}
	if len(result) != nPos {
		return fmt.Errorf("step#%d(%s) 结果行数 %d != 位置数 %d", spec.Seq, spec.Op, len(result), nPos)
	}
	for i, row := range result {
		if len(row) != spec.OutDim {
			return fmt.Errorf("step#%d(%s) 第 %d 行维度 %d != OutDim %d", spec.Seq, spec.Op, i, len(row), spec.OutDim)
		}
	}
	return nil
}

// runPlan 逐步执行一个 (Stage,Turn) 的 plan，返回终止步（argmax）给出的 token。
func (o *orchestrator) runPlan(plan route2plan.Plan, tokens []int) (int, error) {
	injected, err := o.injectRows(plan, tokens)
	if err != nil {
		return 0, err
	}
	outs := make([][][]uint64, plan.Len())
	for seq := 0; seq < plan.Len(); seq++ {
		spec, err := plan.At(seq)
		if err != nil {
			return 0, err
		}
		batch, err := o.buildBatch(spec, injected, outs)
		if err != nil {
			return 0, &stepFailure{Seq: seq, Op: spec.Op, Coord: spec.Coord.Wire(), Status: http.StatusBadRequest, Body: err.Error()}
		}
		resp, err := o.sendStep(spec, batch)
		if err != nil {
			return 0, err
		}
		if spec.Terminal {
			if resp.Token < 0 {
				return 0, &stepFailure{Seq: seq, Op: spec.Op, Coord: spec.Coord.Wire(), Status: http.StatusBadRequest,
					Body: "argmax 响应 token 无效（应为非负采样结果，不得为哨兵 -1）"}
			}
			return resp.Token, nil
		}
		if err := checkResultShape(spec, resp.Result, len(tokens)); err != nil {
			return 0, &stepFailure{Seq: seq, Op: spec.Op, Coord: spec.Coord.Wire(), Status: http.StatusBadRequest, Body: err.Error()}
		}
		outs[seq] = resp.Result
	}
	return 0, fmt.Errorf("plan 未以 Terminal 步结束（plan 合法性被破坏）")
}

// runV2 完整跑一次 prefill + gen 轮 decode，内置 R-RECOVER 恢复循环。
//
// 结构：
//
//	for attempt := 0; ; attempt++ {
//	    toks, err := runOnce(...)        // 完整 prefill + gen 轮
//	    if err == nil { return toks }
//	    if !recoverable(err) { return err }   // 400：调用方缺陷，不允许运行时恢复
//	    recover(err)                          // ① kv_reset 或 ② 新建会话
//	    // 然后**从完整 prefill 重放**（不是从失败的那一步继续）
//	}
func (c *client) runV2(cfg route2plan.ModelConfig, promptLen, gen int) ([]int, error) {
	if promptLen <= 0 {
		return nil, fmt.Errorf("prompt-len 必须 > 0，得到 %d", promptLen)
	}
	if promptLen+gen > cfg.MaxTokens {
		return nil, fmt.Errorf("prompt(%d)+gen(%d) 超出 MaxTokens=%d（请缩短，不允许运行时恢复）",
			promptLen, gen, cfg.MaxTokens)
	}
	sess, err := c.newSession(1)
	if err != nil {
		return nil, err
	}
	o, err := newOrchestrator(c, cfg, sess)
	if err != nil {
		return nil, err
	}
	var expect []int // 上一次尝试已产出的 token（用于重放后的确定性校验）
	for attempt := 0; attempt <= maxRecovery; attempt++ {
		toks, err := o.runOnce(promptLen, gen, expect)
		if err == nil {
			return toks, nil
		}
		var fail *stepFailure
		if e, ok := err.(*stepFailure); ok {
			fail = e
		}
		if fail == nil || !fail.recoverable() {
			// 非 step 失败（如配置/权重错误）或 400 类调用方缺陷：直接失败。
			return nil, err
		}
		log.Printf("[route2-client] R-RECOVER 触发（attempt=%d）: %v", attempt, fail)
		if err := o.recover(fail); err != nil {
			return nil, err
		}
		// 重放是"完整 prefill 重跑"，已生成的 token 作废；expect 用于校验重放确定性。
		if len(toks) > len(expect) {
			expect = toks
		}
	}
	return nil, fmt.Errorf("R-RECOVER 已重试 %d 次仍失败（疑似服务端状态不可恢复，请新建会话后重跑）", maxRecovery)
}

// runOnce 一次"从完整 prefill 重放"：prefill 出一个 token，再逐轮 decode 出剩余 token。
func (o *orchestrator) runOnce(promptLen, gen int, expect []int) ([]int, error) {
	prompt := demoPrompt(o.cfg, promptLen)
	// ---- prefill（Stage=1, Turn=0）----
	prefillPlan, err := route2plan.Build(o.cfg)
	if err != nil {
		return nil, err
	}
	token, err := o.runPlan(prefillPlan, prompt)
	if err != nil {
		return nil, err
	}
	generated := []int{token}
	if err := checkDeterminism(generated, expect); err != nil {
		return nil, err
	}
	// ---- decode（Stage=2, Turn=1..gen-1）----
	for turn := 1; turn < gen; turn++ {
		plan, err := route2plan.BuildTurn(o.cfg, route2plan.StageDecode, uint32(turn))
		if err != nil {
			return nil, err
		}
		tok, err := o.runPlan(plan, []int{generated[turn-1]})
		if err != nil {
			return generated, err
		}
		generated = append(generated, tok)
		if err := checkDeterminism(generated, expect); err != nil {
			return generated, err
		}
	}
	return generated, nil
}

// checkDeterminism 重放确定性护栏（§8.1 附加崩坏门禁之一）：
// 同一次推理在 R-RECOVER 重放后必须产出**逐位相同**的 token 序列。
func checkDeterminism(generated, expect []int) error {
	if len(expect) == 0 {
		return nil
	}
	for i := 0; i < len(generated) && i < len(expect); i++ {
		if generated[i] != expect[i] {
			return fmt.Errorf("确定性崩坏：重放后第 %d 个 token=%d 与首次尝试的 %d 不一致（掩码/状态不可复现）",
				i, generated[i], expect[i])
		}
	}
	return nil
}

// recover 按 §7.4.2 执行恢复：401 ⇒ ② 新建会话；其余（409/5xx/传输层/429）⇒ ① kv_reset。
//
// 为什么 401 只能走 ②：会话本身已失效（过期或被清扫），kv_reset 发过去也会被拒，
// 空转一次只是把失败推迟一轮。
func (o *orchestrator) recover(fail *stepFailure) error {
	if fail.needsNewSession() {
		log.Printf("[route2-client] R-RECOVER ② 新建会话（HTTP %d 只能重建会话）", fail.Status)
		return o.newSessionKeepCfg()
	}
	log.Printf("[route2-client] R-RECOVER ① kv_reset（同会话：KV 清零、pos/turn 归零后从完整 prefill 重放）")
	if err := o.kvReset(); err != nil {
		log.Printf("[route2-client] kv_reset 失败(%v)，改走 ② 新建会话", err)
		return o.newSessionKeepCfg()
	}
	if fail.Status == http.StatusTooManyRequests {
		// 429 已由 kv_reset 清掉 KV；但若规模本身触顶，重放会再次触顶——
		// 这不是运行时能修的（§7.4.2：缩短后重跑），故给出明确指引而不是空转重试。
		return fmt.Errorf("429 kv_cache_full：已 kv_reset，但 prompt+gen 规模可能仍触顶（MaxTokens=%d），请缩短 -prompt-len/-gen 后重跑",
			o.cfg.MaxTokens)
	}
	return nil
}

// kvReset 发 op=kv_reset（§7.1：该 op 不带 batch），KV 清零、pos/turn 归零。
func (o *orchestrator) kvReset() error {
	portal, err := route2plan.Build(o.cfg)
	if err != nil {
		return err
	}
	coord, err := portal.CoordAt(0)
	if err != nil {
		return err
	}
	req := &v2Request{
		RequestID:   o.nextRequestID(),
		Proto:       protoV2,
		ModelID:     o.cfg.ModelID,
		Coord:       coord.Wire(),
		Seq:         0,
		Op:          route2plan.OpKVReset,
		Batch:       nil,
		NRows:       0,
		MaskVersion: 0,
	}
	_, status, body, err := o.c.recomputeV2(o.sess.id, o.sess.ksig, req)
	if err != nil || status/100 != 2 {
		return fmt.Errorf("kv_reset 失败: HTTP %d %s %v", status, body, err)
	}
	// 本地状态归零：重放将从完整 prefill 重新开始。
	return nil
}

// newSessionKeepCfg 新建会话（②），复用同一份模型配置与已缓存权重。
func (o *orchestrator) newSessionKeepCfg() error {
	sess, err := o.c.newSession(o.sess.sessionNo + 1)
	if err != nil {
		return err
	}
	o.sess = sess
	return nil
}

// newSession 完成 attest → ECDH → complete → 派生 K_sig/K_enc/掩码 seed。
func (c *client) newSession(no int) (*session, error) {
	sessionID, serverPub, nonce, err := c.attest()
	if err != nil {
		return nil, fmt.Errorf("attest: %w", err)
	}
	clientPriv, clientPub, err := c.p.GenerateECDHKeyPair()
	if err != nil {
		return nil, fmt.Errorf("生成 ECDH 密钥: %w", err)
	}
	ksig, kenc, err := c.deriveKeys(clientPriv, serverPub, nonce)
	if err != nil {
		return nil, fmt.Errorf("派生会话密钥: %w", err)
	}
	if err := c.attestComplete(sessionID, clientPub); err != nil {
		return nil, fmt.Errorf("attest/complete: %w", err)
	}
	seed, err := c.p.KDF(kenc, nil, []byte(seedInfo), 32)
	if err != nil {
		return nil, fmt.Errorf("派生掩码 seed: %w", err)
	}
	return &session{id: sessionID, ksig: ksig, kenc: kenc, seed: seed, sessionNo: no}, nil
}

// recomputeV2 发一个 proto=2 请求；返回响应、HTTP 状态码、响应体（错误时）、传输层错误。
func (c *client) recomputeV2(sessionID string, ksig []byte, req *v2Request) (*v2Response, int, string, error) {
	canon := canonicalV2(c.p, req)
	req.Signature = hex.EncodeToString(c.p.HMAC(ksig, canon))
	body, _ := json.Marshal(req)
	hr, err := http.NewRequest(http.MethodPost, c.base+"/v1/recompute", bytes.NewReader(body))
	if err != nil {
		return nil, 0, "", err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("X-Session-ID", sessionID)
	resp, err := c.http.Do(hr)
	if err != nil {
		return nil, 0, "", err
	}
	defer resp.Body.Close()
	// 注意：响应体不能沿用 readBody 的 4 KiB 上限——prefill 的结果行数随 prompt 增长
	// （T×Dim 个 uint64，JSON 每元素约 20 字节），4 KiB 必然截断 ⇒ 解析失败。
	raw := readBodyCap(resp.Body, maxRespBytes)
	if resp.StatusCode/100 != 2 {
		return nil, resp.StatusCode, raw, nil
	}
	var rr v2Response
	if err := json.Unmarshal([]byte(raw), &rr); err != nil {
		return nil, resp.StatusCode, raw, fmt.Errorf("解析 /v1/recompute: %w", err)
	}
	return &rr, resp.StatusCode, raw, nil
}

// canonicalV2 严格照 §7.1：
//
//	proto|request_id|coord|seq|model_id|op|n_rows + json(batch)   （再 Hash 后 HMAC）
func canonicalV2(p cryptop.Provider, r *v2Request) []byte {
	buf := []byte(fmt.Sprintf("%d|%s|%s|%d|%s|%s|%d",
		r.Proto, r.RequestID, r.Coord, r.Seq, r.ModelID, r.Op, r.NRows))
	batchJSON, _ := json.Marshal(r.Batch)
	buf = append(buf, batchJSON...)
	return p.Hash(buf)
}

// ---------- 旧 MLP 路径（proto=v1，语义保持原样，不做改动） ----------

// run 执行一条完整前向，返回末层 argmax 的 token。
func (c *client) run(dim, layers int, input string) (uint64, error) {
	if layers < 1 {
		return 0, fmt.Errorf("layers 必须 >= 1")
	}

	// 1) 挑战-响应证明 + 会话
	sessionID, serverPub, nonce, err := c.attest()
	if err != nil {
		return 0, fmt.Errorf("attest: %w", err)
	}
	clientPriv, clientPub, err := c.p.GenerateECDHKeyPair()
	if err != nil {
		return 0, fmt.Errorf("生成 ECDH 密钥: %w", err)
	}
	ksig, kenc, err := c.deriveKeys(clientPriv, serverPub, nonce)
	if err != nil {
		return 0, fmt.Errorf("派生会话密钥: %w", err)
	}
	if err := c.attestComplete(sessionID, clientPub); err != nil {
		return 0, fmt.Errorf("attest/complete: %w", err)
	}

	// 2) 掩码 seed + 第0层掩码流
	seed, err := c.p.KDF(kenc, nil, []byte(seedInfo), 32)
	if err != nil {
		return 0, fmt.Errorf("派生掩码 seed: %w", err)
	}
	stream0, err := masklite.NewStreamDomain(seed, route2MaskModulus, []byte("otpmask/layer/0/v1"))
	if err != nil {
		return 0, fmt.Errorf("第0层掩码流: %w", err)
	}

	// 3) 第0层：V0 = ToMaskDomain(x0) + r0（Mod64 自然回绕）
	x0 := makeInput(dim, input)
	w0, err := route2demo.LayerWeights(0, dim)
	if err != nil {
		return 0, err
	}
	xMask := w0.ToMaskDomain(x0)
	r0 := make([]uint64, dim)
	for i := range r0 {
		r0[i] = stream0.Next() % route2MaskModulus
	}
	V := make([]uint64, dim)
	for i := range V {
		V[i] = xMask[i] + r0[i]
	}

	// 4) 逐层：线性（加速/CPU 回退）→ /v1/recompute →（非末层）用返回的掩码域结果作为下一层 V
	for L := 0; L < layers; L++ {
		w, err := route2demo.LayerWeights(L, dim)
		if err != nil {
			return 0, err
		}
		yCipher, err := c.linear(w, V)
		if err != nil {
			return 0, fmt.Errorf("layer %d 线性层: %w", L, err)
		}
		op := "gelu"
		if L == layers-1 {
			op = "argmax"
		}
		req := &recomputeReq{
			RequestID:   fmt.Sprintf("r2-%d-%d", time.Now().UnixNano(), L),
			Layer:       L,
			Op:          op,
			Batch:       [][]uint64{yCipher},
			MaskVersion: L,
		}
		resp, err := c.recompute(sessionID, ksig, req)
		if err != nil {
			return 0, fmt.Errorf("layer %d recompute: %w", L, err)
		}
		if op == "argmax" {
			if len(resp.Result) != 1 || len(resp.Result[0]) != 1 {
				return 0, fmt.Errorf("argmax 响应格式异常: %+v", resp.Result)
			}
			return resp.Result[0][0], nil
		}
		if len(resp.Result) != 1 || len(resp.Result[0]) != dim {
			return 0, fmt.Errorf("layer %d 补算结果维度异常: got %d", L, len(resp.Result[0]))
		}
		V = resp.Result[0]
	}
	return 0, fmt.Errorf("未产出 token（layers 配置异常）")
}

// linearBatch 对 batch 做线性搬运，返回与 batch 同形的结果（旧路径与新路径共用）。
func (c *client) linearBatch(m *maskedinfer.QuantizedMatrix, batch [][]uint64) ([][]uint64, error) {
	// M5-2：请求级 hint 透传（空 = 池默认，行为与旧版完全一致）；
	// 非法 hint（不在候选列表）由引擎返回 ErrAccelUnavailable → 下方 CPU 回退路径不变。
	out, err := m.AccelLinearInt128Via(c.accelHint, batch)
	if err == nil {
		return out, nil
	}
	// ErrAccelUnavailable（未配置/加载失败/调用失败）→ 回退 CPU 路径
	cpu, cerr := m.CipherLinearInt128(batch)
	if cerr != nil {
		return nil, fmt.Errorf("加速后端不可用(%v)且 CPU 回退失败: %w", err, cerr)
	}
	return cpu, nil
}

// linear 计算 yCipher = W·V（单行）。优先加速后端，不可用回退 CPU 128 位内核。
func (c *client) linear(m *maskedinfer.QuantizedMatrix, V []uint64) ([]uint64, error) {
	out, err := c.linearBatch(m, [][]uint64{V})
	if err != nil {
		return nil, err
	}
	return out[0], nil
}

// attest 发起挑战并验证证明链（report_data 绑定 + ECDSA-P256 验签）。
func (c *client) attest() (sessionID string, serverPub, nonce []byte, err error) {
	nonce, err = c.p.Rand(32)
	if err != nil {
		return "", nil, nil, fmt.Errorf("生成 nonce: %w", err)
	}
	body, _ := json.Marshal(map[string]string{"nonce": hex.EncodeToString(nonce)})
	resp, err := c.http.Post(c.base+"/attest", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, nil, fmt.Errorf("/attest 返回 %d: %s", resp.StatusCode, readBody(resp.Body))
	}
	var ar attestResp
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return "", nil, nil, fmt.Errorf("解析 /attest: %w", err)
	}
	serverPub, err = hex.DecodeString(ar.ServerPub)
	if err != nil {
		return "", nil, nil, fmt.Errorf("server_pub 非 hex: %w", err)
	}
	if err := c.verifyProof(nonce, serverPub, &ar.Proof); err != nil {
		return "", nil, nil, err
	}
	return ar.SessionID, serverPub, nonce, nil
}

// verifyProof 校验：nonce 回显、report_data == H(nonce‖server_pub)、证明签名有效。
// app_hash 依赖具体飞地度量，demo 客户端不强制（留待生产接真实 Quote 时补）。
func (c *client) verifyProof(nonce, serverPub []byte, pw *proofWire) error {
	if pw == nil || pw.ReportData == "" || pw.SigningKey == "" || pw.Signature == "" {
		return fmt.Errorf("证明载荷不完整")
	}
	if pw.Nonce != "" && pw.Nonce != hex.EncodeToString(nonce) {
		return fmt.Errorf("证明 nonce 回显不一致")
	}
	rd, err := hex.DecodeString(pw.ReportData)
	if err != nil {
		return fmt.Errorf("report_data 非 hex: %w", err)
	}
	h := sha256.New()
	h.Write(nonce)
	h.Write(serverPub)
	if !hmac.Equal(rd, h.Sum(nil)) {
		return fmt.Errorf("report_data 与 H(nonce‖server_pub) 不匹配（疑似公钥被替换）")
	}
	sk, err := hex.DecodeString(pw.SigningKey)
	if err != nil {
		return fmt.Errorf("signing_key 非 hex: %w", err)
	}
	sig, err := hex.DecodeString(pw.Signature)
	if err != nil {
		return fmt.Errorf("signature 非 hex: %w", err)
	}
	toSign := append(append([]byte(nil), rd...), sk...)
	if err := cryptop.VerifyP256(sk, toSign, sig); err != nil {
		return fmt.Errorf("证明验签失败: %w", err)
	}
	return nil
}

func (c *client) deriveKeys(clientPriv, serverPub, nonce []byte) (ksig, kenc []byte, err error) {
	shared, err := c.p.ECDH(clientPriv, serverPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH: %w", err)
	}
	sessionKey, err := c.p.KDF(shared, nonce, []byte(sessionInfo), 32)
	if err != nil {
		return nil, nil, fmt.Errorf("会话密钥 KDF: %w", err)
	}
	ksig, err = c.p.KDF(sessionKey, nil, []byte(sigInfo), 32)
	if err != nil {
		return nil, nil, err
	}
	kenc, err = c.p.KDF(sessionKey, nil, []byte(encInfo), 32)
	if err != nil {
		return nil, nil, err
	}
	return ksig, kenc, nil
}

func (c *client) attestComplete(sessionID string, clientPub []byte) error {
	body, _ := json.Marshal(map[string]string{
		"session_id": sessionID,
		"client_pub": hex.EncodeToString(clientPub),
	})
	resp, err := c.http.Post(c.base+"/attest/complete", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("/attest/complete 返回 %d: %s", resp.StatusCode, readBody(resp.Body))
	}
	return nil
}

func (c *client) recompute(sessionID string, ksig []byte, req *recomputeReq) (*recomputeResp, error) {
	canon := c.canonical(req)
	req.Signature = hex.EncodeToString(c.p.HMAC(ksig, canon))
	body, _ := json.Marshal(req)
	hr, err := http.NewRequest(http.MethodPost, c.base+"/v1/recompute", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("X-Session-ID", sessionID)
	resp, err := c.http.Do(hr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("/v1/recompute 返回 %d: %s", resp.StatusCode, readBody(resp.Body))
	}
	var rr recomputeResp
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return nil, fmt.Errorf("解析 /v1/recompute: %w", err)
	}
	return &rr, nil
}

// canonical 与服务端 recomputeCanonical 逐字节一致（旧 v1 路径）。
func (c *client) canonical(r *recomputeReq) []byte {
	buf := []byte(fmt.Sprintf("%s|%d|%s|%d", r.RequestID, r.Layer, r.Op, r.MaskVersion))
	bj, _ := json.Marshal(r.Batch)
	buf = append(buf, bj...)
	return c.p.Hash(buf)
}

func makeInput(dim int, spec string) []float64 {
	if strings.TrimSpace(spec) == "" {
		x := make([]float64, dim)
		for i := range x {
			x[i] = (float64(i) - float64(dim)/2) * 0.05
		}
		return x
	}
	parts := strings.Split(spec, ",")
	x := make([]float64, 0, len(parts))
	for _, s := range parts {
		var v float64
		fmt.Sscanf(strings.TrimSpace(s), "%f", &v)
		x = append(x, v)
	}
	return x
}

func readBody(r io.Reader) string {
	return readBodyCap(r, 4096)
}

// readBodyCap 读取至多 n 字节的响应体（错误正文与正常响应共用，上限由调用方给出）。
func readBodyCap(r io.Reader, n int64) string {
	b, _ := io.ReadAll(io.LimitReader(r, n))
	return string(b)
}

func init() {
	// 便于容器日志即时可见
	log.SetOutput(os.Stderr)
}
