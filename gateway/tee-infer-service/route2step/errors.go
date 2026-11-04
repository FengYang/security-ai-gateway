package route2step

import "fmt"

// StepError 掩码单步的错误（HTTP 码 + 审计码 + 文本）。
//
// 宿主（tee-infer-service main）把本类型转成自身的 stepError 后落审计；
// 本包不依赖宿主，保持可独立编译/测试/复用。
type StepError struct {
	Status int
	Audit  string
	Msg    string
}

func (e *StepError) Error() string { return e.Msg }

// NewStepError 构造 StepError。
func NewStepError(status int, audit, format string, args ...interface{}) *StepError {
	return &StepError{Status: status, Audit: audit, Msg: fmt.Sprintf(format, args...)}
}

// Route2MaskModulus 路线2 掩码模 R（M1 接线，技术方案 §7.7 定案）。
// 取 2^64-1 (=^uint64(0)) 作为 2^64 的等价代表。
const Route2MaskModulus uint64 = ^uint64(0)

// ---- 审计码（§7.3）----
//
// 与宿主 main 的同名常量为同一取值；主仓 main 侧的 auditRecompute* 常量应别名到此处，
// 避免两处字面量漂移（单一事实来源）。
const (
	AuditRecomputeShapeMismatch    = "recompute_shape_mismatch"
	AuditRecomputeUnknownOp        = "recompute_unknown_op"
	AuditRecomputeReplay           = "recompute_replay"
	AuditKVCacheFull               = "kv_cache_full"
	AuditRecomputeStreamFailed     = "recompute_stream_failed"
	AuditRecomputeWeightLoadFailed = "recompute_weight_load_failed"
	AuditRecomputeMaskImageFailed  = "recompute_mask_image_failed"
	AuditRecomputeUnmaskFailed     = "recompute_unmask_failed"
	AuditRecomputeRemaskFailed     = "recompute_remask_failed"
	AuditRecomputeNormFailed       = "recompute_norm_failed"
	AuditRecomputeAttentionFailed  = "recompute_attention_failed"
	AuditRecomputeNonlinearFailed  = "recompute_nonlinear_failed"
	AuditRecomputeKVFailed         = "recompute_kv_failed"
)
