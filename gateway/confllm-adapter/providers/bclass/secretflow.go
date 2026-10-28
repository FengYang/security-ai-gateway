// Package bclass B 类（密码学密态推理）适配器，代表 = 蚂蚁隐语 SecretFlow。
//
// 设计依据：§1.5 / §2（B 类）/ PRD §2 #5。SecretFlow 为任务式（SubmitGraph/PollResult），
// 非 chat 式，接入形态为 SDK / 子进程桥接（无公开 OpenAI 兼容 HTTP API）。
// 本期实现真实桥接骨架（SFBridge：HTTP 优先、子进程兜底）；真实「大模型密算服务」HTTP API
// 公开文档不足，标 pending-doc（不退回 fake-only）。
package bclass

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"security-ai-gateway/gateway/confllm-adapter"
)

// SFFlowSpec 隐语计算图定义（任务式输入）。
type SFFlowSpec struct {
	Name    string          `json:"name"`
	Parties []string        `json:"parties,omitempty"`
	DAG     json.RawMessage `json:"dag"` // 计算图（pending-doc：具体 schema 待对齐隐语 Cloud API）
}

// SFJobStatus 任务状态。
type SFJobStatus string

const (
	SFJobPending SFJobStatus = "pending"
	SFJobRunning SFJobStatus = "running"
	SFJobDone    SFJobStatus = "done"
	SFJobFailed  SFJobStatus = "failed"
)

// SFJob 提交后的任务句柄。
type SFJob struct {
	JobID  string      `json:"jobId"`
	Status SFJobStatus `json:"status"`
	Spec   *SFFlowSpec `json:"spec,omitempty"`
}

// SFResult 轮询得到的任务结果。
type SFResult struct {
	JobID  string          `json:"jobId"`
	Status SFJobStatus     `json:"status"`
	Output json.RawMessage `json:"output,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// SecretFlowProvider B 类密态推理契约（任务式，不混入 OpenAI 主链路）。
type SecretFlowProvider interface {
	ID() string
	Metadata() confllm.ConfidentialityMeta
	SubmitGraph(ctx context.Context, spec *SFFlowSpec) (*SFJob, error)
	PollResult(ctx context.Context, jobID string) (*SFResult, error)
	Health(ctx context.Context) confllm.HealthStatus
}

// SFBridge 隐语真实桥接（HTTP 优先、子进程兜底）。
//
// pending-doc：隐语 Cloud「大模型密算服务」公开 HTTP API 文档不足，此处按
// 「HTTP 优先、子进程兜底」实现真实桥接骨架；endpoint/binary 由用户后续补齐。
type SFBridge struct {
	endpoint   string // 可选：隐语服务 HTTP endpoint（REST）
	binary     string // 可选：secretflow 命令行（python -m secretflow ...）
	httpClient *http.Client
	logger     confllm.Logger
}

// NewSFBridge 构造桥接（endpoint 或 binary 至少其一；皆空 → 调用时报 pending-credential）。
func NewSFBridge(endpoint, binary string, logger confllm.Logger) *SFBridge {
	if logger == nil {
		logger = confllm.NopLogger{}
	}
	return &SFBridge{
		endpoint:   endpoint,
		binary:     binary,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
	}
}

// SubmitGraph 提交计算图（真实桥接：HTTP 优先，其次子进程）。
func (b *SFBridge) SubmitGraph(ctx context.Context, spec *SFFlowSpec) (*SFJob, error) {
	jobID := fmt.Sprintf("sf-%d", time.Now().UnixNano())
	if b.endpoint != "" {
		body, _ := json.Marshal(spec)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint+"/api/v1/graphs", bytes.NewReader(body))
		if err != nil {
			return nil, confllm.NewProviderError(confllm.CodeInvalidRequest, 400, "构造隐语提交请求失败")
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := b.httpClient.Do(req)
		if err != nil {
			return nil, confllm.NewProviderError(confllm.CodeUpstreamError, 502, "隐语 HTTP 提交失败")
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, confllm.NewProviderError(confllm.CodeUpstreamError, 502, "隐语 HTTP 提交返回非 200")
		}
		var out struct {
			JobID string `json:"job_id"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		if out.JobID != "" {
			jobID = out.JobID
		}
	} else if b.binary != "" {
		// 子进程桥接：python -m secretflow submit <dag>（pending-doc 具体命令）。
		cmd := exec.CommandContext(ctx, b.binary, "submit", string(spec.DAG))
		if err := cmd.Run(); err != nil {
			return nil, confllm.NewProviderError(confllm.CodeUpstreamError, 502, "隐语子进程提交失败")
		}
	} else {
		return nil, confllm.NewProviderError(confllm.CodePendingCredential, 503,
			"隐语桥接未配置 endpoint 或 binary（pending-credential）")
	}
	return &SFJob{JobID: jobID, Status: SFJobPending, Spec: spec}, nil
}

// PollResult 轮询结果（真实桥接：HTTP 优先，其次子进程兜底）。
func (b *SFBridge) PollResult(ctx context.Context, jobID string) (*SFResult, error) {
	if b.endpoint != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.endpoint+"/api/v1/jobs/"+jobID, nil)
		if err != nil {
			return nil, confllm.NewProviderError(confllm.CodeInvalidRequest, 400, "构造隐语轮询请求失败")
		}
		resp, err := b.httpClient.Do(req)
		if err != nil {
			return nil, confllm.NewProviderError(confllm.CodeUpstreamError, 502, "隐语 HTTP 轮询失败")
		}
		defer resp.Body.Close()
		var out SFResult
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return nil, confllm.NewProviderError(confllm.CodeUpstreamError, 502, "隐语结果解析失败")
		}
		return &out, nil
	}
	// 子进程兜底：pending-doc（读取本地结果文件）。
	return &SFResult{JobID: jobID, Status: SFJobRunning}, nil
}

// SecretFlowProviderImpl 将 SFBridge 包装为 SecretFlowProvider 接口（B 类：Class=B 密码学密态）。
type SecretFlowProviderImpl struct {
	id     string
	meta   confllm.ConfidentialityMeta
	bridge *SFBridge
}

// NewSecretFlowProvider 构造 B 类 Provider（默认 Class=B）。
func NewSecretFlowProvider(id string, bridge *SFBridge) *SecretFlowProviderImpl {
	return &SecretFlowProviderImpl{
		id: id,
		meta: confllm.ConfidentialityMeta{
			ConfidentialityClass: "B", // B 类：密码学密态推理（FHE/MPC/ZK）
			Attestation:          "unknown",
			DataRetention:        "unknown",
			Deployment:           "self-hosted-cvm",
		},
		bridge: bridge,
	}
}

// 编译期断言：SecretFlowProviderImpl 同时满足统一契约 ConfidentialLLMProvider。
//
// 背景（B 类声明值被吞缺陷）：此前仅实现任务式的 SecretFlowProvider 接口，缺
// Chat/Stream/ListModels → 永远进不了 confllm 注册表，/v1/adminext/models 富化时
// 走「未匹配」分支，把其**已声明的 class=B 降级为 unknown**（比未声明填 unknown 更严重）。
var (
	_ confllm.ConfidentialLLMProvider = (*SecretFlowProviderImpl)(nil)
	_ SecretFlowProvider              = (*SecretFlowProviderImpl)(nil)
)

func (p *SecretFlowProviderImpl) ID() string                            { return p.id }
func (p *SecretFlowProviderImpl) Metadata() confllm.ConfidentialityMeta { return p.meta }
func (p *SecretFlowProviderImpl) SubmitGraph(ctx context.Context, spec *SFFlowSpec) (*SFJob, error) {
	return p.bridge.SubmitGraph(ctx, spec)
}
func (p *SecretFlowProviderImpl) PollResult(ctx context.Context, jobID string) (*SFResult, error) {
	return p.bridge.PollResult(ctx, jobID)
}
func (p *SecretFlowProviderImpl) Health(ctx context.Context) confllm.HealthStatus {
	if p.bridge.endpoint == "" && p.bridge.binary == "" {
		return confllm.HealthStatus{Ready: false, PendingCredential: true, Detail: "隐语桥接未配置", MinConfidentialityClass: "B"}
	}
	return confllm.HealthStatus{Ready: true, MinConfidentialityClass: "B"}
}

// ---------- 统一契约（ConfidentialLLMProvider）适配 ----------
//
// B 类是**任务式**密态推理（SubmitGraph/PollResult），本就没有 chat/completions 语义。
// 适配原则：进注册表以保留已声明的 class=B；chat 式三个方法返回**明确的归一化
// not-implemented 错误**——绝不 panic、绝不伪造成功响应（伪造成功 = 假举证）。

// Region 区域（隐语为国内厂商）。
func (p *SecretFlowProviderImpl) Region() confllm.Region { return confllm.RegionDomestic }

// Capabilities 能力声明：任务式计算图，不提供 chat/stream 协议。
func (p *SecretFlowProviderImpl) Capabilities() confllm.Capabilities {
	return confllm.Capabilities{Protocols: []string{"secretflow-graph"}}
}

// notSupportedErr 归一化 not-implemented 错误（B 类任务式接口不提供 chat 式语义）。
func notSupportedErr(kind string) error {
	return confllm.NewProviderError(confllm.CodeInvalidRequest, http.StatusNotImplemented,
		fmt.Sprintf("B 类密态推理（隐语 SecretFlow）为任务式语义，不提供 %s：请改用 SubmitGraph/PollResult", kind))
}

// Chat 不提供 chat/completions 语义（任务式）。
func (p *SecretFlowProviderImpl) Chat(context.Context, *confllm.ChatRequest) (*confllm.ChatResponse, error) {
	return nil, notSupportedErr("chat/completions")
}

// Stream 不提供流式 chat 语义（任务式）。
func (p *SecretFlowProviderImpl) Stream(context.Context, *confllm.ChatRequest) (confllm.StreamReader, error) {
	return nil, notSupportedErr("stream/chat/completions")
}

// ListModels 不提供 OpenAI 式模型目录（任务式：模型由计算图声明）。
func (p *SecretFlowProviderImpl) ListModels(context.Context) ([]confllm.ModelInfo, error) {
	return nil, notSupportedErr("models 列表")
}

// SecretFlowTypeKey B 类在 confllm 注册表中的类型键。
const SecretFlowTypeKey = "secretflow"

// defaultSecretFlowID 配置未给 id 时的缺省实例 ID。
const defaultSecretFlowID = "secretflow"

// NewSecretFlowAdapter 按统一装配契约（confllm.ProviderConfig）构造 B 类适配器。
//
// endpoint 取 cfg.Endpoint（可为空：桥接未配置 → Health 报 pending-credential，
// 但 Metadata().ConfidentialityClass 仍为已声明的 B，绝不降级为 unknown）；
// binary 取 cfg.VendorOptions["binary"]（可选，子进程兜底）。
func NewSecretFlowAdapter(cfg confllm.ProviderConfig, opts ...confllm.ProviderOption) (confllm.ConfidentialLLMProvider, error) {
	id := cfg.ID
	if strings.TrimSpace(id) == "" {
		id = defaultSecretFlowID
	}
	binary := ""
	if v, ok := cfg.VendorOptions["binary"].(string); ok {
		binary = v
	}
	return NewSecretFlowProvider(id, NewSFBridge(cfg.Endpoint, binary, confllm.ApplyOptions(opts...).Logger())), nil
}

// init 向全局注册表注册 B 类工厂（与其余 12 家同款插件约定）。
func init() {
	confllm.GlobalRegistry.RegisterType(SecretFlowTypeKey, NewSecretFlowAdapter)
}
