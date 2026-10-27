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
