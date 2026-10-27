package bclass

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"security-ai-gateway/gateway/confllm-adapter"
)

// SFFake 隐语 B 类离线验证用 Fake（仅验 SubmitGraph/PollResult 状态机契约，不验真机桥接）。
//
// 顶部注释（QA-6）：本 Fake 仅验证接口契约（任务式状态机），不连接真实隐语服务；真实桥接见 SFBridge。
type SFFake struct {
	id   string
	meta confllm.ConfidentialityMeta
	mu   sync.Mutex
	jobs map[string]*SFJob
}

// NewSFFake 构造离线验证 Fake。
func NewSFFake(id string) *SFFake {
	return &SFFake{
		id: id,
		meta: confllm.ConfidentialityMeta{
			ConfidentialityClass: "B",
			Attestation:          "unknown",
			DataRetention:        "unknown",
			Deployment:           "self-hosted-cvm",
		},
		jobs: make(map[string]*SFJob),
	}
}

func (f *SFFake) ID() string                            { return f.id }
func (f *SFFake) Metadata() confllm.ConfidentialityMeta { return f.meta }

// SubmitGraph 提交任务（内存状态机：pending → running）。
func (f *SFFake) SubmitGraph(ctx context.Context, spec *SFFlowSpec) (*SFJob, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	jobID := fmt.Sprintf("sf-fake-%d", len(f.jobs)+1)
	job := &SFJob{JobID: jobID, Status: SFJobRunning, Spec: spec}
	f.jobs[jobID] = job
	return job, nil
}

// PollResult 轮询结果（running → done 状态机推进）。
func (f *SFFake) PollResult(ctx context.Context, jobID string) (*SFResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	job, ok := f.jobs[jobID]
	if !ok {
		return nil, fmt.Errorf("job not found: %s", jobID)
	}
	if job.Status == SFJobRunning {
		job.Status = SFJobDone
	}
	return &SFResult{
		JobID:  jobID,
		Status: job.Status,
		Output: json.RawMessage(`{"result":"ok"}`),
	}, nil
}

// Health 始终就绪（Fake 不依赖真实桥接）。
func (f *SFFake) Health(ctx context.Context) confllm.HealthStatus {
	return confllm.HealthStatus{Ready: true, MinConfidentialityClass: "B"}
}
