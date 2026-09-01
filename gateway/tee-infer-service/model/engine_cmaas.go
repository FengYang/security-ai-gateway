// Package model — 百炼 Confidential MaaS 引擎（P5，engine_type=cmaas）。
//
// 形态：对接官方机密推理 SDK 构建的 openai-proxy 本地代理（OpenAI 兼容 Chat + SSE）。
// 段② 加密与远程证明（Trustee + Sigstore Rekor 透明日志）由 SDK 在代理进程内完成，
// 网关域不重复实现证明（官方文档："客户端直接访问 TEE 厂商验证硬件生成的远程证明
// 报告真实性"）；tee-infer 与 openai-proxy 同处客户可信域（客户网关内存 ∪
// tee-infer 进程内存 ∪ 阿里验证 TEE 为明文域边界）。
//
// SDK 仓库 github.com/dashscope/dashscope-confidential-maas 为定向邀请制（私有），
// go.mod 不引入（拉取即失败）；开通后两种接线方式（见 docs/GA-CMAAS对接设计.md）：
//  1. 部署 SDK 自带 openai-proxy，本引擎经 OpenAI 兼容接口调用（当前实现，零改动）
//  2. 以进程内 SDK 调用替换（接口已抽象为 Engine，仅替换本文件）
package model

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CmaasEngine 百炼 Confidential MaaS 引擎。
type CmaasEngine struct {
	proxyURL string  // openai-proxy 监听地址（如 http://127.0.0.1:8080）
	apiKey   string  // DASHSCOPE_API_KEY（Bearer 透传代理）
	keyPool  KeyPool // GF.4.2：多账号轮询池；nil = 单账号 apiKey（向后兼容）
	model    string  // 缺省模型 code（cmaas-glm-5.2 等；请求未指定时使用）
	client   *http.Client

	mu              sync.Mutex
	lastAttestation string // 最近一次响应透出的证明/透明度引用（落审计链）
}

// ensure *CmaasEngine implements Engine。
var _ Engine = (*CmaasEngine)(nil)

// NewCmaasEngine 构造 C-MaaS 引擎；proxyURL 为 openai-proxy 地址。
// apiKey/model 可为空（由代理侧环境变量与部署参数决定时）。
func NewCmaasEngine(proxyURL, apiKey, model string) *CmaasEngine {
	return &CmaasEngine{
		proxyURL: strings.TrimSuffix(proxyURL, "/"),
		apiKey:   apiKey,
		model:    model,
		// C-MaaS 流式整体超时与 vLLM 对齐（120s 生成窗口）
		client: &http.Client{Timeout: 120 * time.Second},
	}
}

// SetKeyPool 装配多账号密钥池（GF.4.2 接入点）；nil 回退单账号 apiKey。
// 真机开通多账号后经 NewRoundRobinKeyPool 装配替换，接口不变，仅装配点改动。
func (e *CmaasEngine) SetKeyPool(pool KeyPool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.keyPool = pool
}

// Generate 经 openai-proxy 流式生成（OpenAI 兼容 /v1/chat/completions）。
// 响应中如透出证明/透明度引用头则记录（LastAttestation，供审计链）；
// 任一失败 fail-closed 返回 error（不产出半截明文）。
func (e *CmaasEngine) Generate(req GenerateRequest, onDelta func(delta string) error) error {
	if e.proxyURL == "" {
		return fmt.Errorf("cmaas: 未配置 openai-proxy 地址（-cmaas-url，fail-closed）")
	}
	if req.Model == "" {
		req.Model = e.model
	}
	if req.Model == "" {
		return fmt.Errorf("cmaas: 未指定模型 code（cmaas-glm-5.2 等）")
	}
	var headers [][2]string
	// GF.4.2：多账号轮询获取凭证（nil keyPool 回退单账号 apiKey）。
	// Acquire 为空 = 无可用账号 → fail-closed；Release 按失败标记归还（供熔断扩展）。
	apiKey := e.apiKey
	failed := false
	if e.keyPool != nil {
		apiKey = e.keyPool.Acquire()
		if apiKey == "" {
			return fmt.Errorf("cmaas: 无可用服务商账号（fail-closed）")
		}
		defer func() { e.keyPool.Release(apiKey, failed) }()
	}
	if apiKey != "" {
		headers = append(headers, [2]string{"Authorization", "Bearer " + apiKey})
	}
	// 代理地址按部署固定 base，路径为 OpenAI 兼容标准路径
	url := e.proxyURL + "/v1/chat/completions"
	err := StreamChat(e.client, url, headers, req, onDelta)
	if err != nil {
		failed = true
		return fmt.Errorf("cmaas: %w", err)
	}
	// StreamChat 成功后无法回读响应头（流已消费）；证明引用经 LastAttestation
	// 由代理侧 companion 端点或 SDK 透明度报告目录获取（开通后对齐，
	// 见 GA-CMAAS对接设计.md §4）。
	return nil
}

// Predict C-MaaS 不支持 vectors 载荷（SDK 接口仅接受文本），一律 -1。
func (e *CmaasEngine) Predict(x []float64) int { return -1 }

// RecordAttestation 记录证明/透明度引用（供审计链；透明度报告路径或引用 ID）。
func (e *CmaasEngine) RecordAttestation(ref string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastAttestation = ref
}

// LastAttestation 最近一次证明/透明度引用（空 = 暂无）。
func (e *CmaasEngine) LastAttestation() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastAttestation
}
