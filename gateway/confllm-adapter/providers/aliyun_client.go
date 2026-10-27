package providers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"security-ai-gateway/gateway/confllm-adapter"
	"security-ai-gateway/gateway/confllm-adapter/attest"
)

// aliyunClientImpl 阿里云百炼机密推理真实客户端（vendor-sdk 密态路径）。
//
// 真实形态（K1 终裁 + 用户 18 篇资料分析）：百炼机密推理 = TEE + TNG 可信网关 + Trustee
// 远程证明，厂商交付物为 pai-cc 工具链，**无官方 Go SDK**。故本实现以「pai-cc 子进程」为
// 真实调用路径（对接方案见 docs/详细设计/confllm/百炼机密推理-技术对接方案.md）。
//
// 核心红线：
//   - attest-then-infer fail-closed：每次推理前先 `pai-cc attest` 远程证明，失败即中断，
//     绝不下发 prompt、绝不降级到普通 API（生产红线，与 aliyun-bailian 无回退通道）；
//   - 凭据（AccessKey ID/Secret）经 SecretRef 注入，绝不硬编码/落日志（§7.2/P0-4）；
//   - endpoint / modelCode / workspaceID 为安装期参数，缺省 fail-closed / 可见（登记口径铁律）；
//   - 密态等级唯一事实源 = meta（K7），本 client 不硬编码任何等级。
//
// pending-doc：若阿里后续提供官方 Go SDK 或公开 wire 协议，可将子进程调用原位替换为原生
// HTTP/SDK 调用，适配层（VendorSDKClient 契约）不变。
type aliyunClientImpl struct {
	endpoint      string
	modelCode     string
	workspaceID   string
	paiCCToolPath string
	meta          confllm.ConfidentialityMeta

	secretResolver confllm.SecretResolver
	secretRef      confllm.SecretRef
	staticCred     *confllm.Credential
	attestor       confllm.AttestationVerifier
	logger         confllm.Logger

	// attestTTL 远程证明缓存有效期（避免每次推理都 attest）。
	attestTTL time.Duration

	mu         sync.Mutex
	attestedAt time.Time
	attestedOK bool
}

// newAliyunConfidentialClient 构造真实客户端。构造期不校验关键参数（安装期可能未配齐），
// 由调用期（Chat/Stream/Health）fail-closed 暴露 pending-credential / invalid_request。
func newAliyunConfidentialClient(cfg confllm.ProviderConfig, opts ...confllm.ProviderOption) (*aliyunClientImpl, error) {
	o := confllm.ApplyOptions(opts...)
	c := &aliyunClientImpl{
		endpoint:       strings.TrimRight(cfg.Endpoint, "/"),
		modelCode:      "",
		workspaceID:    "",
		paiCCToolPath:  "/usr/local/bin/pai-cc",
		meta:           fillMeta(cfg.Meta),
		secretResolver: o.SecretResolver(),
		secretRef:      cfg.SecretRef,
		staticCred:     o.StaticCred(),
		attestor:       o.Attestation(),
		logger:         o.Logger(),
		attestTTL:      5 * time.Minute,
	}
	if cfg.VendorSDK != nil {
		c.modelCode = cfg.VendorSDK.ModelCode
		c.workspaceID = cfg.VendorSDK.WorkspaceID
	}
	// 允许经 L2 vendorOptions 覆写 pai-cc 路径（安装期参数覆写点）。
	if v, ok := cfg.VendorOptions["paiCCToolPath"].(string); ok && v != "" {
		c.paiCCToolPath = v
	}
	return c, nil
}

// ---------- 凭据（SecretRef → AccessKey，绝不硬编码/打印） ----------

func (c *aliyunClientImpl) resolveCredential(ctx context.Context) (*confllm.Credential, error) {
	if c.staticCred != nil {
		return c.staticCred, nil
	}
	if c.secretResolver == nil {
		return nil, confllm.NewProviderError(confllm.CodePendingCredential, http.StatusServiceUnavailable,
			"未配置 SecretResolver（凭据解析器）")
	}
	cred, err := c.secretResolver.Resolve(ctx, c.secretRef)
	if err != nil || cred == nil || len(cred.Key) == 0 {
		return nil, confllm.NewProviderError(confllm.CodePendingCredential, http.StatusServiceUnavailable,
			"凭据未配置或解析失败（pending-credential）")
	}
	return cred, nil
}

// aliyunAK 解析后的阿里云 AccessKey 对。
type aliyunAK struct {
	ID     string
	Secret string
}

// parseAliyunAK 从 Credential.Key 解析 AccessKey ID/Secret。
// 约定：broker .env 密文为 JSON {"accessKeyId":"...","accessKeySecret":"..."}；
// 兼容回退 "id:secret"（首个冒号分隔）。绝不打印原始值（§7.2）。
func parseAliyunAK(cred *confllm.Credential) (aliyunAK, error) {
	var ak aliyunAK
	raw := bytes.TrimSpace(cred.Key)
	var j struct {
		AccessKeyID     string `json:"accessKeyId"`
		AccessKeySecret string `json:"accessKeySecret"`
	}
	if err := json.Unmarshal(raw, &j); err == nil && (j.AccessKeyID != "" || j.AccessKeySecret != "") {
		ak.ID, ak.Secret = j.AccessKeyID, j.AccessKeySecret
	} else if i := bytes.Index(raw, []byte(":")); i > 0 {
		ak.ID, ak.Secret = string(raw[:i]), string(raw[i+1:])
	} else {
		return ak, fmt.Errorf("凭据格式无法解析为 AccessKey（期望 JSON 或 id:secret）")
	}
	if ak.ID == "" || ak.Secret == "" {
		return ak, fmt.Errorf("AccessKey ID/Secret 不完整")
	}
	return ak, nil
}

// ---------- 远程证明（attest-then-infer，fail-closed） ----------

// ensureAttested 推理前的远程证明闸门：证明失败 → fail-closed（绝不下发 prompt）。
func (c *aliyunClientImpl) ensureAttested(ctx context.Context) error {
	c.mu.Lock()
	if c.attestedOK && time.Since(c.attestedAt) < c.attestTTL {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	report, err := c.runAttest(ctx)
	if err != nil {
		c.logger.Errorf(ctx, "confllm aliyun-confidential attest failed, prompt NOT sent",
			"provider", "aliyun-confidential", "endpoint", c.endpoint)
		return confllm.NewProviderError(confllm.CodeUpstreamError, http.StatusBadGateway,
			"百炼机密推理远程证明失败（fail-closed，未发送请求）")
	}
	// 本期 attestor 为 Noop/LogOnly（Verdict=unknown，R4）；P2 换 Trustee 真校验后 VerdictFail 即中断。
	res, verr := c.attestor.Verify(ctx, confllm.Evidence{
		Type:   firstNonEmpty(c.meta.Attestation, "unknown"),
		Raw:    report,
		Issuer: "trustee",
		Model:  c.modelCode,
	})
	if verr != nil {
		return confllm.NewProviderError(confllm.CodeUpstreamError, http.StatusBadGateway, "远程证明校验异常")
	}
	if res != nil && res.Verdict == attest.VerdictFail {
		return confllm.NewProviderError(confllm.CodeUpstreamError, http.StatusBadGateway,
			"远程证明校验未通过（fail-closed）")
	}

	c.mu.Lock()
	c.attestedOK, c.attestedAt = true, time.Now()
	c.mu.Unlock()
	return nil
}

// runAttest 执行 `pai-cc attest` 并返回证明报告字节。
func (c *aliyunClientImpl) runAttest(ctx context.Context) ([]byte, error) {
	if c.endpoint == "" {
		return nil, fmt.Errorf("endpoint 未配置")
	}
	cmd := exec.CommandContext(ctx, c.paiCCToolPath, "attest", "--endpoint", c.endpoint, "--output", "-")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("pai-cc attest: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// ---------- VendorSDKClient 实现 ----------

// buildInferArgs 构造 `pai-cc infer` 参数（stream 由调用方显式指定，忽略 req.Stream）。
func (c *aliyunClientImpl) buildInferArgs(req *confllm.ChatRequest, stream bool) ([]string, error) {
	if c.endpoint == "" {
		return nil, confllm.NewProviderError(confllm.CodePendingCredential, http.StatusServiceUnavailable,
			"百炼机密推理 endpoint 未配置（安装期参数）")
	}
	if c.modelCode == "" || c.workspaceID == "" {
		return nil, confllm.NewProviderError(confllm.CodeInvalidRequest, http.StatusBadRequest,
			"modelCode / workspaceID 未配置（安装期参数）")
	}
	msgBytes, err := json.Marshal(req.Messages)
	if err != nil {
		return nil, confllm.NewProviderError(confllm.CodeInvalidRequest, http.StatusBadRequest, "messages 序列化失败")
	}
	args := []string{
		"infer",
		"--endpoint", c.endpoint,
		"--model", c.modelCode,
		"--workspace", c.workspaceID,
		"--messages", string(msgBytes),
		"--stream", fmt.Sprintf("%t", stream),
	}
	if req.MaxTokens > 0 {
		args = append(args, "--max-tokens", fmt.Sprintf("%d", req.MaxTokens))
	}
	if req.Temperature != 0 {
		args = append(args, "--temperature", fmt.Sprintf("%.4f", req.Temperature))
	}
	return args, nil
}

// envWithAK 以子进程环境变量注入 AccessKey（不经命令行参数，防进程列表泄漏）。
func envWithAK(ak aliyunAK) []string {
	return append(os.Environ(),
		"ALIYUN_ACCESS_KEY_ID="+ak.ID,
		"ALIYUN_ACCESS_KEY_SECRET="+ak.Secret,
	)
}

// Chat 非流式机密推理。
func (c *aliyunClientImpl) Chat(ctx context.Context, req *confllm.ChatRequest) (*confllm.ChatResponse, error) {
	start := time.Now()
	cred, err := c.resolveCredential(ctx)
	if err != nil {
		return nil, err
	}
	ak, err := parseAliyunAK(cred)
	if err != nil {
		return nil, confllm.NewProviderError(confllm.CodePendingCredential, http.StatusServiceUnavailable, err.Error())
	}
	if err := c.ensureAttested(ctx); err != nil {
		return nil, err // fail-closed
	}
	args, err := c.buildInferArgs(req, false)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, c.paiCCToolPath, args...)
	cmd.Env = envWithAK(ak)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		// 脱敏：不向客户端回传原始 stderr（§7.2），仅归一错误码；详情只进服务端日志。
		c.logger.Errorf(ctx, "confllm aliyun-confidential infer failed",
			"provider", "aliyun-confidential", "model", c.modelCode, "stderr", truncate(stderr.String(), 200))
		return nil, mapInferError(stderr.String())
	}
	c.logger.Infof(ctx, "confllm upstream chat",
		"provider", "aliyun-confidential", "model", c.modelCode, "status", 200, "duration", time.Since(start).String())
	return parseConfidentialChat(out, c.modelCode)
}

// Stream 流式机密推理：pai-cc 逐行输出，包装为 L1 StreamChunk。
// ctx 取消时 CommandContext 自动 kill 子进程。
func (c *aliyunClientImpl) Stream(ctx context.Context, req *confllm.ChatRequest) (confllm.StreamReader, error) {
	cred, err := c.resolveCredential(ctx)
	if err != nil {
		return nil, err
	}
	ak, err := parseAliyunAK(cred)
	if err != nil {
		return nil, confllm.NewProviderError(confllm.CodePendingCredential, http.StatusServiceUnavailable, err.Error())
	}
	if err := c.ensureAttested(ctx); err != nil {
		return nil, err // fail-closed
	}
	args, err := c.buildInferArgs(req, true)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, c.paiCCToolPath, args...)
	cmd.Env = envWithAK(ak)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, confllm.NewProviderError(confllm.CodeUpstreamError, http.StatusBadGateway, "创建 pai-cc stdout 管道失败")
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, confllm.NewProviderError(confllm.CodeUpstreamError, http.StatusBadGateway, "pai-cc 启动失败")
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	return &paiCCStreamReader{sc: sc, stdout: stdout, cmd: cmd, model: c.modelCode}, nil
}

// ListModels 返回控制台配置的机密推理模型 code（机密推理按部署绑定单一模型，不调远程）。
func (c *aliyunClientImpl) ListModels(ctx context.Context) ([]confllm.ModelInfo, error) {
	if c.modelCode == "" {
		return nil, nil
	}
	return []confllm.ModelInfo{{ID: c.modelCode, OwnedBy: "aliyun-confidential"}}, nil
}

// Health：以远程证明可达性 + 模型配置判定就绪。
func (c *aliyunClientImpl) Health(ctx context.Context) confllm.HealthStatus {
	class := c.meta.ConfidentialityClass
	if c.modelCode == "" || c.workspaceID == "" {
		return confllm.HealthStatus{Ready: false, PendingCredential: true,
			Detail: "pending-credential: modelCode/workspaceID 未配置", MinConfidentialityClass: class}
	}
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := c.runAttest(hctx); err != nil {
		return confllm.HealthStatus{Ready: false, Detail: "attestation-unreachable", MinConfidentialityClass: class}
	}
	return confllm.HealthStatus{Ready: true, MinConfidentialityClass: class}
}

// ---------- pai-cc 流式读取器 ----------

// paiCCStreamReader 逐行消费 pai-cc 流式 stdout，归一为 L1 StreamChunk。
// 兼容两种上游输出：OpenAI 兼容 SSE（data: {...}）与纯文本行（逐行 = 一个 content 增量）。
type paiCCStreamReader struct {
	sc     *bufio.Scanner
	stdout io.ReadCloser
	cmd    *exec.Cmd
	model  string
	waited bool
}

func (r *paiCCStreamReader) Next() (*confllm.StreamChunk, error) {
	for r.sc.Scan() {
		line := strings.TrimSpace(r.sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "data:") {
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if payload == "[DONE]" {
				return nil, r.finish()
			}
			var chunk confllm.StreamChunk
			if err := json.Unmarshal([]byte(payload), &chunk); err == nil && len(chunk.Choices) > 0 {
				if chunk.Model == "" {
					chunk.Model = r.model
				}
				return &chunk, nil
			}
			line = payload // 非 JSON 的 data 行按文本增量处理
		}
		return &confllm.StreamChunk{
			ID:      fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano()),
			Object:  "chat.completion.chunk",
			Model:   r.model,
			Choices: []confllm.StreamChoice{{Index: 0, Delta: confllm.Message{Role: "assistant", Content: line}}},
		}, nil
	}
	if err := r.sc.Err(); err != nil {
		return nil, fmt.Errorf("pai-cc 流读取错误: %w", err)
	}
	return nil, r.finish()
}

// finish 流结束：回收子进程（CommandContext 在 ctx 取消时已 kill，这里兜底 reap）。
func (r *paiCCStreamReader) finish() error {
	if !r.waited {
		r.waited = true
		_ = r.cmd.Wait()
	}
	return io.EOF
}

func (r *paiCCStreamReader) Close() error {
	err := r.stdout.Close()
	if !r.waited {
		r.waited = true
		_ = r.cmd.Wait()
	}
	return err
}

// ---------- 解析 / 错误映射（脱敏） ----------

// parseConfidentialChat 解析非流式输出。若 pai-cc 输出已是 OpenAI 兼容 JSON 直接归一；
// 否则按纯文本包装为单 choice（pending-doc：响应 schema 以控制台实跑为准）。
func parseConfidentialChat(out []byte, model string) (*confllm.ChatResponse, error) {
	var resp confllm.ChatResponse
	if err := json.Unmarshal(out, &resp); err == nil && len(resp.Choices) > 0 {
		if resp.Model == "" {
			resp.Model = model
		}
		return &resp, nil
	}
	return &confllm.ChatResponse{
		ID:      fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano()),
		Object:  "chat.completion",
		Model:   model,
		Choices: []confllm.Choice{{Index: 0, Message: confllm.Message{Role: "assistant", Content: strings.TrimSpace(string(out))}, FinishReason: "stop"}},
	}, nil
}

// mapInferError 将 pai-cc stderr 归一为 6 类错误码（§7.1），不回传原始 stderr（§7.2）。
func mapInferError(stderr string) *confllm.ProviderError {
	s := strings.ToLower(stderr)
	switch {
	case strings.Contains(s, "401") || strings.Contains(s, "unauthorized") ||
		strings.Contains(s, "accesskey") || strings.Contains(s, "signature") || strings.Contains(s, "forbidden"):
		return confllm.NewProviderError(confllm.CodeUnauthorized, http.StatusUnauthorized, "百炼机密推理鉴权失败（凭据无效）")
	case strings.Contains(s, "429") || strings.Contains(s, "rate limit") || strings.Contains(s, "throttl"):
		return confllm.NewProviderError(confllm.CodeRateLimited, http.StatusTooManyRequests, "百炼机密推理限流（429）")
	case strings.Contains(s, "timeout") || strings.Contains(s, "deadline"):
		return confllm.NewProviderError(confllm.CodeUpstreamTimeout, http.StatusGatewayTimeout, "百炼机密推理超时")
	default:
		return confllm.NewProviderError(confllm.CodeUpstreamError, http.StatusBadGateway, "百炼机密推理调用失败")
	}
}

// truncate 截断字符串（日志脱敏：限制上游错误串长度）。
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ---------- 离线验证 Fake（仅测试注入，不替代生产路径） ----------

// AliyunConfidentialClientFake 阿里云客户端离线验证用 Fake（仅验接口契约，不触真实 pai-cc/凭据）。
// 通过 NewAliyunProvider(cfg, WithSDKClient(fake)) 注入。
type AliyunConfidentialClientFake struct {
	lastChat     *confllm.ChatRequest
	fixed        *confllm.ChatResponse
	fail         bool
	failAttest   bool // 模拟远程证明失败 → 验证 fail-closed 红线
	lastAttested bool
}

// NewAliyunConfidentialClientFake 构造离线验证 Fake。
func NewAliyunConfidentialClientFake() *AliyunConfidentialClientFake {
	return &AliyunConfidentialClientFake{}
}

// SetFail 设置是否强制推理失败。
func (f *AliyunConfidentialClientFake) SetFail(v bool) { f.fail = v }

// SetFailAttest 设置是否模拟远程证明失败（fail-closed 验证用）。
func (f *AliyunConfidentialClientFake) SetFailAttest(v bool) { f.failAttest = v }

// LastChat 返回最近一次 Chat 请求（断言用）。
func (f *AliyunConfidentialClientFake) LastChat() *confllm.ChatRequest { return f.lastChat }

func (f *AliyunConfidentialClientFake) Chat(ctx context.Context, req *confllm.ChatRequest) (*confllm.ChatResponse, error) {
	if f.failAttest {
		return nil, confllm.NewProviderError(confllm.CodeUpstreamError, 502, "远程证明失败（fail-closed）")
	}
	if f.fail {
		return nil, confllm.NewProviderError(confllm.CodeUpstreamError, 502, "fake forced failure")
	}
	f.lastChat = req
	if f.fixed != nil {
		return f.fixed, nil
	}
	return &confllm.ChatResponse{
		ID:      "fake-aliyun",
		Object:  "chat.completion",
		Model:   req.Model,
		Choices: []confllm.Choice{{Index: 0, Message: confllm.Message{Role: "assistant", Content: "aliyun confidential mock"}, FinishReason: "stop"}},
		Usage:   confllm.Usage{PromptTokens: 1, CompletionTokens: 3, TotalTokens: 4},
	}, nil
}

func (f *AliyunConfidentialClientFake) Stream(ctx context.Context, req *confllm.ChatRequest) (confllm.StreamReader, error) {
	if f.failAttest {
		return nil, confllm.NewProviderError(confllm.CodeUpstreamError, 502, "远程证明失败（fail-closed）")
	}
	if f.fail {
		return nil, confllm.NewProviderError(confllm.CodeUpstreamError, 502, "fake forced failure")
	}
	return &memStreamReader{chunks: []*confllm.StreamChunk{
		{ID: "fake-aliyun", Object: "chat.completion.chunk", Model: req.Model, Choices: []confllm.StreamChoice{{Index: 0, Delta: confllm.Message{Role: "assistant", Content: "aliyun "}}}},
		{ID: "fake-aliyun", Object: "chat.completion.chunk", Model: req.Model, Choices: []confllm.StreamChoice{{Index: 0, Delta: confllm.Message{Content: "confidential"}}}},
	}}, nil
}

func (f *AliyunConfidentialClientFake) ListModels(ctx context.Context) ([]confllm.ModelInfo, error) {
	return []confllm.ModelInfo{{ID: "aliyun-confidential-model", OwnedBy: "aliyun"}}, nil
}

// Health：等级唯一事实源=meta（K7），Fake 不硬编码等级，返回 unknown。
func (f *AliyunConfidentialClientFake) Health(ctx context.Context) confllm.HealthStatus {
	if f.failAttest {
		return confllm.HealthStatus{Ready: false, Detail: "attestation-unreachable", MinConfidentialityClass: "unknown"}
	}
	return confllm.HealthStatus{Ready: true, MinConfidentialityClass: "unknown"}
}
