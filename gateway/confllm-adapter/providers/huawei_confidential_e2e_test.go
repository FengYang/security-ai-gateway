package providers

import (
	"context"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"security-ai-gateway/gateway/confllm-adapter"
)

// TestHuaweiConfidentialRealE2E 真机冒烟（评审验证补强 R3）。
//
// 受 HW_REAL_E2E=1 门控，否则 t.Skip（待环境就绪）。读取：
//   - HW_ENDPOINT        ：ModelArts 托管推理 endpoint（含 confidential_inference 配置）
//   - HW_X_AUTH_TOKEN    ：IAM Token（生产环境由华为 AK/SK 换取，此处直接使用现场提供的 Token）
//   - HW_MODEL（可选）   ：模型名，默认 deepseek-v4-flash
//
// 因本包 TestMain 将 http.DefaultTransport / net.DefaultResolver 替换为离线守卫，本测试在运行前临时
// 恢复真实网络栈。运行后无需还原：其余测试均使用各自注入的 offlineClient（不受影响），且 TestMain 的零出网
// 断言仅统计 mock.OfflineTransport 实例，本测试不发往 mock，故不误增计数。
func TestHuaweiConfidentialRealE2E(t *testing.T) {
	if os.Getenv("HW_REAL_E2E") != "1" {
		t.Skip("HW_REAL_E2E 未置 1，跳过真机冒烟（待环境就绪）")
	}
	endpoint := os.Getenv("HW_ENDPOINT")
	token := os.Getenv("HW_X_AUTH_TOKEN")
	if endpoint == "" || token == "" {
		t.Fatal("HW_ENDPOINT 与 HW_X_AUTH_TOKEN 必须同时设置")
	}
	model := os.Getenv("HW_MODEL")
	if model == "" {
		model = "deepseek-v4-flash"
		t.Logf("HW_MODEL 未设置，使用默认 %q", model)
	}

	// 临时恢复真实网络（绕过 TestMain 离线守卫）
	http.DefaultTransport = &http.Transport{}
	net.DefaultResolver = &net.Resolver{}

	client := &http.Client{Transport: &http.Transport{}, Timeout: 30 * time.Second}
	p, err := NewHuaweiProvider(confllm.ProviderConfig{ID: "hw-e2e", Endpoint: endpoint},
		confllm.WithHTTPClient(client),
		confllm.WithStaticCredential(&confllm.Credential{Key: []byte(token)}))
	if err != nil {
		t.Fatalf("构造 huawei-confidential 失败：%v", err)
	}
	resp, err := p.Chat(context.Background(), &confllm.ChatRequest{
		Model:    model,
		Messages: []confllm.Message{{Role: "user", Content: "ping"}},
	})
	if err != nil {
		t.Fatalf("真机 Chat 失败：%v", err)
	}
	if len(resp.Choices) == 0 {
		t.Fatal("真机 Chat 响应无 choices")
	}
	t.Logf("HW e2e OK: model=%s choices=%d", resp.Model, len(resp.Choices))
}
