package confllm

import (
	"context"
	"testing"

	"security-ai-gateway/gateway/confllm-adapter/meta"
)

func TestSatisfiesMin(t *testing.T) {
	// min 为空 → 全放行（含 unknown）。
	if !SatisfiesMin(meta.ClassUnknown, "") {
		t.Fatal("空 min 应放行 unknown")
	}
	if !SatisfiesMin(meta.ClassA, "") {
		t.Fatal("空 min 应放行 A")
	}
	// unknown 对任意 min 不可信。
	if SatisfiesMin(meta.ClassUnknown, meta.ClassA) {
		t.Fatal("unknown 不应满足 A")
	}
	// 等级比较（min 为下限门槛：B 高于 C，故 B 满足 min=C）。
	if !SatisfiesMin(meta.ClassB, meta.ClassC) {
		t.Fatal("B 应满足 min=C（B 高于 C，min 为下限门槛）")
	}
	if SatisfiesMin(meta.ClassC, meta.ClassB) {
		t.Fatal("C 不应满足 min=B（C 低于 B）")
	}
	if !SatisfiesMin(meta.ClassA, meta.ClassB) {
		t.Fatal("A 应满足 B")
	}
	if !SatisfiesMin(meta.ClassB, meta.ClassB) {
		t.Fatal("同级应满足")
	}
	// 未登记等级不可信。
	if SatisfiesMin("Z", meta.ClassA) {
		t.Fatal("未登记等级不应满足 A")
	}
}

// fakeMetaProvider 路由过滤测试用最小实现（仅 Metadata 有效）。
type fakeMetaProvider struct{ cls string }

func (f fakeMetaProvider) ID() string     { return "x" }
func (f fakeMetaProvider) Region() Region { return RegionDomestic }
func (f fakeMetaProvider) Metadata() ConfidentialityMeta {
	return ConfidentialityMeta{ConfidentialityClass: f.cls}
}
func (f fakeMetaProvider) Capabilities() Capabilities { return Capabilities{} }
func (f fakeMetaProvider) Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	return nil, nil
}
func (f fakeMetaProvider) Stream(ctx context.Context, req *ChatRequest) (StreamReader, error) {
	return nil, nil
}
func (f fakeMetaProvider) ListModels(ctx context.Context) ([]ModelInfo, error) { return nil, nil }
func (f fakeMetaProvider) Health(ctx context.Context) HealthStatus             { return HealthStatus{} }

func TestFilterProviders(t *testing.T) {
	providers := []ConfidentialLLMProvider{
		fakeMetaProvider{cls: meta.ClassA},
		fakeMetaProvider{cls: meta.ClassB},
		fakeMetaProvider{cls: meta.ClassUnknown},
	}
	all, err := FilterProviders(providers, "")
	if err != nil || len(all) != 3 {
		t.Fatalf("空 min 应返回全部：%v", err)
	}
	a, err := FilterProviders(providers, meta.ClassA)
	if err != nil || len(a) != 1 {
		t.Fatalf("min=A 应只剩 1 个：%v len=%d", err, len(a))
	}
	if a[0].Metadata().ConfidentialityClass != meta.ClassA {
		t.Fatal("过滤结果应为 A")
	}
	// min=C 为最低门槛 → A、B 均满足（仅 unknown 被排除）。
	c, err := FilterProviders(providers, meta.ClassC)
	if err != nil || len(c) != 2 {
		t.Fatalf("min=C 应剩 2 个（A/B 均高于 C）：%v len=%d", err, len(c))
	}
	// 无满足项 → 报错（非静默降级）：未登记等级对所有候选均不成立。
	if _, err := FilterProviders(providers, "Z"); err == nil {
		t.Fatal("min=Z 无满足项应报错（非静默降级）")
	}
}
