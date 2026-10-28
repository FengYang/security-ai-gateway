// Package confllm_test — provider 类型注册清单测试（防漏注册的回归网）。
//
// 背景（本次验收评审发现的阻断级缺陷）：providers/azure.go 全文无 init()，
// 导致 NewFromConfig{Type:"azure"} 报「未注册 provider 类型」、装配必失败；
// 其余 11 家均有 init() 注册（tencent.go / volcengine.go / gcp.go / aws.go …）。
// 漏注册在编译期静默无声（工厂函数存在即通过编译），只能靠运行期清单测试兜住。
//
// 断言（缺一即失败）：
//  1. 12 个类型键在 confllm.GlobalRegistry 中**已注册**（NewFromConfig 不报「未注册」）；
//  2. 每个类型键**可构造**（工厂返回非 nil 实例、无 error、ID() 与 cfg.ID 一致）；
//  3. 负向：未注册的类型键必须报错（证明清单断言本身有效，非空跑）。
//
// 全程离线（P0-5 离线纪律）：HTTP 型注入 mock.NewOfflineTransport + 静态凭据，
// SDK 型注入 *Fake 客户端。
package confllm_test

import (
	"net/http"
	"strings"
	"testing"

	confllm "security-ai-gateway/gateway/confllm-adapter"
	"security-ai-gateway/gateway/confllm-adapter/mock"
	"security-ai-gateway/gateway/confllm-adapter/providers"
)

// registeredTypeKeys 必须全部注册的 12 个类型键（装配契约，新增厂商须同步登记）。
var registeredTypeKeys = []string{
	"tencent",
	"volcengine",
	"nearai",
	"privatemode",
	"azure",
	"gcp",
	"aws",
	"aliyun-confidential",
	"aliyun-bailian",
	"huawei-confidential",
	"huawei-maas",
	"mobilecloud",
}

// offlineProviderOptions 离线构造选项（HTTP 型：离线 Transport + 静态凭据）。
func offlineProviderOptions() []confllm.ProviderOption {
	return []confllm.ProviderOption{
		confllm.WithHTTPClient(&http.Client{Transport: mock.NewOfflineTransport()}),
		confllm.WithStaticCredential(&confllm.Credential{Key: []byte("registry-manifest-test-key")}),
	}
}

// TestProviderTypeRegistryManifest 【防漏注册】12 个类型键全部已注册且可构造。
func TestProviderTypeRegistryManifest(t *testing.T) {
	if len(registeredTypeKeys) != 12 {
		t.Fatalf("清单本身应含 12 个类型键，实际 %d（新增厂商须同步登记）", len(registeredTypeKeys))
	}
	for _, typ := range registeredTypeKeys {
		typ := typ
		t.Run(typ, func(t *testing.T) {
			cfg := confllm.ProviderConfig{Type: typ, ID: "manifest-" + typ}
			opts := offlineProviderOptions()
			// SDK 型（阿里 CAI / 华为密态 SDK）以 *Fake 注入，绝不触真实 SDK 与网络。
			switch typ {
			case "aliyun-confidential":
				opts = append(opts, confllm.WithSDKClient(providers.NewAliyunConfidentialClientFake()))
			case "huawei-confidential":
				opts = append(opts, confllm.WithSDKClient(providers.NewHuaweiConfidentialClientFake()))
			}
			p, err := confllm.GlobalRegistry.NewFromConfig(cfg, opts...)
			if err != nil {
				t.Fatalf("类型 %q 未注册或构造失败（漏注册 = 装配必失败）：%v", typ, err)
			}
			if p == nil {
				t.Fatalf("类型 %q 工厂返回 nil 实例", typ)
			}
			if p.ID() != cfg.ID {
				t.Fatalf("类型 %q 实例 ID=%q 期望 %q", typ, p.ID(), cfg.ID)
			}
			// 密态四字段必须已归一（不得空串：wire 层禁 omitempty，空串即举证失败）。
			m := p.Metadata()
			for k, v := range map[string]string{
				"confidentialityClass": m.ConfidentialityClass,
				"attestation":          m.Attestation,
				"dataRetention":        m.DataRetention,
				"deployment":           m.Deployment,
			} {
				if v == "" {
					t.Fatalf("类型 %q 构造后 meta.%s 为空串（应归一为 unknown）", typ, k)
				}
			}
		})
	}
}

// TestProviderTypeRegistryManifestNegative 【负向】未注册类型键必须报错（清单断言非空跑）。
func TestProviderTypeRegistryManifestNegative(t *testing.T) {
	const absent = "no-such-provider-type"
	for _, typ := range registeredTypeKeys {
		if typ == absent {
			t.Fatalf("负向用例类型 %q 不应出现在清单中", absent)
		}
	}
	_, err := confllm.GlobalRegistry.NewFromConfig(confllm.ProviderConfig{Type: absent, ID: "x"})
	if err == nil {
		t.Fatalf("未注册类型 %q 应报错，实际构造成功（清单断言失效）", absent)
	}
	if !strings.Contains(err.Error(), "未注册 provider 类型") {
		t.Fatalf("未注册类型的错误文案不符，实际：%v", err)
	}
}
