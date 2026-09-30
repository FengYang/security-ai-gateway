package route_test

import (
	"encoding/hex"
	"testing"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/routecache"
	"security-ai-gateway/gateway/gateway-core/internal/route"
)

// 用生产包真实结构做跨模块集成：gateway-core 签发 → JSON → 插件 routecache 验签+查询。
// 避免手工复制结构导致的字段名/tag 漂移。
func TestCrossModuleSignVerify(t *testing.T) {
	keyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatal(err)
	}

	// 网关侧签发
	signer, err := route.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	tbl := route.NewRouteTable(1, 1725500000)
	tbl.Routes = []route.TableRoute{
		{Tenant: "tenant-a", Model: "qwen-plus", DefaultEngine: "cmaas", FallbackEngine: "vllm", Target: ""},
	}
	if err := signer.SignTable(tbl); err != nil {
		t.Fatal(err)
	}
	t.Logf("客户端签名exp=%x", tbl.Signature)

	// 插件侧：用与 gateway-core 同构的 RouteTable 定义重新验签比对
	plugin := routecache.New(key)
	pt := &routecache.RouteTable{
		Version:   tbl.Version,
		UpdatedAt: tbl.UpdatedAt,
		Routes:    toPluginRoutes(tbl.Routes),
		Signature: tbl.Signature,
	}
	if !routecache.Verify(key, pt) {
		t.Fatalf("插件侧 verify() 失败：exp签名与 canon 不一致")
	}
	if !plugin.Update(pt) {
		t.Fatalf("插件 Update 失败")
	}
	if r := plugin.Lookup("tenant-a", "qwen-plus"); r == nil || r.DefaultEngine != "cmaas" {
		t.Fatalf("应为 cmaas, got %+v", r)
	}

	// 篡改引擎 → 插件拒绝
	tampered := pt
	tampered.Routes[0].DefaultEngine = "evil"
	if plugin.Update(tampered) {
		t.Fatal("篡改后的表应被拒绝")
	}
}

func toPluginRoutes(rs []route.TableRoute) []routecache.TableRoute {
	out := make([]routecache.TableRoute, len(rs))
	for i, r := range rs {
		eps := make([]routecache.TableEndpoint, len(r.Endpoints))
		for j, ep := range r.Endpoints {
			eps[j] = routecache.TableEndpoint{
				Name: ep.Name, URL: ep.URL, Weight: ep.Weight,
				Priority: ep.Priority, Enabled: ep.Enabled,
				Auth: routecache.EndpointAuth{
					Type: ep.Auth.Type, SecretRef: ep.Auth.SecretRef,
				},
			}
		}
		tenants := make([]string, len(r.Canary.AllowedTenants))
		copy(tenants, r.Canary.AllowedTenants)
		out[i] = routecache.TableRoute{
			Tenant: r.Tenant, Model: r.Model, DefaultEngine: r.DefaultEngine,
			FallbackEngine: r.FallbackEngine, Target: r.Target,
			Endpoints: eps, Strategy: r.Strategy,
			Canary: routecache.RouteCanary{
				Enabled: r.Canary.Enabled, TargetEndpoint: r.Canary.TargetEndpoint,
				TargetWeight: r.Canary.TargetWeight, RampStep: r.Canary.RampStep,
				RampIntervalMs: r.Canary.RampIntervalMs,
				RollbackThreshold: r.Canary.RollbackThreshold,
				RollbackMinSamples: r.Canary.RollbackMinSamples,
				AllowedTenants: tenants,
			},
		}
	}
	return out
}