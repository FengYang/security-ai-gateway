package route_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"security-ai-gateway/gateway/gateway-core/internal/route"
	"security-ai-gateway/gateway/wasm/otpmask-plugin/routecache"
)

// testRouteVerifier 同步 HMAC-SHA256 验签接缝（单测专用；生产由插件注入经 cryptop sidecar 的实现，§4.7）。
type testRouteVerifier struct{ key []byte }

func (v testRouteVerifier) VerifySym(_ string, data, sig []byte, cb func(ok bool, err error)) {
	m := hmac.New(sha256.New, v.key)
	_, _ = m.Write(data)
	cb(hmac.Equal(sig, m.Sum(nil)), nil)
}

func verifyRouteTable(v routecache.Verifier, t *routecache.RouteTable) bool {
	var ok bool
	v.VerifySym("", t.CanonicalBytes(), t.Signature, func(a bool, _ error) { ok = a })
	return ok
}

func updateRouteCache(c *routecache.Cache, t *routecache.RouteTable) bool {
	var ok bool
	c.Update(t, func(a bool) { ok = a })
	return ok
}

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
	verifier := testRouteVerifier{key: key}
	plugin := routecache.New(verifier, "")
	pt := &routecache.RouteTable{
		Version:   tbl.Version,
		UpdatedAt: tbl.UpdatedAt,
		Routes:    toPluginRoutes(tbl.Routes),
		Signature: tbl.Signature,
	}
	if !verifyRouteTable(verifier, pt) {
		t.Fatalf("插件侧 verify() 失败：exp签名与 canon 不一致")
	}
	if !updateRouteCache(plugin, pt) {
		t.Fatalf("插件 Update 失败")
	}
	if r := plugin.Lookup("tenant-a", "qwen-plus"); r == nil || r.DefaultEngine != "cmaas" {
		t.Fatalf("应为 cmaas, got %+v", r)
	}

	// 篡改引擎 → 插件拒绝
	tampered := pt
	tampered.Routes[0].DefaultEngine = "evil"
	if updateRouteCache(plugin, tampered) {
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
		out[i] = routecache.TableRoute{
			Tenant: r.Tenant, Model: r.Model, DefaultEngine: r.DefaultEngine,
			FallbackEngine: r.FallbackEngine, Target: r.Target,
			Endpoints: eps, Strategy: r.Strategy,
		}
		if r.Canary != nil {
			tenants := make([]string, len(r.Canary.AllowedTenants))
			copy(tenants, r.Canary.AllowedTenants)
			out[i].Canary = &routecache.RouteCanary{
				Enabled: r.Canary.Enabled, TargetEndpoint: r.Canary.TargetEndpoint,
				TargetWeight: r.Canary.TargetWeight, RampStep: r.Canary.RampStep,
				RampIntervalMs: r.Canary.RampIntervalMs,
				RollbackThreshold: r.Canary.RollbackThreshold,
				RollbackMinSamples: r.Canary.RollbackMinSamples,
				AllowedTenants:     tenants,
			}
		}
	}
	return out
}