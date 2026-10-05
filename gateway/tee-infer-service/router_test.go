// 双路线路由测试。
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"security-ai-gateway/gateway/teecore"
	"security-ai-gateway/protocol/go"
	"security-ai-gateway/protocol/go/cryptoops"
)

// TestRouteConfigParse 路由配置解析。
func TestRouteConfigParse(t *testing.T) {
	cfg, err := ParseRouteConfig([]byte(`{
		"tenant": {"tenant-a": {"engine": "masked_vector", "attest": "quote"}},
		"model": {"qwen2.5-0.5b": {"engines": ["tee_gpu", "masked_vector"], "tier": "small"}},
		"default_engine": "tee_gpu",
		"require_quote": false
	}`))
	if err != nil {
		t.Fatal(err)
	}
	engines, attest, err := cfg.Resolve("tenant-a", "qwen2.5-0.5b")
	if err != nil {
		t.Fatal(err)
	}
	if len(engines) != 1 || engines[0] != "masked_vector" {
		t.Fatalf("租户覆盖失败: %v", engines)
	}
	if attest != "quote" {
		t.Fatalf("attest 应为 quote: %s", attest)
	}
	// 未知模型 → 缺省路线 1
	engines2, _, err := cfg.Resolve("other", "unknown-model")
	if err != nil {
		t.Fatal(err)
	}
	if engines2[0] != "tee_gpu" {
		t.Fatalf("缺省引擎应为 tee_gpu: %v", engines2)
	}
}

// TestRouteValidate engine_type 不匹配 fail-closed；token 模式生产拒绝。
func TestRouteValidate(t *testing.T) {
	cfg := DefaultRouteConfig()
	// 合法：mock 模型双路线
	if err := cfg.ValidateRequest("t1", "mock", "masked_vector", "quote"); err != nil {
		t.Fatalf("合法请求被拒: %v", err)
	}
	if err := cfg.ValidateRequest("t1", "mock", "", ""); err != nil {
		t.Fatalf("缺省请求被拒: %v", err)
	}
	// 未知引擎
	if err := cfg.ValidateRequest("t1", "mock", "cpu_plaintext", "quote"); err == nil {
		t.Fatal("未知引擎未被拒绝")
	}
	// 生产强制 quote：token 拒绝
	prod := DefaultRouteConfig()
	prod.RequireQuote = true
	if err := prod.ValidateRequest("t1", "mock", "tee_gpu", "token"); err == nil {
		t.Fatal("生产 token 模式未被拒绝")
	}
}

// TestDualRouteInferE2E 双路线 e2e：路线 1（tee_gpu）与路线 2（masked_vector）均走通。
func TestDualRouteInferE2E(t *testing.T) {
	_, ts := newM9Server(t)

	doInfer := func(engineType string) int {
		t.Helper()
		// 签发密钥（token 模式测试）
		keyBody, _ := json.Marshal(map[string]string{"model": "mock", "request_id": nextTestRequestID("dr")})
		keyReq, _ := http.NewRequest("POST", ts.URL+"/key/issue", bytes.NewReader(keyBody))
		keyReq.Header.Set("X-Attest-Token", testAttest)
		keyResp, err := http.DefaultClient.Do(keyReq)
		if err != nil {
			t.Fatal(err)
		}
		defer keyResp.Body.Close()
		var ki keyIssueResponse
		if err := json.NewDecoder(keyResp.Body).Decode(&ki); err != nil {
			t.Fatal(err)
		}
		seed, _ := hex.DecodeString(ki.Seed)
		nonceB, _ := hex.DecodeString(ki.Nonce)
		vec := []uint64{10, 20, 30}
		cv, err := maskVector(seed, maskModulus, vec)
		if err != nil {
			t.Fatal(err)
		}
		req := &protocol.InferenceRequest{
			RequestID:     nextTestRequestID("inf"),
			TimestampNS:   time.Now().UnixNano(),
			Model:         "mock",
			MaxNewTokens:  1,
			Nonce:         nonceB,
			CipherVectors: []protocol.CipherVector{{Data: cv}},
			EngineType:    engineType,
			AttestType:    protocol.AttestTypeToken,
		}
		cryptoops.SignRequest(bytes.Repeat([]byte{0x42}, 32), req)
		enc, _ := protocol.EncodeRequest(req)
		infReq, _ := http.NewRequest("POST", ts.URL+"/v1/infer", bytes.NewReader(enc))
		resp, err := http.DefaultClient.Do(infReq)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// 路线 1（缺省 tee_gpu 显式指定）→ 200
	if code := doInfer("tee_gpu"); code != 200 {
		t.Fatalf("路线 1 infer 返回 %d", code)
	}
	// 路线 2（masked_vector，mock 模型在注册表中）→ 200
	if code := doInfer("masked_vector"); code != 200 {
		t.Fatalf("路线 2 infer 返回 %d", code)
	}
	// 非法引擎 → 400（fail-closed）
	if code := doInfer("cpu_plaintext"); code != 400 {
		t.Fatalf("非法引擎应 400, got %d", code)
	}
}

// TestOrderedEnginesCostPolicy D-6 成本路由：按价格升序。
func TestOrderedEnginesCostPolicy(t *testing.T) {
	cfg := DefaultRouteConfig()
	cfg.Policy = "cost"
	got := cfg.OrderedEngines("mock")
	// mock Costs：cmaas 0.5 < masked_vector 1.5 < tee_gpu 3.0
	want := []string{protocol.EngineTypeCMAAS, protocol.EngineTypeMaskedVector, protocol.EngineTypeTEEGPU}
	assertEngineOrder(t, got, want)
}

// TestOrderedEnginesQualityPolicy 质量路由：按质量降序（tee_gpu 95 首选）。
func TestOrderedEnginesQualityPolicy(t *testing.T) {
	cfg := DefaultRouteConfig()
	cfg.Policy = "quality"
	got := cfg.OrderedEngines("mock")
	want := []string{protocol.EngineTypeTEEGPU, protocol.EngineTypeMaskedVector, protocol.EngineTypeCMAAS}
	assertEngineOrder(t, got, want)
}

// TestOrderedEnginesLatencyPolicy 延迟路由：按 P50 升序。
func TestOrderedEnginesLatencyPolicy(t *testing.T) {
	cfg := DefaultRouteConfig()
	cfg.Policy = "latency"
	got := cfg.OrderedEngines("mock")
	// tee_gpu 80 < masked_vector 120 < cmaas 200
	want := []string{protocol.EngineTypeTEEGPU, protocol.EngineTypeMaskedVector, protocol.EngineTypeCMAAS}
	assertEngineOrder(t, got, want)
}

// TestOrderedEnginesNoPolicy 缺省策略保持声明序（向后兼容，不改变既有行为）。
func TestOrderedEnginesNoPolicy(t *testing.T) {
	cfg := DefaultRouteConfig()
	got := cfg.OrderedEngines("mock")
	want := []string{protocol.EngineTypeTEEGPU, protocol.EngineTypeMaskedVector, protocol.EngineTypeCMAAS}
	assertEngineOrder(t, got, want)
}

// TestOrderedEnginesUnknownPolicy 未知策略保守保持声明序（防误路由）。
func TestOrderedEnginesUnknownPolicy(t *testing.T) {
	cfg := DefaultRouteConfig()
	cfg.Policy = "weird"
	got := cfg.OrderedEngines("mock")
	want := []string{protocol.EngineTypeTEEGPU, protocol.EngineTypeMaskedVector, protocol.EngineTypeCMAAS}
	assertEngineOrder(t, got, want)
}

// TestOrderedEnginesUnknownModel 未知模型回退缺省引擎单元素。
func TestOrderedEnginesUnknownModel(t *testing.T) {
	cfg := DefaultRouteConfig()
	got := cfg.OrderedEngines("no-such-model")
	if len(got) != 1 || got[0] != protocol.EngineTypeTEEGPU {
		t.Fatalf("未知模型应回退 [tee_gpu], got %v", got)
	}
}

// TestResolveEngineExplicitFailClosed 显式指定引擎不可用时 fail-closed（不静默降级）。
func TestResolveEngineExplicitFailClosed(t *testing.T) {
	srv, _ := newM9Server(t)
	if _, err := srv.engineFor(protocol.EngineTypeCMAAS); err == nil {
		t.Skip("测试环境已配置 cmaas，跳过 fail-closed 断言")
	}
	// 显式指定 cmaas 但未配置 → 必须返回 error（503），不得 failover 到 tee_gpu
	if _, _, err := srv.resolveEngineWithFailover("t1", "mock", protocol.EngineTypeCMAAS); err == nil {
		t.Fatal("显式指定 cmaas 未配置应 fail-closed，不得降级到其他引擎")
	}
}

// TestResolveEngineAutoFailover 自动择优（preferred 为空）时按成本顺序 failover。
func TestResolveEngineAutoFailover(t *testing.T) {
	srv, _ := newM9Server(t)
	// 默认无 cmaas：成本策略下首候选 cmaas 应被跳过，failover 到后续引擎
	srv.route.Policy = "cost"
	et, eng, err := srv.resolveEngineWithFailover("t1", "mock", "")
	if err != nil {
		t.Fatalf("自动择优 failover 应成功，但失败: %v", err)
	}
	// mock 成本排序：cmaas(0.5) < masked_vector(1.5) < tee_gpu(3.0)；
	// cmaas 未配置被跳过 → 应落到 masked_vector（engineFor 可服务）或 tee_gpu
	if et != protocol.EngineTypeMaskedVector && et != protocol.EngineTypeTEEGPU {
		t.Fatalf("failover 应落到可用引擎，got %q", et)
	}
	if eng == nil {
		t.Fatal("返回引擎不应为 nil")
	}
}

func assertEngineOrder(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("引擎顺序长度不匹配: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("引擎顺序不匹配（索引 %d）: got %v want %v", i, got, want)
		}
	}
}

func TestEngineTypeRouting(t *testing.T) {
	km, _ := teecore.NewKeyManager(0)
	req := &protocol.InferenceRequest{
		RequestID:     "et-001",
		TimestampNS:   time.Now().UnixNano(),
		Model:         "mock",
		MaxNewTokens:  1,
		Nonce:         []byte("n"),
		CipherVectors: []protocol.CipherVector{{Data: []uint64{1}}},
		EngineType:    protocol.EngineTypeMaskedVector,
		AttestType:    protocol.AttestTypeQuote,
	}
	km.Close()
	enc, _ := protocol.EncodeRequest(req)
	dec, err := protocol.DecodeRequest(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.EngineType != protocol.EngineTypeMaskedVector || dec.AttestType != protocol.AttestTypeQuote {
		t.Fatalf("协议字段传递失败: engine=%q attest=%q", dec.EngineType, dec.AttestType)
	}
}
