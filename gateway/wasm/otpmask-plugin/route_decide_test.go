package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"
	"time"

	"security-ai-gateway/gateway/rxroute"
	"security-ai-gateway/gateway/rxroute/rxsign"
	"security-ai-gateway/gateway/wasm/otpmask-plugin/routecache"
)

// route_decide_test.go — §6 降级阶梯的纯逻辑用例（decideRoute 无 hostcall，宿主可测）。

func routeKey() []byte { return []byte("0123456789abcdef0123456789abcdef") }

// testTableVerifier 同步 HMAC-SHA256 验签接缝（单测专用；crypto/* 仅测试允许）。
// 生产路径由插件注入经 cryptop sidecar 的 sidecarTableVerifier（§4.7），语义等价。
type testTableVerifier struct{ key []byte }

func (v testTableVerifier) VerifySym(_ string, data, sig []byte, cb func(ok bool, err error)) {
	m := hmac.New(sha256.New, v.key)
	_, _ = m.Write(data)
	cb(hmac.Equal(sig, m.Sum(nil)), nil)
}

// signTableForTest / newRouteCacheForTest / updateRouteCacheSync 单测接缝辅助。
func signTableForTest(key []byte, t *routecache.RouteTable) {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(t.CanonicalBytes())
	t.Signature = m.Sum(nil)
}

func newRouteCacheForTest(key []byte) *routecache.Cache {
	return routecache.New(testTableVerifier{key: key}, "")
}

func newRouteCacheForTestOpts(key []byte, opt routecache.Options) *routecache.Cache {
	return routecache.NewWithOptions(testTableVerifier{key: key}, "", opt)
}

func updateRouteCacheSync(c *routecache.Cache, t *routecache.RouteTable) bool {
	var ok bool
	c.Update(t, func(a bool) { ok = a })
	return ok
}

// signedTable 构造已签名的默认路由表（tenant-a/qwen-plus → cmaas）。
func signedTable(version int, updatedAt int64) *routecache.RouteTable {
	t := &routecache.RouteTable{Version: version, UpdatedAt: updatedAt, Routes: []routecache.TableRoute{
		{Tenant: "tenant-a", Model: "qwen-plus", DefaultEngine: "cmaas", Target: "https://cmaas.local"},
	}}
	signTableForTest(routeKey(), t)
	return t
}

// TestDecideRouteL1Prescription 处方有效且带 preferred_engine → L1，不降级、不 fail-closed。
func TestDecideRouteL1Prescription(t *testing.T) {
	now := time.Unix(1725500000, 0)
	c := newRouteCacheForTest(routeKey())
	updateRouteCacheSync(c, signedTable(1, now.Unix()))

	signer, err := rxsign.NewSigner(routeKey())
	if err != nil {
		t.Fatal(err)
	}
	tok, err := signer.Issue(&rxroute.RoutePrescription{
		Tenant: "tenant-a", Model: "qwen-plus", CreatedAt: now.Unix(),
		Policy: &rxroute.RoutePolicy{PreferredEngine: "yrproxy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// 验签（生产路径由 verifyPrescriptionAsync 经 sidecar 完成；此处直接调 rxsign，语义等价）。
	p, err := rxsign.VerifyWith(routeKey(), tok, now)
	if err != nil {
		t.Fatalf("处方应验签通过：%v", err)
	}
	d, rxErr, failReason := decideRoute(c, "tenant-a", "qwen-plus", p.Policy.PreferredEngine, nil, now)
	if rxErr != nil {
		t.Fatalf("不应有验签错误：%v", rxErr)
	}
	if failReason != "" {
		t.Fatalf("不应 fail-closed：%s", failReason)
	}
	if d.Source != routecache.SourcePrescription || d.Engine != "yrproxy" || d.Degraded {
		t.Fatalf("应为 L1 不降级且引擎 yrproxy，got %+v", d)
	}
}

// TestDecideRouteL2Degraded 无处方（或处方无效）→ 降级 L2，且不 fail-closed。
func TestDecideRouteL2Degraded(t *testing.T) {
	now := time.Unix(1725500000, 0)
	c := newRouteCacheForTest(routeKey())
	updateRouteCacheSync(c, signedTable(1, now.Unix()))

	// 无处方
	d, _, failReason := decideRoute(c, "tenant-a", "qwen-plus", "", nil, now)
	if failReason != "" {
		t.Fatalf("L2 命中不应 fail-closed：%s", failReason)
	}
	if d.Source != routecache.SourceCache || !d.Degraded || d.Engine != "cmaas" || d.Target != "https://cmaas.local" {
		t.Fatalf("应降级 L2 用缓存路由，got %+v", d)
	}

	// 处方签名无效 → 同样降级 L2（处方问题不直接拒绝）
	_, verr := rxsign.VerifyWith(routeKey(), "a.b.c", now)
	if verr == nil {
		t.Fatal("伪造处方应验签失败")
	}
	d2, rxErr, failReason2 := decideRoute(c, "tenant-a", "qwen-plus", "", verr, now)
	if rxErr == nil {
		t.Fatal("处方无效应传回 rxErr（供日志）")
	}
	if failReason2 != "" || d2.Source != routecache.SourceCache {
		t.Fatalf("处方无效应降级 L2 而非 fail-closed，got %+v reason=%s", d2, failReason2)
	}
}

// TestDecideRouteFailClosed 无处方且缓存未命中 → 密态 fail-closed（§6：密态语义不可降级）。
func TestDecideRouteFailClosed(t *testing.T) {
	now := time.Unix(1725500000, 0)
	c := newRouteCacheForTest(routeKey()) // 空缓存

	d, _, failReason := decideRoute(c, "tenant-a", "qwen-plus", "", nil, now)
	if failReason == "" {
		t.Fatal("无路由必须 fail-closed")
	}
	if d.Source != routecache.SourceNone {
		t.Fatalf("应为 SourceNone，got %+v", d)
	}
}

// TestDecideRouteStaleFailClosed 缓存超 max_stale → 按未命中处理并 fail-closed（不静默用陈旧路由）。
func TestDecideRouteStaleFailClosed(t *testing.T) {
	base := time.Unix(1725500000, 0)
	c := newRouteCacheForTestOpts(routeKey(), routecache.Options{
		MaxStale: 60 * time.Second,
		Now:      func() time.Time { return base.Add(61 * time.Second) },
	})
	updateRouteCacheSync(c, signedTable(1, base.Unix()))

	d, _, failReason := decideRoute(c, "tenant-a", "qwen-plus", "", nil, base.Add(61*time.Second))
	if failReason == "" || !d.Stale {
		t.Fatalf("超 max_stale 应 fail-closed 且标记 Stale，got %+v reason=%q", d, failReason)
	}
}
