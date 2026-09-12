package main

import (
	"testing"
	"time"

	"security-ai-gateway/gateway/rxroute"
	"security-ai-gateway/gateway/wasm/otpmask-plugin/routecache"
)

// route_decide_test.go — §6 降级阶梯的纯逻辑用例（decideRoute 无 hostcall，宿主可测）。

func routeKey() []byte { return []byte("0123456789abcdef0123456789abcdef") }

// signedTable 构造已签名的默认路由表（tenant-a/qwen-plus → cmaas）。
func signedTable(version int, updatedAt int64) *routecache.RouteTable {
	t := &routecache.RouteTable{Version: version, UpdatedAt: updatedAt, Routes: []routecache.TableRoute{
		{Tenant: "tenant-a", Model: "qwen-plus", DefaultEngine: "cmaas", Target: "https://cmaas.local"},
	}}
	routecache.Sign(routeKey(), t)
	return t
}

// TestDecideRouteL1Prescription 处方有效且带 preferred_engine → L1，不降级、不 fail-closed。
func TestDecideRouteL1Prescription(t *testing.T) {
	now := time.Unix(1725500000, 0)
	c := routecache.New(routeKey())
	c.Update(signedTable(1, now.Unix()))

	signer, err := rxroute.NewSigner(routeKey())
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
	d, rxErr, failReason := decideRoute(c, routeKey(), "tenant-a", "qwen-plus", tok, now)
	if rxErr != nil {
		t.Fatalf("处方应验签通过：%v", rxErr)
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
	c := routecache.New(routeKey())
	c.Update(signedTable(1, now.Unix()))

	// 无处方
	d, _, failReason := decideRoute(c, routeKey(), "tenant-a", "qwen-plus", "", now)
	if failReason != "" {
		t.Fatalf("L2 命中不应 fail-closed：%s", failReason)
	}
	if d.Source != routecache.SourceCache || !d.Degraded || d.Engine != "cmaas" || d.Target != "https://cmaas.local" {
		t.Fatalf("应降级 L2 用缓存路由，got %+v", d)
	}

	// 处方签名无效 → 同样降级 L2（处方问题不直接拒绝）
	d2, rxErr, failReason2 := decideRoute(c, routeKey(), "tenant-a", "qwen-plus", "a.b.c", now)
	if rxErr == nil {
		t.Fatal("伪造处方应验签失败")
	}
	if failReason2 != "" || d2.Source != routecache.SourceCache {
		t.Fatalf("处方无效应降级 L2 而非 fail-closed，got %+v reason=%s", d2, failReason2)
	}
}

// TestDecideRouteFailClosed 无处方且缓存未命中 → 密态 fail-closed（§6：密态语义不可降级）。
func TestDecideRouteFailClosed(t *testing.T) {
	now := time.Unix(1725500000, 0)
	c := routecache.New(routeKey()) // 空缓存

	d, _, failReason := decideRoute(c, routeKey(), "tenant-a", "qwen-plus", "", now)
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
	c := routecache.NewWithOptions(routeKey(), routecache.Options{
		MaxStale: 60 * time.Second,
		Now:      func() time.Time { return base.Add(61 * time.Second) },
	})
	c.Update(signedTable(1, base.Unix()))

	d, _, failReason := decideRoute(c, routeKey(), "tenant-a", "qwen-plus", "", base.Add(61*time.Second))
	if failReason == "" || !d.Stale {
		t.Fatalf("超 max_stale 应 fail-closed 且标记 Stale，got %+v reason=%q", d, failReason)
	}
}
