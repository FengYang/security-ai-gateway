package routecache

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

func testKey() []byte { return []byte("0123456789abcdef0123456789abcdef") }

func sign(key []byte, t *RouteTable) {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(t.canon())
	t.Signature = h.Sum(nil)
}

func validTable(version int) *RouteTable {
	return &RouteTable{Version: version, UpdatedAt: 1725500000, Routes: []TableRoute{
		{Tenant: "tenant-a", Model: "qwen-plus", DefaultEngine: "cmaas", FallbackEngine: "vllm"},
	}}
}

func TestUpdateAndLookup(t *testing.T) {
	c := New(testKey())
	tbl := validTable(1)
	sign(testKey(), tbl)
	if !c.Update(tbl) {
		t.Fatal("合法表应接受")
	}
	if c.Version() != 1 {
		t.Fatalf("版本应为 1，got %d", c.Version())
	}
	r := c.Lookup("tenant-a", "qwen-plus")
	if r == nil || r.DefaultEngine != "cmaas" {
		t.Fatalf("应命中 cmaas，got %+v", r)
	}
	if r := c.Lookup("tenant-a", "missing"); r != nil {
		t.Fatalf("未知 model 应 nil")
	}
}

func TestRejectBadSignature(t *testing.T) {
	c := New(testKey())
	// 用错误密钥签名
	tbl := validTable(1)
	sign([]byte("00000000000000000000000000000000"), tbl)
	if c.Update(tbl) {
		t.Fatal("签名无效的表应拒绝")
	}
	if c.Version() != 0 {
		t.Fatal("拒绝后缓存应为空")
	}
}

func TestRejectRollback(t *testing.T) {
	c := New(testKey())
	for _, v := range []int{3, 2, 1, 5, 4} {
		tbl := validTable(v)
		sign(testKey(), tbl)
		c.Update(tbl)
	}
	if c.Version() != 5 {
		t.Fatalf("缓存应保留最高版本 5，got %d", c.Version())
	}
}

func TestTamperedRejected(t *testing.T) {
	c := New(testKey())
	tbl := validTable(1)
	sign(testKey(), tbl)
	tbl.Routes[0].DefaultEngine = "evil"
	// 篡改后未重新签名
	if c.Update(tbl) {
		t.Fatal("篡改后未重签应拒绝")
	}
}

func TestDecidePriority(t *testing.T) {
	c := New(testKey())
	tbl := validTable(3) // tenant-a/qwen-plus -> cmaas
	sign(testKey(), tbl)
	c.Update(tbl)

	// L1 处方引擎优先
	if d := c.Decide("tenant-a", "qwen-plus", "yrproxy"); d.Engine != "yrproxy" || d.Target != "" {
		t.Fatalf("处方引擎应优先，got %+v", d)
	}
	// 无处方 → L2 缓存
	if d := c.Decide("tenant-a", "qwen-plus", ""); d.Engine != "cmaas" {
		t.Fatalf("应回退缓存 default cmaas，got %+v", d)
	}
	// 未命中 → 零值
	if d := c.Decide("nope", "nope", ""); d.Engine != "" || d.Target != "" {
		t.Fatalf("未命中应返回零值，got %+v", d)
	}
}