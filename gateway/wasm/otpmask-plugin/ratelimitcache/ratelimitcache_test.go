package ratelimitcache

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// testVerifier 同步 HMAC-SHA256 验签接缝（单测专用；crypto/* 仅测试允许）。
// 生产路径由插件注入经 cryptop sidecar 的实现（§4.7），语义等价（同步交付）。
type testVerifier struct{ key []byte }

func (v testVerifier) VerifySym(_ string, data, sig []byte, cb func(ok bool, err error)) {
	m := hmac.New(sha256.New, v.key)
	_, _ = m.Write(data)
	cb(hmac.Equal(sig, m.Sum(nil)), nil)
}

func sign(key []byte, t *Table) {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(t.canon())
	t.Signature = m.Sum(nil)
}

func newTestCache(key []byte) *Cache { return New(testVerifier{key: key}, "") }

func updateSync(c *Cache, t *Table) bool {
	var ok bool
	c.Update(t, func(a bool) { ok = a })
	return ok
}

func verifySync(key []byte, t *Table) bool {
	var ok bool
	testVerifier{key: key}.VerifySym("", t.canon(), t.Signature, func(a bool, _ error) { ok = a })
	return ok
}

// TestCanonFixtureFromExternalSigner 锁定"控制面签发端（gateway-core）↔ 本包 canon 编码"契约。
//
// 背景：本包与管理面的 `internal/ratelimit` 故意不共享代码（插件不能 import 控制面 internal 包），
// 若 canon 不一致，拉取会被**静默拒绝**（保留空表/旧表），在容器里只看到"拉取成功但不生效"。
// 本用例把该契约变成可离线判定的事实。
//
// 固定向量：version=2, issued_at=2026-09-13T10:00:00Z,
// rules=[{id:t-a-rate, kind:rate, scope:tenant, target:t-a, rpm:600, action:reject, enabled:true}]
// 规范字节（PS 打印，与 gateway-core Table.CanonicalBytes 同形）：
//
//	{"version":2,"issued_at":"2026-09-13T10:00:00Z","rules":[{"id":"t-a-rate","kind":"rate","scope":"tenant","target":"t-a","rpm":600,"action":"reject","enabled":true}]}
//
// 签名：HMAC-SHA256（key = hex 解码的 32 字节 K_rx），由 **PowerShell + .NET** 独立实现算出。
func TestCanonFixtureFromExternalSigner(t *testing.T) {
	key, err := hex.DecodeString("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString("A7MO9AAKzn7aY75p9u4NWqxESdMY627jO1UfyeDCe5c=")
	if err != nil {
		t.Fatal(err)
	}
	tbl := &Table{
		Version:  2,
		IssuedAt: "2026-09-13T10:00:00Z",
		Rules: []Rule{
			{ID: "t-a-rate", Kind: "rate", Scope: "tenant", Target: "t-a", RPM: 600, Action: "reject", Enabled: true},
		},
		Signature: sig,
	}
	t.Logf("本包 canon = %s", string(tbl.canon()))
	if !verifySync(key, tbl) {
		t.Fatalf("外部签名与本包 canon 不匹配（gateway-core CanonicalBytes 须与本包逐字节一致）\n本包 canon = %s", string(tbl.canon()))
	}
	// 篡改规则内容 → 验签必败（防"签名与内容脱钩"）
	tampered := *tbl
	tampered.Rules = []Rule{{ID: "t-a-rate", Kind: "rate", Scope: "tenant", Target: "t-a", RPM: 6000, Action: "reject", Enabled: true}}
	if verifySync(key, &tampered) {
		t.Fatal("篡改后应验签失败")
	}
}

// TestUpdateAntiRollback Cache 准入：验签 + 版本严格递增（重复/回退拒绝，保留旧表）。
func TestUpdateAntiRollback(t *testing.T) {
	key, _ := hex.DecodeString("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	c := newTestCache(key)
	if c.Loaded() || c.Version() != 0 {
		t.Fatalf("初始应无表: loaded=%v version=%d", c.Loaded(), c.Version())
	}

	mk := func(version int, rpm int64) *Table {
		t := &Table{Version: version, IssuedAt: "2026-09-13T10:00:00Z", Rules: []Rule{
			{ID: "t-a-rate", Kind: "rate", Scope: "tenant", Target: "t-a", RPM: rpm, Action: "reject", Enabled: true},
		}}
		sign(key, t)
		return t
	}
	if !updateSync(c, mk(2, 600)) || c.Version() != 2 || len(c.Rules()) != 1 {
		t.Fatalf("首次入缓存应成功: version=%d", c.Version())
	}
	// 同版本 → 拒绝（防同版本内容漂移）
	if updateSync(c, mk(2, 1200)) || c.Version() != 2 {
		t.Fatalf("同版本应拒绝: version=%d rules=%+v", c.Version(), c.Rules())
	}
	// 版本回退 → 拒绝并**保留旧表**
	if updateSync(c, mk(1, 60)) || c.Version() != 2 {
		t.Fatalf("版本回退应拒绝并保留旧表: version=%d", c.Version())
	}
	// 更高版本 → 接受
	if !updateSync(c, mk(3, 1200)) || c.Version() != 3 {
		t.Fatalf("更高版本应接受: version=%d", c.Version())
	}
	// 验签失败 → 拒绝（保留旧表）
	bad := mk(4, 60)
	bad.Signature[0] ^= 0xFF
	if updateSync(c, bad) || c.Version() != 3 {
		t.Fatalf("验签失败应拒绝: version=%d", c.Version())
	}
}
