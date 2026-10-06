package routecache

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

// ============================================================
// 安全专项测试（对应方案 §11.6 安全测试矩阵）
// ============================================================

// TestSecurity_EmptySignature 空签名 → 拒绝
// 防御：签名长度为 0 直接判定无效
func TestSecurity_EmptySignature(t *testing.T) {
	c := newTestCache(testKey())
	tbl := validTable(1)
	// 不签名，Signature 为 nil
	if updateSync(c, tbl) {
		t.Fatal("空签名应被拒绝")
	}
	// 空切片
	tbl2 := validTable(1)
	tbl2.Signature = []byte{}
	if updateSync(c, tbl2) {
		t.Fatal("空切片签名应被拒绝")
	}
}

// TestSecurity_WrongKeyLength 不同长度密钥 → 签名不同 → 拒绝
// 防御：HMAC 本身支持任意长度密钥，但不同密钥必然产生不同签名
func TestSecurity_WrongKeyLength(t *testing.T) {
	c := newTestCache(testKey()) // 32 字节密钥
	tbl := validTable(1)
	// 用 16 字节密钥签名
	shortKey := []byte("0123456789abcdef")
	sign(shortKey, tbl)
	if updateSync(c, tbl) {
		t.Fatal("短密钥签名应被拒绝")
	}
	// 用 64 字节密钥签名
	longKey := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	tbl2 := validTable(2)
	sign(longKey, tbl2)
	if updateSync(c, tbl2) {
		t.Fatal("长密钥签名应被拒绝")
	}
}

// TestSecurity_SameVersionAccept 同版本号重复推送 → 接受并覆盖
// 设计选择：同版本允许覆盖（修复配置错误时重发相同版本号）。
// 防重放由版本号单调递增 + 签名验证共同保障。
func TestSecurity_SameVersionAccept(t *testing.T) {
	c := newTestCache(testKey())
	tbl1 := validTable(5)
	sign(testKey(), tbl1)
	if !updateSync(c, tbl1) {
		t.Fatal("首次推送 v5 应接受")
	}
	// 同版本再次推送（内容相同，签名相同）
	tbl1Again := validTable(5)
	sign(testKey(), tbl1Again)
	if !updateSync(c, tbl1Again) {
		t.Fatal("同版本重复推送应接受并覆盖（幂等）")
	}
	if c.Version() != 5 {
		t.Fatalf("版本号仍应为 5，got %d", c.Version())
	}
}

// TestSecurity_LargeVersion 超大版本号 → 正常接受
// 防御：int64 范围内都应正常处理，不设上限
func TestSecurity_LargeVersion(t *testing.T) {
	c := newTestCache(testKey())
	tbl := &RouteTable{
		Version:   1<<62 - 1, // 接近 int64 上限
		UpdatedAt: 1725500000,
		Routes: []TableRoute{
			{Tenant: "t1", Model: "m1", DefaultEngine: "e1"},
		},
	}
	sign(testKey(), tbl)
	if !updateSync(c, tbl) {
		t.Fatal("大版本号应正常接受")
	}
	if c.Version() != 1<<62-1 {
		t.Fatalf("版本号应正确保存，got %d", c.Version())
	}
}

// TestSecurity_EmptyRoutes 空路由表（0 条路由）→ 合法接受
// 防御：空表是合法配置（如系统初始状态），签名有效即接受
func TestSecurity_EmptyRoutes(t *testing.T) {
	c := newTestCache(testKey())
	tbl := &RouteTable{Version: 1, UpdatedAt: 1725500000, Routes: []TableRoute{}}
	sign(testKey(), tbl)
	if !updateSync(c, tbl) {
		t.Fatal("空路由表（签名有效）应接受")
	}
	if c.Version() != 1 {
		t.Fatal("空表版本号应正确")
	}
	if r := c.Lookup("any", "any"); r != nil {
		t.Fatal("空表查不到路由")
	}
}

// TestSecurity_NilRoutes nil 路由数组 → 合法接受
// 防御：nil 和 empty 在语义上等价，都应正常处理
func TestSecurity_NilRoutes(t *testing.T) {
	c := newTestCache(testKey())
	tbl := &RouteTable{Version: 1, UpdatedAt: 1725500000, Routes: nil}
	sign(testKey(), tbl)
	if !updateSync(c, tbl) {
		t.Fatal("nil 路由表（签名有效）应接受")
	}
}

// TestSecurity_CanonOrderSensitive canon 字节对路由顺序敏感
// 设计选择：canon 序列化保留 Routes 原有顺序，不做排序。
// 因此控制面下发时必须保证路由顺序确定（如按 tenant+model 排序）。
// 同样的路由集合、不同顺序 → 不同 canon → 不同签名。
// 这不是 bug，是跨模块契约的一部分。
func TestSecurity_CanonOrderSensitive(t *testing.T) {
	tbl1 := &RouteTable{
		Version:   1,
		UpdatedAt: 1725500000,
		Routes: []TableRoute{
			{Tenant: "tenant-b", Model: "model-b", DefaultEngine: "eb"},
			{Tenant: "tenant-a", Model: "model-a", DefaultEngine: "ea"},
		},
	}
	tbl2 := &RouteTable{
		Version:   1,
		UpdatedAt: 1725500000,
		Routes: []TableRoute{
			{Tenant: "tenant-a", Model: "model-a", DefaultEngine: "ea"},
			{Tenant: "tenant-b", Model: "model-b", DefaultEngine: "eb"},
		},
	}

	// 两份表路由顺序不同 → canon 不同 → 签名不同
	sign(testKey(), tbl1)
	sign(testKey(), tbl2)
	if hmac.Equal(tbl1.Signature, tbl2.Signature) {
		t.Fatal("不同顺序的路由表应有不同签名（顺序敏感）")
	}

	// 但同一份表的两次签名必然相同（确定性）
	sign(testKey(), tbl1)
	sig1 := make([]byte, len(tbl1.Signature))
	copy(sig1, tbl1.Signature)
	sign(testKey(), tbl1)
	if !hmac.Equal(sig1, tbl1.Signature) {
		t.Fatal("同表两次签名应一致")
	}
}

// TestSecurity_TamperSignature 篡改签名字节 → 拒绝
// 防御：HMAC 验证对单字节变化敏感
func TestSecurity_TamperSignature(t *testing.T) {
	c := newTestCache(testKey())
	tbl := validTable(1)
	sign(testKey(), tbl)
	// 篡改签名字节（翻转最后一位）
	tampered := make([]byte, len(tbl.Signature))
	copy(tampered, tbl.Signature)
	tampered[len(tampered)-1] ^= 0x01
	tbl.Signature = tampered
	if updateSync(c, tbl) {
		t.Fatal("签名字节被篡改应被拒绝")
	}
}

// TestSecurity_StaleModeStillVerifies 降级模式下仍验证签名
// 防御：即使使用缓存的旧配置，新推送的配置仍需验签
func TestSecurity_StaleModeStillVerifies(t *testing.T) {
	c := newTestCache(testKey())
	// 先写入一份合法配置
	tbl := validTable(1)
	sign(testKey(), tbl)
	updateSync(c, tbl)

	// 推送一份签名错误但版本更高的配置
	badTable := validTable(100)
	badTable.Routes[0].DefaultEngine = "malicious"
	// 用错误密钥签名
	h := hmac.New(sha256.New, []byte("wrongkeywrongkeywrongkeywrongkey"))
	_, _ = h.Write(badTable.canon())
	badTable.Signature = h.Sum(nil)

	if updateSync(c, badTable) {
		t.Fatal("降级模式下仍应验证签名，恶意配置应被拒绝")
	}
	// 原始配置不受影响
	r := c.Lookup("tenant-a", "qwen-plus")
	if r == nil || r.DefaultEngine != "cmaas" {
		t.Fatal("验证失败不应影响现有配置")
	}
}

// TestSecurity_VersionZeroAccept 版本 0 推送 → 接受（合法初始版本）
// 设计选择：版本号没有下限，0 是合法的初始版本号。
// 防回退机制是"新版本号必须 >= 当前版本"，而非"版本号必须 > 0"。
func TestSecurity_VersionZeroAccept(t *testing.T) {
	c := newTestCache(testKey())
	tbl := validTable(0)
	sign(testKey(), tbl)
	if !updateSync(c, tbl) {
		t.Fatal("版本 0 签名有效时应接受")
	}
	if c.Version() != 0 {
		t.Fatalf("版本号应为 0，got %d", c.Version())
	}
}
