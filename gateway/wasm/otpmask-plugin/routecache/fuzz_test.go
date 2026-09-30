package routecache

import (
	"crypto/hmac"
	"encoding/binary"
	"testing"
)

// ============================================================
// Fuzz 测试靶场（对应方案 §11.6 安全测试 · fuzz 子项）
//
// 目标：
//   1. FuzzUpdate_SignatureRejectsBadInput — 随机签名不会被误接受
//   2. FuzzUpdate_RoundTripStable          — 合法签名→更新→查询 的 round-trip 一致性
//   3. FuzzCanon_Deterministic             — canon 序列化确定性
//   4. FuzzLookup_NoPanic                  — Lookup 在任意输入下不 panic
//
// 运行方式：
//   go test -fuzz=FuzzUpdate_SignatureRejectsBadInput -fuzztime=30s ./routecache/
//   go test -fuzz=FuzzUpdate_RoundTripStable -fuzztime=30s ./routecache/
//   所有 fuzz target 一起跑：
//   go test -fuzz=. -fuzztime=10s ./routecache/
// ============================================================

// ------------------------------------------------------------
// Fuzz 1: 签名验证的鲁棒性
// 不变量：随机字节作为签名时，Update 必然返回 false
// ------------------------------------------------------------

func FuzzUpdate_SignatureRejectsBadInput(f *testing.F) {
	// 种子语料：各种长度/模式的签名字节
	seeds := [][]byte{
		nil,
		{},
		{0x00},
		{0xff, 0xff, 0xff, 0xff},
		make([]byte, 32), // 全零 32 字节（刚好 SHA256 长度）
		make([]byte, 64),
		[]byte("not a valid hmac signature at all"),
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
	}
	for _, s := range seeds {
		f.Add(s)
	}

	key := testKey()
	// 构造一份合法内容的表（版本 42），但签名被替换为随机字节
	base := &RouteTable{
		Version:   42,
		UpdatedAt: 1725500000,
		Routes: []TableRoute{
			{Tenant: "fuzz-tenant", Model: "fuzz-model", DefaultEngine: "fuzz-engine"},
		},
	}

	f.Fuzz(func(t *testing.T, sig []byte) {
		c := New(key)
		tbl := *base // 拷贝
		tbl.Signature = sig
		if c.Update(&tbl) {
			t.Fatalf("随机签名应被拒绝，但 Update 返回 true。sig=%x", sig)
		}
		if c.Version() != 0 {
			t.Fatalf("拒绝后版本号仍应为 0，got %d", c.Version())
		}
	})
}

// ------------------------------------------------------------
// Fuzz 2: 签名-验签 round-trip 一致性
// 不变量：用 key 签名的表必然能通过同 key 的验签，且 Lookup 结果与原表一致
//
// 输入编码（从 []byte 解码出一张 RouteTable）：
//   - 前 2 字节：路由数 N（uint16 big-endian）
//   - 后续字节：按顺序解码 N 条路由
//   - 每条路由：tenant_len(1B) + tenant + model_len(1B) + model + engine_len(1B) + engine
//
// 解码失败（字节不够）直接 skip，不视为错误。
// ------------------------------------------------------------

func FuzzUpdate_RoundTripStable(f *testing.F) {
	// 种子语料：
	//   - 0 路由
	//   - 1 条简单路由
	//   - 2 条路由
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{
		0x00, 0x01, // N=1
		0x03, 0x61, 0x62, 0x63, // tenant "abc" (3B)
		0x04, 0x6d, 0x6f, 0x64, 0x6c, // model "model" (4B)
		0x05, 0x63, 0x6d, 0x61, 0x61, 0x73, // engine "cmaas" (5B)
	})
	f.Add([]byte{
		0x00, 0x02, // N=2
		0x01, 0x74, 0x01, 0x6d, 0x01, 0x65, // t / m / e
		0x02, 0x74, 0x32, 0x02, 0x6d, 0x32, 0x02, 0x65, 0x32, // t2 / m2 / e2
	})

	key := testKey()

	f.Fuzz(func(t *testing.T, data []byte) {
		tbl, ok := decodeRouteTable(data)
		if !ok {
			// 输入字节不足以解码出一张表——正常，fuzzer 会继续变异
			return
		}

		c := New(key)
		Sign(key, tbl)

		// 不变量 1：自己签名的表必然能通过 Verify
		if !Verify(key, tbl) {
			t.Fatal("自签名的表 Verify 应返回 true")
		}
		// 不变量 2：Update 应成功接受
		if !c.Update(tbl) {
			t.Fatal("自签名的表 Update 应返回 true")
		}
		// 不变量 3：版本号正确
		if c.Version() != tbl.Version {
			t.Fatalf("版本号不匹配: want %d, got %d", tbl.Version, c.Version())
		}
		// 不变量 4：每条不同的 (tenant, model) 都能正确 lookup
		// 注意：如果解码出重复的 tenant+model，Lookup 返回第一条匹配，
		//       后续重复条目被遮蔽——这是 Lookup 的预期行为，不是 bug。
		seen := make(map[string]bool)
		for _, r := range tbl.Routes {
			key := r.Tenant + "\x00" + r.Model
			if seen[key] {
				continue // 重复 key 被第一条遮蔽，跳过验证
			}
			seen[key] = true
			got := c.Lookup(r.Tenant, r.Model)
			if got == nil {
				t.Fatalf("Lookup 未命中: tenant=%q model=%q", r.Tenant, r.Model)
			}
			if got.DefaultEngine != r.DefaultEngine {
				t.Fatalf("Lookup engine 不匹配: want %q, got %q", r.DefaultEngine, got.DefaultEngine)
			}
		}
		// 不变量 5：不存在的租户查不到
		if r := c.Lookup("__not_exist__", "__not_exist__"); r != nil {
			t.Fatal("不存在的租户应返回 nil")
		}
	})
}

// ------------------------------------------------------------
// Fuzz 3: canon 序列化确定性
// 不变量：同一张表连续两次 canon() 结果完全相同
// ------------------------------------------------------------

func FuzzCanon_Deterministic(f *testing.F) {
	// 种子：复用 Fuzz 2 的种子解码格式
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{
		0x00, 0x01,
		0x03, 0x61, 0x62, 0x63,
		0x04, 0x6d, 0x6f, 0x64, 0x6c,
		0x05, 0x63, 0x6d, 0x61, 0x61, 0x73,
	})
	f.Add([]byte{
		0x00, 0x02,
		0x01, 0x74, 0x01, 0x6d, 0x01, 0x65,
		0x02, 0x74, 0x32, 0x02, 0x6d, 0x32, 0x02, 0x65, 0x32,
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		tbl, ok := decodeRouteTable(data)
		if !ok {
			return
		}
		c1 := tbl.canon()
		c2 := tbl.canon()
		if !hmac.Equal(c1, c2) {
			t.Fatalf("canon 非确定: 第一次 %x, 第二次 %x", c1, c2)
		}
	})
}

// ------------------------------------------------------------
// Fuzz 4: Lookup 不 panic
// 不变量：任意随机字节作为 tenant/model 查询，都不会 panic
// ------------------------------------------------------------

func FuzzLookup_NoPanic(f *testing.F) {
	// 种子：各种组合（空/ASCII/Unicode/二进制）
	f.Add("", "")
	f.Add("tenant-a", "model-a")
	f.Add("", "model-only")
	f.Add("tenant-only", "")
	f.Add("\x00\x01\x02", "\xff\xfe\xfd")
	f.Add("Unicode-租户-测试", "模型-名-🚀")
	f.Add("a very long tenant name that might cause issues with buffer", "and a very long model name too just to see what happens")

	// 先写入一张基准表，使 Lookup 有东西可查
	key := testKey()

	f.Fuzz(func(t *testing.T, tenant, model string) {
		c := New(key)
		base := validTable(1)
		Sign(key, base)
		c.Update(base)

		// 不变量：Lookup 不 panic；返回值要么 nil，要么非 nil 且字段有效
		r := c.Lookup(tenant, model)
		if r == nil {
			// 未命中正常
			return
		}
		// 命中则字段非空
		if r.Tenant == "" || r.Model == "" {
			t.Fatalf("命中的路由字段不应为空: tenant=%q model=%q", r.Tenant, r.Model)
		}
	})
}

// ============================================================
// 辅助：从 []byte 解码出 RouteTable（供 fuzz 用，不导出）
//
// 编码格式：
//   [0:2]   路由数 N（uint16 big-endian）
//   [2:]    连续 N 条路由，每条格式：
//             tenant_len (1B) + tenant
//             model_len  (1B) + model
//             engine_len (1B) + default_engine
//
// 解码失败返回 ok=false（fuzzer 跳过该输入）。
// ============================================================

func decodeRouteTable(data []byte) (*RouteTable, bool) {
	if len(data) < 2 {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(data[0:2]))
	// 限制最多 100 条路由，避免 fuzzer 生成超大输入导致超时
	if n > 100 {
		n = 100
	}
	rest := data[2:]

	routes := make([]TableRoute, 0, n)
	for i := 0; i < n; i++ {
		// tenant
		if len(rest) < 1 {
			return nil, false
		}
		tl := int(rest[0])
		rest = rest[1:]
		if len(rest) < tl {
			return nil, false
		}
		tenant := string(rest[:tl])
		rest = rest[tl:]

		// model
		if len(rest) < 1 {
			return nil, false
		}
		ml := int(rest[0])
		rest = rest[1:]
		if len(rest) < ml {
			return nil, false
		}
		model := string(rest[:ml])
		rest = rest[ml:]

		// engine
		if len(rest) < 1 {
			return nil, false
		}
		el := int(rest[0])
		rest = rest[1:]
		if len(rest) < el {
			return nil, false
		}
		engine := string(rest[:el])
		rest = rest[el:]

		routes = append(routes, TableRoute{
			Tenant:        tenant,
			Model:         model,
			DefaultEngine: engine,
		})
	}

	return &RouteTable{
		Version:   n + 1, // 版本号 = 路由数+1（保证唯一）
		UpdatedAt: 1725500000 + int64(n),
		Routes:    routes,
	}, true
}
