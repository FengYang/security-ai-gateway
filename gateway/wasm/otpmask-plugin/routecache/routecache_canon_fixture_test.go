package routecache

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// TestCanonFixtureFromExternalSigner 锁定"外部签发端 ↔ 本包 canon 编码"契约。
//
// 背景（门禁 #5 演练）：宿主 stub 用**独立实现**（PowerShell + .NET HMACSHA256）签发路由表；
// 若其规范字节与本包 canon() 不一致，表会被**静默拒绝**（缓存为空 → 降级不发生），
// 而在容器里只能看到"拉取成功但没生效"，极难定位。本用例把该契约变成可离线判定的事实。
//
// 固定向量：version=1, updated_at=1725500000,
// routes=[{tenant:tenant-a, model:qwen-plus, default_engine:cmaas, target:https://cmaas.local}]
// 规范字节（146 字节，由 PS 打印）：
//
//	{"version":1,"updated_at":1725500000,"routes":[{"tenant":"tenant-a","model":"qwen-plus","default_engine":"cmaas","target":"https://cmaas.local"}]}
//
// 签名（HMAC-SHA256，key = hex 解码后的 32 字节，base64 标准带填充）：见下方常量。
func TestCanonFixtureFromExternalSigner(t *testing.T) {
	key, err := hex.DecodeString("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString("hPrJ54bcL9aAkGcrpm1v+QdwcQBC1GleoEroRK5l5Fg=")
	if err != nil {
		t.Fatal(err)
	}
	rt := &RouteTable{
		Version:   1,
		UpdatedAt: 1725500000,
		Routes: []TableRoute{
			{Tenant: "tenant-a", Model: "qwen-plus", DefaultEngine: "cmaas", Target: "https://cmaas.local"},
		},
		Signature: sig,
	}
	t.Logf("本包 canon = %s", string(rt.canon()))
	if !verifySync(testVerifier{key: key}, rt) {
		t.Fatalf("外部签名与本包 canon 不匹配（外部签发端需与本包 canon 逐字节一致）\n本包 canon = %s", string(rt.canon()))
	}
}
