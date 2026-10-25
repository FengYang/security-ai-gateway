// P2-4 T-1.7 / QA P1-1 回归：启动装配（api.New）**不得**覆盖快照恢复出的策略表。
//
// 取证背景（QA 实跑）：恢复后路由表 v7（7 条）/限流表 v5 → 经启动装配后变 v1，
// 且被再次落盘 → 磁盘快照也变 v1（持久化对路由/限流表失效）。
package api

import (
	"path/filepath"
	"testing"
	"time"

	"security-ai-gateway/gateway/gateway-core/internal/ratelimit"
	"security-ai-gateway/gateway/gateway-core/internal/route"
	"security-ai-gateway/gateway/gateway-core/internal/store"
	"security-ai-gateway/gateway/mcpsec"
)

// newTestSigners 构造三个签名器（与 server_test.go 同口径）。
func newTestSigners(t *testing.T) (*route.Signer, *mcpsec.Signer, *ratelimit.Signer) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	sig, err := route.NewSigner(key)
	if err != nil {
		t.Fatalf("构造路由签名器失败: %v", err)
	}
	msig, err := mcpsec.NewSigner(key)
	if err != nil {
		t.Fatalf("构造 MCP 签名器失败: %v", err)
	}
	rlsig, err := ratelimit.NewSigner(key)
	if err != nil {
		t.Fatalf("构造限流签名器失败: %v", err)
	}
	return sig, msig, rlsig
}

// TestNewKeepsRestoredTablesAndSnapshot 恢复态（路由表 v7/7 条、限流表 v5）经启动
// 装配后**仍是 v7/v5**，且磁盘快照不被默认表覆盖。
func TestNewKeepsRestoredTablesAndSnapshot(t *testing.T) {
	sig, msig, rlsig := newTestSigners(t)

	// 1) 构造"快照恢复态"store：路由表 v7（7 条路由）、限流表 v5。
	mem := store.NewMemory()
	restored := route.NewRouteTable(7, 1700000000)
	for i := 0; i < 7; i++ {
		restored.Routes = append(restored.Routes, route.TableRoute{
			Tenant: "tenant-a", Model: "model-" + string(rune('a'+i)), DefaultEngine: "cmaas",
		})
	}
	mem.SaveRouteTable(restored)
	mem.SaveRateLimitTable(ratelimit.NewTable(5, time.Unix(1700000000, 0)))

	// 2) 落盘快照（模拟上一次运行留下的磁盘状态）。
	path := filepath.Join(t.TempDir(), "snap.json")
	ss := store.NewSnapshotStore(mem, path, nil)
	if err := ss.Persist(); err != nil {
		t.Fatalf("落盘快照失败: %v", err)
	}

	// 3) 重启：空内存 + LoadSnapshot 恢复（与 main.go 装配一致），再走 api.New。
	mem2 := store.NewMemory()
	ss2 := store.NewSnapshotStore(mem2, path, nil)
	if err := ss2.LoadSnapshot(); err != nil {
		t.Fatalf("快照恢复失败: %v", err)
	}
	defRT := route.NewRouteTable(1, time.Now().Unix())
	defRL := ratelimit.NewTable(1, time.Now())
	New(sig, msig, rlsig, nil, ss2, "tok", defRT, defRL)

	// 4) 生效表仍为恢复值（**不得**被启动默认表 v1 覆盖）。
	got := ss2.GetRouteTable()
	if got == nil || got.Version != 7 || len(got.Routes) != 7 {
		t.Fatalf("路由表被覆盖: got=%+v want v7/7 条", got)
	}
	gotRL := ss2.GetRateLimitTable()
	if gotRL == nil || gotRL.Version != 5 {
		t.Fatalf("限流表被覆盖: got=%+v want v5", gotRL)
	}

	// 5) 磁盘快照保持 7（装配不得把 v1 写回磁盘）——重新加载校验。
	mem3 := store.NewMemory()
	ss3 := store.NewSnapshotStore(mem3, path, nil)
	if err := ss3.LoadSnapshot(); err != nil {
		t.Fatalf("快照重新加载失败: %v", err)
	}
	if r := ss3.GetRouteTable(); r == nil || r.Version != 7 || len(r.Routes) != 7 {
		t.Fatalf("磁盘快照路由表不符: got=%+v want v7/7 条", r)
	}
	if r := ss3.GetRateLimitTable(); r == nil || r.Version != 5 {
		t.Fatalf("磁盘快照限流表不符: got=%+v want v5", r)
	}
}

// TestNewWritesDefaultsOnEmptyStore 兼容口径：store 无表时，启动默认表仍须写入
// （既有行为不变——首次启动/纯内存场景必须拿到已签名默认表）。
func TestNewWritesDefaultsOnEmptyStore(t *testing.T) {
	sig, msig, rlsig := newTestSigners(t)
	st := store.NewMemory()
	defRT := route.NewRouteTable(1, 1700000000)
	defRL := ratelimit.NewTable(1, time.Unix(1700000000, 0))
	New(sig, msig, rlsig, nil, st, "tok", defRT, defRL)
	if got := st.GetRouteTable(); got == nil || got.Version != 1 {
		t.Fatalf("空 store 应写入默认路由表: got=%+v", got)
	}
	if got := st.GetRateLimitTable(); got == nil || got.Version != 1 {
		t.Fatalf("空 store 应写入默认限流表: got=%+v", got)
	}
	// 传 nil 默认表时不得写入（既有口径不变）。
	st2 := store.NewMemory()
	New(sig, msig, rlsig, nil, st2, "tok", nil, nil)
	if got := st2.GetRouteTable(); got != nil {
		t.Fatalf("nil 默认表不应写入: got=%+v", got)
	}
	if got := st2.GetRateLimitTable(); got != nil {
		t.Fatalf("nil 默认限流表不应写入: got=%+v", got)
	}
}
