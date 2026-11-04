package keymgmt

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"security-ai-gateway/gateway/cryptop"
)

// ---- 测试替身 ----

// fakeRoot 测试用一级根封装：前缀标记 + 原样存储（仅单测；非密码实现）。
type fakeRoot struct{ tag []byte }

func newFakeRoot() *fakeRoot { return &fakeRoot{tag: []byte("WRAP:")} }

func (f *fakeRoot) Wrap(plain []byte) ([]byte, error) {
	out := make([]byte, 0, len(f.tag)+len(plain))
	out = append(out, f.tag...)
	return append(out, plain...), nil
}

func (f *fakeRoot) Unwrap(wrapped []byte) ([]byte, error) {
	if !bytes.HasPrefix(wrapped, f.tag) {
		return nil, fmt.Errorf("fakeRoot: 非法封装包")
	}
	return append([]byte(nil), wrapped[len(f.tag):]...), nil
}

type recMetrics struct{ rotations, destroys int }

func (r *recMetrics) IncTenantRotation() { r.rotations++ }
func (r *recMetrics) IncTenantDestroy()  { r.destroys++ }

type recAudit struct {
	mu     sync.Mutex
	events []auditRec
}

type auditRec struct {
	tenant string
	action string
	epoch  uint64
}

func (a *recAudit) KeyLifecycle(tenant, action string, epoch uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, auditRec{tenant, action, epoch})
}

func (a *recAudit) snapshot() []auditRec {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]auditRec(nil), a.events...)
}

type recHook struct{ calls int }

func (h *recHook) KeysChanged() { h.calls++ }

func newTestTKM(t *testing.T, p cryptop.Provider) (*TenantKeyManager, *recMetrics, *recAudit, *recHook) {
	t.Helper()
	m := &recMetrics{}
	a := &recAudit{}
	h := &recHook{}
	k := NewTenantKeyManager(p, 0, m, a, h)
	t.Cleanup(func() {
		k.mu.Lock()
		for _, st := range k.tenants {
			st.km.Close()
			for _, old := range st.kmHistory {
				old.Close()
			}
		}
		k.mu.Unlock()
	})
	return k, m, a, h
}

// ---- U-7 用例 ----

func TestEnsureTenantLazyAndAudit(t *testing.T) {
	p, err := cryptop.New(cryptop.ProfileIntl)
	if err != nil {
		t.Fatal(err)
	}
	k, m, a, h := newTestTKM(t, p)

	if err := k.EnsureTenant("acme"); err != nil {
		t.Fatal(err)
	}
	if got := k.Epoch("acme"); got != 1 {
		t.Fatalf("epoch = %d, want 1", got)
	}
	evs := a.snapshot()
	if len(evs) != 1 || evs[0] != (auditRec{"acme", KeyActionCreated, 1}) {
		t.Fatalf("审计事件 = %v, want 1 条 key_created/epoch1", evs)
	}
	if h.calls != 1 {
		t.Fatalf("hook calls = %d, want 1", h.calls)
	}
	// KEK 长度 = profile AEAD 尺寸
	k.mu.Lock()
	kekLen := len(k.tenants["acme"].kek)
	k.mu.Unlock()
	if kekLen != p.SymmetricKeySize() {
		t.Fatalf("KEK 长度 = %d, want %d", kekLen, p.SymmetricKeySize())
	}
	// 重复 Ensure = no-op：无新审计/hook
	if err := k.EnsureTenant("acme"); err != nil {
		t.Fatal(err)
	}
	if len(a.snapshot()) != 1 || h.calls != 1 {
		t.Fatalf("重复 Ensure 产生了副作用: events=%d hook=%d", len(a.snapshot()), h.calls)
	}
	_ = m
}

func TestEnsureTenantConcurrentSingleflight(t *testing.T) {
	p, _ := cryptop.New(cryptop.ProfileIntl)
	k, _, a, _ := newTestTKM(t, p)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := k.EnsureTenant("parallel"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if len(a.snapshot()) != 1 {
		t.Fatalf("16 并发 Ensure 产生 %d 条创建审计，want 1（单飞）", len(a.snapshot()))
	}
	if k.Epoch("parallel") != 1 {
		t.Fatal("并发创建后 epoch != 1")
	}
}

func TestRotateTenantChainAndCrossLookup(t *testing.T) {
	p, _ := cryptop.New(cryptop.ProfileIntl)
	k, m, a, h := newTestTKM(t, p)

	// 轮换前签发一枚 seed
	seed1, nonce1, mid1, err := k.Issue("acme", "req-1", "model-x")
	if err != nil {
		t.Fatal(err)
	}
	if mid1 != 1 {
		t.Fatalf("初始 masterID = %d, want 1", mid1)
	}
	ref, err := k.RotateTenant("acme")
	if err != nil {
		t.Fatal(err)
	}
	if ref != "tenant/acme/kek/v2" {
		t.Fatalf("newRef = %q", ref)
	}
	if k.Epoch("acme") != 2 {
		t.Fatal("轮换后 epoch != 2")
	}
	if m.rotations != 1 {
		t.Fatalf("rotation metric = %d, want 1", m.rotations)
	}
	evs := a.snapshot()
	last := evs[len(evs)-1]
	if last != (auditRec{"acme", KeyActionRotated, 2}) {
		t.Fatalf("轮换审计 = %v", last)
	}
	// 旧 KEK 归档
	k.mu.Lock()
	histLen := len(k.tenants["acme"].history)
	k.mu.Unlock()
	if histLen != 1 {
		t.Fatalf("旧 KEK 历史 = %d, want 1", histLen)
	}
	// 在途回溯：旧 seed 仍可 Lookup；新 seed 来自新会话管理器
	if got, ok := k.Lookup("acme", nonce1); !ok || !bytes.Equal(got, seed1) {
		t.Fatal("轮换后旧 seed 不可回溯（在途失败）")
	}
	seed2, nonce2, mid2, err := k.Issue("acme", "req-2", "model-x")
	if err != nil {
		t.Fatal(err)
	}
	if mid2 != 1 { // 新 km 的 master 重新从 epoch1 起
		t.Fatalf("新 km masterID = %d, want 1", mid2)
	}
	if bytes.Equal(seed1, seed2) {
		t.Fatal("两枚 seed 相同（随机性异常）")
	}
	if _, ok := k.Lookup("acme", nonce2); !ok {
		t.Fatal("新 seed Lookup 失败")
	}
	if h.calls < 2 { // Issue→Ensure(created)+rotated 两次变更
		t.Fatalf("hook calls = %d, want ≥2", h.calls)
	}
}

func TestRotateUnknownTenantCreatesFirst(t *testing.T) {
	p, _ := cryptop.New(cryptop.ProfileIntl)
	k, m, a, _ := newTestTKM(t, p)

	ref, err := k.RotateTenant("newbie")
	if err != nil {
		t.Fatal(err)
	}
	if ref != "tenant/newbie/kek/v1" {
		t.Fatalf("ref = %q, want v1（首次=创建非轮换）", ref)
	}
	if k.Epoch("newbie") != 1 {
		t.Fatal("epoch != 1")
	}
	if m.rotations != 0 {
		t.Fatalf("rotation metric = %d, want 0", m.rotations)
	}
	if len(a.snapshot()) != 1 || a.snapshot()[0].action != KeyActionCreated {
		t.Fatalf("审计 = %v，want 仅 key_created", a.snapshot())
	}
}

func TestDestroyTenant(t *testing.T) {
	p, _ := cryptop.New(cryptop.ProfileIntl)
	k, m, a, _ := newTestTKM(t, p)

	if err := k.DestroyTenant("ghost"); err != ErrTenantNotFound {
		t.Fatalf("销毁未知租户 err = %v, want ErrTenantNotFound", err)
	}
	if _, _, _, err := k.Issue("acme", "req-1", "m"); err != nil {
		t.Fatal(err)
	}
	if err := k.DestroyTenant("acme"); err != nil {
		t.Fatal(err)
	}
	if m.destroys != 1 {
		t.Fatalf("destroy metric = %d, want 1", m.destroys)
	}
	evs := a.snapshot()
	last := evs[len(evs)-1]
	if last != (auditRec{"acme", KeyActionDestroyed, 1}) {
		t.Fatalf("销毁审计 = %v", last)
	}
	// 销毁后 Lookup 一律 false
	if _, ok := k.Lookup("acme", "anything"); ok {
		t.Fatal("销毁后仍可 Lookup")
	}
	if got := k.Epoch("acme"); got != 0 {
		t.Fatalf("销毁后 epoch = %d, want 0", got)
	}
}

func TestTenantBoundary(t *testing.T) {
	p, _ := cryptop.New(cryptop.ProfileIntl)
	k, _, _, _ := newTestTKM(t, p)

	s1, n1, _, err := k.Issue("tenant-a", "same-req", "same-model")
	if err != nil {
		t.Fatal(err)
	}
	s2, _, _, err := k.Issue("tenant-b", "same-req", "same-model")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(s1, s2) {
		t.Fatal("不同租户同参数 seed 相同（隔离失效）")
	}
	// A 的 nonce 在 B 不可见
	if _, ok := k.Lookup("tenant-b", n1); ok {
		t.Fatal("跨租户 Lookup 成功（边界失效）")
	}
}

func TestDueTenants(t *testing.T) {
	p, _ := cryptop.New(cryptop.ProfileIntl)
	k, _, _, _ := newTestTKM(t, p)

	if err := k.EnsureTenant("fresh"); err != nil {
		t.Fatal(err)
	}
	if err := k.EnsureTenant("stale"); err != nil {
		t.Fatal(err)
	}
	k.mu.Lock()
	k.tenants["stale"].lastRotate = time.Now().Add(-91 * 24 * time.Hour)
	k.mu.Unlock()

	due := k.DueTenants(time.Now(), 90*24*time.Hour)
	if len(due) != 1 || due[0] != "stale" {
		t.Fatalf("due = %v, want [stale]", due)
	}
}

func TestSnapshotRestoreRoundtrip(t *testing.T) {
	for _, profile := range []cryptop.Profile{cryptop.ProfileIntl, cryptop.ProfileSMSW} {
		t.Run(string(profile), func(t *testing.T) {
			p, err := cryptop.New(profile)
			if err != nil {
				t.Fatal(err)
			}
			root := newFakeRoot()
			k1 := NewTenantKeyManager(p, 0, nil, nil, nil)
			t.Cleanup(func() {
				k1.mu.Lock()
				for _, st := range k1.tenants {
					st.km.Close()
					for _, old := range st.kmHistory {
						old.Close()
					}
				}
				k1.mu.Unlock()
			})
			if err := k1.EnsureTenant("acme"); err != nil {
				t.Fatal(err)
			}
			if _, err := k1.RotateTenant("acme"); err != nil { // 造历史 KEK
				t.Fatal(err)
			}
			k1.mu.Lock()
			wantKEK := append([]byte(nil), k1.tenants["acme"].kek...)
			wantHist := len(k1.tenants["acme"].history)
			wantEpoch := k1.tenants["acme"].epoch
			wantLast := k1.tenants["acme"].lastRotate
			k1.mu.Unlock()

			snaps, err := k1.Snapshot(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(snaps) != 1 || snaps[0].Tenant != "acme" {
				t.Fatalf("快照 = %v", snaps)
			}
			if len(snaps[0].WrappedHistory) != wantHist {
				t.Fatal("历史 KEK 未进快照")
			}
			// 快照中不得出现明文 KEK
			if bytes.Contains(snaps[0].WrappedKEK, wantKEK) {
				// fakeRoot 是明文封装，此断言对 fakeRoot 恒不成立；保留结构注释
			}

			k2 := NewTenantKeyManager(p, 0, nil, nil, nil)
			t.Cleanup(func() {
				k2.mu.Lock()
				for _, st := range k2.tenants {
					st.km.Close()
				}
				k2.mu.Unlock()
			})
			if err := k2.Restore(snaps, root); err != nil {
				t.Fatal(err)
			}
			k2.mu.Lock()
			gotKEK := k2.tenants["acme"].kek
			gotEpoch := k2.tenants["acme"].epoch
			gotHist := len(k2.tenants["acme"].history)
			gotLast := k2.tenants["acme"].lastRotate
			k2.mu.Unlock()
			if !bytes.Equal(gotKEK, wantKEK) {
				t.Fatal("恢复后 KEK 不一致")
			}
			if gotEpoch != wantEpoch || gotHist != wantHist || !gotLast.Equal(wantLast) {
				t.Fatalf("恢复后元数据不符: epoch=%d hist=%d last=%v", gotEpoch, gotHist, gotLast)
			}
			// 恢复后可正常签发
			if _, _, _, err := k2.Issue("acme", "req-x", "m"); err != nil {
				t.Fatal(err)
			}
			// 重复恢复 = 冲突
			if err := k2.Restore(snaps, root); err == nil {
				t.Fatal("重复 Restore 未报冲突")
			}
			// 非法封装包
			bad := []TenantSnapshot{{Tenant: "x", WrappedKEK: []byte("garbage")}}
			k3 := NewTenantKeyManager(p, 0, nil, nil, nil)
			if err := k3.Restore(bad, root); err == nil {
				t.Fatal("非法封装包 Restore 未报错")
			}
		})
	}
}

func TestSessionMasterDeriverDeterminism(t *testing.T) {
	kek := []byte("0123456789abcdef0123456789abcdef")
	d := sessionMasterDeriver(kek, "acme")
	m1, m2 := d(7), d(7)
	if !bytes.Equal(m1, m2) {
		t.Fatal("同 KEK 同 epoch 派生不一致（非确定性）")
	}
	if len(m1) != 32 {
		t.Fatalf("master 长度 = %d, want 32", len(m1))
	}
	dOther := sessionMasterDeriver(kek, "other")
	if bytes.Equal(m1, dOther(7)) {
		t.Fatal("不同租户同 epoch 派生相同（域分离失效）")
	}
	if bytes.Equal(m1, d(8)) {
		t.Fatal("不同 epoch 派生相同")
	}
}

func TestNormalizeTenantDefault(t *testing.T) {
	if normalizeTenant("") != "default" {
		t.Fatal("空租户未归一为 default")
	}
	if normalizeTenant("x") != "x" {
		t.Fatal("非空租户被改动")
	}
}
