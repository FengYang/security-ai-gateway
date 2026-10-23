package testkit

import (
	"errors"
	"testing"
	"time"
)

// 构造一个带正确 MAC 的目录项（复用 §7.3.1 的 V-1 形态）。
func signedDir(t *testing.T, key []byte) KeyDirectory {
	t.Helper()
	kd := v1Dir(t)
	mac, err := DirectoryMAC(kd, key)
	if err != nil {
		t.Fatalf("计算 MAC 失败: %v", err)
	}
	kd.MAC = hexStr(mac)
	return kd
}

func hexStr(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}

func TestDirCachePutGetAndMiss(t *testing.T) {
	key := macKey()
	now := time.Now()
	c := NewDirCache("g", key, 30*time.Second, func() time.Time { return now })
	kd := signedDir(t, key)
	if err := c.Put(kd); err != nil {
		t.Fatalf("Put 失败: %v", err)
	}
	got, err := c.Get(kd.KeyID)
	if err != nil {
		t.Fatalf("Get 失败: %v", err)
	}
	if got.KeyID != kd.KeyID {
		t.Fatalf("取出错误: %+v", got)
	}
	if _, err := c.Get("unknown-key"); err == nil {
		t.Fatalf("未命中应报错")
	} else if !errors.Is(err, ErrDirUnknown) {
		t.Fatalf("错误应为 ErrDirUnknown，实测 %v", err)
	}
}

// TestDirCacheRejectsOldVersion 版本单调：旧版本不得覆盖。
func TestDirCacheRejectsOldVersion(t *testing.T) {
	key := macKey()
	now := time.Now()
	c := NewDirCache("g", key, 30*time.Second, func() time.Time { return now })
	kd := signedDir(t, key) // version 7
	if err := c.Put(kd); err != nil {
		t.Fatalf("Put 失败: %v", err)
	}
	older := signedDir(t, key)
	older.Version = 6
	older.MAC = hexStr(mustMAC(t, older, key))
	if err := c.Put(older); err == nil {
		t.Fatalf("旧版本覆盖应被拒绝")
	} else if !errors.Is(err, ErrDirOldVersion) {
		t.Fatalf("错误应为 ErrDirOldVersion，实测 %v", err)
	}
	// 新版本应接受
	newer := signedDir(t, key)
	newer.Version = 8
	newer.MAC = hexStr(mustMAC(t, newer, key))
	if err := c.Put(newer); err != nil {
		t.Fatalf("新版本应被接受: %v", err)
	}
}

func mustMAC(t *testing.T, kd KeyDirectory, key []byte) []byte {
	t.Helper()
	m, err := DirectoryMAC(kd, key)
	if err != nil {
		t.Fatalf("MAC 失败: %v", err)
	}
	return m
}

// TestDirCacheMACFailureInvalidates MAC 校验失败必须失效，不得继续用旧值。
func TestDirCacheMACFailureInvalidates(t *testing.T) {
	key := macKey()
	now := time.Now()
	c := NewDirCache("g", key, 30*time.Second, func() time.Time { return now })
	kd := signedDir(t, key)
	if err := c.Put(kd); err != nil {
		t.Fatalf("Put 失败: %v", err)
	}
	// 篡改缓存中的 MAC（模拟 etcd 侧被越权写）
	tampered := kd
	tampered.Version = 99
	tampered.MAC = hexStr(mustMAC(t, kd, key)) // MAC 与 version 不匹配
	c.entries[kd.KeyID] = &cacheEntry{kd: tampered, validated: true, lastGoodAt: now}

	if _, err := c.Get(kd.KeyID); err == nil {
		t.Fatalf("MAC 失败应报错")
	} else if !errors.Is(err, ErrDirMACInvalid) {
		t.Fatalf("错误应为 ErrDirMACInvalid，实测 %v", err)
	}
	if _, _, macFails, _ := c.Stats(); macFails == 0 {
		t.Fatalf("MAC 失败计数应增加")
	}
	// 再次 Get 必须是 miss（已被失效），而不是返回旧值
	if _, err := c.Get(kd.KeyID); err == nil {
		t.Fatalf("失效后再次 Get 应报错（不得回退旧值）")
	}
}

// TestDirCacheStalenessWindow etcd 失联：窗口内可服务，超过 max_stale 后 fail-closed。
func TestDirCacheStalenessWindow(t *testing.T) {
	key := macKey()
	now := time.Now()
	c := NewDirCache("g", key, 30*time.Second, func() time.Time { return now })
	kd := signedDir(t, key)
	if err := c.Put(kd); err != nil {
		t.Fatalf("Put 失败: %v", err)
	}
	// 模拟 etcd 停机 20s（< max_stale 30s）
	now = now.Add(20 * time.Second)
	if _, err := c.Get(kd.KeyID); err != nil {
		t.Fatalf("窗口内应继续服务: %v", err)
	}
	// 超过 max_stale
	now = now.Add(15 * time.Second)
	if _, err := c.Get(kd.KeyID); err == nil {
		t.Fatalf("超过 max_stale 应 fail-closed")
	} else if !errors.Is(err, ErrDirStale) {
		t.Fatalf("错误应为 ErrDirStale，实测 %v", err)
	}
}

// TestDirCacheNonReadyReplica 副本非 ready 不得用于路由。
func TestDirCacheNonReadyReplica(t *testing.T) {
	key := macKey()
	now := time.Now()
	c := NewDirCache("g", key, 30*time.Second, func() time.Time { return now })
	kd := signedDir(t, key)
	kd.State = "destroyed"
	kd.MAC = hexStr(mustMAC(t, kd, key))
	if err := c.Put(kd); err != nil {
		t.Fatalf("Put 失败: %v", err)
	}
	if _, err := c.Get(kd.KeyID); err == nil {
		t.Fatalf("非 ready 副本应被拒绝")
	}
}

// TestDirCacheCheckWriter 目录 writer 与当前 lease 不一致不得作为路由依据。
func TestDirCacheCheckWriter(t *testing.T) {
	key := macKey()
	now := time.Now()
	c := NewDirCache("g", key, 30*time.Second, func() time.Time { return now })
	kd := signedDir(t, key)
	if err := c.CheckWriter(kd, 42, "pod-uid-1:boot-1"); err != nil {
		t.Fatalf("writer 与 lease 一致应通过: %v", err)
	}
	if err := c.CheckWriter(kd, 43, "pod-uid-1:boot-1"); err == nil {
		t.Fatalf("epoch 不一致应被拒绝")
	}
	if err := c.CheckWriter(kd, 42, "pod-uid-9:boot-9"); err == nil {
		t.Fatalf("boot_id 不一致应被拒绝")
	}
}

// TestDirCacheEmptyMACKeyRejected 空 MAC 密钥不得写入（§6.2.2 红线）。
func TestDirCacheEmptyMACKeyRejected(t *testing.T) {
	now := time.Now()
	c := NewDirCache("g", nil, 30*time.Second, func() time.Time { return now })
	kd := v1Dir(t)
	if err := c.Put(kd); err == nil {
		t.Fatalf("空 MAC 密钥应拒绝写入")
	}
}

// TestDirCacheInvalidateOnlyOneKey Invalidate 只失效指定项。
func TestDirCacheInvalidateOnlyOneKey(t *testing.T) {
	key := macKey()
	now := time.Now()
	c := NewDirCache("g", key, 30*time.Second, func() time.Time { return now })
	a := signedDir(t, key)
	if err := c.Put(a); err != nil {
		t.Fatalf("Put 失败: %v", err)
	}
	b := signedDir(t, key)
	b.KeyID = "fedcba9876543210fedcba9876543210"
	b.MAC = hexStr(mustMAC(t, b, key))
	if err := c.Put(b); err != nil {
		t.Fatalf("Put 失败: %v", err)
	}
	c.Invalidate(a.KeyID)
	if _, err := c.Get(a.KeyID); err == nil {
		t.Fatalf("a 应已失效")
	}
	if _, err := c.Get(b.KeyID); err != nil {
		t.Fatalf("b 不应被连带清除: %v", err)
	}
}
