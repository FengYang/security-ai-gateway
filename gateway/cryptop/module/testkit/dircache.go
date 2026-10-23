package testkit

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// 本文件实现《P2--HSM集成》D-18 / §6.2.2 的目录本地缓存契约（测试基座）：
//   - 数据面从缓存读目录，控制存储短时失联时可在 max_stale 窗口内继续服务已缓存 ready 副本；
//   - MAC 校验失败必须失效并告警，不得"跳过该项继续用旧值"；
//   - 缓存按 version 单调接受，拒绝旧版本覆盖；
//   - 缓存项携带 writer_epoch/writer_boot_id，且必须等于当前 lease 才可作为路由依据。

// ErrDirStale 缓存已超过 max_stale 窗口（fail-closed）。
var ErrDirStale = errors.New("testkit: group_key_directory_inconsistent")

// ErrDirMACInvalid 目录 MAC 校验失败。
var ErrDirMACInvalid = errors.New("testkit: group_key_directory_inconsistent: MAC 校验失败")

// ErrDirUnknown 缓存未命中。
var ErrDirUnknown = errors.New("testkit: group_key_unavailable")

// ErrDirOldVersion 旧版本覆盖被拒绝。
var ErrDirOldVersion = errors.New("testkit: group_key_directory_inconsistent: 旧版本不得覆盖")

// ErrDirWriterMismatch writer_epoch/boot_id 与当前 lease 不一致。
var ErrDirWriterMismatch = errors.New("testkit: group_stale_epoch")

type cacheEntry struct {
	kd         KeyDirectory
	validated  bool
	lastGoodAt time.Time
}

// DirCache 目录本地缓存。
type DirCache struct {
	mu        sync.Mutex
	gid       string
	maxStale  time.Duration
	macKey    []byte
	entries   map[string]*cacheEntry
	now       func() time.Time
	hits      uint64
	misses    uint64
	staleHits uint64
	macFails  uint64
}

func NewDirCache(gid string, macKey []byte, maxStale time.Duration, now func() time.Time) *DirCache {
	if now == nil {
		now = time.Now
	}
	return &DirCache{gid: gid, macKey: macKey, maxStale: maxStale, entries: map[string]*cacheEntry{}, now: now}
}

// Put 写入/更新缓存：拒绝旧版本覆盖，并校验 MAC（失败则不入库）。
func (c *DirCache) Put(kd KeyDirectory) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.macKey) == 0 {
		return fmt.Errorf("testkit: 目录 MAC 密钥为空（§6.2.2：不得退化为无 MAC 目录）")
	}
	if prev, ok := c.entries[kd.KeyID]; ok && kd.Version <= prev.kd.Version {
		c.macFails++
		return fmt.Errorf("%w: 已有 v%d，收到 v%d", ErrDirOldVersion, prev.kd.Version, kd.Version)
	}
	if err := VerifyDirectoryMAC(kd, c.macKey); err != nil {
		c.macFails++
		return fmt.Errorf("%w: %v", ErrDirMACInvalid, err)
	}
	c.entries[kd.KeyID] = &cacheEntry{kd: kd, validated: true, lastGoodAt: c.now()}
	return nil
}

// Get 读取缓存：先校验 MAC，再校验 state=ready 与新鲜度；任一项不符即 fail-closed。
func (c *DirCache) Get(keyID string) (KeyDirectory, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[keyID]
	if !ok {
		c.misses++
		return KeyDirectory{}, fmt.Errorf("%w: key_id=%s", ErrDirUnknown, keyID)
	}
	// MAC 校验失败必须失效，不得回退旧值。
	if err := VerifyDirectoryMAC(e.kd, c.macKey); err != nil {
		delete(c.entries, keyID)
		c.macFails++
		return KeyDirectory{}, fmt.Errorf("%w: %v", ErrDirMACInvalid, err)
	}
	if e.kd.State != "ready" {
		return KeyDirectory{}, fmt.Errorf("%w: 副本状态 %s 非 ready", ErrDirUnknown, e.kd.State)
	}
	if c.now().Sub(e.lastGoodAt) > c.maxStale {
		c.staleHits++
		return KeyDirectory{}, fmt.Errorf("%w: 缓存已过期（max_stale=%s）", ErrDirStale, c.maxStale)
	}
	c.hits++
	return e.kd, nil
}

// CheckWriter 校验目录写者是否为当前组主（供路由前判定）。
func (c *DirCache) CheckWriter(kd KeyDirectory, leaseEpoch uint64, leaseBootID string) error {
	if kd.WriterEpoch != leaseEpoch || kd.WriterBootID != leaseBootID {
		return fmt.Errorf("%w: 目录 writer(epoch=%d,boot=%s) 与当前 lease(epoch=%d,boot=%s) 不一致",
			ErrDirWriterMismatch, kd.WriterEpoch, kd.WriterBootID, leaseEpoch, leaseBootID)
	}
	return nil
}

// Invalidate 仅失效指定项，不清空全量缓存。
func (c *DirCache) Invalidate(keyID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, keyID)
}

func (c *DirCache) Stats() (hits, misses, macFailures, staleHits uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses, c.macFails, c.staleHits
}
