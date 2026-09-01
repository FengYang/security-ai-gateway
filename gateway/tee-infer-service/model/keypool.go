// Package model — 服务商 Key 池（GF.4.2 接入点）
//
// C-MaaS 多账号场景：将"单一 apiKey"扩展为"多账号轮询 + 按 key 关联证明引用"。
// 本文件提供 KeyPool 接口与默认轮询实现（纯内存、无外部依赖、可单测），
// 作为真机到位后的接入点；CmaasEngine 现保持单账号（NewCmaasEngine），
// 开通多账号后经 NewRoundRobinKeyPool 装配替换（接口不变，仅装配点改动）。
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// KeyPool 服务商账号/密钥池。Acquire 返回当前应使用的凭证（轮询/故障驱动），
// Release 在单次调用结束归还（可携带失败标记触发淘汰），
// 使多账号 failover 与限流脱敏在明文域内可插拔。
type KeyPool interface {
	Acquire() string // 下一个可用凭证（空 = 无可用账号，fail-closed）
	Release(key string, failed bool)
	Len() int
}

// RoundRobinKeyPool 轮询密钥池（线程安全）。失败账号不立即剔除（避免误淘汰），
// 由上层按失败次数/熔断策略决策；本实现聚焦轮询顺序与并发安全。
type RoundRobinKeyPool struct {
	mu     sync.Mutex
	keys   []string
	next   int
	failed map[string]int // key -> 连续失败计数（预留熔断接入）
}

// NewRoundRobinKeyPool 构造轮询密钥池；keys 非空（空则 Acquire 恒返回空，fail-closed）。
func NewRoundRobinKeyPool(keys ...string) *RoundRobinKeyPool {
	return &RoundRobinKeyPool{
		keys:   append([]string(nil), keys...),
		failed: make(map[string]int),
	}
}

// Acquire 返回下一个可用凭证并推进轮询指针。
func (p *RoundRobinKeyPool) Acquire() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.keys) == 0 {
		return ""
	}
	k := p.keys[p.next]
	p.next = (p.next + 1) % len(p.keys)
	return k
}

// Release 归还并记录失败（连续失败计数，供后续熔断扩展）。
func (p *RoundRobinKeyPool) Release(key string, failed bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !failed {
		p.failed[key] = 0
		return
	}
	p.failed[key]++
}

// Len 返回池内凭证数。
func (p *RoundRobinKeyPool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.keys)
}

// KeyFingerprint 凭证指纹（sha256 前 8 hex）。GF.4.2 计量归属（评审 P1-4）：
// 审计/计量事件以指纹标识所用服务商账号（平台维度消耗核算），
// 全程不落明文 key，与租户维度（tenant_id）双口径分离。
func KeyFingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:4])
}
