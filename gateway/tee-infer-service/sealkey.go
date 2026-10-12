package main

// T4 密封密钥来源抽象（P1-8，GAP-04）。
//
// 设计决策（D-5 v1.5 定稿）：
//   - 本期 KMS 注入为唯一可施工路径
//   - TDX 派生（deriveFromTDX）为 TODO(实测确认)，不做虚实现
//   - fail-closed：启动期强校验非空非默认值，KMS 不可达绝不回退随机
//
// 分层：
//   kmsClient（传输层抽象）
//     ↓
//   SealKeySource（密钥来源接口）
//     ← kmsSealKeySource（生产，KMS 注入）
//     ← envSealKeySource（dev/CI，环境变量 hex）
//     ← tdxDerivedSealKeySource（TODO）
//
// 零化（C-4）：
//   密钥字节使用完毕后须调用 zeroBytes 清内存。
//   keystore.zero 未导出，本地实现（逐字节写零）。
//
// 安全约束：
//   - 不在日志/错误信息中输出密钥值
//   - 错误消息只描述"长度/格式/来源"，不含密钥材料
//   - 测试用例不硬编码真实密钥形态（用固定测试向量 + 零化后校验）

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ---- kmsClient 接口（RV-02 定稿） ----

// kmsClient KMS 客户端抽象（传输层）。
//
// 二选一实现：
//   - 云厂商 KMS SDK 适配（AWS KMS / Aliyun KMS / 华为云 KMS 等）
//   - HashiCorp Vault（KV v2 引擎）
//
// ref 语义由实现决定：云 KMS 是密钥 ID/ARN；Vault 是 secret path。
type kmsClient interface {
	// Get 从 KMS 获取密钥明文。
	// 返回密钥的原始字节（调用方负责零化）。
	// KMS 不可达 / 鉴权失败 / 密钥不存在 → 返回 error（fail-closed）。
	Get(ctx context.Context, ref string) ([]byte, error)
}

// ---- SealKeySource 接口 ----

// SealKeySource 密封密钥来源。
//
// 返回的密钥字节由调用方持有并负责零化（zeroBytes）。
// 任何路径下都不回退到随机生成（fail-closed 原则）。
type SealKeySource interface {
	// Load 加载密封密钥。
	// 返回非空、长度合法的密钥字节；失败返回 error。
	Load(ctx context.Context) ([]byte, error)
}

// ---- zeroBytes（C-4 零化） ----

// zeroBytes 将字节切片清零（安全零化）。
//
// 使用 for 循环逐字节写零，不依赖编译器优化消除。
// keystore.zero 未导出（v1.5 §6.4 明确声明），故本地实现。
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ---- envSealKeySource（dev/CI 路径） ----

// envSealKeySource 从环境变量读取 hex 编码的密封密钥。
//
// 注意：这是 dev/CI 路径，生产环境应使用 kmsSealKeySource。
// fail-closed：环境变量未设置 / 非法 → 报错，**绝不回退随机**。
type envSealKeySource struct {
	envName   string
	keySize   int // 期望的密钥长度（字节）
	nameLabel string // 错误消息中的标识（如 "seal" / "seal-history-0"）
}

// NewEnvSealKeySource 构造环境变量密钥源（dev/CI 用）。
//
// keySize 为期望的密钥字节数（AES-256=32 / SM4=16），由 cryptoProvider 决定。
// 不使用 cryptoProvider 以避免循环依赖（调用方传）。
func NewEnvSealKeySource(envName string, keySize int) SealKeySource {
	return &envSealKeySource{
		envName:   envName,
		keySize:   keySize,
		nameLabel: "seal",
	}
}

// Load 从环境变量加载密封密钥。
//
// fail-closed：
//   - 环境变量未设置 → 报错
//   - hex 解码失败 → 报错
//   - 长度不匹配 → 报错
// 绝不回退随机。
func (s *envSealKeySource) Load(_ context.Context) ([]byte, error) {
	v := os.Getenv(s.envName)
	if v == "" {
		return nil, fmt.Errorf("sealkey: 环境变量 %s 未设置（fail-closed，不回退随机）", s.envName)
	}
	k, err := hex.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("sealkey: %s hex 解码失败", s.nameLabel)
	}
	if len(k) != s.keySize {
		return nil, fmt.Errorf("sealkey: %s 长度 %d 字节，期望 %d", s.nameLabel, len(k), s.keySize)
	}
	return k, nil
}

// ---- kmsSealKeySource（生产路径） ----

// kmsSealKeySource 从 KMS 获取密封密钥。
//
// fail-closed：
//   - kmsClient 为 nil → 启动报错
//   - ref 为空 → 启动报错
//   - KMS 返回空 → 报错
//   - KMS 不可达 → 报错
//   - 长度不匹配 → 报错
// 绝不回退随机。
type kmsSealKeySource struct {
	client  kmsClient
	ref     string // KMS 密钥引用（ID/ARN/path）
	keySize int    // 期望的密钥长度（字节）
}

// NewKmsSealKeySource 构造 KMS 密钥源（生产用）。
//
// 启动期强校验：client 和 ref 均不可为空。
func NewKmsSealKeySource(client kmsClient, ref string, keySize int) (SealKeySource, error) {
	if client == nil {
		return nil, errors.New("sealkey: KMS client 不能为 nil（fail-closed）")
	}
	if strings.TrimSpace(ref) == "" {
		return nil, errors.New("sealkey: KMS ref 不能为空（fail-closed）")
	}
	if keySize <= 0 {
		return nil, fmt.Errorf("sealkey: 非法 keySize=%d", keySize)
	}
	return &kmsSealKeySource{
		client:  client,
		ref:     ref,
		keySize: keySize,
	}, nil
}

// Load 从 KMS 加载密封密钥。
//
// fail-closed：KMS 不可达 / 返回空 / 长度不符 → 报错。
// 绝不回退随机。
func (s *kmsSealKeySource) Load(ctx context.Context) ([]byte, error) {
	k, err := s.client.Get(ctx, s.ref)
	if err != nil {
		return nil, fmt.Errorf("sealkey: 从 KMS 获取失败: %w", err)
	}
	if len(k) == 0 {
		return nil, errors.New("sealkey: KMS 返回空密钥（fail-closed）")
	}
	if len(k) != s.keySize {
		// 零化后再丢弃
		zeroBytes(k)
		return nil, fmt.Errorf("sealkey: KMS 密钥长度 %d 字节，期望 %d", len(k), s.keySize)
	}
	return k, nil
}

// ---- 历史密钥环加载 ----

// LoadSealKeyRing 加载历史密封密钥环（用于旧数据解密封）。
//
// source 列表按优先级排序（主密钥 = 第 0 项）。
// 所有来源均 fail-closed：任一来源失败 → 整体失败。
//
// 调用方负责零化返回的所有密钥字节（遍历 ring 调 zeroBytes）。
func LoadSealKeyRing(ctx context.Context, sources []SealKeySource) ([][]byte, error) {
	if len(sources) == 0 {
		return nil, errors.New("sealkey: 密钥源列表不能为空（fail-closed）")
	}
	ring := make([][]byte, 0, len(sources))
	for i, src := range sources {
		k, err := src.Load(ctx)
		if err != nil {
			// 失败时零化已加载的密钥
			for _, loaded := range ring {
				zeroBytes(loaded)
			}
			return nil, fmt.Errorf("sealkey: 第 %d 个密钥源加载失败: %w", i, err)
		}
		ring = append(ring, k)
	}
	return ring, nil
}

// ---- TDX 派生（TODO，占位） ----

// tdxDerivedSealKeySource TDX 派生密封密钥源。
//
// TODO(实测确认)：v1.5 定稿本期不实现，需真机 TDX 原语确认后再补。
// 保留结构体占位以便后续扩展，不暴露构造函数。
type tdxDerivedSealKeySource struct {
	// 预留：TDX 派生参数（measurement binding / context）
}

// 编译期保证（若未来实现，须满足接口）
var _ SealKeySource = (*tdxDerivedSealKeySource)(nil)

// Load 未实现。
func (s *tdxDerivedSealKeySource) Load(_ context.Context) ([]byte, error) {
	return nil, errors.New("sealkey: TDX 派生密封密钥未实现（TODO: 需真机 TDX 原语实测确认）")
}

// ---- 安全说明 ----
//
// D-T4-1（研发日志）：zeroBytes 用 for 循环逐字节写零，而非 crypto/subtle.XORBytes。
// 依据：1) 零化只需写零，不需要 XOR；2) 不引入新 import；3) for 循环语义清晰
// 且 Go 编译器在当前版本下不会对可见副作用的循环做死代码消除（b[i] = 0 是可见写入）。
// 若未来发现编译器优化导致零化失效，切换到 runtime.KeepAlive + 指针写入的实现。
//
// D-T4-2：错误消息不含密钥材料。所有错误只描述"长度/来源/格式"，绝不输出密钥字节。
// 依据：密钥属高敏感资产，任何明文输出都扩大泄露面。违反后需紧急轮换密钥。
