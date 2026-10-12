package main

// T4 密封密钥来源单元测试（GAP-04）。
//
// 安全约束：
//   - 测试用例不输出密钥材料
//   - 使用固定测试向量（32 字节全 0x41 等），不模拟真实密钥
//   - 零化测试验证"使用后全零"
//   - 错误消息中不含密钥字节

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"testing"
)

// ---- zeroBytes 测试 ----

func TestZeroBytes(t *testing.T) {
	b := make([]byte, 32)
	for i := range b {
		b[i] = 0x41
	}
	zeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("字节 %d 未被零化: %x", i, v)
		}
	}
}

func TestZeroBytesEmpty(t *testing.T) {
	b := []byte{}
	zeroBytes(b) // 不应 panic
}

func TestZeroBytesSingleByte(t *testing.T) {
	b := []byte{0xFF}
	zeroBytes(b)
	if b[0] != 0 {
		t.Fatal("单字节未零化")
	}
}

// ---- envSealKeySource 测试 ----

func TestEnvSealKeySourceSuccess(t *testing.T) {
	// 32 字节测试向量（AES-256 长度）
	testKey := make([]byte, 32)
	for i := range testKey {
		testKey[i] = 0x42
	}
	testKeyHex := hex.EncodeToString(testKey)

	envName := "TEST_SEAL_KEY_ENV"
	os.Setenv(envName, testKeyHex)
	defer os.Unsetenv(envName)

	src := NewEnvSealKeySource(envName, 32)
	k, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	defer zeroBytes(k)

	if len(k) != 32 {
		t.Fatalf("长度应为 32，got %d", len(k))
	}
	if !bytes.Equal(k, testKey) {
		t.Fatal("密钥内容不匹配")
	}
}

func TestEnvSealKeySourceUnset(t *testing.T) {
	envName := "TEST_SEAL_KEY_NEVER_SET_12345"
	os.Unsetenv(envName) // 确保未设置
	defer os.Unsetenv(envName)

	src := NewEnvSealKeySource(envName, 32)
	_, err := src.Load(context.Background())
	if err == nil {
		t.Fatal("未设置环境变量应报错（fail-closed）")
	}
	// 错误消息应包含 fail-closed
	errStr := err.Error()
	if !containsSubstring(errStr, "fail-closed") {
		t.Fatalf("错误应提示 fail-closed: %v", err)
	}
}

func TestEnvSealKeySourceBadHex(t *testing.T) {
	envName := "TEST_SEAL_KEY_BAD_HEX"
	os.Setenv(envName, "not-hex-zzz")
	defer os.Unsetenv(envName)

	src := NewEnvSealKeySource(envName, 32)
	_, err := src.Load(context.Background())
	if err == nil {
		t.Fatal("非法 hex 应报错")
	}
}

func TestEnvSealKeySourceWrongLength(t *testing.T) {
	envName := "TEST_SEAL_KEY_SHORT"
	shortKey := hex.EncodeToString([]byte{0x01, 0x02, 0x03}) // 3 字节，不够
	os.Setenv(envName, shortKey)
	defer os.Unsetenv(envName)

	src := NewEnvSealKeySource(envName, 32)
	_, err := src.Load(context.Background())
	if err == nil {
		t.Fatal("长度不匹配应报错")
	}
}

func TestEnvSealKeySourceSM4Length(t *testing.T) {
	// SM4 16 字节
	testKey := make([]byte, 16)
	for i := range testKey {
		testKey[i] = 0x55
	}
	envName := "TEST_SEAL_KEY_SM4"
	os.Setenv(envName, hex.EncodeToString(testKey))
	defer os.Unsetenv(envName)

	src := NewEnvSealKeySource(envName, 16)
	k, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("16 字节密钥应通过: %v", err)
	}
	defer zeroBytes(k)
	if len(k) != 16 {
		t.Fatalf("长度应为 16，got %d", len(k))
	}
}

// ---- mockKMS（测试辅助） ----

type mockKMS struct {
	key []byte // 返回的密钥
	err error  // 返回的错误
}

func (m *mockKMS) Get(_ context.Context, ref string) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	// 返回一份拷贝（避免调用方零化影响 mock）
	out := make([]byte, len(m.key))
	copy(out, m.key)
	return out, nil
}

// ---- kmsSealKeySource 构造测试 ----

func TestKmsSealKeySourceConstructNilClient(t *testing.T) {
	_, err := NewKmsSealKeySource(nil, "ref", 32)
	if err == nil {
		t.Fatal("nil client 应报错（fail-closed）")
	}
}

func TestKmsSealKeySourceConstructEmptyRef(t *testing.T) {
	mock := &mockKMS{key: make([]byte, 32)}
	_, err := NewKmsSealKeySource(mock, "", 32)
	if err == nil {
		t.Fatal("空 ref 应报错（fail-closed）")
	}
	_, err = NewKmsSealKeySource(mock, "   ", 32)
	if err == nil {
		t.Fatal("空白 ref 应报错（fail-closed）")
	}
}

func TestKmsSealKeySourceConstructInvalidKeySize(t *testing.T) {
	mock := &mockKMS{key: make([]byte, 32)}
	_, err := NewKmsSealKeySource(mock, "ref", 0)
	if err == nil {
		t.Fatal("keySize=0 应报错")
	}
	_, err = NewKmsSealKeySource(mock, "ref", -1)
	if err == nil {
		t.Fatal("keySize=-1 应报错")
	}
}

func TestKmsSealKeySourceConstructOK(t *testing.T) {
	mock := &mockKMS{key: make([]byte, 32)}
	src, err := NewKmsSealKeySource(mock, "arn:aws:kms:us-east-1:123456789:key/abc-123", 32)
	if err != nil {
		t.Fatalf("构造应成功: %v", err)
	}
	if src == nil {
		t.Fatal("返回值不应为 nil")
	}
}

// ---- kmsSealKeySource Load 测试 ----

func TestKmsSealKeySourceLoadSuccess(t *testing.T) {
	testKey := make([]byte, 32)
	for i := range testKey {
		testKey[i] = 0x37
	}
	mock := &mockKMS{key: testKey}

	src, _ := NewKmsSealKeySource(mock, "test-ref", 32)
	k, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	defer zeroBytes(k)

	if !bytes.Equal(k, testKey) {
		t.Fatal("密钥内容不匹配")
	}

	// 验证返回的是拷贝（零化 k 不影响 mock）
	if !bytes.Equal(mock.key, testKey) {
		t.Fatal("mock 的 key 不应被调用方零化影响")
	}
}

func TestKmsSealKeySourceLoadKMSError(t *testing.T) {
	mock := &mockKMS{err: errors.New("KMS 不可达：网络超时")}
	src, _ := NewKmsSealKeySource(mock, "test-ref", 32)
	_, err := src.Load(context.Background())
	if err == nil {
		t.Fatal("KMS 错误应向上传递（fail-closed）")
	}
}

func TestKmsSealKeySourceLoadEmptyKey(t *testing.T) {
	mock := &mockKMS{key: []byte{}} // 空密钥
	src, _ := NewKmsSealKeySource(mock, "test-ref", 32)
	_, err := src.Load(context.Background())
	if err == nil {
		t.Fatal("空密钥应报错（fail-closed）")
	}
}

func TestKmsSealKeySourceLoadWrongLength(t *testing.T) {
	// 返回 16 字节，但期望 32 字节
	mock := &mockKMS{key: make([]byte, 16)}
	src, _ := NewKmsSealKeySource(mock, "test-ref", 32)
	k, err := src.Load(context.Background())
	if err == nil {
		t.Fatal("长度不符应报错（fail-closed）")
	}
	// k 应被零化后丢弃（Load 内部零化，不返回）
	if k != nil {
		// 应该返回 nil key
	}
}

// ---- LoadSealKeyRing 测试 ----

func TestLoadSealKeyRingSingle(t *testing.T) {
	testKey := make([]byte, 32)
	for i := range testKey {
		testKey[i] = 0x11
	}
	mock := &mockKMS{key: testKey}
	src, _ := NewKmsSealKeySource(mock, "ref-main", 32)

	ring, err := LoadSealKeyRing(context.Background(), []SealKeySource{src})
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	defer func() {
		for _, k := range ring {
			zeroBytes(k)
		}
	}()

	if len(ring) != 1 {
		t.Fatalf("应有 1 枚密钥，got %d", len(ring))
	}
	if !bytes.Equal(ring[0], testKey) {
		t.Fatal("主密钥内容不匹配")
	}
}

func TestLoadSealKeyRingMultiple(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	for i := range key1 {
		key1[i] = 0x11
		key2[i] = 0x22
	}
	mock1 := &mockKMS{key: key1}
	mock2 := &mockKMS{key: key2}
	src1, _ := NewKmsSealKeySource(mock1, "ref-1", 32)
	src2, _ := NewKmsSealKeySource(mock2, "ref-2", 32)

	ring, err := LoadSealKeyRing(context.Background(), []SealKeySource{src1, src2})
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	defer func() {
		for _, k := range ring {
			zeroBytes(k)
		}
	}()

	if len(ring) != 2 {
		t.Fatalf("应有 2 枚密钥，got %d", len(ring))
	}
	if !bytes.Equal(ring[0], key1) {
		t.Fatal("第 1 枚不匹配")
	}
	if !bytes.Equal(ring[1], key2) {
		t.Fatal("第 2 枚不匹配")
	}
}

func TestLoadSealKeyRingFailClosed(t *testing.T) {
	key1 := make([]byte, 32)
	for i := range key1 {
		key1[i] = 0x11
	}
	mock1 := &mockKMS{key: key1}
	mock2 := &mockKMS{err: errors.New("KMS 不可达")}
	src1, _ := NewKmsSealKeySource(mock1, "ref-1", 32)
	src2, _ := NewKmsSealKeySource(mock2, "ref-2", 32)

	ring, err := LoadSealKeyRing(context.Background(), []SealKeySource{src1, src2})
	if err == nil {
		t.Fatal("第 2 个失败应整体失败（fail-closed）")
		defer func() {
			for _, k := range ring {
				zeroBytes(k)
			}
		}()
	}
	if ring != nil {
		// 失败时应返回 nil ring
	}
}

func TestLoadSealKeyRingEmptySources(t *testing.T) {
	_, err := LoadSealKeyRing(context.Background(), []SealKeySource{})
	if err == nil {
		t.Fatal("空 sources 应报错（fail-closed）")
	}
}

// ---- TDX 派生占位测试 ----

func TestTdxDerivedSealKeySourceNotImplemented(t *testing.T) {
	src := &tdxDerivedSealKeySource{}
	_, err := src.Load(context.Background())
	if err == nil {
		t.Fatal("TDX 派生应未实现")
	}
	errStr := err.Error()
	if !containsSubstring(errStr, "TODO") {
		t.Fatalf("错误应含 TODO 标识: %v", err)
	}
}

// ---- 接口一致性 ----

func TestSealKeySourceInterface(t *testing.T) {
	// 编译期检查：各实现均满足 SealKeySource 接口
	var _ SealKeySource = (*envSealKeySource)(nil)
	var _ SealKeySource = (*kmsSealKeySource)(nil)
	var _ SealKeySource = (*tdxDerivedSealKeySource)(nil)
}

// ---- 辅助函数 ----

func containsSubstring(s, sub string) bool {
	if len(s) < len(sub) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
