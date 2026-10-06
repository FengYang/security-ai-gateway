// Enclave 抽象层测试。
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"

	"security-ai-gateway/gateway/cryptop"
	protocol "security-ai-gateway/protocol/go"
)

// TestMockEnclaveSealUnseal 密封-解封往返一致性（A3 密钥驻留基础）。
func TestMockEnclaveSealUnseal(t *testing.T) {
	e, err := NewMockEnclave()
	if err != nil {
		t.Fatalf("NewMockEnclave: %v", err)
	}
	secret := []byte("master-key-material-32-bytes!!")
	sealed, err := e.Seal(secret, "master")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// 密封输出必须不同于明文
	if bytes.Equal(sealed, secret) {
		t.Fatal("密封输出与明文相同")
	}
	unsealed, err := e.Unseal(sealed, "master")
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if !bytes.Equal(unsealed, secret) {
		t.Fatal("解封结果与原文不一致")
	}
}

// TestMockEnclaveSealContextMismatch 上下文不匹配必须解封失败（防跨用途）。
func TestMockEnclaveSealContextMismatch(t *testing.T) {
	e, _ := NewMockEnclave()
	sealed, err := e.Seal([]byte("secret"), "master")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Unseal(sealed, "other-context"); err == nil {
		t.Fatal("错误上下文解封未被拒绝")
	}
	// 篡改密封数据必须失败
	sealed[len(sealed)-1] ^= 0xFF
	if _, err := e.Unseal(sealed, "master"); err == nil {
		t.Fatal("篡改密封数据未被拒绝")
	}
}

// TestMockEnclaveMeasureStable 测量值必须稳定（Seal 上下文绑定与远程证明依赖）。
func TestMockEnclaveMeasureStable(t *testing.T) {
	e1, _ := NewMockEnclave()
	e2, _ := NewMockEnclave()
	m1, _ := e1.Measure()
	m2, _ := e2.Measure()
	if !bytes.Equal(m1, m2) {
		t.Fatal("mock 测量值不稳定（同实现应一致）")
	}
	want := sha256.Sum256([]byte("mock-enclave-measurement:v1"))
	if !bytes.Equal(m1, want[:]) {
		t.Fatal("mock 测量值不符合预期摘要")
	}
}

// TestMockEnclaveAttest 证明载荷：nonce 回显 + report_data 回显 + 签名可验证（A1 基础 + P1b 绑定）。
func TestMockEnclaveAttest(t *testing.T) {
	e, _ := NewMockEnclave()
	challenge := []byte("client-challenge-32-bytes-xxxxxxxx")
	serverPub := []byte("server-ephemeral-pub-raw-bytes!!!")
	reportData := reportDataBinding(challenge, serverPub)

	// report_data 为空必须报错（绑定材料必填，防跳过绑定）
	if _, err := e.Attest(challenge, nil); err == nil {
		t.Fatal("空 report_data 未被拒绝")
	}
	proof, err := e.Attest(challenge, reportData)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if !bytes.Equal(proof.Nonce, challenge) {
		t.Fatal("nonce 回显不一致")
	}
	if !bytes.Equal(proof.ReportData, reportData) {
		t.Fatal("report_data 回显不一致")
	}
	if proof.Platform != "mock" {
		t.Fatalf("platform 应为 mock: %q", proof.Platform)
	}
	if proof.Measurements["app_hash"] == "" {
		t.Fatal("measurements 缺少 app_hash")
	}
	// 校验签名：对 (report_data || signing_key) 的 sha256 用 signing_key 对应公钥验签
	x, y := elliptic.Unmarshal(elliptic.P256(), proof.SigningKey)
	if x == nil {
		t.Fatal("signing_key 非 P-256 公钥")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	toSign := append(append([]byte(nil), reportData...), proof.SigningKey...)
	h := sha256.Sum256(toSign)
	r := new(big.Int).SetBytes(proof.Signature[:32])
	s := new(big.Int).SetBytes(proof.Signature[32:])
	if !ecdsa.Verify(pub, h[:], r, s) {
		t.Fatal("证明载荷签名验证失败")
	}
}

// TestNewPlatformEnclave 平台接入语义：未知/未接入平台报错；
// tdx 已接入——无 TDX 硬件环境（开发机/CI）构造失败（fail-fast，防静默降级），
// 真 TDX 环境构造成功且平台标识正确（真机黄金路径）。
func TestNewPlatformEnclave(t *testing.T) {
	if _, err := newPlatformEnclave("unknown-xyz"); err == nil {
		t.Fatal("未知平台应返回错误")
	}
	if _, err := newPlatformEnclave("sgx"); err == nil {
		t.Fatal("sgx 未接入应返回错误")
	}
	e, err := newPlatformEnclave("tdx")
	if err != nil {
		t.Logf("无 TDX 硬件环境（预期 fail-fast）: %v", err)
		return
	}
	if e.Platform() != "tdx" {
		t.Fatalf("真机平台标识应为 tdx: %q", e.Platform())
	}
	if m, err := e.Measure(); err != nil || len(m) != 32 {
		t.Fatalf("真机测量值异常: %v %d", err, len(m))
	}
}

// TestTdxReportData 绑定材料扩展：32B→64B 前缀、余零、超长截断。
func TestTdxReportData(t *testing.T) {
	rd32 := make([]byte, 32)
	for i := range rd32 {
		rd32[i] = byte(i)
	}
	rd := tdxReportData(rd32)
	if !bytes.Equal(rd[:32], rd32) {
		t.Fatal("REPORTDATA 前 32B 应为绑定材料原样")
	}
	for _, b := range rd[32:] {
		if b != 0 {
			t.Fatal("REPORTDATA 后 32B 应置零")
		}
	}
	// 超长截断：只取前 32B
	long := make([]byte, 64)
	copy(long, rd32)
	rd2 := tdxReportData(long)
	if rd2 != rd {
		t.Fatal("超长绑定材料应截断为前 32B")
	}
	// 短材料：前缀填充
	short := []byte("short-binding")
	rd3 := tdxReportData(short)
	if !bytes.Equal(rd3[:len(short)], short) {
		t.Fatal("短绑定材料应前缀填充")
	}
}

// TestSealFileRoundtrip 密封文件写入-读取往返一致（A3 密钥驻留：重启经 Unseal 恢复）。
func TestSealFileRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/seal.bin"
	// mock 密封密钥固定（模拟 TEE 平台绑定密钥持久存在；重启后仍可 Unseal）
	t.Setenv(mockSealKeyEnv, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	// 第一次：写入密封文件
	e, _ := NewMockEnclave()
	master := []byte("master-key-32-bytes-aaaaaaaaaaaa")
	kSig := []byte("sig-key-32-bytes-bbbbbbbbbbbbbb")
	mb, _ := e.Seal(master, "master")
	sb, _ := e.Seal(kSig, "k_sig")
	if err := writeSealFile(path, mb, sb); err != nil {
		t.Fatalf("writeSealFile: %v", err)
	}

	// 第二次：读取并恢复（模拟重启：新 MockEnclave 实例 + 同一平台密钥）
	e2, _ := NewMockEnclave()
	mb2, sb2 := readSealFile(path)
	if mb2 == nil || sb2 == nil {
		t.Fatal("readSealFile 返回 nil")
	}
	master2, err := e2.Unseal(mb2, "master")
	if err != nil {
		t.Fatalf("Unseal master: %v", err)
	}
	kSig2, err := e2.Unseal(sb2, "k_sig")
	if err != nil {
		t.Fatalf("Unseal k_sig: %v", err)
	}
	if string(master2) != string(master) || string(kSig2) != string(kSig) {
		t.Fatal("密封恢复结果不一致")
	}

	// 不存在的文件返回 nil
	if a, b := readSealFile(dir + "/missing.bin"); a != nil || b != nil {
		t.Fatal("缺失密封文件应返回 nil")
	}
}

// ---- B5-a：suite 版本化双读（§5.4.3 组⑨；T-7.1/T-7.2/T-7.4）----

// newSealTestEnclave 直接构造仅用于密封测试的 mock 飞地（不经 env/证明密钥）。
func newSealTestEnclave(currentKey []byte, ring [][]byte) *MockEnclave {
	return &MockEnclave{sealKey: currentKey, sealKeyRing: ring, platform: "mock"}
}

// assembleSealBlob 按指定 provider 手工装配密封 blob：
// suite=0 旧格式（无前缀）；否则 suite‖AAD‖nonce‖ct。
func assembleSealBlob(t *testing.T, prov cryptop.Provider, suite byte, key, plaintext []byte, ctx string) []byte {
	t.Helper()
	aad := contextHashFor(prov, ctx)
	nonce, sealed, err := prov.SealWithNonce(key, plaintext, aad)
	if err != nil {
		t.Fatalf("装配密封 blob 失败: %v", err)
	}
	if suite == 0 {
		out := make([]byte, 0, len(aad)+len(nonce)+len(sealed))
		out = append(out, aad...)
		out = append(out, nonce...)
		out = append(out, sealed...)
		return out
	}
	out := make([]byte, 0, 1+len(aad)+len(nonce)+len(sealed))
	out = append(out, suite)
	out = append(out, aad...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out
}

// legacyCtxWithFirstByte 搜索一个 context，使其旧格式 blob 首字节（AAD 首字节）
// 恰为 want——构造"旧 blob 首字节撞 suite 值"的认证判别场景。
func legacyCtxWithFirstByte(t *testing.T, want byte) string {
	t.Helper()
	for i := 0; i < 100000; i++ {
		ctx := fmt.Sprintf("ambig-%d", i)
		if contextHashFor(hashProvSHA256, ctx)[0] == want {
			return ctx
		}
	}
	t.Fatalf("未找到首字节=0x%02x 的上下文", want)
	return ""
}

func TestStorageSealDualRead(t *testing.T) {
	intlKey := bytes.Repeat([]byte{0x11}, 32) // AES-256
	smKey := bytes.Repeat([]byte{0x22}, 16)   // SM4
	plaintext := []byte("sealed-master-key-material-32B")
	const ctx = "master"

	t.Run("T-7.1 intl 写→sm 读（密钥环）", func(t *testing.T) {
		blob := assembleSealBlob(t, hashProvSHA256, protocol.SuiteAESGCM, intlKey, plaintext, ctx)
		// sm 侧：当前 SM4 密钥 + 环内保留旧 AES 密钥
		smSide := newSealTestEnclave(smKey, [][]byte{intlKey})
		got, err := smSide.Unseal(blob, ctx)
		if err != nil {
			t.Fatalf("sm 侧解 intl blob 失败: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatal("解封明文不符")
		}
		// 环内缺旧密钥 → 拒绝（fail-closed）
		if _, err := newSealTestEnclave(smKey, nil).Unseal(blob, ctx); err == nil {
			t.Fatal("环内无 AES 密钥却解封成功")
		}
	})

	t.Run("T-7.2 sm 写→intl 回滚读（密钥环）", func(t *testing.T) {
		blob := assembleSealBlob(t, hashProvSM3, protocol.SuiteSM4GCM, smKey, plaintext, ctx)
		intlSide := newSealTestEnclave(intlKey, [][]byte{smKey})
		got, err := intlSide.Unseal(blob, ctx)
		if err != nil {
			t.Fatalf("intl 侧解 sm blob 失败: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatal("解封明文不符")
		}
	})

	t.Run("T-7.4 旧格式（无前缀）fail-safe 按 AES 解析", func(t *testing.T) {
		legacy := assembleSealBlob(t, hashProvSHA256, 0, intlKey, plaintext, ctx)
		// intl 进程当前密钥即可解
		if got, err := newSealTestEnclave(intlKey, nil).Unseal(legacy, ctx); err != nil {
			t.Fatalf("intl 侧解旧 blob 失败: %v", err)
		} else if !bytes.Equal(got, plaintext) {
			t.Fatal("明文不符")
		}
		// sm 进程须环内保留 AES 旧密钥
		if got, err := newSealTestEnclave(smKey, [][]byte{intlKey}).Unseal(legacy, ctx); err != nil {
			t.Fatalf("sm 侧解旧 blob 失败: %v", err)
		} else if !bytes.Equal(got, plaintext) {
			t.Fatal("明文不符")
		}
	})

	t.Run("旧 blob 首字节撞 0x01：AEAD 认证判别后回退", func(t *testing.T) {
		c := legacyCtxWithFirstByte(t, protocol.SuiteAESGCM)
		legacy := assembleSealBlob(t, hashProvSHA256, 0, intlKey, plaintext, c)
		got, err := newSealTestEnclave(intlKey, nil).Unseal(legacy, c)
		if err != nil {
			t.Fatalf("首字节 0x01 旧 blob 回退解封失败: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatal("明文不符")
		}
	})

	t.Run("旧 blob 首字节撞 0x02：SM4 预解析失败后回退", func(t *testing.T) {
		c := legacyCtxWithFirstByte(t, protocol.SuiteSM4GCM)
		legacy := assembleSealBlob(t, hashProvSHA256, 0, intlKey, plaintext, c)
		got, err := newSealTestEnclave(intlKey, nil).Unseal(legacy, c)
		if err != nil {
			t.Fatalf("首字节 0x02 旧 blob 回退解封失败: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatal("明文不符")
		}
	})

	t.Run("密钥环按序试解：第二枚命中", func(t *testing.T) {
		blob := assembleSealBlob(t, hashProvSHA256, protocol.SuiteAESGCM, intlKey, plaintext, ctx)
		wrong := bytes.Repeat([]byte{0x33}, 32)
		side := newSealTestEnclave(smKey, [][]byte{wrong, intlKey})
		got, err := side.Unseal(blob, ctx)
		if err != nil {
			t.Fatalf("环内第二枚密钥应解封: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatal("明文不符")
		}
	})

	t.Run("篡改/上下文错均拒绝（即使环内有密钥）", func(t *testing.T) {
		blob := assembleSealBlob(t, hashProvSHA256, protocol.SuiteAESGCM, intlKey, plaintext, ctx)
		side := newSealTestEnclave(smKey, [][]byte{intlKey})
		tampered := make([]byte, len(blob))
		copy(tampered, blob)
		tampered[len(tampered)-1] ^= 0xFF
		if _, err := side.Unseal(tampered, ctx); err == nil {
			t.Fatal("篡改 blob 未被拒绝")
		}
		if _, err := side.Unseal(blob, "other-context"); err == nil {
			t.Fatal("上下文不符未被拒绝")
		}
	})

	t.Run("新写入恒定带 suite 前缀", func(t *testing.T) {
		e := newSealTestEnclave(intlKey, nil)
		blob, err := e.Seal(plaintext, ctx)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if blob[0] != protocol.SuiteAESGCM {
			t.Fatalf("intl 新 blob 首字节应为 0x01，实际 0x%02x", blob[0])
		}
	})
}

// TestLoadSealKeyHistory 历史密钥环 env 解析（冒号分隔；32/16 可混；非法拒绝）。
func TestLoadSealKeyHistory(t *testing.T) {
	const envName = "TEST_SEAL_KEY_HISTORY"
	t.Setenv(envName, "")
	ring, err := loadSealKeyHistory(envName)
	if err != nil || ring != nil {
		t.Fatalf("未设置时应返回 nil: %v %d", err, len(ring))
	}
	t.Setenv(envName,
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:0123456789abcdef0123456789abcdef")
	ring, err = loadSealKeyHistory(envName)
	if err != nil || len(ring) != 2 || len(ring[0]) != 32 || len(ring[1]) != 16 {
		t.Fatalf("两枚混列解析异常: %v %+v", err, ring)
	}
	t.Setenv(envName, "not-hex")
	if _, err := loadSealKeyHistory(envName); err == nil {
		t.Fatal("非法 hex 应返回错误")
	}
	t.Setenv(envName, "0123456789abcdef") // 8B：长度不合法
	if _, err := loadSealKeyHistory(envName); err == nil {
		t.Fatal("非 32/16 字节密钥应返回错误")
	}
}
