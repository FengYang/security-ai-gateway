package attestverify

// T1 DCAP 验证器单元测试（GAP-01）。
//
// 聚焦可本地验证的逻辑：
//   - 构造选项（GetCollateral / TTL / allowlist / getter）
//   - 接口一致性（DcapVerifier 实现 AttestationVerifier）
//   - 空/非法 quote 拒绝（fail-closed）
//   - report_data 绑定校验（checkReportData，常量时间）
//   - 度量白名单集成（DcapVerifier + MeasurementAllowlist 联动）
//   - collateral 缓存初始状态
//
// 完整 DCAP 签名链验证需真实 PCS + 真机 Quote，
// 属集成测试范畴（不在本单测范围）。

import (
	"crypto/sha256"
	"testing"
	"time"

	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
)

// ---- 基本构造测试 ----

func TestDcapVerifierNew(t *testing.T) {
	v := NewDcapVerifier()
	if v == nil {
		t.Fatal("构造失败")
	}
	if !v.getCollateral {
		t.Fatal("默认应开启 collateral 获取")
	}
	if v.collateralTTL != time.Hour {
		t.Fatalf("默认 TTL 应为 1h，got %v", v.collateralTTL)
	}
}

func TestDcapVerifierOptions(t *testing.T) {
	al, _ := newMeasurementAllowlistFromConfig(defaultAllowlistConfig(), MeasurementModeEnforce)
	v := NewDcapVerifier(
		WithGetCollateral(false),
		WithCollateralTTL(30*time.Minute),
		WithMeasurementAllowlist(al),
	)
	if v.getCollateral {
		t.Fatal("应关闭 collateral 获取")
	}
	if v.collateralTTL != 30*time.Minute {
		t.Fatalf("TTL 应为 30m，got %v", v.collateralTTL)
	}
	if v.allowlist == nil {
		t.Fatal("allowlist 应被设置")
	}
}

func TestDcapVerifierImplementsInterface(t *testing.T) {
	// 编译期检查：DcapVerifier 实现 AttestationVerifier 接口
	var _ AttestationVerifier = (*DcapVerifier)(nil)
}

// ---- 空 quote / 非法格式 ----

func TestDcapVerifierEmptyQuote(t *testing.T) {
	v := NewDcapVerifier(WithGetCollateral(false))
	_, err := v.VerifyQuote(nil, []byte("report-data"))
	if err == nil {
		t.Fatal("nil quote 应拒绝")
	}
	_, err = v.VerifyQuote([]byte{}, []byte("report-data"))
	if err == nil {
		t.Fatal("空 quote 应拒绝")
	}
}

func TestDcapVerifierMalformedQuote(t *testing.T) {
	v := NewDcapVerifier(WithGetCollateral(false))
	// 随机字节，非合法 Quote 格式
	cases := [][]byte{
		[]byte("not a quote"),
		[]byte{0x01, 0x02, 0x03},
		make([]byte, 100), // 全零
	}
	for i, tc := range cases {
		_, err := v.VerifyQuote(tc, []byte("report-data"))
		if err == nil {
			t.Fatalf("case %d: 非法 quote 应拒绝", i)
		}
	}
}

// ---- report_data 绑定测试 ----

func TestDcapVerifierCheckReportDataMatch(t *testing.T) {
	v := NewDcapVerifier()

	reportDataInput := []byte("hello-attestation-handshake")
	expectedHash := sha256.Sum256(reportDataInput)
	reportData := make([]byte, 64)
	copy(reportData, expectedHash[:])

	q := &tdxpb.QuoteV4{
		TdQuoteBody: &tdxpb.TDQuoteBody{
			ReportData: reportData,
		},
	}

	if err := v.checkReportData(q, reportDataInput); err != nil {
		t.Fatalf("report_data 匹配应通过: %v", err)
	}
}

func TestDcapVerifierCheckReportDataMismatch(t *testing.T) {
	v := NewDcapVerifier()

	reportDataInput := []byte("hello-attestation-handshake")
	wrongInput := []byte("wrong-data")
	expectedHash := sha256.Sum256(reportDataInput)
	reportData := make([]byte, 64)
	copy(reportData, expectedHash[:])

	q := &tdxpb.QuoteV4{
		TdQuoteBody: &tdxpb.TDQuoteBody{
			ReportData: reportData,
		},
	}

	if err := v.checkReportData(q, wrongInput); err == nil {
		t.Fatal("report_data 不匹配应报错")
	}
}

func TestDcapVerifierCheckReportDataNilBody(t *testing.T) {
	v := NewDcapVerifier()
	q := &tdxpb.QuoteV4{} // TdQuoteBody 为 nil
	if err := v.checkReportData(q, []byte("x")); err == nil {
		t.Fatal("nil body 应报错")
	}
}

func TestDcapVerifierCheckReportDataShort(t *testing.T) {
	v := NewDcapVerifier()
	q := &tdxpb.QuoteV4{
		TdQuoteBody: &tdxpb.TDQuoteBody{
			ReportData: []byte{0x01, 0x02, 0x03}, // 不足 32B
		},
	}
	if err := v.checkReportData(q, []byte("x")); err == nil {
		t.Fatal("report_data 太短应报错")
	}
}

func TestDcapVerifierCheckReportDataExact32Bytes(t *testing.T) {
	v := NewDcapVerifier()
	// report_data 恰好 32B（TDX 规范中 report_data 是 64B，
	// 但我们只校验前 32B = SHA-256 digest）
	input := []byte("test-32byte")
	hash := sha256.Sum256(input)
	reportData := hash[:] // 32B

	q := &tdxpb.QuoteV4{
		TdQuoteBody: &tdxpb.TDQuoteBody{
			ReportData: reportData,
		},
	}
	if err := v.checkReportData(q, input); err != nil {
		t.Fatalf("32B report_data 应通过: %v", err)
	}
}

// ---- 度量白名单集成测试（proto 级别） ----

func TestDcapVerifierWithAllowlistEnforce(t *testing.T) {
	al, _ := newMeasurementAllowlistFromConfig(defaultAllowlistConfig(), MeasurementModeEnforce)
	v := NewDcapVerifier(
		WithGetCollateral(false),
		WithMeasurementAllowlist(al),
	)
	if v.allowlist == nil {
		t.Fatal("allowlist 应已设置")
	}
	if v.allowlist.Mode() != MeasurementModeEnforce {
		t.Fatalf("模式应为 enforce，got %v", v.allowlist.Mode())
	}

	// 构造匹配的 Quote（proto 级别，不转 ABI）
	q := &tdxpb.QuoteV4{
		TdQuoteBody: &tdxpb.TDQuoteBody{
			MrTd: testMeasurement(0xAA),
			Rtmrs: [][]byte{
				testMeasurement(0x01),
				testMeasurement(0x02),
				testMeasurement(0x03),
				testMeasurement(0x04),
			},
		},
	}

	matched, err := v.allowlist.CheckQuoteMeasurements(q)
	if err != nil {
		t.Fatalf("白名单校验应通过: %v", err)
	}
	if len(matched) != 5 {
		t.Fatalf("应有 5 个匹配项，got %d", len(matched))
	}
}

func TestDcapVerifierWithAllowlistShadow(t *testing.T) {
	al, _ := newMeasurementAllowlistFromConfig(defaultAllowlistConfig(), MeasurementModeShadow)
	v := NewDcapVerifier(
		WithGetCollateral(false),
		WithMeasurementAllowlist(al),
	)

	if v.allowlist.Mode() != MeasurementModeShadow {
		t.Fatalf("模式应为 shadow，got %v", v.allowlist.Mode())
	}
}

func TestDcapVerifierNoAllowlist(t *testing.T) {
	v := NewDcapVerifier(WithGetCollateral(false))
	if v.allowlist != nil {
		t.Fatal("未配置时 allowlist 应为 nil")
	}
}

// ---- collateral 缓存初始状态 ----

func TestDcapVerifierCacheInitialInvalid(t *testing.T) {
	v := NewDcapVerifier(WithGetCollateral(false))
	if v.CollateralCacheValid() {
		t.Fatal("初始缓存应无效")
	}
}

func TestDcapVerifierBuildVerifyOptionsDefault(t *testing.T) {
	v := NewDcapVerifier() // 默认 getCollateral=true
	opts := v.buildVerifyOptions()
	if !opts.GetCollateral {
		t.Fatal("默认应从 PCS 获取 collateral")
	}
}

func TestDcapVerifierBuildVerifyOptionsNoCollateral(t *testing.T) {
	v := NewDcapVerifier(WithGetCollateral(false))
	opts := v.buildVerifyOptions()
	if opts.GetCollateral {
		t.Fatal("关闭后不应从 PCS 获取 collateral")
	}
}

// ---- 常量时间比对验证（行为验证） ----

func TestDcapVerifierReportDataConstantTime(t *testing.T) {
	v := NewDcapVerifier()
	input := []byte("test-input")
	hash := sha256.Sum256(input)

	// 完全匹配
	q1 := &tdxpb.QuoteV4{
		TdQuoteBody: &tdxpb.TDQuoteBody{ReportData: hash[:]},
	}
	if err := v.checkReportData(q1, input); err != nil {
		t.Fatalf("匹配应通过: %v", err)
	}

	// 第一个字节不同 → 应不匹配
	badHash := make([]byte, 32)
	copy(badHash, hash[:])
	badHash[0] ^= 0xFF
	q2 := &tdxpb.QuoteV4{
		TdQuoteBody: &tdxpb.TDQuoteBody{ReportData: badHash},
	}
	if err := v.checkReportData(q2, input); err == nil {
		t.Fatal("首字节不同应不匹配")
	}

	// 最后一个字节不同 → 应不匹配
	badHash2 := make([]byte, 32)
	copy(badHash2, hash[:])
	badHash2[31] ^= 0xFF
	q3 := &tdxpb.QuoteV4{
		TdQuoteBody: &tdxpb.TDQuoteBody{ReportData: badHash2},
	}
	if err := v.checkReportData(q3, input); err == nil {
		t.Fatal("末字节不同应不匹配")
	}
	// 注意：真正的常量时间需要时序测量，这里只验证行为正确性
}
