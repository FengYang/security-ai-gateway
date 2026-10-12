package attestverify

// T2 度量白名单单元测试（GAP-03）。
//
// 覆盖场景：
//   - 合法度量（MRTD + RTMR0..3 全匹配）→ 通过
//   - MRTD 不匹配 → 拒绝
//   - 某一 RTMR 不匹配 → 拒绝
//   - MRTD 长度不符 → 拒绝
//   - RTMR 数量不足 → 拒绝
//   - Quote 为 nil / TdQuoteBody 为 nil → 拒绝
//   - shadow 模式：不匹配不拒绝，仅返回已匹配项
//   - 配置加载：合法 JSON / 非法路径 / 非法长度 / platform 错误
//   - 常量时间比对（通过代码审查保证；测试验证行为正确性）
//   - app_hash 兼容（ContainsAppHash）

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
)

// 测试辅助：生成 48 字节的确定性度量值。
func testMeasurement(prefix byte) []byte {
	b := make([]byte, measurementHashSize)
	for i := range b {
		b[i] = prefix
	}
	return b
}

// 测试辅助：构造合法的 QuoteV4（MRTD + RTMR[0..3]）。
func makeQuoteV4(mrtd []byte, rtmrs [][]byte) *tdxpb.QuoteV4 {
	return &tdxpb.QuoteV4{
		TdQuoteBody: &tdxpb.TDQuoteBody{
			MrTd: mrtd,
			Rtmrs: rtmrs,
		},
	}
}

// 测试辅助：构造默认白名单配置。
func defaultAllowlistConfig() *MeasurementAllowlistConfig {
	return &MeasurementAllowlistConfig{
		Platform:   "tdx",
		Definition: "v1.0",
		MRTD:       hex.EncodeToString(testMeasurement(0xAA)),
		RTMR: []string{
			hex.EncodeToString(testMeasurement(0x01)),
			hex.EncodeToString(testMeasurement(0x02)),
			hex.EncodeToString(testMeasurement(0x03)),
			hex.EncodeToString(testMeasurement(0x04)),
		},
		AppHash: []string{"hash-1", "hash-2"},
	}
}

func TestMeasurementAllowlistHappyPath(t *testing.T) {
	al, err := newMeasurementAllowlistFromConfig(defaultAllowlistConfig(), MeasurementModeEnforce)
	if err != nil {
		t.Fatalf("构造白名单失败: %v", err)
	}
	if al.Definition() != "v1.0" {
		t.Fatalf("definition 不匹配: %s", al.Definition())
	}

	mrtd := testMeasurement(0xAA)
	rtmrs := [][]byte{
		testMeasurement(0x01),
		testMeasurement(0x02),
		testMeasurement(0x03),
		testMeasurement(0x04),
	}
	q := makeQuoteV4(mrtd, rtmrs)

	matched, err := al.CheckQuoteMeasurements(q)
	if err != nil {
		t.Fatalf("合法度量应通过: %v", err)
	}
	// 预期 5 项：mrtd + rtmr0..3
	if len(matched) != 5 {
		t.Fatalf("匹配项数应为 5，got %d: %v", len(matched), matched)
	}
	// 检查包含指定度量名
	want := map[string]bool{"mrtd": true, "rtmr0": true, "rtmr1": true, "rtmr2": true, "rtmr3": true}
	for _, m := range matched {
		if !want[m] {
			t.Fatalf("意外的匹配项: %s", m)
		}
	}
}

func TestMeasurementAllowlistMRTDMismatch(t *testing.T) {
	al, err := newMeasurementAllowlistFromConfig(defaultAllowlistConfig(), MeasurementModeEnforce)
	if err != nil {
		t.Fatalf("构造白名单失败: %v", err)
	}
	// MRTD 错误
	badMRTD := testMeasurement(0xBB) // 白名单是 0xAA
	rtmrs := [][]byte{
		testMeasurement(0x01),
		testMeasurement(0x02),
		testMeasurement(0x03),
		testMeasurement(0x04),
	}
	q := makeQuoteV4(badMRTD, rtmrs)

	_, err = al.CheckQuoteMeasurements(q)
	if err == nil {
		t.Fatal("MRTD 不匹配应拒绝")
	}
}

func TestMeasurementAllowlistRTMRMismatch(t *testing.T) {
	al, err := newMeasurementAllowlistFromConfig(defaultAllowlistConfig(), MeasurementModeEnforce)
	if err != nil {
		t.Fatalf("构造白名单失败: %v", err)
	}
	mrtd := testMeasurement(0xAA)
	// RTMR2 错误（白名单是 0x03，用 0x33）
	rtmrs := [][]byte{
		testMeasurement(0x01),
		testMeasurement(0x02),
		testMeasurement(0x33), // 错
		testMeasurement(0x04),
	}
	q := makeQuoteV4(mrtd, rtmrs)

	_, err = al.CheckQuoteMeasurements(q)
	if err == nil {
		t.Fatal("RTMR 不匹配应拒绝")
	}
}

func TestMeasurementAllowlistMRTDBadLength(t *testing.T) {
	al, err := newMeasurementAllowlistFromConfig(defaultAllowlistConfig(), MeasurementModeEnforce)
	if err != nil {
		t.Fatalf("构造白名单失败: %v", err)
	}
	// MRTD 长度不足（不是 48B）
	shortMRTD := []byte{0xAA, 0xBB, 0xCC} // 3B
	rtmrs := [][]byte{
		testMeasurement(0x01),
		testMeasurement(0x02),
		testMeasurement(0x03),
		testMeasurement(0x04),
	}
	q := makeQuoteV4(shortMRTD, rtmrs)

	_, err = al.CheckQuoteMeasurements(q)
	if err == nil {
		t.Fatal("MRTD 长度不符应拒绝")
	}
}

func TestMeasurementAllowlistRTMRShort(t *testing.T) {
	al, err := newMeasurementAllowlistFromConfig(defaultAllowlistConfig(), MeasurementModeEnforce)
	if err != nil {
		t.Fatalf("构造白名单失败: %v", err)
	}
	mrtd := testMeasurement(0xAA)
	// 只有 2 个 RTMR（应该 4 个）
	rtmrs := [][]byte{
		testMeasurement(0x01),
		testMeasurement(0x02),
	}
	q := makeQuoteV4(mrtd, rtmrs)

	_, err = al.CheckQuoteMeasurements(q)
	if err == nil {
		t.Fatal("RTMR 数量不足应拒绝")
	}
}

func TestMeasurementAllowlistNilQuote(t *testing.T) {
	al, err := newMeasurementAllowlistFromConfig(defaultAllowlistConfig(), MeasurementModeEnforce)
	if err != nil {
		t.Fatalf("构造白名单失败: %v", err)
	}
	_, err = al.CheckQuoteMeasurements(nil)
	if err == nil {
		t.Fatal("nil Quote 应拒绝")
	}
}

func TestMeasurementAllowlistNilBody(t *testing.T) {
	al, err := newMeasurementAllowlistFromConfig(defaultAllowlistConfig(), MeasurementModeEnforce)
	if err != nil {
		t.Fatalf("构造白名单失败: %v", err)
	}
	q := &tdxpb.QuoteV4{} // TdQuoteBody 为 nil
	_, err = al.CheckQuoteMeasurements(q)
	if err == nil {
		t.Fatal("nil TdQuoteBody 应拒绝")
	}
}

func TestMeasurementAllowlistShadowMode(t *testing.T) {
	al, err := newMeasurementAllowlistFromConfig(defaultAllowlistConfig(), MeasurementModeShadow)
	if err != nil {
		t.Fatalf("构造白名单失败: %v", err)
	}
	// MRTD + RTMR0 正确，RTMR2 错误
	mrtd := testMeasurement(0xAA)
	rtmrs := [][]byte{
		testMeasurement(0x01),
		testMeasurement(0x22), // 错（白名单是 0x02）
		testMeasurement(0x03),
		testMeasurement(0x04),
	}
	q := makeQuoteV4(mrtd, rtmrs)

	// shadow 模式：不返回 error，仅返回已匹配项
	matched, err := al.CheckQuoteMeasurements(q)
	if err != nil {
		t.Fatalf("shadow 模式不应返回错误: %v", err)
	}
	// mrtd + rtmr0 应该匹配（rtmr1 及以后不匹配，所以只到 rtmr0）
	if len(matched) != 2 {
		t.Fatalf("shadow 模式下应有 2 个匹配项（mrtd, rtmr0），got %d: %v", len(matched), matched)
	}
}

func TestMeasurementAllowlistShadowModeMRTDWrong(t *testing.T) {
	al, err := newMeasurementAllowlistFromConfig(defaultAllowlistConfig(), MeasurementModeShadow)
	if err != nil {
		t.Fatalf("构造白名单失败: %v", err)
	}
	badMRTD := testMeasurement(0xBB)
	rtmrs := [][]byte{
		testMeasurement(0x01),
		testMeasurement(0x02),
		testMeasurement(0x03),
		testMeasurement(0x04),
	}
	q := makeQuoteV4(badMRTD, rtmrs)

	matched, err := al.CheckQuoteMeasurements(q)
	if err != nil {
		t.Fatalf("shadow 模式不应返回错误: %v", err)
	}
	if len(matched) != 0 {
		t.Fatalf("MRTD 错误时 shadow 模式应有 0 个匹配项，got %d", len(matched))
	}
}

func TestMeasurementAllowlistSetMode(t *testing.T) {
	al, err := newMeasurementAllowlistFromConfig(defaultAllowlistConfig(), MeasurementModeEnforce)
	if err != nil {
		t.Fatalf("构造白名单失败: %v", err)
	}
	if al.Mode() != MeasurementModeEnforce {
		t.Fatal("初始模式应为 enforce")
	}
	al.SetMode(MeasurementModeShadow)
	if al.Mode() != MeasurementModeShadow {
		t.Fatal("切换后应为 shadow")
	}
}

func TestMeasurementAllowlistConfigLoading(t *testing.T) {
	dir := t.TempDir()
	_ = dir // 保留供后续扩展

	t.Run("EmptyPath", func(t *testing.T) {
		_, err := NewMeasurementAllowlist("", MeasurementModeEnforce)
		if err == nil {
			t.Fatal("空路径应报错")
		}
	})

	t.Run("FileNotExist", func(t *testing.T) {
		_, err := NewMeasurementAllowlist(filepath.Join(dir, "nonexist.json"), MeasurementModeEnforce)
		if err == nil {
			t.Fatal("不存在的文件应报错")
		}
	})

	t.Run("BadPlatform", func(t *testing.T) {
		bad := defaultAllowlistConfig()
		bad.Platform = "sgx"
		_, err := newMeasurementAllowlistFromConfig(bad, MeasurementModeEnforce)
		if err == nil {
			t.Fatal("非 tdx 平台应报错")
		}
	})

	t.Run("BadMRTDHex", func(t *testing.T) {
		bad := defaultAllowlistConfig()
		bad.MRTD = "zzzz" // 非 hex
		_, err := newMeasurementAllowlistFromConfig(bad, MeasurementModeEnforce)
		if err == nil {
			t.Fatal("非法 MRTD hex 应报错")
		}
	})

	t.Run("BadMRTDLength", func(t *testing.T) {
		bad := defaultAllowlistConfig()
		bad.MRTD = hex.EncodeToString([]byte{0xAA, 0xBB}) // 太短
		_, err := newMeasurementAllowlistFromConfig(bad, MeasurementModeEnforce)
		if err == nil {
			t.Fatal("MRTD 长度不对应报错")
		}
	})

	t.Run("BadRTMRCount", func(t *testing.T) {
		bad := defaultAllowlistConfig()
		bad.RTMR = bad.RTMR[:3] // 只有 3 个
		_, err := newMeasurementAllowlistFromConfig(bad, MeasurementModeEnforce)
		if err == nil {
			t.Fatal("RTMR 不是 4 个应报错")
		}
	})

	t.Run("BadRTMRHex", func(t *testing.T) {
		bad := defaultAllowlistConfig()
		bad.RTMR[1] = "nothex"
		_, err := newMeasurementAllowlistFromConfig(bad, MeasurementModeEnforce)
		if err == nil {
			t.Fatal("非法 RTMR hex 应报错")
		}
	})

	t.Run("NilConfig", func(t *testing.T) {
		_, err := newMeasurementAllowlistFromConfig(nil, MeasurementModeEnforce)
		if err == nil {
			t.Fatal("nil 配置应报错")
		}
	})
}

func TestMeasurementAllowlistAppHashCompat(t *testing.T) {
	al, err := newMeasurementAllowlistFromConfig(defaultAllowlistConfig(), MeasurementModeEnforce)
	if err != nil {
		t.Fatalf("构造白名单失败: %v", err)
	}
	if !al.ContainsAppHash("hash-1") {
		t.Fatal("hash-1 应在白名单内")
	}
	if !al.ContainsAppHash("hash-2") {
		t.Fatal("hash-2 应在白名单内")
	}
	if al.ContainsAppHash("hash-3") {
		t.Fatal("hash-3 不应在白名单内")
	}
}

func TestMeasurementModeFromString(t *testing.T) {
	tests := []struct {
		input string
		want  MeasurementMode
		err   bool
	}{
		{"", MeasurementModeEnforce, false},
		{"enforce", MeasurementModeEnforce, false},
		{"shadow", MeasurementModeShadow, false},
		{"ENFORCE", MeasurementModeEnforce, true}, // 大小写敏感
		{"invalid", MeasurementModeEnforce, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := MeasurementModeFromString(tt.input)
			if (err != nil) != tt.err {
				t.Fatalf("error = %v, wantErr = %v", err, tt.err)
			}
			if !tt.err && got != tt.want {
				t.Fatalf("got mode %d, want %d", got, tt.want)
			}
		})
	}
}

// TestLoadFromJSONFile 测试从 JSON 文件加载白名单（端到端）。
func TestLoadFromJSONFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.json")

	// 写 JSON 配置文件
	cfg := defaultAllowlistConfig()
	// 直接用 encoding/json 序列化
	jsonData := []byte(`{
		"platform": "` + cfg.Platform + `",
		"definition": "` + cfg.Definition + `",
		"mrtd": "` + cfg.MRTD + `",
		"rtmr": ["` + cfg.RTMR[0] + `", "` + cfg.RTMR[1] + `", "` + cfg.RTMR[2] + `", "` + cfg.RTMR[3] + `"],
		"app_hash": ["hash-1", "hash-2"]
	}`)
	if err := os.WriteFile(path, jsonData, 0o600); err != nil {
		t.Fatalf("写配置文件失败: %v", err)
	}

	al, err := NewMeasurementAllowlist(path, MeasurementModeEnforce)
	if err != nil {
		t.Fatalf("从文件加载白名单失败: %v", err)
	}
	if al.Definition() != "v1.0" {
		t.Fatalf("definition 不对: %s", al.Definition())
	}
	if !al.ContainsAppHash("hash-1") {
		t.Fatal("app_hash 加载失败")
	}
}
