package cryptopmodule

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

// detSeq SHA-256 计数器模式生成确定性 n 字节伪随机样本。确定性保证测试
// 可复现；分布均匀性足以通过三项启动检测（n=2500）与上电检测全量档
// （n=2500000，种子经实测挑选，见 TestRunRandSelfCheckPowerOnRetryThenPass）。
func detSeq(n int, seed string) []byte {
	buf := make([]byte, n)
	var ctr uint64
	h := sha256.New()
	for off := 0; off < len(buf); off += 32 {
		h.Reset()
		h.Write([]byte(seed))
		var c [8]byte
		binary.BigEndian.PutUint64(c[:], ctr)
		h.Write(c[:])
		copy(buf[off:], h.Sum(nil))
		ctr++
	}
	return buf
}

func TestRunRandSelfCheckQuickPass(t *testing.T) {
	rep, err := RunRandSelfCheck(bytes.NewReader(detSeq(2500, "p2-3-rand-quick-pass")), RandCheckQuick)
	if err != nil {
		t.Fatalf("RunRandSelfCheck 过程失败: %v", err)
	}
	if !rep.Passed {
		t.Fatalf("确定性均匀样本应通过: %s", rep)
	}
	if len(rep.Items) != 3 {
		t.Fatalf("quick 档应含 3 项检测，实际 %d", len(rep.Items))
	}
	if rep.Bits != 20000 {
		t.Fatalf("样本规模应为 20000 bit，实际 %d", rep.Bits)
	}
	if rep.Alpha != 0.01 {
		t.Fatalf("quick 档显著水平应为 0.01（GB/T 32915-2016），实际 %g", rep.Alpha)
	}
	if rep.Detail != "" {
		t.Fatalf("通过时 Detail 应为空，实际 %q", rep.Detail)
	}
}

func TestRunRandSelfCheckQuickNegative(t *testing.T) {
	cases := []struct {
		name string
		data func() []byte
		want string // 期望失败的检测项（子串）
	}{
		{"全零序列", func() []byte { return make([]byte, 2500) }, "单比特频数检测"},
		{"全一序列", func() []byte { return bytes.Repeat([]byte{0xFF}, 2500) }, "单比特频数检测"},
		{"0101 交替", func() []byte {
			b := make([]byte, 2500)
			for i := range b {
				b[i] = 0xAA
			}
			return b
		}, "游程总数检测"},
		{"稀疏序列", func() []byte {
			b := make([]byte, 2500)
			b[0] = 0x01 // 2500 字节中仅 1 个 1 比特
			return b
		}, "单比特频数检测"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep, err := RunRandSelfCheck(bytes.NewReader(c.data()), RandCheckQuick)
			if err != nil {
				t.Fatalf("RunRandSelfCheck 过程失败: %v", err)
			}
			if rep.Passed {
				t.Fatalf("病态序列应判失败: %s", rep)
			}
			if !strings.Contains(rep.Detail, c.want) {
				t.Fatalf("Detail 应含 %q，实际 %q", c.want, rep.Detail)
			}
			if !strings.Contains(rep.String(), "FAIL") {
				t.Fatalf("String() 摘要应含 FAIL: %s", rep.String())
			}
		})
	}
}

func TestRunRandSelfCheckShortRead(t *testing.T) {
	// 样本不足（100 字节 < 2500）：检测过程失败，error 非 nil。
	if _, err := RunRandSelfCheck(bytes.NewReader(make([]byte, 100)), RandCheckQuick); err == nil {
		t.Fatal("短样本应返回读取错误")
	}
	if _, err := RunRandSelfCheck(bytes.NewReader(nil), RandCheckQuick); err == nil {
		t.Fatal("空 reader 应返回读取错误")
	}
	// io.Reader 语义错误应被包装传递。
	if _, err := RunRandSelfCheck(errReader{}, RandCheckQuick); err == nil {
		t.Fatal("reader 错误应被传递")
	}
}

func TestRunRandSelfCheckPowerOn(t *testing.T) {
	// 上电检测全量档：病态输入应判失败（15 项×20 组，读满 2.5MB 全零后判定）。
	rep, err := RunRandSelfCheck(bytes.NewReader(bytes.Repeat([]byte{0x00}, 20*1000000/8)), RandCheckPowerOn)
	if err != nil {
		t.Fatalf("上电检测过程失败: %v", err)
	}
	if rep.Passed {
		t.Fatal("全零输入应判上电检测失败")
	}
	if rep.Alpha != 0.0001 {
		t.Fatalf("上电检测均匀性水平应为 0.0001，实际 %g", rep.Alpha)
	}
	// 短 reader：过程错误。
	if _, err := RunRandSelfCheck(bytes.NewReader(make([]byte, 16)), RandCheckPowerOn); err == nil {
		t.Fatal("上电检测短样本应返回过程错误")
	}
}

func TestRunRandSelfCheckBadProfile(t *testing.T) {
	if _, err := RunRandSelfCheck(bytes.NewReader(nil), RandCheckProfile(99)); err == nil {
		t.Fatal("未知档位应返回错误")
	}
}

func TestRandCheckProfileString(t *testing.T) {
	cases := map[RandCheckProfile]string{
		RandCheckQuick:      "quick",
		RandCheckPowerOn:    "power-on",
		RandCheckProfile(9): "unknown",
	}
	for p, want := range cases {
		if got := p.String(); !strings.Contains(got, want) {
			t.Errorf("RandCheckProfile(%d).String()=%q，应含 %q", int(p), got, want)
		}
	}
}

func TestRandHealthStatusInt(t *testing.T) {
	cases := []struct {
		s    RandHealthStatus
		want int
	}{
		{RandHealthUnknown, -1},
		{RandHealthPassed, 1},
		{RandHealthFailed, 0},
	}
	for _, c := range cases {
		if got := c.s.Int(); got != c.want {
			t.Errorf("RandHealthStatus(%d).Int()=%d，应为 %d", int(c.s), got, c.want)
		}
	}
}

// errReader 恒失败的 io.Reader（验证错误透传）。
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// TestRunRandSelfCheckQuickRetryThenPass 误拒率对策：首检失败（全零序列
// 三项必败）后重新采样复检通过——整体判 PASS 且 Attempts=2。
// 依据：单样本 α=0.01 三项合计误拒率约 2.5%（.248 SoftHSM 实测 200 次
// 误拒 5 次），启动门禁不重试会把健康模块误拒下线（可用性缺陷）。
func TestRunRandSelfCheckQuickRetryThenPass(t *testing.T) {
	bad := make([]byte, 2500) // 全零：三项必败
	good := detSeq(2500, "p2-3-rand-quick-retry")
	rep, err := RunRandSelfCheck(io.MultiReader(bytes.NewReader(bad), bytes.NewReader(good)), RandCheckQuick)
	if err != nil {
		t.Fatalf("RunRandSelfCheck 过程失败: %v", err)
	}
	if !rep.Passed {
		t.Fatalf("复检应通过: %s", rep)
	}
	if rep.Attempts != 2 {
		t.Fatalf("Attempts=%d want 2（首检失败 + 复检通过）", rep.Attempts)
	}
	if rep.Detail != "" {
		t.Fatalf("通过时 Detail 应为空，实际 %q", rep.Detail)
	}
}

// TestRunRandSelfCheckQuickPersistentFail fail-closed 不放松：持续坏熵源
// （全零序列）连续 3 次必败，整体判 FAIL 且 Detail 含连续失败摘要。
func TestRunRandSelfCheckQuickPersistentFail(t *testing.T) {
	bad := make([]byte, 2500*randQuickCheckAttempts)
	rep, err := RunRandSelfCheck(bytes.NewReader(bad), RandCheckQuick)
	if err != nil {
		t.Fatalf("RunRandSelfCheck 过程失败: %v", err)
	}
	if rep.Passed {
		t.Fatalf("持续坏熵源应判失败: %s", rep)
	}
	if rep.Attempts != randQuickCheckAttempts {
		t.Fatalf("Attempts=%d want %d", rep.Attempts, randQuickCheckAttempts)
	}
	if !strings.Contains(rep.Detail, "连续 3 次") {
		t.Fatalf("Detail 应含连续失败摘要，实际 %q", rep.Detail)
	}
}

// TestRunRandSelfCheckPowerOnRetryThenPass power-on 档误拒率对策：
// 首检失败（全零必败）后复检通过——整体 PASS 且 Attempts=2。
// 依据：库判据每项 ≥19/20 组 × 15 项，健康熵源误拒率约 20%
// （.248 SoftHSM 实测复现：重叠子序列检测 18/20）；验收流程
// 不含复跑会把合格设备判废。
func TestRunRandSelfCheckPowerOnRetryThenPass(t *testing.T) {
	const n = 20 * 1000000 / 8
	bad := bytes.Repeat([]byte{0x00}, n)
	good := detSeq(n, "p2-3-rand-poweron-retry")
	rep, err := RunRandSelfCheck(io.MultiReader(bytes.NewReader(bad), bytes.NewReader(good)), RandCheckPowerOn)
	if err != nil {
		t.Fatalf("RunRandSelfCheck 过程失败: %v", err)
	}
	if !rep.Passed {
		t.Fatalf("复检应通过: %s", rep)
	}
	if rep.Attempts != 2 {
		t.Fatalf("Attempts=%d want 2（首检失败 + 复检通过）", rep.Attempts)
	}
}
