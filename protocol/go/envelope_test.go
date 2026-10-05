package protocol

// P1a 信封 framing 单测（P0-4 §5.4.5 拆包后本包仅留 framing）：
// 反重放计数器窗口、SSE 严格序号。
// AEAD 往返/篡改/方向/上下文绑定/版本套件拒绝等**密码求值**测试已下沉
// `protocol/go/cryptoops`（envelope_test.go，包 cryptoops）。

import "testing"

func TestCounterWindow(t *testing.T) {
	// 期望决策序列与 cross_test.py 中 Python CounterWindow 完全一致（跨语言一致性）
	cases := []struct {
		counter uint64
		accept  bool
	}{
		{1, true}, // 窗口启动
		{2, true},
		{3, true},
		{2, false}, // 重放（窗口内重复）
		{5, true},  // 跳号前进
		{4, true},  // 有界乱序容忍
		{4, false}, // 乱序后重放
		{10, true},
		{12, true},
		{11, true},  // 有界乱序
		{6, true},   // 窗口内未见过的旧计数器（合法新值）
		{100, true}, // 大步前进（窗口清空重置）
		{100, false},
		{12, false}, // 落后窗口（highest-100 距离 88 ≥ 64）
	}
	var w CounterWindow
	for i, c := range cases {
		err := w.Check(c.counter)
		if (err == nil) != c.accept {
			t.Fatalf("计数器 %d 期望 accept=%v，实际 err=%v（第 %d 例）", c.counter, c.accept, err, i+1)
		}
	}
}

func TestCheckStreamSequence(t *testing.T) {
	if err := CheckStreamSequence(0, 1); err != nil {
		t.Fatalf("合法首分片被拒绝: %v", err)
	}
	if err := CheckStreamSequence(1, 2); err != nil {
		t.Fatalf("合法递增被拒绝: %v", err)
	}
	if err := CheckStreamSequence(1, 1); err == nil {
		t.Fatal("重复分片序号未被拒绝")
	}
	if err := CheckStreamSequence(1, 3); err == nil {
		t.Fatal("跳号分片未被拒绝")
	}
	if err := CheckStreamSequence(2, 1); err == nil {
		t.Fatal("回退分片序号未被拒绝")
	}
}
