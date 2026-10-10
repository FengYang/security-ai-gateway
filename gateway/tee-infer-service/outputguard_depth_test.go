package main

// S1-6（G18）输出处理深度档位（透传／仅拦截／拦截+改写）单测：
//   - deriveOutputDepth：档位＝mode＋mask 的派生视图（off→passthrough；shadow 不因 mask 升级；
//     仅 enforcing＋mask 才是 block+rewrite）；
//   - validateOutputDepth：缺省不声明 → 通过；声明值须与派生值一致；非法取值/不一致 → 报错
//     （**关键**：不得由档位参数隐式开启拦截/改写——enforcing 仅启动参数可开、改写须属地书面确认）；
//   - 源码不变量：启动校验、快照字段与 mode 变更审计证据三处接线必须在位。

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestDeriveOutputDepth(t *testing.T) {
	cases := []struct {
		mode string
		mask bool
		want string
	}{
		{outputGuardOff, false, outputDepthPassthrough},
		{outputGuardOff, true, outputDepthPassthrough}, // off 下 mask 无意义（不处理）
		{outputGuardShadow, false, outputDepthBlockOnly},
		{outputGuardShadow, true, outputDepthBlockOnly}, // shadow 只记不拦 → 不因 mask 升级为 rewrite
		{outputGuardEnforcing, false, outputDepthBlockOnly},
		{outputGuardEnforcing, true, outputDepthBlockRewrite},
	}
	for _, c := range cases {
		if got := deriveOutputDepth(c.mode, c.mask); got != c.want {
			t.Errorf("deriveOutputDepth(%q, %v) = %q，want %q", c.mode, c.mask, got, c.want)
		}
	}
}

func TestValidateOutputDepth(t *testing.T) {
	// 缺省（未声明）→ 一律通过（零行为变更：档位只读派生）
	for _, actual := range []string{outputDepthPassthrough, outputDepthBlockOnly, outputDepthBlockRewrite} {
		if err := validateOutputDepth("", actual); err != nil {
			t.Fatalf("未声明档位应通过，actual=%q：%v", actual, err)
		}
	}

	// 一致 → 通过
	if err := validateOutputDepth(outputDepthBlockOnly, outputDepthBlockOnly); err != nil {
		t.Fatalf("档位一致应通过：%v", err)
	}
	if err := validateOutputDepth(outputDepthBlockRewrite, outputDepthBlockRewrite); err != nil {
		t.Fatalf("档位一致应通过：%v", err)
	}

	// 非法取值 → 报错
	if err := validateOutputDepth("block", outputDepthBlockOnly); err == nil {
		t.Fatal("非法档位取值应报错")
	}

	// 不一致 → 报错；且**不得隐式开拦截/改写**：
	// 声明 block+rewrite 而实际 mode=off（派生 passthrough）必须失败
	for _, c := range []struct {
		requested string
		actual    string
	}{
		{outputDepthBlockRewrite, outputDepthPassthrough},
		{outputDepthBlockRewrite, outputDepthBlockOnly},
		{outputDepthBlockOnly, outputDepthPassthrough},
		{outputDepthPassthrough, outputDepthBlockOnly},
	} {
		err := validateOutputDepth(c.requested, c.actual)
		if err == nil {
			t.Fatalf("声明 %q 与实际派生 %q 不一致应报错（不得隐式开关）", c.requested, c.actual)
		}
		if !strings.Contains(err.Error(), "不隐式开启拦截/改写") {
			t.Fatalf("错误信息须点明「不隐式开关」纪律，实际：%v", err)
		}
	}
}

// TestSourceInvariant_OutputDepthWiring S1-6 源码不变量锁：三处接线缺一即失去可核验性——
// 启动期一致性校验、GET /config 快照的派生档位、mode 变更审计证据中的档位。
func TestSourceInvariant_OutputDepthWiring(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("读取 main.go 失败：%v", err)
	}
	s := string(src)
	for _, want := range []string{
		"validateOutputDepth(*outputGuardDepth, deriveOutputDepth(srv.outputGuardMode, srv.outputGuardMaskEnabled))",
		`" depth=" + deriveOutputDepth(req.Mode, s.outputGuardMaskEnabled)`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("main.go 缺少 S1-6 档位接线：%s", want)
		}
	}
	// GET /config 快照的派生档位接线：**空白容忍匹配**——源文件经 gofmt 后会按最宽字段名对
	// struct 字面量做列对齐（`OutputDepth:` 后补空格），旧的字面串断言会因**纯格式变更**误报
	// （P1-2 M2 tracing 提交 `edc2935` 对齐 main.go 即触发该回归）。此处改用正则，只锁
	// 「接线存在」语义、不锁空白，避免同类脆弱断言复发。
	if !regexp.MustCompile(`OutputDepth:\s+deriveOutputDepth\(ogMode, s\.outputGuardMaskEnabled\),`).MatchString(s) {
		t.Fatalf("main.go 缺少 S1-6 档位接线：OutputDepth: deriveOutputDepth(ogMode, s.outputGuardMaskEnabled),")
	}
}
