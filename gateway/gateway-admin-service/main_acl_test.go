package main

import "testing"

// TestBuildConfllmModelGuardRejectsInvalidJSON 验证 ACL 配置解析失败 → 返回 error（fail-closed），
// 不得 fail-open 静默放行（旧实现仅 log.Printf 后 return nil，会被 guard==nil 判成全放行）。
func TestBuildConfllmModelGuardRejectsInvalidJSON(t *testing.T) {
	guard, err := buildConfllmModelGuard("{not json")
	if err == nil {
		t.Fatal("非法 JSON 应返回 error（fail-closed），实际 nil")
	}
	if guard != nil {
		t.Fatal("出错时 guard 应为 nil，实际非 nil")
	}
}

// TestBuildConfllmModelGuardEmptyEnvDisablesACL 验证 env 为空 → 不启用 ACL（向后兼容）。
func TestBuildConfllmModelGuardEmptyEnvDisablesACL(t *testing.T) {
	guard, err := buildConfllmModelGuard("")
	if err != nil {
		t.Fatalf("env 为空不应报错，实际: %v", err)
	}
	if guard != nil {
		t.Fatal("env 为空时 guard 应为 nil（不启用 ACL）")
	}
}

// TestBuildConfllmModelGuardValidJSON 验证合法 JSON → 正确的 allowlist 语义。
func TestBuildConfllmModelGuardValidJSON(t *testing.T) {
	env := `{"t1":["m1","*"],"t2":["m2"]}`
	guard, err := buildConfllmModelGuard(env)
	if err != nil {
		t.Fatalf("合法 JSON 不应报错，实际: %v", err)
	}
	if guard == nil {
		t.Fatal("合法 JSON 时 guard 不应为 nil")
	}
	cases := []struct {
		tenant, model string
		want          bool
	}{
		{"t1", "m1", true},  // 显式允许
		{"t1", "m9", true},  // "*" 通配
		{"t2", "m2", true},  // 显式允许
		{"t2", "m9", false}, // 不在白名单
		{"t3", "m1", false}, // 租户不在清单
	}
	for _, c := range cases {
		if got := guard(c.tenant, c.model); got != c.want {
			t.Errorf("guard(%q,%q)=%v, want %v", c.tenant, c.model, got, c.want)
		}
	}
}
