package cryptopsvc

// metrics_profile_test.go —— #9 cryptop_profile_info 多序列化专项测试
// （P1-5 §6.4 R-S3-3 / R-28：degrade 时配置档与生效档各占一条序列，
// 绝不复用同一序列同时表达两个档位；active 标签表达真实生效档位）。

import (
	"strings"
	"testing"

	"security-ai-gateway/gateway/cryptop"
)

// renderProfileInfo 仅渲染 #9 段（辅助：整段 render 会杂入其它指标）。
func renderProfileInfo(t *testing.T, m *metrics) string {
	t.Helper()
	var sb strings.Builder
	m.render(&sb)
	return sb.String()
}

func TestProfileInfoSingleSeriesOnStartup(t *testing.T) {
	m := newMetrics()
	prov, err := cryptop.New(cryptop.ProfileIntl)
	if err != nil {
		t.Fatalf("New(intl): %v", err)
	}
	m.setProfileInfo(prov)

	raw := renderProfileInfo(t, m)
	want := `cryptop_profile_info{profile="intl",meets_mpy="false",compliance_note="` +
		"国际算法（AES-GCM/SHA-256/X25519）；不满足密评要求（GB/T 39786-2021 三级），不得用于政企合规声明" +
		`",active="true"} 1`
	if !strings.Contains(raw, want) {
		t.Fatalf("启动期应仅一条 active=true 序列:\nwant %q\ngot:\n%s", want, raw)
	}
	if strings.Count(raw, "cryptop_profile_info{") != 1 {
		t.Fatalf("启动期应仅一条 #9 序列，got:\n%s", raw)
	}
}

// TestProfileInfoDegradeTwoSeries 核心场景（R-S3-3）：
// 配置档登记后 degrade 到另一档——两条序列并存，
// 配置档 active=false、生效档 active=true，互不覆盖。
func TestProfileInfoDegradeTwoSeries(t *testing.T) {
	m := newMetrics()
	if mod, err := cryptop.New(cryptop.ProfileSMModule); err == nil {
		// sm-module 已可实现（厂商后接线后）：直接用真实档验证。
		m.setProfileInfo(mod)
	} else {
		// 当前 sm-module 尚未接线厂商后端：用 intl 模拟"配置档"（与 degrade 目标异名）。
		prov, err := cryptop.New(cryptop.ProfileIntl)
		if err != nil {
			t.Fatalf("New(intl): %v", err)
		}
		m.setProfileInfo(prov)
	}
	sw, err := cryptop.New(cryptop.ProfileSMSW)
	if err != nil {
		t.Fatalf("New(sm-software): %v", err)
	}
	m.setProfileInfo(sw) // degrade：生效档迁移

	raw := renderProfileInfo(t, m)
	if strings.Count(raw, "cryptop_profile_info{") != 2 {
		t.Fatalf("degrade 后应并存两条 #9 序列，got:\n%s", raw)
	}
	// 生效档必须恰有一条 active="true"
	if strings.Count(raw, `active="true"`) != 1 {
		t.Fatalf("恰有一条 active=true（真实生效档位），got:\n%s", raw)
	}
	// 生效档必须是 sm-software（本用例中 degrade 目标）
	if !strings.Contains(raw, `cryptop_profile_info{profile="sm-software",meets_mpy="false",compliance_note="国密算法软件实现（SM2/SM3/SM4）；不满足密评要求（自研/软件实现无法提供安全性证明，密评 FAQ 判不符合），仅限功能验证与非政企场景",active="true"} 1`) {
		t.Fatalf("sm-software 应为 active=true 生效档，got:\n%s", raw)
	}
}

// TestProfileInfoReactivate 恢复：再次激活原档时 active 标签随迁，序列不丢失。
func TestProfileInfoReactivate(t *testing.T) {
	m := newMetrics()
	intl, _ := cryptop.New(cryptop.ProfileIntl)
	sw, _ := cryptop.New(cryptop.ProfileSMSW)
	m.setProfileInfo(intl)
	m.setProfileInfo(sw) // 切走
	m.setProfileInfo(intl) // 切回

	raw := renderProfileInfo(t, m)
	if strings.Count(raw, `active="true"`) != 1 {
		t.Fatalf("恰一条 active=true，got:\n%s", raw)
	}
	if !strings.Contains(raw, `profile="intl"`) || !strings.Contains(raw, `profile="sm-software"`) {
		t.Fatalf("两条历史序列均应保留（可观测配置/生效对比），got:\n%s", raw)
	}
	// active=true 必须落在 intl 上（切回后的生效档）
	for _, line := range strings.Split(raw, "\n") {
		if strings.Contains(line, `profile="intl"`) && strings.Contains(line, "cryptop_profile_info{") {
			if !strings.Contains(line, `active="true"`) {
				t.Fatalf("切回后 intl 应为 active=true，got line: %s", line)
			}
		}
	}
}
