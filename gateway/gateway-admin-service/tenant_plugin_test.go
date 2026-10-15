package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// normalizeYAML 归一化行尾与尾部空行，避免 CRLF/LF 与 EOF 换行差异导致误报。
func normalizeYAML(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.TrimRight(s, "\n") + "\n"
}

// TestPluginTemplatesOnDiskMatchEmbedded 断言磁盘基线 == 内置常量（防漂移，§4.3.6 模板资产化）。
func TestPluginTemplatesOnDiskMatchEmbedded(t *testing.T) {
	for scenario, embedded := range embeddedPluginTemplates {
		path := filepath.Join("..", "..", "deploy", "tenant-plugins", scenario+".yaml")
		onDisk, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读取磁盘模板 %s 失败: %v", path, err)
		}
		if normalizeYAML(string(onDisk)) != normalizeYAML(embedded) {
			t.Errorf("场景 %s 磁盘模板与内置常量不一致（%s）", scenario, path)
		}
	}
}

// TestRenderPluginSetPerScenario 逐场景渲染 + 预检通过（V-S1）。
func TestRenderPluginSetPerScenario(t *testing.T) {
	for _, scenario := range knownScenarios() {
		chain, ver, err := renderPluginSet(scenario)
		if err != nil {
			t.Fatalf("场景 %s 渲染失败: %v", scenario, err)
		}
		if ver != pluginTemplateVersion {
			t.Errorf("场景 %s 模板版本=%q，期望 %q", scenario, ver, pluginTemplateVersion)
		}
		if len(chain) == 0 {
			t.Errorf("场景 %s 插件链为空", scenario)
		}
	}
}

// TestScenarioMatrixMatchesSpec 断言场景 → 段①/段② 推导符合 §3.6.2 矩阵（V-S1/V-S2）。
func TestScenarioMatrixMatchesSpec(t *testing.T) {
	cases := []struct {
		scenario    string
		segment1    bool
		segment2    string
		wantOtpmask bool
	}{
		{scenarioS1, false, segment2None, false},
		{scenarioS2, true, segment2VendorSDK, true},
		{scenarioS3a, true, segment2EnclavePlaintext, true},
		{scenarioS3b, true, segment2CrossNodeMTLS, true},
		{scenarioS4, true, segment2CiphertextDomain, true},
	}
	for _, c := range cases {
		spec, ok := lookupScenario(c.scenario)
		if !ok {
			t.Fatalf("场景 %s 未登记", c.scenario)
		}
		if spec.Segment1 != c.segment1 {
			t.Errorf("%s segment1=%v，期望 %v", c.scenario, spec.Segment1, c.segment1)
		}
		if spec.Segment2Mode != c.segment2 {
			t.Errorf("%s segment2_mode=%q，期望 %q", c.scenario, spec.Segment2Mode, c.segment2)
		}
		if spec.AccessMode != accessModeASegmented {
			t.Errorf("%s access_mode=%q，期望恒 %q", c.scenario, spec.AccessMode, accessModeASegmented)
		}
		// 模板段① 开关与场景推导一致
		tmpl, err := loadPluginTemplate(c.scenario)
		if err != nil {
			t.Fatalf("加载 %s 模板失败: %v", c.scenario, err)
		}
		if tmpl.Segment1 != c.segment1 {
			t.Errorf("%s 模板 segment1=%v，期望 %v", c.scenario, tmpl.Segment1, c.segment1)
		}
		if tmpl.Segment2Mode != c.segment2 {
			t.Errorf("%s 模板 segment2_mode=%q，期望 %q", c.scenario, tmpl.Segment2Mode, c.segment2)
		}
		hasOtp := false
		for _, p := range tmpl.Chain {
			if p.Name == "otpmask" {
				hasOtp = true
			}
		}
		if hasOtp != c.wantOtpmask {
			t.Errorf("%s otpmask 存在=%v，期望 %v", c.scenario, hasOtp, c.wantOtpmask)
		}
	}
}

// TestChainOrderConstraints 断言链序硬约束：cors 首、ai-proxy 末（路由前）、otpmask 先于 ai-proxy。
func TestChainOrderConstraints(t *testing.T) {
	for _, scenario := range knownScenarios() {
		chain, _, err := renderPluginSet(scenario)
		if err != nil {
			t.Fatalf("场景 %s 渲染失败: %v", scenario, err)
		}
		if chain[0].Name != "cors" {
			t.Errorf("%s 首插件=%s，期望 cors", scenario, chain[0].Name)
		}
		if chain[len(chain)-1].Name != "ai-proxy" {
			t.Errorf("%s 末插件=%s，期望 ai-proxy（其后接路由）", scenario, chain[len(chain)-1].Name)
		}
		otp, proxy := -1, -1
		for i, p := range chain {
			switch p.Name {
			case "otpmask":
				otp = i
			case "ai-proxy":
				proxy = i
			}
		}
		if otp >= 0 && otp > proxy {
			t.Errorf("%s otpmask(idx=%d) 必须早于 ai-proxy(idx=%d)", scenario, otp, proxy)
		}
	}
}

// TestS5NotSelectable 断言 S5（暂缓）不可开通（D-13）。
func TestS5NotSelectable(t *testing.T) {
	if _, _, err := renderPluginSet("s5"); err == nil {
		t.Error("S5 暂缓场景应被拒绝，却渲染成功")
	}
	if _, ok := lookupScenario("s5"); ok {
		t.Error("S5 不应出现在可开通场景矩阵")
	}
}

// TestPrecheckRejectsConflict 断言同类限流插件冲突被拦截（§4.3.6 验收）。
func TestPrecheckRejectsConflict(t *testing.T) {
	tmpl, err := loadPluginTemplate(scenarioS1)
	if err != nil {
		t.Fatalf("加载 s1 失败: %v", err)
	}
	// 追加第二个限流类插件 → 应冲突
	tmpl.Chain = append(tmpl.Chain, pluginEntry{Name: "key-rate-limit", Order: 95})
	if err := precheckPluginSet(tmpl); err == nil {
		t.Error("同链两个限流类插件应被预检拦截，却通过")
	}
}

// TestPrecheckRejectsMissingRequired 断言缺失必需插件被拦截。
func TestPrecheckRejectsMissingRequired(t *testing.T) {
	tmpl, err := loadPluginTemplate(scenarioS1)
	if err != nil {
		t.Fatalf("加载 s1 失败: %v", err)
	}
	var kept []pluginEntry
	for _, p := range tmpl.Chain {
		if p.Name == "ai-proxy" {
			continue
		}
		kept = append(kept, p)
	}
	tmpl.Chain = kept
	if err := precheckPluginSet(tmpl); err == nil {
		t.Error("缺失 ai-proxy 应被预检拦截，却通过")
	}
}

// TestPrecheckOtpmaskOrder 断言 otpmask 晚于 ai-proxy 被拦截（§4.3.6 关键修正）。
func TestPrecheckOtpmaskOrder(t *testing.T) {
	tmpl := &pluginTemplate{
		Segment1: true,
		Chain: []pluginEntry{
			{Name: "cors", Order: 10},
			{Name: "key-auth", Order: 20},
			{Name: "ip-restriction", Order: 30},
			{Name: "replay-protection", Order: 35},
			{Name: "request-validation", Order: 40},
			{Name: "ai-quota", Order: 45},
			{Name: "ai-token-ratelimit", Order: 50},
			{Name: "ai-statistics", Order: 55},
			{Name: "ai-proxy", Order: 60},
			{Name: "otpmask", Order: 70},
		},
	}
	if err := precheckPluginSet(tmpl); err == nil {
		t.Error("otpmask 晚于 ai-proxy 应被预检拦截，却通过")
	}
}

// TestPrecheckSegment1Consistency 断言段① 开关与 otpmask 必须一致。
func TestPrecheckSegment1Consistency(t *testing.T) {
	// segment1=true 但无 otpmask
	noOtp := &pluginTemplate{
		Segment1: true,
		Chain: []pluginEntry{
			{Name: "cors", Order: 10}, {Name: "key-auth", Order: 20},
			{Name: "ip-restriction", Order: 30}, {Name: "replay-protection", Order: 35},
			{Name: "request-validation", Order: 40}, {Name: "ai-quota", Order: 45},
			{Name: "ai-token-ratelimit", Order: 50}, {Name: "ai-statistics", Order: 55},
			{Name: "ai-proxy", Order: 60},
		},
	}
	if err := precheckPluginSet(noOtp); err == nil {
		t.Error("segment1=true 缺 otpmask 应被拦截")
	}
}

// TestHigressReuseRate 断言复用率 ≥ 70%（V-S9）。
func TestHigressReuseRate(t *testing.T) {
	rate, reused, denom := higressReuseRate()
	if denom == 0 {
		t.Fatal("治理面能力分母为 0")
	}
	if rate < 0.70 {
		t.Errorf("复用率 %.4f（%d/%d）低于验收线 70%%", rate, reused, denom)
	}
	if !pluginReusePassing() {
		t.Error("pluginReusePassing() 应为 true")
	}
}

// TestPluginSetJSONRoundTrip 断言 plugin_set JSON 往返（表 ⑧ 落库）。
func TestPluginSetJSONRoundTrip(t *testing.T) {
	chain, _, err := renderPluginSet(scenarioS2)
	if err != nil {
		t.Fatalf("渲染 s2 失败: %v", err)
	}
	raw, err := marshalPluginSet(chain)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	back, err := unmarshalPluginSet(raw)
	if err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	if len(back) != len(chain) {
		t.Fatalf("往返后长度不等：%d != %d", len(back), len(chain))
	}
	for i := range chain {
		if back[i].Name != chain[i].Name || back[i].Order != chain[i].Order {
			t.Errorf("第 %d 项不一致：%+v != %+v", i, back[i], chain[i])
		}
	}
}

// TestDiffPluginSet 断言差异对比。
func TestDiffPluginSet(t *testing.T) {
	desired := []pluginEntry{{Name: "a", Order: 1}, {Name: "b", Order: 2}}
	current := []pluginEntry{{Name: "a", Order: 9}, {Name: "c", Order: 3}}
	d := diffPluginSet(desired, current)
	if len(d.Changed) != 1 || d.Changed[0] != "a" {
		t.Errorf("changed=%v，期望 [a]", d.Changed)
	}
	if len(d.Removed) != 1 || d.Removed[0] != "c" {
		t.Errorf("removed=%v，期望 [c]", d.Removed)
	}
	if len(d.Added) != 1 || d.Added[0] != "b" {
		t.Errorf("added=%v，期望 [b]", d.Added)
	}
	if d.InSync {
		t.Error("存在差异时 InSync 应为 false")
	}
}
