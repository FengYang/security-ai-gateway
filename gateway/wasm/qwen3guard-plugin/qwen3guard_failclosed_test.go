// B3（合规达标最小集 G13）合规回归锁：明文侧审核服务不可用一律 fail-closed。
//
// 背景：此前 9 处「不可用」分支为 fail-open 放行（与项目 fail-closed 哲学及备案口径冲突），
// 已改为：请求/响应路径即时拒答、流式路径整流终止。本文件锁定该口径，防止回归。
//
// 口径与例外：
//   - 覆盖（6 + 3 处）：构造送检体失败 / 分发（连接/超时）失败 / 非 200 / 解析失败；
//   - 例外（保持原行为，另行登记为已知限制）：max_body_bytes 超限 bypass（资源防护类，
//     不属"审核服务不可用"）；请求/响应取不到配置 content path ⇒ 跳过送检（无可检内容）。
package main

import (
	"os"
	"strings"
	"testing"
)

func readPluginSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", name, err)
	}
	return string(b)
}

// 覆盖计数：新增/删除 fail-closed 处置点必须同步本测试（口径变更需显式过审）。
func TestFailClosedSitesCovered(t *testing.T) {
	src := readPluginSource(t, "main.go")

	if n := strings.Count(src, "failClosedDeny(c, log,"); n != 6 {
		t.Errorf("请求/响应路径 fail-closed 处置点 = %d，期望 6（request/response × build/dispatch/parse）", n)
	}
	if n := strings.Count(src, "failClosedBlockStream(ctx, c, log,"); n != 3 {
		t.Errorf("流式路径 fail-closed 处置点 = %d，期望 3（build/dispatch/parse）", n)
	}
	if n := strings.Count(src, "ResumeHttpRequest()"); n != 1 {
		t.Errorf("ResumeHttpRequest 剩余 = %d，期望 1（仅请求放行分支）——不得用于不可用分支", n)
	}
	// 2 处均有据：响应放行分支 + releasePendingStream 的 forceEndStream 路径（非不可用分支）。
	if n := strings.Count(src, "ResumeHttpResponse()"); n != 2 {
		t.Errorf("ResumeHttpResponse 剩余 = %d，期望 2（响应放行分支 + releasePendingStream.forceEndStream）——不得用于不可用分支", n)
	}
}

// 例外白名单：仅剩资源防护类的 bypass 允许出现 fail-open 文案。
func TestOnlyResourceGuardAllowsFailOpen(t *testing.T) {
	src := readPluginSource(t, "main.go")
	for i, line := range strings.Split(src, "\n") {
		if strings.Contains(line, "fail open") && !strings.Contains(line, "max_body_bytes") {
			t.Errorf("main.go:%d 存在非例外 fail-open 文案/行为：%s", i+1, strings.TrimSpace(line))
		}
	}
}
