// broker_secret_test.go — broker 凭据托管单测（apiTokens Secret 化 M2 A-1）。
//
// 覆盖：文件 Secret 存储（原子写/权限/空文件 fail-closed）、目录装配（空目录 = 0 provider）、
// 参数校验（名/Key/upstream/路径白名单）、HTTP 端点（角色授权、Key 不回显、customUrl）、
// 热加载（路由表切换、坏配置保留旧值）、漂移检测、并发安全（-race）。
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// ---------- 辅助 ----------

// testSettings 返回指向临时目录的 broker 设置。
func testSettings(t *testing.T) *brokerSettings {
	t.Helper()
	return &brokerSettings{
		secretsDir: t.TempDir(),
		publicBase: "http://broker.test:19096",
	}
}

// testProvider 构造一个 provider（https 上游，供解析/校验用例）。
func testProvider(t *testing.T) *brokerProvider {
	t.Helper()
	u, prefixes, err := parseProviderEntry("phala", "https://inference.phala.com", nil)
	if err != nil {
		t.Fatalf("parseProviderEntry: %v", err)
	}
	return &brokerProvider{upstream: u, key: []byte(testKey), allowPathPrefixes: prefixes}
}

// newTestSecretMux 组装与 main 同构的凭据端点路由。
func newTestSecretMux(cfg *config, bs *brokerSettings, bc *brokerConfig) (*http.ServeMux, *brokerHandler) {
	bh := newBrokerHandler(bc)
	sh := newBrokerSecretHandler(bs, bh, nil)
	mux := http.NewServeMux()
	mux.HandleFunc(brokerAPIBase, authMiddleware(cfg, sh.handleList))
	mux.HandleFunc(brokerAPIBase+"/", authMiddleware(cfg, sh.handleItem))
	return mux, bh
}

// doSecret 以指定用户令牌发起请求。
func doSecret(t *testing.T, mux *http.ServeMux, sub, method, target string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = strings.NewReader(string(raw))
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, reader)
	req.Header.Set("Authorization", "Bearer "+testSignToken(t, testSecret, claims{
		Sub: sub, Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience,
	}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// ---------- 文件 Secret 存储 ----------

func TestWriteProviderFileRoundTripAndPerms(t *testing.T) {
	bs := testSettings(t)
	if err := writeProviderFile(bs.secretsDir, "phala", "https://inference.phala.com", testKey, defaultBrokerPathPrefixes); err != nil {
		t.Fatalf("writeProviderFile: %v", err)
	}

	// 原子性：不得残留 .tmp
	if _, err := os.Stat(providerFilePath(bs.secretsDir, "phala") + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("原子写入后不应残留 .tmp 文件")
	}

	// 权限 0600（POSIX 语义；Windows 无 POSIX 权限位，仅断言文件可读）
	info, err := os.Stat(providerFilePath(bs.secretsDir, "phala"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("凭据文件权限 = %o，期望 600", perm)
		}
	}

	// 回读一致
	p, err := parseProviderFile(providerFilePath(bs.secretsDir, "phala"), "phala")
	if err != nil {
		t.Fatalf("parseProviderFile: %v", err)
	}
	if string(p.key) != testKey || p.upstream.Host != "inference.phala.com" {
		t.Fatalf("回读不一致：host=%s keyLen=%d", p.upstream.Host, len(p.key))
	}
	if len(p.allowPathPrefixes) != len(defaultBrokerPathPrefixes) {
		t.Fatalf("白名单缺省集未生效：%v", p.allowPathPrefixes)
	}
}

// 空文件（truncate 半写）必须报错，绝不解析为"provider 不存在"（A-4 处置）。
func TestParseProviderFileEmptyIsError(t *testing.T) {
	bs := testSettings(t)
	path := providerFilePath(bs.secretsDir, "phala")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseProviderFile(path, "phala"); err == nil {
		t.Fatal("空凭据文件必须报错（fail-closed：保留旧配置，不得静默摘除）")
	}

	// 缺 key 字段同样报错
	partial := "ADMIN_BROKER_UPSTREAM_PHALA=https://inference.phala.com\n"
	if err := os.WriteFile(path, []byte(partial), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseProviderFile(path, "phala"); err == nil {
		t.Fatal("缺 key 字段必须报错")
	}
}

func TestDeleteProviderFileIdempotent(t *testing.T) {
	bs := testSettings(t)
	if err := writeProviderFile(bs.secretsDir, "phala", "https://inference.phala.com", testKey, nil); err != nil {
		t.Fatal(err)
	}
	if err := deleteProviderFile(bs.secretsDir, "phala"); err != nil {
		t.Fatalf("首次删除应成功：%v", err)
	}
	if err := deleteProviderFile(bs.secretsDir, "phala"); err != nil {
		t.Fatalf("重复删除应幂等成功：%v", err)
	}
}

// ---------- 目录装配 ----------

// 目录存在即接管：空目录 = 合法 0 provider（不回退环境变量）。
func TestLoadBrokerConfigFromDirEmptyIsZeroProviders(t *testing.T) {
	bs := testSettings(t)
	t.Setenv("ADMIN_BROKER_PROVIDERS_JSON", `{"envonly":{"upstream":"https://example.com"}}`)
	t.Setenv("ADMIN_BROKER_KEY_ENVONLY", testKey)

	cfg, fromDir, err := openBrokerConfig(bs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !fromDir {
		t.Fatal("目录存在时应走目录模式")
	}
	if cfg == nil || len(cfg.providers) != 0 {
		t.Fatalf("空目录应解析为 0 provider（env 不得复活），实际 %+v", cfg)
	}
}

// 目录不存在 → 回落环境变量路径（M1 兼容）。
func TestOpenBrokerConfigFallsBackToEnv(t *testing.T) {
	bs := &brokerSettings{secretsDir: filepath.Join(t.TempDir(), "not-exist")}
	t.Setenv("ADMIN_BROKER_PROVIDERS_JSON", `{"envonly":{"upstream":"https://example.com"}}`)
	t.Setenv("ADMIN_BROKER_KEY_ENVONLY", testKey)

	cfg, fromDir, err := openBrokerConfig(bs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if fromDir {
		t.Fatal("目录不存在时不应走目录模式")
	}
	if cfg == nil || cfg.providers["envonly"] == nil {
		t.Fatalf("应回落 env 路径装载 envonly，实际 %+v", cfg)
	}
}

// 任一文件损坏 → 整体装载失败（不做部分降级）。
func TestLoadBrokerConfigFromDirCorruptFailsWholeLoad(t *testing.T) {
	bs := testSettings(t)
	if err := writeProviderFile(bs.secretsDir, "good", "https://example.com", testKey, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(providerFilePath(bs.secretsDir, "bad"), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBrokerConfigFromDir(bs.secretsDir); err == nil {
		t.Fatal("存在损坏文件时整体装载必须失败（fail-closed）")
	}
}

// ---------- 参数校验 ----------

func TestProviderNameValidation(t *testing.T) {
	valid := []string{"phala", "phala-broker", "a1", strings.Repeat("a", maxProviderNameLen)}
	for _, name := range valid {
		if err := validateProviderName(name); err != nil {
			t.Fatalf("应通过：%q → %v", name, err)
		}
	}
	invalid := []string{"", "-lead", "Upper", "has_underscore", "has/slash", "has.dot", strings.Repeat("a", maxProviderNameLen+1)}
	for _, name := range invalid {
		if err := validateProviderName(name); err == nil {
			t.Fatalf("应拒绝：%q", name)
		}
	}
}

func TestProviderKeyValidation(t *testing.T) {
	if err := validateProviderKey("p", strings.Repeat("k", minProviderKeyLen-1)); err == nil {
		t.Fatal("过短 key 应拒绝")
	}
	if err := validateProviderKey("p", strings.Repeat("k", maxProviderKeyLen+1)); err == nil {
		t.Fatal("过长 key 应拒绝")
	}
	if err := validateProviderKey("p", strings.Repeat("k", minProviderKeyLen)); err != nil {
		t.Fatalf("合法长度应通过：%v", err)
	}
}

func TestUpstreamSchemeDefaultsToHTTPS(t *testing.T) {
	if _, _, err := parseProviderEntry("p", "http://example.com", nil); err == nil {
		t.Fatal("默认应拒绝 http 上游")
	}
	if _, _, err := parseProviderEntry("p", "ftp://example.com", nil); err == nil {
		t.Fatal("应拒绝非 http(s) 上游")
	}
	if _, _, err := parseProviderEntry("p", "https://", nil); err == nil {
		t.Fatal("缺 host 应拒绝")
	}
	if _, _, err := parseProviderEntry("p", "https://example.com", nil); err != nil {
		t.Fatalf("https 上游应通过：%v", err)
	}
}

func TestPathPrefixValidation(t *testing.T) {
	if _, _, err := parseProviderEntry("p", "https://example.com", []string{"v1/models"}); err == nil {
		t.Fatal("非 / 开头应拒绝")
	}
	if _, _, err := parseProviderEntry("p", "https://example.com", []string{"/v1/../../etc"}); err == nil {
		t.Fatal("含 .. 应拒绝")
	}
	if _, _, err := parseProviderEntry("p", "https://example.com", []string{"/" + strings.Repeat("x", maxPathPrefixLen+1)}); err == nil {
		t.Fatal("过长前缀应拒绝")
	}
	tooMany := make([]string, maxPathPrefixes+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("/v1/p%d", i)
	}
	if _, _, err := parseProviderEntry("p", "https://example.com", tooMany); err == nil {
		t.Fatal("前缀项数超限应拒绝")
	}
}

func TestKeyFingerprintStableAndOpaque(t *testing.T) {
	fp := keyFingerprint([]byte(testKey))
	if len(fp) != 8 {
		t.Fatalf("指纹长度应为 8，实际 %d", len(fp))
	}
	if fp == testKey || strings.Contains(testKey, fp) {
		t.Fatal("指纹不得泄露 Key 内容")
	}
	if keyFingerprint([]byte(testKey)) != fp {
		t.Fatal("同 Key 指纹应稳定")
	}
	if keyFingerprint([]byte(testKey+"x")) == fp {
		t.Fatal("不同 Key 指纹应不同")
	}
}

// ---------- HTTP 端点 ----------

func TestUpsertListAndNoKeyEcho(t *testing.T) {
	bs := testSettings(t)
	mux, bh := newTestSecretMux(testCfg(), bs, &brokerConfig{providers: map[string]*brokerProvider{}})

	rec := doSecret(t, mux, testAdminUser, http.MethodPost, brokerAPIBase+"/phala", map[string]interface{}{
		"upstream": "https://inference.phala.com",
		"key":      testKey,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("upsert 期望 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), testKey) {
		t.Fatalf("upsert 响应泄露 Key：%s", rec.Body.String())
	}
	var up upsertResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &up); err != nil {
		t.Fatal(err)
	}
	wantURL := bs.publicBase + brokerPathPrefix + "phala/v1/chat/completions"
	if up.CustomURL != wantURL {
		t.Fatalf("customUrl = %q，期望 %q", up.CustomURL, wantURL)
	}
	if bh.currentRoutes()["phala"] == nil {
		t.Fatal("upsert 后路由应即时生效（reloadNow）")
	}

	// 列表：含指纹、不含 Key
	rec = doSecret(t, mux, testAdminUser, http.MethodGet, brokerAPIBase, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list 期望 200，实际 %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, testKey) {
		t.Fatalf("列表泄露 Key：%s", body)
	}
	if !strings.Contains(body, keyFingerprint([]byte(testKey))) {
		t.Fatalf("列表应含 Key 指纹：%s", body)
	}

	// 详情：不含 Key
	rec = doSecret(t, mux, testAdminUser, http.MethodGet, brokerAPIBase+"/phala", nil)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), testKey) {
		t.Fatalf("详情响应异常（code=%d）：%s", rec.Code, rec.Body.String())
	}
}

func TestSecretEndpointsRoleAuthorization(t *testing.T) {
	bs := testSettings(t)
	mux, _ := newTestSecretMux(testCfg(), bs, &brokerConfig{providers: map[string]*brokerProvider{}})

	// auditor（白名单外）写 → 403，且不得落盘
	rec := doSecret(t, mux, "bob", http.MethodPost, brokerAPIBase+"/phala", map[string]interface{}{
		"upstream": "https://inference.phala.com",
		"key":      testKey,
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("auditor 写入应 403，实际 %d", rec.Code)
	}
	if _, err := os.Stat(providerFilePath(bs.secretsDir, "phala")); !os.IsNotExist(err) {
		t.Fatal("403 请求不得产生任何落盘副作用")
	}

	// auditor 读 → 放行
	rec = doSecret(t, mux, "bob", http.MethodGet, brokerAPIBase, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("auditor 读取应放行，实际 %d", rec.Code)
	}

	// auditor 删除 → 403
	rec = doSecret(t, mux, "bob", http.MethodDelete, brokerAPIBase+"/phala", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("auditor 删除应 403，实际 %d", rec.Code)
	}
}

func TestUpsertValidationRejectsBadInput(t *testing.T) {
	bs := testSettings(t)
	mux, _ := newTestSecretMux(testCfg(), bs, &brokerConfig{providers: map[string]*brokerProvider{}})

	cases := []struct {
		name string
		path string
		body map[string]interface{}
	}{
		{"http 上游", "/phala", map[string]interface{}{"upstream": "http://example.com", "key": testKey}},
		{"key 过短", "/phala", map[string]interface{}{"upstream": "https://example.com", "key": "short"}},
		{"上游缺 host", "/phala", map[string]interface{}{"upstream": "https://", "key": testKey}},
		{"路径非 / 开头", "/phala", map[string]interface{}{"upstream": "https://example.com", "key": testKey, "allowPathPrefixes": []string{"v1/models"}}},
		{"provider 名非法", "/Bad", map[string]interface{}{"upstream": "https://example.com", "key": testKey}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doSecret(t, mux, testAdminUser, http.MethodPost, brokerAPIBase+tc.path, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("期望 400，实际 %d：%s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), testKey) {
				t.Fatalf("错误响应泄露 Key：%s", rec.Body.String())
			}
		})
	}
}

func TestDeleteReturnsWarningAndOrphanDetection(t *testing.T) {
	bs := testSettings(t)
	crFile := filepath.Join(t.TempDir(), "ai-proxy.internal.yaml")
	bs.crFile = crFile
	if err := os.WriteFile(crFile, []byte("openaiCustomUrl: http://host.docker.internal:19096/llm-broker/phala/v1/chat/completions\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mux, _ := newTestSecretMux(testCfg(), bs, &brokerConfig{providers: map[string]*brokerProvider{}})

	if rec := doSecret(t, mux, testAdminUser, http.MethodPost, brokerAPIBase+"/phala", map[string]interface{}{
		"upstream": "https://inference.phala.com", "key": testKey,
	}); rec.Code != http.StatusOK {
		t.Fatalf("upsert 失败：%d", rec.Code)
	}

	// 托管在位时：CR 引用命中已知 provider → 无孤儿
	rec := doSecret(t, mux, testAdminUser, http.MethodGet, brokerAPIBase, nil)
	if strings.Contains(rec.Body.String(), "orphanDetected") {
		t.Fatalf("已知 provider 不应报漂移：%s", rec.Body.String())
	}

	// 删除后：CR 仍引用 → 返回联动告警 + 列表报漂移
	rec = doSecret(t, mux, testAdminUser, http.MethodDelete, brokerAPIBase+"/phala", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete 期望 200，实际 %d", rec.Code)
	}
	var del deleteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &del); err != nil {
		t.Fatal(err)
	}
	if len(del.AffectedProviders) != 1 || del.AffectedProviders[0] != "phala" || del.Warning == "" {
		t.Fatalf("删除应返回 CR 联动告警，实际 %+v", del)
	}

	rec = doSecret(t, mux, testAdminUser, http.MethodGet, brokerAPIBase, nil)
	if !strings.Contains(rec.Body.String(), "orphanDetected") || !strings.Contains(rec.Body.String(), "phala") {
		t.Fatalf("删除后列表应报漂移：%s", rec.Body.String())
	}
	// 幂等：再次删除 → 404（已不存在）
	if rec := doSecret(t, mux, testAdminUser, http.MethodDelete, brokerAPIBase+"/phala", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("重复删除应 404，实际 %d", rec.Code)
	}
}

func TestDetectOrphansIgnoresKnownAndDisabledWhenNoCRFile(t *testing.T) {
	dir := t.TempDir()
	cr := filepath.Join(dir, "cr.yaml")
	content := "u1: /llm-broker/known/v1/chat/completions\n" +
		"u2: /llm-broker/ghost-a/v1/models\n" +
		"u3: /llm-broker/ghost-b/v1/embeddings\n" +
		"u4: /llm-broker/ghost-a/v1/chat/completions\n"
	if err := os.WriteFile(cr, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	orphans, err := detectOrphans(cr, map[string]struct{}{"known": {}})
	if err != nil {
		t.Fatalf("detectOrphans: %v", err)
	}
	if len(orphans) != 2 || orphans[0] != "ghost-a" || orphans[1] != "ghost-b" {
		t.Fatalf("漂移检测结果异常：%v", orphans)
	}

	if got, err := detectOrphans("", map[string]struct{}{}); err != nil || got != nil {
		t.Fatalf("未配置 CR 文件时应关闭检测，实际 %v %v", got, err)
	}
}

// ---------- 热加载 ----------

// 坏配置不摘除内存配置：写入损坏文件后 reload 失败，旧路由仍生效。
func TestReloadFailureKeepsPreviousRoutes(t *testing.T) {
	bs := testSettings(t)
	bc := &brokerConfig{providers: map[string]*brokerProvider{"phala": testProvider(t)}}
	bh := newBrokerHandler(bc)
	sh := newBrokerSecretHandler(bs, bh, nil)

	// 目录里放一个损坏文件 → reloadNow 必须失败且路由表不变
	if err := os.WriteFile(providerFilePath(bs.secretsDir, "broken"), []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sh.reloadNow(); err == nil {
		t.Fatal("损坏配置下 reloadNow 应失败")
	}
	if bh.currentRoutes()["phala"] == nil {
		t.Fatal("reload 失败时必须保留旧路由表（fail-closed）")
	}

	// 清理损坏文件后 reload 成功 → 路由表按目录内容替换（0 provider）
	if err := os.Remove(providerFilePath(bs.secretsDir, "broken")); err != nil {
		t.Fatal(err)
	}
	if err := sh.reloadNow(); err != nil {
		t.Fatalf("修复后 reload 应成功：%v", err)
	}
	if len(bh.currentRoutes()) != 0 {
		t.Fatalf("目录为空时路由表应为空，实际 %d", len(bh.currentRoutes()))
	}
}

// ---------- 并发 ----------

// 并发 upsert 与 reload/读取，-race 下不得报数据竞争（验证配置原子切换）。
//
// 注：并发**删除**不纳入本用例——Windows 无 POSIX「打开时可 unlink」语义，
// reloader 的 ReadFile 与 Remove 相撞会瞬时失败（平台特性，非数据竞争）；
// 删除路径由 TestDeleteProviderFileIdempotent 单线程覆盖。
func TestConcurrentUpsertAndReload(t *testing.T) {
	bs := testSettings(t)
	bh := newBrokerHandler(&brokerConfig{providers: map[string]*brokerProvider{}})
	sh := newBrokerSecretHandler(bs, bh, nil)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("p%d", i)
			if err := writeProviderFile(bs.secretsDir, name, "https://example.com", testKey, nil); err != nil {
				t.Errorf("write %s: %v", name, err)
				return
			}
			// 并发 reload 与读取（reloadNow 可因目录瞬时变化而失败，属预期，不判失败）
			_ = sh.reloadNow()
			_ = bh.currentRoutes()
		}(i)
	}
	wg.Wait()

	// 全部写盘完成后做一次确定性重载（并发期最后一次 reload 可能早于全部文件就位）
	if err := sh.reloadNow(); err != nil {
		t.Fatalf("并发写入后重载应成功：%v", err)
	}
	if got := bh.providerCount(); got != 8 {
		t.Fatalf("8 个 provider 写入后应全部生效，实际 %d", got)
	}
}

// 统计辅助：确认 metrics 渲染含 reload 失败族（供运维观测）。
func TestMetricsRendersReloadFailedFamily(t *testing.T) {
	m := newAdminMetrics()
	m.incBrokerReloadFailed()
	var buf bytes.Buffer
	m.render(&buf)
	if !strings.Contains(buf.String(), "gateway_admin_broker_config_reload_failed_total 1") {
		t.Fatalf("指标缺 reload 失败族：\n%s", buf.String())
	}
}
