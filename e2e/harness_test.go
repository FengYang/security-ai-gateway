//go:build e2e

// Package e2e — GA-计费 P0-3 §10.3 端到端测试（进程级真实链路）。
//
// 形态（经用户裁定）：**进程级**——`go build` 产出 gateway-admin-service 与
// tee-infer-service 二进制，随机端口以子进程启动，驱动**仅经 HTTP** 访问两服务；
// 不依赖 docker-compose（本机可完整跑通，亦可入 CI）。
//
// 与 §10.3 原文"docker-compose / kind"的差异：编排形态不同，但同样跑通
// "真机 tee-infer + gateway-admin-service"两服务真实 HTTP 链路（已在进度文档登记）。
//
// 运行：
//
//	go test -tags e2e ./e2e/ -v -timeout 15m
package e2e

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// E2E 固定测试凭证（仅测试用；非生产值）。
const (
	teeSigKeyHex   = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	teeAttestToken = "e2e-attest-token"
	teeAdminToken  = "e2e-admin-token"
	teeMeterToken  = "e2e-meter-token"

	adminJWTSecret  = "e2e-admin-jwt-shared-secret-0123456789"
	adminIssuer     = "higress-console"
	adminAudience   = "gateway-admin-service"
	adminUser       = "e2e-admin"
	e2eEventsSecret = "e2e-events-secret"
	e2eSigningKey   = "e2e-bill-signing-key-0123456789"
)

var b64url = base64.RawURLEncoding

// utc8 计费归日时区（与 tee-infer 窗口/计费 day 同口径）。
var utc8 = time.FixedZone("UTC+8", 8*3600)

// ---------- 构建与进程管理 ----------

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, ".."))
}

func goBuild(t *testing.T, root, out, pkg string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s 失败: %v\n%s", pkg, err, b)
	}
}

// start 启动子进程；测试结束（含失败）时杀进程，并在失败时打印其日志。
func start(t *testing.T, name, bin string, args, env []string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动 %s 失败: %v", name, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("---- %s 日志 ----\n%s", name, buf.String())
		}
	})
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitOK(t *testing.T, rawurl string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(rawurl)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("等待 %s 就绪超时", rawurl)
}

// ---------- HTTP / JWT 辅助 ----------

func do(t *testing.T, method, url string, headers map[string]string, body []byte) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// adminToken 签发内部 HS256 JWT（与 admin-service auth.go 契约一致）。
func adminToken(sub, role, tenant string) string {
	now := time.Now().Unix()
	hdr, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	cl := map[string]any{
		"sub": sub, "role": role, "iss": adminIssuer, "aud": adminAudience,
		"iat": now, "exp": now + 3600,
	}
	if tenant != "" {
		cl["tenant"] = tenant
	}
	cb, _ := json.Marshal(cl)
	si := b64url.EncodeToString(hdr) + "." + b64url.EncodeToString(cb)
	mac := hmac.New(sha256.New, []byte(adminJWTSecret))
	mac.Write([]byte(si))
	return si + "." + b64url.EncodeToString(mac.Sum(nil))
}

func authHdr(sub, role, tenant string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + adminToken(sub, role, tenant)}
}

// ---------- 服务栈 ----------

type stack struct {
	root      string
	dir       string
	admBin    string
	teeURL    string
	admURL    string
	billingDB string
}

// startStack 构建并以子进程启动 tee-infer + gateway-admin-service（billing 启用）。
func startStack(t *testing.T) *stack {
	t.Helper()
	root := repoRoot(t)
	dir := t.TempDir()
	teeBin := filepath.Join(dir, "tee-infer"+exeSuffix())
	admBin := filepath.Join(dir, "gateway-admin-service"+exeSuffix())
	goBuild(t, root, teeBin, "./gateway/tee-infer-service")
	goBuild(t, root, admBin, "./gateway/gateway-admin-service")

	teePort := freePort(t)
	teeURL := fmt.Sprintf("http://127.0.0.1:%d", teePort)
	start(t, "tee-infer", teeBin, []string{
		"-listen", fmt.Sprintf("127.0.0.1:%d", teePort),
		"-sig-key", teeSigKeyHex,
		"-attest-token", teeAttestToken,
		"-admin-token", teeAdminToken,
		"-meter-token", teeMeterToken,
		"-audit-file", filepath.Join(dir, "tee-audit.jsonl"),
		// 威胁模型 GAP-01：E2E 用 mock 飞地，须显式声明开发模式（生产禁 mock）。
		"-dev-mode",
	}, os.Environ())
	waitOK(t, teeURL+"/healthz", 30*time.Second)

	// 价格表：覆盖 vectors 默认引擎 modelKey（tee_gpu/mock）
	pricing := filepath.Join(dir, "pricing.json")
	if err := os.WriteFile(pricing, []byte(`{"version":"e2e-v1","currency":"CNY","models":{
	  "tee_gpu/mock":{"in_coef":1,"out_coef":1,
	    "tiers":[{"up_to_tokens":0,"in_per_1k":1,"out_per_1k":2}]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	admPort := freePort(t)
	admURL := fmt.Sprintf("http://127.0.0.1:%d", admPort)
	db := filepath.Join(dir, "billing.db")
	start(t, "gateway-admin-service", admBin, nil, adminEnv(admPort, teeURL, db, pricing, true))
	waitOK(t, admURL+"/healthz", 30*time.Second)

	return &stack{root: root, dir: dir, admBin: admBin, teeURL: teeURL, admURL: admURL, billingDB: db}
}

// adminEnv 构造 admin-service 环境变量（billingOn=false 用于 E2E-4 的对照实例）。
func adminEnv(port int, teeURL, db, pricing string, billingOn bool) []string {
	env := append(os.Environ(),
		"ADMIN_SVC_LISTEN=127.0.0.1:"+strconv.Itoa(port),
		"ADMIN_SVC_JWT_SECRET="+adminJWTSecret,
		"ADMIN_SVC_JWT_ISSUER="+adminIssuer,
		"ADMIN_SVC_JWT_AUD="+adminAudience,
		"ADMIN_SVC_ROLE_ADMINS="+adminUser,
		// /usage 代理（M2 A-2'）：与 billing 开关无关，两个实例都要指向同一 tee
		"ADMIN_TEE_INFER_URL="+teeURL,
		"ADMIN_TEE_INFER_TOKEN="+teeMeterToken,
	)
	if !billingOn {
		return append(env, "BILLING_ENABLED=false")
	}
	return append(env,
		"BILLING_ENABLED=true",
		"BILLING_STORE_DRIVER=sqlite",
		"BILLING_STORE_DSN="+db,
		"BILLING_SOURCE_TEE_URL="+teeURL,
		"BILLING_SOURCE_ADMIN_TOKEN_REF=env:E2E_TEE_ADMIN_TOKEN",
		"BILLING_SOURCE_SYNC_MODE=pull",
		"BILLING_SOURCE_PULL_INTERVAL=10s",
		"BILLING_SOURCE_PULL_LOOKBACK=1h",
		"BILLING_SOURCE_PUSH_ENABLED=false",
		"BILLING_RATING_PRICE_TABLE="+pricing,
		"BILLING_SECRETS_EVENTS_SECRET_REF=env:E2E_EVENTS_SECRET",
		"BILLING_SECRETS_SIGNING_KEY_REF=env:E2E_SIGNING_KEY",
		"BILLING_SCHEDULE_ENABLED=true",
		// G1 审计链：启用后计费写动作（plan_upsert/plan_bind/bill_freeze/…）落链，
		// 供 E2E-5 经 GET /v1/adminext/audit-chain 断言（M4 T9 写链路）。
		"ADMIN_AUDIT_FILE="+filepath.Join(filepath.Dir(db), "admin-audit.jsonl"),
		"E2E_TEE_ADMIN_TOKEN="+teeAdminToken,
		"E2E_EVENTS_SECRET="+e2eEventsSecret,
		"E2E_SIGNING_KEY="+e2eSigningKey,
	)
}

// startAdminOff 启动 billing 关闭的对照 admin 实例（复用同一 tee），返回其基址。
func (s *stack) startAdminOff(t *testing.T) string {
	t.Helper()
	port := freePort(t)
	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	start(t, "admin-billing-off", s.admBin, nil,
		adminEnv(port, s.teeURL, filepath.Join(s.dir, "off.db"), filepath.Join(s.dir, "pricing.json"), false))
	waitOK(t, url+"/healthz", 30*time.Second)
	return url
}

// dayUTC8 当前 UTC+8 自然日（计费归日口径）。
func dayUTC8() string { return time.Now().In(utc8).Format("2006-01-02") }

func mustJSON(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("JSON 解析失败: %v\n%s", err, b)
	}
}
