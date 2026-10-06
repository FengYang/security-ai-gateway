//go:build e2e

// s2_harness_e2e_test.go —— P0-4 §11.4/11.5 集成回归辅助（B6#14）。
//
// 在既有进程级 harness（harness_test.go：goBuild/start/freePort/waitOK/do/adminEnv）
// 之上补齐 S2 集成所需的真实进程与客户端：
//   - cryptopsvc sidecar（真实二进制；intl/sm 两档）
//   - audit-verify CLI（独立验证器）
//   - gateway-core 进程（产出 core 审计链）
//   - 插件 cryptoclient 的同步 HTTP Transport（驱动真实 sidecar）
//   - 按 profile 参数化启动 tee-infer / admin
package e2e

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm3"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/cryptoclient"
)

// appendEnv 覆盖式合并环境变量（同名替换而非追加——Windows 进程内 Getenv 对重复键
// 取首个，append 同名无法覆盖原值）。
func appendEnv(base []string, kv ...string) []string {
	for _, x := range kv {
		name := strings.SplitN(x, "=", 2)[0]
		idx := -1
		for i, b := range base {
			if strings.HasPrefix(b, name+"=") {
				idx = i
				break
			}
		}
		if idx >= 0 {
			base[idx] = x
		} else {
			base = append(base, x)
		}
	}
	return base
}

// adminTokenFor 按目标进程 profile 签发内部 JWT（sm 进程的签名经 HMAC-SM3，
// 与 admin-service auth.go 的 cryptop MAC 一致；intl=HMAC-SHA256）。
func adminTokenFor(profile, sub, role, tenant string) string {
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
	hashFn := sha256.New
	if profile != "intl" {
		hashFn = sm3.New
	}
	m := hmac.New(hashFn, []byte(adminJWTSecret))
	m.Write([]byte(si))
	return si + "." + b64url.EncodeToString(m.Sum(nil))
}

// authHdrFor 按 profile 返回鉴权头。
func authHdrFor(profile, sub, role, tenant string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + adminTokenFor(profile, sub, role, tenant)}
}

// ---------- cryptopsvc sidecar ----------

// startSidecar 构建并启动真实 sidecar，返回其基址（进程随测试结束清理）。
func startSidecar(t *testing.T, dir, profile, maskPRG string, extraEnv []string) string {
	t.Helper()
	bin := filepath.Join(dir, "cryptopsvc"+exeSuffix())
	goBuild(t, repoRoot(t), bin, "./gateway/cryptopsvc/cmd/cryptopsvc")
	port := freePort(t)
	addr := "127.0.0.1:" + strconv.Itoa(port)
	args := []string{"-listen", addr, "-profile", profile}
	if maskPRG != "" {
		args = append(args, "-mask-prg", maskPRG)
	}
	start(t, "cryptopsvc("+profile+")", bin, args, append(os.Environ(), extraEnv...))
	url := "http://" + addr
	waitOK(t, url+"/v1/capabilities", 30*time.Second)
	return url
}

// sidecarCaps 读取 sidecar capabilities。
func sidecarCaps(t *testing.T, base string) cryptoclient.Capabilities {
	t.Helper()
	code, body := do(t, http.MethodGet, base+"/v1/capabilities", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("capabilities 期望 200，实际 %d: %s", code, body)
	}
	var caps cryptoclient.Capabilities
	mustJSON(t, body, &caps)
	return caps
}

// ---------- audit-verify CLI ----------

// buildAuditVerify 构建独立验证 CLI，返回二进制路径。
func buildAuditVerify(t *testing.T, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "audit-verify"+exeSuffix())
	goBuild(t, repoRoot(t), bin, "./gateway/audit-verify/cmd/audit-verify")
	return bin
}

// runAuditVerify 以 JSON 结论运行验证 CLI，返回退出码与输出。
func runAuditVerify(t *testing.T, bin, chainFile, schema string) (int, []byte) {
	t.Helper()
	cmd := exec.Command(bin, "-file", chainFile, "-schema", schema, "-json")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, out
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), out
	}
	t.Fatalf("运行 audit-verify 异常: %v\n%s", err, out)
	return -1, out
}

// assertVerifyOK 断言 CLI 退出码 0 且 JSON 中 ok=true。
func assertVerifyOK(t *testing.T, bin, chainFile, schema string) {
	t.Helper()
	rc, out := runAuditVerify(t, bin, chainFile, schema)
	if rc != 0 {
		t.Fatalf("audit-verify(%s) 期望 exit0，实际 %d:\n%s", schema, rc, out)
	}
	var res struct {
		OK bool `json:"ok"`
	}
	mustJSON(t, out, &res)
	if !res.OK {
		t.Fatalf("audit-verify(%s) ok=false:\n%s", schema, out)
	}
}

// ---------- gateway-core ----------

// startCore 构建并启动 gateway-core（OTP_CORE_AUDIT_FILE 产出 core 链），返回基址。
func startCore(t *testing.T, dir, auditFile string) string {
	t.Helper()
	bin := filepath.Join(dir, "gateway-core"+exeSuffix())
	goBuild(t, repoRoot(t), bin, "./gateway/gateway-core/cmd")
	port := freePort(t)
	env := append(os.Environ(),
		"OTP_CORE_SIG_KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		"OTP_CORE_ADDR=127.0.0.1:"+strconv.Itoa(port),
		"OTP_CORE_AUDIT_FILE="+auditFile,
	)
	start(t, "gateway-core", bin, nil, env)
	url := "127.0.0.1:" + strconv.Itoa(port)
	waitTCP(t, url, 30*time.Second)
	return "http://" + url
}

// waitTCP 轮询直到 TCP 可连。
func waitTCP(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("等待 %s TCP 就绪超时", addr)
}

// ---------- tee-infer 参数化 ----------

// teeSpec tee 进程参数（固定凭证来自 harness 常量）。
type teeSpec struct {
	Profile   string // -crypto-profile
	MaskPRG   string // -mask-prg（空=随 profile）
	SealFile  string // -seal-file（空=内存模式）
	AuditFile string
	ExtraEnv  []string
}

// startTeeProcess 按指定 profile 启动真实 tee-infer，返回基址。
func startTeeProcess(t *testing.T, dir string, spec teeSpec) string {
	t.Helper()
	bin := filepath.Join(dir, "tee-infer"+exeSuffix())
	goBuild(t, repoRoot(t), bin, "./gateway/tee-infer-service")
	port := freePort(t)
	args := []string{
		"-listen", "127.0.0.1:" + strconv.Itoa(port),
		"-sig-key", teeSigKeyHex,
		"-attest-token", teeAttestToken,
		"-admin-token", teeAdminToken,
		"-meter-token", teeMeterToken,
		"-audit-file", spec.AuditFile,
		"-dev-mode",
		"-crypto-profile", spec.Profile,
	}
	if spec.MaskPRG != "" {
		args = append(args, "-mask-prg", spec.MaskPRG)
	}
	if spec.SealFile != "" {
		args = append(args, "-seal-file", spec.SealFile)
	}
	start(t, "tee-infer("+spec.Profile+")", bin, args, append(os.Environ(), spec.ExtraEnv...))
	url := "http://127.0.0.1:" + strconv.Itoa(port)
	waitOK(t, url+"/healthz", 30*time.Second)
	return url
}

// ---------- admin 参数化 ----------

// startAdminProcess 按 CRYPTO_PROFILE 启动 admin（billing 开关复用 adminEnv），返回基址。
// extraEnv 追加进程环境（如 INT-4 所需 CRYPTOPSVC_URL）。
func startAdminProcess(t *testing.T, dir, profile, teeURL, db, pricing string, billingOn bool,
	extraEnv []string) string {
	t.Helper()
	bin := filepath.Join(dir, "gateway-admin-service"+exeSuffix())
	goBuild(t, repoRoot(t), bin, "./gateway/gateway-admin-service")
	port := freePort(t)
	svcEnv := appendEnv(adminEnv(port, teeURL, db, pricing, billingOn), "CRYPTO_PROFILE="+profile)
	svcEnv = appendEnv(svcEnv, extraEnv...)
	start(t, "gateway-admin("+profile+")", bin, nil, svcEnv)
	url := "http://127.0.0.1:" + strconv.Itoa(port)
	waitOK(t, url+"/healthz", 30*time.Second)
	return url
}

// ---------- 插件 cryptoclient 的 HTTP Transport ----------

// httpTransport 以 net/http 同步驱动真实 sidecar（实现 cryptoclient.Transport）。
// 回调在同一调用栈内执行，语义等价于插件侧 DispatchHttpCall 的响应回调。
type httpTransport struct {
	base string
}

func newHTTPTransport(base string) *httpTransport { return &httpTransport{base: base} }

func (t *httpTransport) do(method, path string, headers [][2]string, body []byte,
	cb cryptoclient.ResponseCallback, timeoutMS uint32) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, t.base+path, reader)
	if err != nil {
		return err
	}
	for _, h := range headers {
		req.Header.Set(h[0], h[1])
	}
	client := &http.Client{Timeout: time.Duration(timeoutMS) * time.Millisecond}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	cb(resp.StatusCode, resp.Header, raw)
	return nil
}

func (t *httpTransport) Post(path string, headers [][2]string, body []byte,
	cb cryptoclient.ResponseCallback, timeoutMS uint32) error {
	return t.do(http.MethodPost, path, headers, body, cb, timeoutMS)
}

func (t *httpTransport) Get(path string, headers [][2]string,
	cb cryptoclient.ResponseCallback, timeoutMS uint32) error {
	return t.do(http.MethodGet, path, headers, nil, cb, timeoutMS)
}

// ---------- 小工具 ----------

// waitCapsProfile 轮询直到 capabilities 反映期望 profile/prg（sidecar 重启后用）。
// 注意：基址在 sidecar 换端口时由调用方更新；这里仅同址轮询。
func waitCapsProfile(t *testing.T, base, profile, prg string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		code, body := do(t, http.MethodGet, base+"/v1/capabilities", nil, nil)
		if code == http.StatusOK {
			var caps struct {
				Profile string `json:"profile"`
				MaskPRG string `json:"mask_prg"`
			}
			if json.Unmarshal(body, &caps) == nil &&
				caps.Profile == profile && (prg == "" || caps.MaskPRG == prg) {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("等待 sidecar profile=%s prg=%s 超时", profile, prg)
}
