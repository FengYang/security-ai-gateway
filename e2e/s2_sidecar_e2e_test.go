//go:build e2e

// s2_sidecar_e2e_test.go —— P0-4 §11.4 INT-2（sidecar↔插件端到端）、
// INT-4（profile 切换；§12.6 两阶段：受理 → 滚动 → 全域一致性）、
// §11.5 E2E-06（sidecar 停机 fail-closed）。
//
// 全部为真实进程级链路：go build 二进制 → 子进程 → 仅经 HTTP 驱动；
// 插件侧密码学唯一路径是 cryptoclient → sidecar，客户端自身零密码实现。
package e2e

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/cryptoclient"
)

// ---------- CPS 回调 → 同步等待 ----------

type cpsResult[T any] struct {
	v   T
	err error
}

func await[T any](t *testing.T, d time.Duration, f func(cb func(T, error))) (T, error) {
	t.Helper()
	ch := make(chan cpsResult[T], 1)
	f(func(v T, err error) { ch <- cpsResult[T]{v: v, err: err} })
	select {
	case r := <-ch:
		return r.v, r.err
	case <-time.After(d):
		t.Fatalf("await 超时（%s）", d)
		var zero T
		return zero, nil
	}
}

func await2[A, B any](t *testing.T, d time.Duration,
	f func(cb func(A, B, error))) (A, B, error) {
	t.Helper()
	type r2 struct {
		a   A
		b   B
		err error
	}
	ch := make(chan r2, 1)
	f(func(a A, b B, err error) { ch <- r2{a: a, b: b, err: err} })
	select {
	case r := <-ch:
		return r.a, r.b, r.err
	case <-time.After(d):
		t.Fatalf("await2 超时（%s）", d)
		var za A
		var zb B
		return za, zb, nil
	}
}

func await3[A, B, C any](t *testing.T, d time.Duration,
	f func(cb func(A, B, C, error))) (A, B, C, error) {
	t.Helper()
	type r3 struct {
		a   A
		b   B
		c   C
		err error
	}
	ch := make(chan r3, 1)
	f(func(a A, b B, c C, err error) { ch <- r3{a: a, b: b, c: c, err: err} })
	select {
	case r := <-ch:
		return r.a, r.b, r.c, r.err
	case <-time.After(d):
		t.Fatalf("await3 超时（%s）", d)
		var za A
		var zb B
		var zc C
		return za, zb, zc, nil
	}
}

func awaitErr(t *testing.T, d time.Duration, f func(cb func(error))) error {
	t.Helper()
	ch := make(chan error, 1)
	f(func(err error) { ch <- err })
	select {
	case err := <-ch:
		return err
	case <-time.After(d):
		t.Fatalf("awaitErr 超时（%s）", d)
		return nil
	}
}

// ---------- 可手动停止的进程（sidecar / admin 滚动用） ----------

type managedProc struct {
	name string
	cmd  *exec.Cmd
	log  bytes.Buffer
	once sync.Once
	url  string
	addr string
	port int
}

func (p *managedProc) stop() {
	p.once.Do(func() {
		_ = p.cmd.Process.Kill()
		_, _ = p.cmd.Process.Wait()
	})
}

// waitAddrFree 等待被 kill 进程释放监听地址（同址滚动时用）。
func waitAddrFree(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		l, err := net.Listen("tcp", addr)
		if err == nil {
			l.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("等待地址 %s 释放超时", addr)
}

// startManagedSidecar 构建并启动真实 sidecar；addr 非空时在该地址同址重启。
func startManagedSidecar(t *testing.T, dir, profile, prg, keysJSON, addr string) *managedProc {
	t.Helper()
	if addr != "" {
		waitAddrFree(t, addr)
	} else {
		addr = "127.0.0.1:" + strconv.Itoa(freePort(t))
	}
	bin := filepath.Join(dir, "cryptopsvc"+exeSuffix())
	if _, err := os.Stat(bin); err != nil {
		goBuild(t, repoRoot(t), bin, "./gateway/cryptopsvc/cmd/cryptopsvc")
	}
	args := []string{"-listen", addr, "-profile", profile}
	if prg != "" {
		args = append(args, "-mask-prg", prg)
	}
	p := &managedProc{name: "cryptopsvc(" + profile + "/" + prg + ")", addr: addr}
	p.cmd = exec.Command(bin, args...)
	p.cmd.Env = append(cleanEnv(), "CRYPTO_STATIC_KEYS="+keysJSON)
	p.cmd.Stdout = &p.log
	p.cmd.Stderr = &p.log
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("启动 %s 失败: %v", p.name, err)
	}
	p.url = "http://" + addr
	t.Cleanup(func() {
		p.stop()
		if t.Failed() {
			t.Logf("---- %s 日志 ----\n%s", p.name, p.log.String())
		}
	})
	waitOK(t, p.url+"/v1/capabilities", 30*time.Second)
	return p
}

// startManagedAdmin 按 CRYPTO_PROFILE 启动真实 admin；port>0 时同址重启。
func startManagedAdmin(t *testing.T, dir, profile, teeURL, db, pricing string, port int,
	billingOn bool, extraEnv []string) *managedProc {
	t.Helper()
	if port > 0 {
		addr := "127.0.0.1:" + strconv.Itoa(port)
		waitAddrFree(t, addr)
	} else {
		port = freePort(t)
	}
	bin := filepath.Join(dir, "gateway-admin-service"+exeSuffix())
	if _, err := os.Stat(bin); err != nil {
		goBuild(t, repoRoot(t), bin, "./gateway/gateway-admin-service")
	}
	env := appendEnv(adminEnv(port, teeURL, db, pricing, billingOn), "CRYPTO_PROFILE="+profile)
	env = appendEnv(env, extraEnv...)
	addr := "127.0.0.1:" + strconv.Itoa(port)
	p := &managedProc{name: "gateway-admin(" + profile + ")", addr: addr, port: port}
	p.cmd = exec.Command(bin)
	p.cmd.Env = env
	p.cmd.Stdout = &p.log
	p.cmd.Stderr = &p.log
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("启动 %s 失败: %v", p.name, err)
	}
	p.url = "http://" + addr
	t.Cleanup(func() {
		p.stop()
		if t.Failed() {
			t.Logf("---- %s 日志 ----\n%s", p.name, p.log.String())
		}
	})
	waitOK(t, p.url+"/healthz", 30*time.Second)
	return p
}

// ---------- 环境与脚本 ----------

// cleanEnv 剔除代理变量（Go net/http 与脚本内 curl 默认读取；#13 已实测需剔除）。
func cleanEnv() []string {
	src := os.Environ()
	out := make([]string, 0, len(src))
	for _, kv := range src {
		lower := strings.ToLower(kv)
		if strings.HasPrefix(lower, "http_proxy=") ||
			strings.HasPrefix(lower, "https_proxy=") ||
			strings.HasPrefix(lower, "all_proxy=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// bashPath 定位 bash（Windows = Git for Windows；无则 skip INT-4 脚本链路）。
func bashPath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		if _, err := exec.LookPath("bash"); err != nil {
			t.Skip("bash 不可用，跳过脚本链路")
		}
		return "bash"
	}
	candidates := []string{`C:\Program Files\Git\bin\bash.exe`}
	if root := os.Getenv("GIT_INSTALL_ROOT"); root != "" {
		candidates = append([]string{filepath.Join(root, "bin", "bash.exe")}, candidates...)
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	t.Skip("Git for Windows bash 不可用，跳过脚本链路")
	return ""
}

// runSwitchScript 运行 cryptop-switch-profile.sh，返回退出码与输出。
func runSwitchScript(t *testing.T, adminURL, sidecarURL, jwt, from, to, prg, mode string) (int, string) {
	t.Helper()
	root := repoRoot(t)
	cmd := exec.Command(bashPath(t), filepath.Join(root, "scripts", "cryptop-switch-profile.sh"))
	cmd.Dir = root
	cmd.Env = append(cleanEnv(),
		"FROM="+from, "TO="+to, "MODE="+mode, "PRG="+prg,
		"ADMIN="+adminURL, "ADMIN_TOKEN="+jwt,
		"CRYPTOPSVC_URL="+sidecarURL)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	}
	t.Fatalf("运行切换脚本异常: %v\n%s", err, out)
	return -1, ""
}

// runVerifyConsistency 运行 cryptop-verify-consistency.sh <want>，返回退出码与输出。
func runVerifyConsistency(t *testing.T, sidecarURL, want string) (int, string) {
	t.Helper()
	root := repoRoot(t)
	cmd := exec.Command(bashPath(t),
		filepath.Join(root, "scripts", "cryptop-verify-consistency.sh"), want)
	cmd.Dir = root
	cmd.Env = append(cleanEnv(), "CRYPTOPSVC_URL="+sidecarURL)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	}
	t.Fatalf("运行一致性脚本异常: %v\n%s", err, out)
	return -1, ""
}

// postSwitch 直接调 profile 切换端点（INT-4 步2/步5 受理阶段用）。
func postSwitch(t *testing.T, adminURL, jwt, from, to, prg, mode string) (int, []byte) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"from": from, "to": to, "mode": mode, "mask_prg": prg, "confirm": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return do(t, http.MethodPost, adminURL+"/v1/adminext/cryptop/profile",
		map[string]string{"Authorization": "Bearer " + jwt}, body)
}

// ---------- 静态测试密钥（R-16：长度须 == SymmetricKeySize，intl=32 / sm=16） ----------

const (
	intlAEADHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	intlMACHex  = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
	smAEADHex   = "0123456789abcdef0123456789abcdef"
	smMACHex    = "fedcba9876543210fedcba9876543210"
)

func staticKeysJSON(profile string) string {
	if profile == "intl" {
		return `{"aead":"` + intlAEADHex + `","mac":"` + intlMACHex + `"}`
	}
	return `{"aead":"` + smAEADHex + `","mac":"` + smMACHex + `"}`
}

// sessionFixture 构造服务端静态密钥对与 nonce：intl=X25519，sm=SM2。
func sessionFixture(t *testing.T, peerAlg string) (pub, nonce []byte) {
	t.Helper()
	nonce = make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	if peerAlg == "sm2" {
		priv, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		// 裸未压缩点 04||X||Y（sm2.ParseUncompressedPublicKey 入参）。
		return elliptic.Marshal(priv.Curve, priv.PublicKey.X, priv.PublicKey.Y), nonce
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv.Public().(*ecdh.PublicKey).Bytes(), nonce
}

// ---------- INT-2：sidecar↔插件端到端（两档） ----------

func TestINT2_SidecarPlugin(t *testing.T) {
	t.Run("intl", func(t *testing.T) { int2Run(t, "intl") })
	t.Run("sm-software", func(t *testing.T) { int2Run(t, "sm-software") })
}

func int2Run(t *testing.T, profile string) {
	dir := t.TempDir()
	m := startManagedSidecar(t, dir, profile, "", staticKeysJSON(profile), "")
	maskVer := "hmac-sha256"
	seedLen := 32
	peerAlg := "x25519"
	if profile != "intl" {
		maskVer = "sm4"
		seedLen = 16
		peerAlg = "sm2"
	}
	c := cryptoclient.New(newHTTPTransport(m.url), nil, nil,
		cryptoclient.Config{TimeoutMS: 5000, MaskVersion: maskVer})

	caps, err := await(t, 10*time.Second, func(cb func(cryptoclient.Capabilities, error)) {
		c.LoadCapabilities(cb)
	})
	if err != nil {
		t.Fatalf("LoadCapabilities: %v", err)
	}
	if caps.Profile != profile {
		t.Fatalf("capabilities profile 期望 %q，得 %q", profile, caps.Profile)
	}
	if caps.MaskPRG != maskVer {
		t.Fatalf("capabilities mask_prg 期望 %q，得 %q", maskVer, caps.MaskPRG)
	}

	data := []byte("int2-sidecar-plugin")

	// Hash：摘要定长 32B（intl=SHA-256 / sm=SM3）。
	digest, err := await(t, 10*time.Second, func(cb func([]byte, error)) {
		c.Hash(data, cb)
	})
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if len(digest) != 32 {
		t.Fatalf("hash 长度期望 32，得 %d", len(digest))
	}

	// HMAC（intl=HMAC-SHA256 / sm=SM3-HMAC）。
	mac, err := await(t, 10*time.Second, func(cb func([]byte, error)) {
		c.HMAC(cryptoclient.KeyRef("mac"), data, cb)
	})
	if err != nil {
		t.Fatalf("HMAC: %v", err)
	}
	if len(mac) != 32 {
		t.Fatalf("mac 长度期望 32，得 %d", len(mac))
	}

	// HMAC 确定性：同输入复算逐字节一致、改输入则不同（对齐用户裁决 D1：
	// sidecar /v1/verify 的 key_ref 分支是签名验签，HMAC 校验不走该端点）。
	macAgain, err := await(t, 10*time.Second, func(cb func([]byte, error)) {
		c.HMAC(cryptoclient.KeyRef("mac"), data, cb)
	})
	if err != nil {
		t.Fatalf("HMAC 复算: %v", err)
	}
	if !bytes.Equal(mac, macAgain) {
		t.Fatal("同输入 HMAC 不确定")
	}
	macOther, err := await(t, 10*time.Second, func(cb func([]byte, error)) {
		c.HMAC(cryptoclient.KeyRef("mac"), append(data, '!'), cb)
	})
	if err != nil {
		t.Fatalf("HMAC 异输入: %v", err)
	}
	if bytes.Equal(mac, macOther) {
		t.Fatal("不同输入 HMAC 不应相同")
	}

	// Verify 端点：外部 P-256/SHA-256 签名经 sidecar 验（alg="p256"，§5.4.2 恒国际，
	// 两档同路径）；合法→true、篡改→false（HTTP 200，非错误）。
	// VerifyP256 契约：pub=SEC1 未压缩点、msg=原始消息（内部 SHA-256）、sig=裸 r‖s 64B。
	signPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256Digest := sha256.Sum256(data)
	sigR, sigS, err := ecdsa.Sign(rand.Reader, signPriv, p256Digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	sigR.FillBytes(sig[:32])
	sigS.FillBytes(sig[32:])
	pubBytes := elliptic.Marshal(signPriv.Curve, signPriv.X, signPriv.Y)
	ok, err := await[bool](t, 10*time.Second, func(cb func(bool, error)) {
		c.Verify(nil, pubBytes, data, sig, "p256", cb)
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("合法 P256 签名 verify 期望 true")
	}
	ok, err = await[bool](t, 10*time.Second, func(cb func(bool, error)) {
		c.Verify(nil, pubBytes, append(data, '!'), sig, "p256", cb)
	})
	if err != nil {
		t.Fatalf("Verify(篡改): %v", err)
	}
	if ok {
		t.Fatal("篡改数据 verify 期望 false")
	}

	// Seal → Open 往返（intl=AES-256-GCM / sm=SM4-GCM；nonce 由 sidecar 生成）。
	aad := []byte("aad-int2")
	pt := []byte("plain-secret")
	nonce, ct, err := await2(t, 10*time.Second,
		func(cb func([]byte, []byte, error)) {
			c.Seal(cryptoclient.KeyRef("aead"), aad, nil, pt, cb)
		})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(nonce) == 0 {
		t.Fatal("Seal 返回 nonce 为空")
	}
	if len(ct) == 0 || bytes.Equal(ct, pt) {
		t.Fatal("Seal 密文异常")
	}
	pt2, err := await(t, 10*time.Second, func(cb func([]byte, error)) {
		c.Open(cryptoclient.KeyRef("aead"), aad, nonce, ct, cb)
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, pt2) {
		t.Fatalf("Open 往返不一致：%q vs %q", pt, pt2)
	}

	// MaskStream：seed 长度随 PRG（hmac=32 / sm4=16），模算术结果 < modulus。
	seed := bytes.Repeat([]byte{0x5a}, seedLen)
	vals, err := await(t, 10*time.Second, func(cb func([]uint64, error)) {
		c.MaskStream(seed, []byte("int2"), 8, 1_000_003, cb)
	})
	if err != nil {
		t.Fatalf("MaskStream: %v", err)
	}
	if len(vals) != 8 {
		t.Fatalf("mask 数量期望 8，得 %d", len(vals))
	}
	for i, v := range vals {
		if v >= 1_000_003 {
			t.Fatalf("mask[%d]=%d 越界（modulus=1000003）", i, v)
		}
	}

	// Session 端到端：ECDH/SM2 协商出临时会话密钥，SessionEnd 后引用立即销毁。
	serverPub, sessNonce := sessionFixture(t, peerAlg)
	ksig, kenc, clientPub, err := await3(t, 10*time.Second,
		func(cb func(cryptoclient.KeyRef, cryptoclient.KeyRef, []byte, error)) {
			c.SessionBegin(serverPub, sessNonce, "", cb)
		})
	if err != nil {
		t.Fatalf("SessionBegin: %v", err)
	}
	if len(clientPub) == 0 {
		t.Fatal("SessionBegin 未返回 client_pub")
	}
	if err := awaitErr(t, 10*time.Second, func(cb func(error)) {
		c.SessionEnd(ksig, kenc, cb)
	}); err != nil {
		t.Fatalf("SessionEnd: %v", err)
	}
	if _, err := await(t, 10*time.Second, func(cb func([]byte, error)) {
		c.HMAC(ksig, data, cb)
	}); err == nil {
		t.Fatal("SessionEnd 后会话 KeyRef 须失效")
	}
}

// ---------- INT-4：profile 切换两阶段（受理 → 滚动 → 一致性） ----------

func TestINT4_ProfileSwitch(t *testing.T) {
	dir := t.TempDir()
	intlToken := adminTokenFor("intl", adminUser, "admin", "")
	smToken := adminTokenFor("sm-software", adminUser, "admin", "")

	// 初始 intl 栈（sidecar 与 admin 同 profile；CRYPTOPSVC_URL 指向 sidecar）。
	intlSC := startManagedSidecar(t, dir, "intl", "", staticKeysJSON("intl"), "")
	intlADM := startManagedAdmin(t, dir, "intl", "http://unused",
		filepath.Join(dir, "adm-intl.db"), "", 0, false,
		[]string{"CRYPTOPSVC_URL=" + intlSC.url})

	// 步1：hot 跨 provider → 409 restart_required（脚本 exit3）。
	rc, out := runSwitchScript(t, intlADM.url, intlSC.url, intlToken,
		"intl", "sm-software", "bridge", "hot")
	if rc != 3 {
		t.Fatalf("步1 hot 跨 provider：期望 exit3，得 %d: %s", rc, out)
	}

	// 步2：restart 受理（治理面批准 + 审计；进程运行时此刻仍 intl）。
	if code, body := postSwitch(t, intlADM.url, intlToken,
		"intl", "sm-software", "bridge", "restart"); code != http.StatusOK {
		t.Fatalf("步2 restart 受理：期望 200，得 %d: %s", code, body)
	}

	// 步3：全域滚动——sidecar 与 admin 均以 sm-software/bridge 同址重启 → 一致性 exit0。
	intlSC.stop()
	intlADM.stop()
	smSC := startManagedSidecar(t, dir, "sm-software", "bridge",
		staticKeysJSON("sm-software"), intlSC.addr)
	smADM := startManagedAdmin(t, dir, "sm-software", "http://unused",
		filepath.Join(dir, "adm-sm.db"), "", intlADM.port, false,
		[]string{"CRYPTOPSVC_URL=" + smSC.url})
	rc, out = runVerifyConsistency(t, smSC.url, "sm-software")
	if rc != 0 {
		t.Fatalf("步3 切后一致性：期望 exit0，得 %d: %s", rc, out)
	}
	// 新 admin 进程 current=sm：对其 hot 跨 provider 亦须 exit3（证明运行时确已切换）。
	rc, out = runSwitchScript(t, smADM.url, smSC.url, smToken,
		"sm-software", "intl", "hmac-sha256", "hot")
	if rc != 3 {
		t.Fatalf("步3b 新栈 hot 跨 provider：期望 exit3，得 %d: %s", rc, out)
	}

	// 步4：同 provider PRG hot——先受理（sidecar 仍处 bridge，与 from 态一致；目标
	// prg=sm4 相对 caps 的 bridge 有变更），脚本内置 consistency（bridge 对 sm 合法）
	// exit0；随后滚 sidecar bridge→sm4，再复核一致性。
	rc, out = runSwitchScript(t, smADM.url, smSC.url, smToken,
		"sm-software", "sm-software", "sm4", "hot")
	if rc != 0 {
		t.Fatalf("步4 PRG hot：期望 exit0，得 %d: %s", rc, out)
	}
	smSC.stop()
	sm4SC := startManagedSidecar(t, dir, "sm-software", "sm4",
		staticKeysJSON("sm-software"), smSC.addr)
	rc, out = runVerifyConsistency(t, sm4SC.url, "sm-software")
	if rc != 0 {
		t.Fatalf("步4b 滚后一致性：期望 exit0，得 %d: %s", rc, out)
	}

	// 步5：回滚 intl——hot 再拒 → restart 受理 → 全域滚动 → 一致性 exit0。
	rc, out = runSwitchScript(t, smADM.url, sm4SC.url, smToken,
		"sm-software", "intl", "hmac-sha256", "hot")
	if rc != 3 {
		t.Fatalf("步5a 回滚 hot：期望 exit3，得 %d: %s", rc, out)
	}
	if code, body := postSwitch(t, smADM.url, smToken,
		"sm-software", "intl", "hmac-sha256", "restart"); code != http.StatusOK {
		t.Fatalf("步5b 回滚受理：期望 200，得 %d: %s", code, body)
	}
	sm4SC.stop()
	smADM.stop()
	backSC := startManagedSidecar(t, dir, "intl", "",
		staticKeysJSON("intl"), sm4SC.addr)
	backADM := startManagedAdmin(t, dir, "intl", "http://unused",
		filepath.Join(dir, "adm-back.db"), "", smADM.port, false,
		[]string{"CRYPTOPSVC_URL=" + backSC.url})
	_ = backADM // 回滚后 admin 进程保活至测试结束（cleanup 统一停）
	rc, out = runVerifyConsistency(t, backSC.url, "intl")
	if rc != 0 {
		t.Fatalf("步5c 回滚一致性：期望 exit0，得 %d: %s", rc, out)
	}
}

// ---------- E2E-06：sidecar 停机 fail-closed（无本地回退） ----------

func TestE2E06_SidecarDownFailClosed(t *testing.T) {
	dir := t.TempDir()
	m := startManagedSidecar(t, dir, "intl", "", staticKeysJSON("intl"), "")
	c := cryptoclient.New(newHTTPTransport(m.url), nil, nil,
		cryptoclient.Config{TimeoutMS: 3000, MaskVersion: "hmac-sha256"})

	if _, err := await(t, 10*time.Second, func(cb func([]byte, error)) {
		c.Hash([]byte("pre-down"), cb)
	}); err != nil {
		t.Fatalf("停机前调用应成功: %v", err)
	}

	m.stop()

	// 各调用路径一律 ErrTransport（cryptoclient 无任何密码学本地实现，结构上无回退可能）。
	oneValueOps := []struct {
		name string
		run  func(cb func([]byte, error))
	}{
		{"hash", func(cb func([]byte, error)) { c.Hash([]byte("x"), cb) }},
		{"hmac", func(cb func([]byte, error)) { c.HMAC("mac", []byte("x"), cb) }},
		{"open", func(cb func([]byte, error)) {
			c.Open("aead", nil, nil, []byte("x"), cb)
		}},
	}
	for _, op := range oneValueOps {
		if _, err := await(t, 10*time.Second,
			func(cb func([]byte, error)) { op.run(cb) }); !errors.Is(err, cryptoclient.ErrTransport) {
			t.Fatalf("%s: 期望 ErrTransport，得 %v", op.name, err)
		}
	}
	if _, _, err := await2(t, 10*time.Second,
		func(cb func([]byte, []byte, error)) {
			c.Seal("aead", nil, nil, []byte("x"), cb)
		}); !errors.Is(err, cryptoclient.ErrTransport) {
		t.Fatalf("seal: 期望 ErrTransport，得 %v", err)
	}
}
