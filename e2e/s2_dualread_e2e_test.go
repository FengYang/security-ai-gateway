//go:build e2e

// s2_dualread_e2e_test.go —— P0-4 §11.4 INT-5 双读混跑、§11.5 E2E-03/04。
//
// 两类持久化载体的跨 profile 可读性（均为真实进程 + 真实持久化文件）：
//   - 密封载体（tee seal-file）：suite 字节版本化 + 历史密封密钥环（OTPMASK_MOCK_SEAL_KEY_HISTORY）；
//   - 计费载体（sqlite + 账单签名）：签名前缀自述算法（hmac-sha256:/hmac-sm3:），
//     对侧进程按前缀分派复算（§5.4.3 组⑬）。
package e2e

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// ---------- 可手动停止的 tee-infer ----------

// startManagedTee 按 teeSpec 启动真实 tee-infer（可手动 stop 做跨 profile 重启）。
func startManagedTee(t *testing.T, dir string, spec teeSpec) *managedProc {
	t.Helper()
	bin := filepath.Join(dir, "tee-infer"+exeSuffix())
	if _, err := os.Stat(bin); err != nil {
		goBuild(t, repoRoot(t), bin, "./gateway/tee-infer-service")
	}
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
	addr := "127.0.0.1:" + strconv.Itoa(port)
	p := &managedProc{name: "tee-infer(" + spec.Profile + ")", addr: addr, port: port}
	p.cmd = exec.Command(bin, args...)
	p.cmd.Env = append(cleanEnv(), spec.ExtraEnv...)
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

// ---------- INT-5 密封载体：seal-file 跨 profile 恢复（E2E-03/04 密封侧） ----------

func TestINT5_DualReadSeal(t *testing.T) {
	t.Run("intl写_sm读", func(t *testing.T) {
		dir := t.TempDir()
		sealFile := filepath.Join(dir, "state.seal")
		intl := startManagedTee(t, dir, teeSpec{
			Profile:   "intl",
			SealFile:  sealFile,
			AuditFile: filepath.Join(dir, "tee-audit-intl.jsonl"),
			ExtraEnv:  []string{"OTPMASK_MOCK_SEAL_KEY=" + intlAEADHex},
		})
		if code, body := teeInfer(t, intl.url, "int5-seal-a", 1); code != http.StatusOK {
			t.Fatalf("intl 写：推理期望 200，得 %d: %s", code, body)
		}
		intl.stop()

		// sm 进程持历史环中的 intl 32B 密钥，Unseal 同一 seal-file 成功（能启动即通过）。
		sm := startManagedTee(t, dir, teeSpec{
			Profile:   "sm-software",
			SealFile:  sealFile,
			AuditFile: filepath.Join(dir, "tee-audit-sm.jsonl"),
			ExtraEnv: []string{
				"OTPMASK_MOCK_SEAL_KEY=" + smAEADHex,
				"OTPMASK_MOCK_SEAL_KEY_HISTORY=" + intlAEADHex,
			},
		})
		if code, body := teeInfer(t, sm.url, "int5-seal-a", 1); code != http.StatusOK {
			t.Fatalf("sm 读：解封后期望推理 200，得 %d: %s", code, body)
		}
	})

	t.Run("sm写_intl读", func(t *testing.T) {
		dir := t.TempDir()
		sealFile := filepath.Join(dir, "state.seal")
		sm := startManagedTee(t, dir, teeSpec{
			Profile:   "sm-software",
			SealFile:  sealFile,
			AuditFile: filepath.Join(dir, "tee-audit-sm.jsonl"),
			ExtraEnv:  []string{"OTPMASK_MOCK_SEAL_KEY=" + smAEADHex},
		})
		if code, body := teeInfer(t, sm.url, "int5-seal-b", 1); code != http.StatusOK {
			t.Fatalf("sm 写：推理期望 200，得 %d: %s", code, body)
		}
		sm.stop()

		// intl 进程持历史环中的 sm 16B 密钥，Unseal SM4-GCM suite blob 成功。
		intl := startManagedTee(t, dir, teeSpec{
			Profile:   "intl",
			SealFile:  sealFile,
			AuditFile: filepath.Join(dir, "tee-audit-intl.jsonl"),
			ExtraEnv: []string{
				"OTPMASK_MOCK_SEAL_KEY=" + intlAEADHex,
				"OTPMASK_MOCK_SEAL_KEY_HISTORY=" + smAEADHex,
			},
		})
		if code, body := teeInfer(t, intl.url, "int5-seal-b", 1); code != http.StatusOK {
			t.Fatalf("intl 读：解封后期望推理 200，得 %d: %s", code, body)
		}
	})
}

// ---------- INT-5 计费载体：sqlite 账单跨 profile 验签（E2E-03/04 计费侧） ----------

const int5PricingJSON = `{"version":"int5-v1","currency":"CNY","models":{
  "tee_gpu/mock":{"in_coef":1,"out_coef":1,
    "tiers":[{"up_to_tokens":0,"in_per_1k":1,"out_per_1k":2}]}}}`

func TestINT5_DualReadBilling(t *testing.T) {
	dir := t.TempDir()
	pricingPath := filepath.Join(dir, "pricing.json")
	if err := os.WriteFile(pricingPath, []byte(int5PricingJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "billing.db")

	// intl 栈出账（签名 hmac-sha256: 前缀）。
	intlTee := startManagedTee(t, dir, teeSpec{
		Profile:   "intl",
		AuditFile: filepath.Join(dir, "tee-intl.jsonl"),
	})
	intlADM := startManagedAdmin(t, dir, "intl", intlTee.url, db, pricingPath, 0, true, nil)
	billIntl := issueBill(t, "intl", intlTee.url, intlADM.url, "int5-a")

	// sm 进程打开同一 DB：同一签名密钥 + 按签名前缀分派 SHA-256 复算 → valid。
	intlADM.stop()
	smTee := startManagedTee(t, dir, teeSpec{
		Profile:   "sm-software",
		AuditFile: filepath.Join(dir, "tee-sm.jsonl"),
	})
	smADM := startManagedAdmin(t, dir, "sm-software", smTee.url, db, pricingPath,
		intlADM.port, true, nil)
	assertBillValid(t, "sm-software", smADM.url, billIntl)

	// 反向：sm 栈出账（hmac-sm3: 前缀）。
	billSM := issueBill(t, "sm-software", smTee.url, smADM.url, "int5-b")

	// intl 进程重开同一 DB：按前缀分派 SM3-HMAC 复算 → valid。
	smADM.stop()
	intlADM2 := startManagedAdmin(t, dir, "intl", intlTee.url, db, pricingPath,
		smADM.port, true, nil)
	assertBillValid(t, "intl", intlADM2.url, billSM)
}

// ---------- 辅助 ----------

// issueBill 经一次推理 → 等拉取入账 → 日结，返回账单 id。
func issueBill(t *testing.T, profile, teeURL, admURL, tenant string) string {
	t.Helper()
	if code, body := teeInfer(t, teeURL, tenant, 3); code != http.StatusOK {
		t.Fatalf("[%s] 推理期望 200，得 %d: %s", tenant, code, body)
	}
	waitLedgerTenant(t, profile, admURL, tenant, 90*time.Second)

	code, body := do(t, http.MethodPost, admURL+billingBase+"/close-daily",
		authHdrFor(profile, adminUser, "admin", ""),
		[]byte(`{"tenant":"`+tenant+`","day":"`+dayUTC8()+`"}`))
	if code != http.StatusOK {
		t.Fatalf("[%s] 日结期望 200，得 %d: %s", tenant, code, body)
	}
	var res struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	mustJSON(t, body, &res)
	if res.ID == "" || res.Status != "issued" {
		t.Fatalf("[%s] 账单异常: %+v", tenant, res)
	}
	return res.ID
}

// waitLedgerTenant 轮询直到某租户账本出现条目（等待 S-1 增量拉取，pull_interval=10s）。
func waitLedgerTenant(t *testing.T, profile, admURL, tenant string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		code, body := do(t, http.MethodGet,
			admURL+billingBase+"/ledger?tenant="+tenant,
			authHdrFor(profile, adminUser, "admin", ""), nil)
		if code == http.StatusOK {
			var out struct {
				Entries []json.RawMessage `json:"entries"`
			}
			if json.Unmarshal(body, &out) == nil && len(out.Entries) > 0 {
				return
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("等待账本入账超时（tenant=%s）", tenant)
}

// assertBillValid 断言账单 verify 端点返回 200 且 valid=true。
func assertBillValid(t *testing.T, profile, admURL, billID string) {
	t.Helper()
	code, body := do(t, http.MethodGet,
		admURL+billingBase+"/bills/"+billID+"/verify",
		authHdrFor(profile, adminUser, "admin", ""), nil)
	if code != http.StatusOK {
		t.Fatalf("账单 %s verify 期望 200，得 %d: %s", billID, code, body)
	}
	var v struct {
		Valid bool `json:"valid"`
	}
	mustJSON(t, body, &v)
	if !v.Valid {
		t.Fatalf("账单 %s 验签应 valid: %s", billID, body)
	}
}
