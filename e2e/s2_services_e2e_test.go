//go:build e2e

// s2_services_e2e_test.go —— INT-1/INT-3（P0-4 §11.4；承载 E2E-01/02）。
//
// INT-1：真实 tee-infer 进程 ×intl/sm 两档——attest token → key/issue → /v1/infer
// 全链路成功（响应 HMAC-SHA256 验签与 profile 无关），审计 WORM 链与密封文件落盘，
// 审计 hash_alg 随 profile（缺省=SHA-256 / sm3）。
//
// INT-3：真实 audit-verify CLI 独立验证 tee/admin/core 三链（两 profile 共 5 个链文件，
// 含 SM3），并断言 intl(SHA)→sm(SM3) 混合链逐事件分派闭合。
package e2e

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// TestINT1_CryptoServiceChain E2E-01（intl）/ E2E-02（sm-software）。
func TestINT1_CryptoServiceChain(t *testing.T) {
	t.Run("intl", func(t *testing.T) { int1Run(t, "intl", "") })
	t.Run("sm-software", func(t *testing.T) { int1Run(t, "sm-software", "") })
}

func int1Run(t *testing.T, profile, maskPRG string) {
	t.Helper()
	dir := t.TempDir()
	auditFile := filepath.Join(dir, "audit.jsonl")
	sealFile := filepath.Join(dir, "seal.bin")
	teeURL := startTeeProcess(t, dir, teeSpec{
		Profile: profile, MaskPRG: maskPRG, AuditFile: auditFile, SealFile: sealFile,
	})

	if code, body := teeInfer(t, teeURL, "int1-"+profile, 3); code != http.StatusOK {
		t.Fatalf("推理期望 200，实际 %d: %s", code, body)
	}

	wantAlg := map[string]string{"intl": "", "sm-software": "sm3"}[profile]
	events := readJSONLines(t, auditFile)
	if len(events) == 0 {
		t.Fatal("审计链为空")
	}
	for i, ev := range events {
		var e struct {
			HashAlg string `json:"hash_alg"`
		}
		raw, _ := json.Marshal(ev)
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("审计行 %d JSON 非法: %v", i, err)
		}
		if e.HashAlg != wantAlg {
			t.Fatalf("审计行 %d hash_alg=%q 期望 %q（profile=%s）", i, e.HashAlg, wantAlg, profile)
		}
	}

	info, err := os.Stat(sealFile)
	if err != nil {
		t.Fatalf("密封文件未产生: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("密封文件为空")
	}
}

// TestINT3_CrossServiceAuditVerify 三链独立验证 + SM3 + 混合链。
func TestINT3_CrossServiceAuditVerify(t *testing.T) {
	dir := t.TempDir()
	verifyBin := buildAuditVerify(t, dir)

	profiles := []struct {
		name   string
		dbName string
	}{
		{"intl", "intl.db"},
		{"sm-software", "sm.db"},
	}
	for _, p := range profiles {
		workDir := t.TempDir()
		teeAudit := filepath.Join(workDir, "tee-audit.jsonl")
		admAudit := filepath.Join(workDir, "admin-audit.jsonl")
		teeURL := startTeeProcess(t, workDir, teeSpec{Profile: p.name, AuditFile: teeAudit})
		// billing 关闭：INT-3 只需要 admin 审计链（quota_set），不依赖账单体系。
		admURL := startAdminProcess(t, workDir, p.name, teeURL,
			filepath.Join(workDir, p.dbName), "", false,
			[]string{
				"ADMIN_AUDIT_FILE=" + admAudit,
				// quota 端点转发用 X-Admin-Token（usage 代理的 meter token 对 /usage/quota 无效）。
				"ADMIN_TEE_INFER_TOKEN=" + teeAdminToken,
			})

		if code, body := teeInfer(t, teeURL, "int3-tee-"+p.name, 2); code != http.StatusOK {
			t.Fatalf("[%s] tee 链产出推理期望 200，实际 %d: %s", p.name, code, body)
		}
		quotaBody := []byte(`{"tenant":"int3-` + p.name + `","max_tokens":1000000}`)
		if code, body := do(t, http.MethodPost, admURL+"/v1/adminext/usage/quota",
			authHdrFor(p.name, adminUser, "admin", ""), quotaBody); code != http.StatusOK {
			t.Fatalf("[%s] quota 期望 200，实际 %d: %s", p.name, code, body)
		}

		assertVerifyOK(t, verifyBin, teeAudit, "tee")
		assertVerifyOK(t, verifyBin, admAudit, "admin")
	}

	// core 链：gateway-core 进程 + PUT /ratelimits（未设鉴权 token=内网免鉴权）。
	coreDir := t.TempDir()
	coreAudit := filepath.Join(coreDir, "core-audit.jsonl")
	coreURL := startCore(t, coreDir, coreAudit)
	if code, body := do(t, http.MethodPut, coreURL+"/ratelimits",
		map[string]string{"Content-Type": "application/json"},
		[]byte(coreValidTableJSON)); code != http.StatusOK {
		t.Fatalf("core PUT /ratelimits 期望 200，实际 %d: %s", code, body)
	}
	assertVerifyOK(t, verifyBin, coreAudit, "core")

	// 混合链：intl tee 写 SHA 事件 → 复制链文件 → sm tee 在副本上追加 SM3 事件。
	mixDir := t.TempDir()
	intlMixAudit := filepath.Join(mixDir, "intl-mix.jsonl")
	intlTeeURL := startTeeProcess(t, mixDir, teeSpec{Profile: "intl", AuditFile: intlMixAudit})
	if code, body := teeInfer(t, intlTeeURL, "int3-mix-intl", 1); code != http.StatusOK {
		t.Fatalf("混合链 intl 段期望 200，实际 %d: %s", code, body)
	}
	hybridAudit := filepath.Join(mixDir, "hybrid.jsonl")
	if err := copyFile(intlMixAudit, hybridAudit); err != nil {
		t.Fatalf("复制混合链底本失败: %v", err)
	}
	smTeeURL := startTeeProcess(t, t.TempDir(), teeSpec{
		Profile: "sm-software", AuditFile: hybridAudit,
	})
	if code, body := teeInfer(t, smTeeURL, "int3-mix-sm", 1); code != http.StatusOK {
		t.Fatalf("混合链 sm 段期望 200，实际 %d: %s", code, body)
	}
	events := readJSONLines(t, hybridAudit)
	if len(events) < 2 {
		t.Fatalf("混合链事件数 %d < 2", len(events))
	}
	assertVerifyOK(t, verifyBin, hybridAudit, "tee")
}

// ---------- 辅助 ----------

// coreValidTableJSON 对齐 core 包 ratelimits_test.go validTableJSON（种子表 v1 → PUT v2）。
const coreValidTableJSON = `{"version":2,"issued_at":"2026-09-13T10:00:00Z","rules":[
{"id":"t-a-rate","kind":"rate","scope":"tenant","target":"t-a","rpm":600,"action":"reject","enabled":true}]}`

// readJSONLines 读取 JSON Lines 为通用 map 切片。
func readJSONLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("打开 %s 失败: %v", path, err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("JSON Lines 解析失败: %v\n%s", err, line)
		}
		out = append(out, m)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	return out
}

// copyFile 复制文件内容（审计链底本复制用）。
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
