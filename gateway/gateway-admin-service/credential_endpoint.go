// Package main — 段① 凭据只读投递端点（Phase 1 门禁 #8 / GF.2.5 第一步）。
//
// 设计：GF.2.5「Secret 与 KMS/Vault 集成」——WasmPlugin config 为静态 JSON、不支持
// secretKeyRef，故 sig_key/attest_token 若由流水线替换进 CR 则 CR 内仍为明文。
// 本端点让 otpmask 插件改为**运行时周期拉取**：CR 内不再出现真实密钥，只保留
// 服务地址与一个受限读取令牌（明文通道，内网 + 令牌，见方案选定）。
//
// 契约：
//
//	GET /v1/adminext/credentials/{name}
//	请求头：X-Credential-Token: <共享令牌>（常量时间比较；未配置令牌 = 端点不注册）
//	响应：  {"name":"...","sig_key":"<64 hex>","attest_token":"<...>"}
//	错误：  401 令牌错误 / 404 名称未支持 / 405 非 GET / 503 凭据文件缺失或损坏（fail-closed）
//
// 安全约束：
//   - 凭据值**绝不入日志/错误信息**（与 broker 同规则）；
//   - 文件须 0600（Windows 无 Unix 权限语义，跳过该校验并如实说明）；
//   - 只读端点：无任何写路径（写凭据仍走 broker / 高敏变更复核 D8）。
package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
)

// credentialAPIBase 段① 凭据只读端点前缀。
const credentialAPIBase = "/v1/adminext/credentials"

// credentialNameOTPMask 唯一受支持的凭据集名（第一版：仅 otpmask 段① 密钥）。
const credentialNameOTPMask = "otpmask-keys"

// defaultCredentialFile 凭据文件缺省路径（deploy/secrets/ 整目录已 gitignore）。
const defaultCredentialFile = "deploy/secrets/otpmask-keys.env"

// credentialSettings 端点配置（env 注入）。
//
// ADMIN_CREDENTIAL_TOKEN 未配置 = 端点不注册（fail-closed：绝不裸奔投递凭据）。
type credentialSettings struct {
	file  string // 凭据文件（KEY=VALUE 行）
	token string // 共享读取令牌（required）
}

// loadCredentialSettings 解析配置（均带缺省；token 缺失返回 nil = 特性关闭）。
func loadCredentialSettings() *credentialSettings {
	token := os.Getenv("ADMIN_CREDENTIAL_TOKEN")
	if token == "" {
		return nil
	}
	file := os.Getenv("ADMIN_CREDENTIAL_FILE")
	if file == "" {
		file = defaultCredentialFile
	}
	return &credentialSettings{file: file, token: token}
}

// credentialHandler 只读凭据投递 handler。
type credentialHandler struct {
	settings *credentialSettings
}

func newCredentialHandler(s *credentialSettings) *credentialHandler {
	return &credentialHandler{settings: s}
}

// credentialResponse 投递响应（字段名与 otpmask 插件 config 对齐，便于直接反序列化）。
type credentialResponse struct {
	Name        string `json:"name"`
	SigKeyHex   string `json:"sig_key"`
	AttestToken string `json:"attest_token"`
}

// handle 处理 /v1/adminext/credentials/{name}（仅 GET）。
func (h *credentialHandler) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	// 常量时间比较：避免令牌逐字节比较的时序侧信道。
	got := r.Header.Get("X-Credential-Token")
	if subtle.ConstantTimeCompare([]byte(got), []byte(h.settings.token)) != 1 {
		// 不记录令牌内容，仅记录来源与结果
		log.Printf("[credential] 令牌校验失败 remote=%s", r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "令牌无效")
		return
	}

	name := strings.TrimPrefix(r.URL.Path, credentialAPIBase+"/")
	if name != credentialNameOTPMask {
		writeError(w, http.StatusNotFound, "未支持的凭据集: "+name)
		return
	}

	resp, err := loadCredentialFile(h.settings.file)
	if err != nil {
		// fail-closed：文件缺失/损坏一律 503，不回退、不返回空值（否则插件侧会拿到空密钥）。
		log.Printf("[credential] 读取失败（fail-closed）: %v", err)
		writeError(w, http.StatusServiceUnavailable, "凭据不可用")
		return
	}
	resp.Name = name
	log.Printf("[credential] 投递 ok name=%s sig_key_len=%d", name, len(resp.SigKeyHex))
	writeJSON(w, http.StatusOK, resp)
}

// loadCredentialFile 读取并校验凭据文件（KEY=VALUE 行；sig_key 必须为 64 位 hex）。
func loadCredentialFile(path string) (*credentialResponse, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("凭据文件不可读: %w", err)
	}
	// 权限收紧校验（Windows 无 Unix 权限位语义，跳过后如实记录）。
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("凭据文件权限过宽（%o，要求 600）", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("凭据文件读取失败: %w", err)
	}

	var sigKey, attestToken string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "sig_key":
			sigKey = strings.TrimSpace(v)
		case "attest_token":
			attestToken = strings.TrimSpace(v)
		}
	}
	if err := validateSigKeyHex(sigKey); err != nil {
		return nil, err
	}
	if len(attestToken) < minProviderKeyLen {
		return nil, errors.New("凭据文件缺少 attest_token（或过短）")
	}
	return &credentialResponse{SigKeyHex: sigKey, AttestToken: attestToken}, nil
}

// validateSigKeyHex 校验 K_sig：必须为 64 位十六进制（32 字节）。
func validateSigKeyHex(v string) error {
	if v == "" {
		return errors.New("凭据文件缺少 sig_key")
	}
	if len(v) != 64 {
		return fmt.Errorf("sig_key 长度非法（%d，要求 64 位 hex）", len(v))
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return errors.New("sig_key 含非十六进制字符")
		}
	}
	return nil
}
