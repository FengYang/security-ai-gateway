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
//   - 文件权限严禁 world 位与组写（0600 或 K8s Secret+fsGroup 下的 0640 均可；Windows 无 Unix 权限语义，跳过该校验并如实说明）；
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

// 受支持的凭据集名（C 项起多集合）。
const (
	// credentialNameOTPMask 段① 密钥集（K_sig + attest token）。
	credentialNameOTPMask = "otpmask-keys"
	// credentialNameCoreChannel gateway-core 拉取通道令牌集（限流表拉取的 Bearer 令牌）。
	credentialNameCoreChannel = "core-channel"
)

// defaultCredentialFile 凭据文件缺省路径（deploy/secrets/ 整目录已 gitignore）。
// core-channel 的推荐路径为 deploy/secrets/gateway-core-token.env（经 ADMIN_CREDENTIAL_SETS 显式指定）。
const defaultCredentialFile = "deploy/secrets/otpmask-keys.env"

// minChannelTokenLen 通道令牌最小长度（防御性下限：短令牌易被撞库/暴力枚举）。
const minChannelTokenLen = 32

// fieldWhitelist 各凭据集的**字段白名单（代码内固定，配置不得放宽）**：
// 即使配置文件多写字段，也不会被投递出去。
var fieldWhitelist = map[string][]string{
	credentialNameOTPMask:     {"sig_key", "attest_token"},
	credentialNameCoreChannel: {"token"},
}

// credentialSet 一个凭据集（名称 → 文件 + **该集合独立**读取令牌 + 字段白名单）。
//
// 独立读令牌＝最小权限：core-channel 的令牌不能读 otpmask-keys（跨集合一律 401）。
type credentialSet struct {
	Name  string
	File  string
	Token string
}

// credentialSettings 端点配置（env 注入）。
//
// 支持两种写法（同时存在时以 ADMIN_CREDENTIAL_SETS 为准）：
//
//	ADMIN_CREDENTIAL_SETS="otpmask-keys:<file>:<token>,core-channel:<file>:<token>"
//	ADMIN_CREDENTIAL_TOKEN=<token> [+ ADMIN_CREDENTIAL_FILE]   # 单集合兼容（等价于仅 otpmask-keys）
//
// 未配置（无任何集合）= 端点不注册（fail-closed：绝不裸奔投递凭据）。
type credentialSettings struct {
	sets []credentialSet
}

// loadCredentialSettings 解析配置；无可用集合返回 nil（特性关闭）。
func loadCredentialSettings() *credentialSettings {
	if raw := os.Getenv("ADMIN_CREDENTIAL_SETS"); strings.TrimSpace(raw) != "" {
		var sets []credentialSet
		for _, item := range strings.Split(raw, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			parts := strings.Split(item, ":")
			if len(parts) != 3 {
				log.Printf("[credential] ADMIN_CREDENTIAL_SETS 条目非法（须 name:file:token），已跳过")
				continue
			}
			name, file, token := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
			if _, ok := fieldWhitelist[name]; !ok {
				log.Printf("[credential] 未支持的凭据集 %q（已知：otpmask-keys/core-channel），已跳过", name)
				continue
			}
			if file == "" || token == "" {
				log.Printf("[credential] 凭据集 %s 缺少 file/token，已跳过", name)
				continue
			}
			sets = append(sets, credentialSet{Name: name, File: file, Token: token})
		}
		if len(sets) == 0 {
			return nil
		}
		return &credentialSettings{sets: sets}
	}
	// 单集合兼容写法
	token := os.Getenv("ADMIN_CREDENTIAL_TOKEN")
	if token == "" {
		return nil
	}
	file := os.Getenv("ADMIN_CREDENTIAL_FILE")
	if file == "" {
		file = defaultCredentialFile
	}
	return &credentialSettings{sets: []credentialSet{{Name: credentialNameOTPMask, File: file, Token: token}}}
}

// find 按名称取凭据集（无 → nil）。
func (s *credentialSettings) find(name string) *credentialSet {
	for i := range s.sets {
		if s.sets[i].Name == name {
			return &s.sets[i]
		}
	}
	return nil
}

// credentialHandler 只读凭据投递 handler。
type credentialHandler struct {
	settings *credentialSettings
}

// newCredentialHandler 构造 handler；**未配置任何集合时返回 nil**（端点不注册，
// 与 main.go 的 `if csh := ...; csh != nil` 配合，避免"未配置却注册了端点"的裸奔风险）。
func newCredentialHandler(s *credentialSettings) *credentialHandler {
	if s == nil {
		return nil
	}
	return &credentialHandler{settings: s}
}

// setNames 返回已配置的集合名（日志用；**不含任何凭据/令牌值**）。
func (s *credentialSettings) setNames() string {
	names := make([]string, 0, len(s.sets))
	for i := range s.sets {
		names = append(names, s.sets[i].Name)
	}
	return strings.Join(names, ",")
}

// credentialResponse 投递响应（字段名与插件 config 对齐，便于直接反序列化）。
// 按集合字段白名单填充：otpmask-keys → sig_key/attest_token；core-channel → token。
type credentialResponse struct {
	Name        string `json:"name"`
	SigKeyHex   string `json:"sig_key,omitempty"`
	AttestToken string `json:"attest_token,omitempty"`
	Token       string `json:"token,omitempty"`
}

// handle 处理 /v1/adminext/credentials/{name}（仅 GET）。
//
// 顺序：方法 → 集合查找（未知 404，不泄露令牌归属）→ **该集合的**读令牌常量时间比较（失败 401）
// → 读取并校验文件（缺失/损坏/权限过宽 503，fail-closed）→ 按白名单投递。
func (h *credentialHandler) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	name := strings.TrimPrefix(r.URL.Path, credentialAPIBase+"/")
	set := h.settings.find(name)
	if set == nil {
		writeError(w, http.StatusNotFound, "未支持的凭据集: "+name)
		return
	}
	// 常量时间比较：避免令牌逐字节比较的时序侧信道（每集合独立令牌＝最小权限）
	got := r.Header.Get("X-Credential-Token")
	if subtle.ConstantTimeCompare([]byte(got), []byte(set.Token)) != 1 {
		// 不记录令牌内容，仅记录来源、集合与结果
		log.Printf("[credential] 令牌校验失败 name=%s remote=%s", name, r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "令牌无效")
		return
	}

	resp, err := loadCredentialFile(set.Name, set.File)
	if err != nil {
		// fail-closed：文件缺失/损坏一律 503，不回退、不返回空值（否则插件侧会拿到空密钥）。
		log.Printf("[credential] 读取失败（fail-closed）name=%s: %v", name, err)
		writeError(w, http.StatusServiceUnavailable, "凭据不可用")
		return
	}
	log.Printf("[credential] 投递 ok name=%s fields=%d", name, whitelistLen(set.Name))
	writeJSON(w, http.StatusOK, resp)
}

// whitelistLen 白名单字段数（仅用于日志，不含凭据值）。
func whitelistLen(name string) int { return len(fieldWhitelist[name]) }

// loadCredentialFile 读取并校验凭据文件（KEY=VALUE 行；**仅取白名单字段**，其余一律丢弃）。
// 校验：文件 0600（Windows 跳过并如实说明）；otpmask-keys 的 sig_key 须 64 位 hex 且 attest_token 非短；
// core-channel 的 token 须 ≥ minChannelTokenLen。
func loadCredentialFile(name, path string) (*credentialResponse, error) {
	if _, ok := fieldWhitelist[name]; !ok {
		return nil, errors.New("未知凭据集")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("凭据文件不可读: %w", err)
	}
	// 权限收紧校验：禁止 **world 位**（他人读/写/执行）与**组可写**。
	//
	// 为什么不是"恰为 0600"（2026-09-13 本地集群实测纠正）：K8s Secret 卷在 pod 配置了 `fsGroup`
	// 时——非 root 容器读取 Secret 文件的必要前提——kubelet 会把挂载文件权限改写为 **0640**
	// （owner rw + 组只读），恒不满足"恰为 0600"⇒ 凭据端点恒 503、插件永远取不到通道令牌。
	// 故口径改为安全等价的最小可行集：不得被他人访问、不得组可写；0600/0640/0440 均接受。
	// （Windows 无 Unix 权限位语义，跳过并如实说明。）
	if runtime.GOOS != "windows" {
		perm := info.Mode().Perm()
		if perm&0o007 != 0 || perm&0o020 != 0 {
			return nil, fmt.Errorf("凭据文件权限过宽（%o：禁止 world 位与组写；应为 0600，或 K8s Secret+fsGroup 下的 0640）", perm)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("凭据文件读取失败: %w", err)
	}

	allowed := map[string]bool{}
	for _, f := range fieldWhitelist[name] {
		allowed[f] = true
	}
	vals := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if k = strings.TrimSpace(k); allowed[k] {
			vals[k] = strings.TrimSpace(v)
		}
	}

	resp := &credentialResponse{Name: name}
	switch name {
	case credentialNameOTPMask:
		if err := validateSigKeyHex(vals["sig_key"]); err != nil {
			return nil, err
		}
		if len(vals["attest_token"]) < minProviderKeyLen {
			return nil, errors.New("凭据文件缺少 attest_token（或过短）")
		}
		resp.SigKeyHex, resp.AttestToken = vals["sig_key"], vals["attest_token"]
	case credentialNameCoreChannel:
		if len(vals["token"]) < minChannelTokenLen {
			return nil, fmt.Errorf("凭据文件缺少 token（或短于 %d）", minChannelTokenLen)
		}
		resp.Token = vals["token"]
	default:
		return nil, errors.New("未知凭据集")
	}
	return resp, nil
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
