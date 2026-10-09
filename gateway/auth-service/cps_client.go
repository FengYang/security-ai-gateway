// cps_client.go — cryptopsvc（CPS）HMAC 客户端。
//
// 定位（§5.4.5 / §8 依赖 5）：JWT 签名密钥**不本地配置**，由 CPS 以 KeyRef 持有；
// 本服务仅发起 HMAC 求值，密钥字节永不进入本进程（C-5，插件/服务零密码）。
//
// 契约：POST {base}/v1/hmac {"key_ref":"otpmask/jwt/v1","data":"<base64 std>"} → {"mac":"<base64 std>"}
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// cpsClient cryptopsvc HMAC 客户端。
type cpsClient struct {
	baseURL string
	keyRef  string
	client  *http.Client
}

// newCPSClient 构造客户端（baseURL 带 scheme://host[:port]）。
func newCPSClient(baseURL, keyRef string, timeout time.Duration) *cpsClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &cpsClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		keyRef:  keyRef,
		client:  &http.Client{Timeout: timeout},
	}
}

// HMAC 经 CPS 以 KeyRef 指定密钥对 data 求 HMAC（intl=HMAC-SHA256；sm=HMAC-SM3，随 CPS profile）。
func (c *cpsClient) HMAC(data []byte) ([]byte, error) {
	body, err := json.Marshal(map[string]string{
		"key_ref": c.keyRef,
		"data":    base64.StdEncoding.EncodeToString(data),
	})
	if err != nil {
		return nil, fmt.Errorf("cps: marshal req: %w", err)
	}
	resp, err := c.client.Post(c.baseURL+"/v1/hmac", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("cps: hmac http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cps: hmac status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		MAC string `json:"mac"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("cps: hmac decode: %w", err)
	}
	mac, err := base64.StdEncoding.DecodeString(out.MAC)
	if err != nil {
		return nil, fmt.Errorf("cps: hmac mac 非法 base64: %w", err)
	}
	if len(mac) == 0 {
		return nil, fmt.Errorf("cps: hmac 返回空 mac")
	}
	return mac, nil
}

// Ping 探测 KeyRef 可用（启动 fail-closed，§8 依赖 5：CPS 不可达拒绝启动）。
func (c *cpsClient) Ping() error {
	if _, err := c.HMAC([]byte("otpmask-auth-service-ping")); err != nil {
		return err
	}
	return nil
}
