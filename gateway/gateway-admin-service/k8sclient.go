// P1-2 全链路 tracing：Collector allow-list 热更 wiring —— in-cluster K8s REST 客户端。
//
// 设计（方案 B3，2026-10-08 定案）：
//   - 以 **Collector ConfigMap 为唯一事实源**（天然持久、跨副本一致、可审计）；
//   - admin-service 读取该 ConfigMap、替换 allow-list、PATCH 回去，并 PATCH
//     otel-collector Deployment 的 pod-template 注解触发滚动重建（Collector 无原生热重载）；
//   - 权限由 RBAC `resourceNames` 收敛到**单个** ConfigMap + **单个** Deployment。
//
// 实现取舍：**标准库直连 K8s REST**（SA token + CA），不引入 client-go
// （避免重依赖与 THIRD-PARTY-NOTICES 变更），仅需 GET/PATCH 两种操作。
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// saDir in-cluster ServiceAccount 挂载目录（token/CA/namespace）。
const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// k8sClient 极简 K8s REST 客户端（仅 ConfigMap/Deployment 的 get/patch）。
type k8sClient struct {
	baseURL string // 形如 https://10.0.0.1:443
	token   string
	ns      string // 本 Pod 所在 namespace（SA 文件）
	httpc   *http.Client
}

// newInClusterK8sClient 从 in-cluster 环境构建客户端。
// 非集群内（缺 KUBERNETES_SERVICE_HOST / SA 文件）→ 返回 error，调用方按 fail-closed 处理
// （端点返回 503，绝不"假装成功"）。
func newInClusterK8sClient() (*k8sClient, error) {
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	if host == "" {
		return nil, fmt.Errorf("k8s: 非 in-cluster 环境（KUBERNETES_SERVICE_HOST 未设置）")
	}
	if port == "" {
		port = "443"
	}
	tokB, err := os.ReadFile(saDir + "/token")
	if err != nil {
		return nil, fmt.Errorf("k8s: 读取 SA token 失败: %w", err)
	}
	nsB, err := os.ReadFile(saDir + "/namespace")
	if err != nil {
		return nil, fmt.Errorf("k8s: 读取 SA namespace 失败: %w", err)
	}
	caB, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("k8s: 读取 SA CA 失败: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caB) {
		return nil, fmt.Errorf("k8s: 解析 SA CA 失败")
	}
	return &k8sClient{
		baseURL: "https://" + host + ":" + port,
		token:   strings.TrimSpace(string(tokB)),
		ns:      strings.TrimSpace(string(nsB)),
		httpc: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			},
		},
	}, nil
}

// do 发起一次 K8s API 请求；非 2xx → 返回带状态码与响应体的错误。
func (c *k8sClient) do(ctx context.Context, method, path, contentType string, body []byte) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("k8s: 请求 %s %s 失败: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("k8s: %s %s 返回 %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}

// getConfigMapData 读取 ConfigMap 指定 key 的文本内容。
func (c *k8sClient) getConfigMapData(ctx context.Context, name, key string) (string, error) {
	path := fmt.Sprintf("/api/v1/namespaces/%s/configmaps/%s", c.ns, name)
	raw, err := c.do(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return "", err
	}
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(raw, &cm); err != nil {
		return "", fmt.Errorf("k8s: 解析 ConfigMap 失败: %w", err)
	}
	v, ok := cm.Data[key]
	if !ok {
		return "", fmt.Errorf("k8s: ConfigMap %s 缺少键 %q", name, key)
	}
	return v, nil
}

// patchConfigMapData 以 JSON merge patch 更新 ConfigMap 的 data[key] 与注解。
// merge patch 对嵌套对象是**递归合并**，不会覆盖其它 data 键或其它注解。
func (c *k8sClient) patchConfigMapData(ctx context.Context, name, key, val string, ann map[string]string) error {
	body := map[string]any{"data": map[string]string{key: val}}
	if len(ann) > 0 {
		body["metadata"] = map[string]any{"annotations": ann}
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/api/v1/namespaces/%s/configmaps/%s", c.ns, name)
	_, err = c.do(ctx, http.MethodPatch, path, "application/merge-patch+json", b)
	return err
}

// patchDeploymentPodAnnotations 以 JSON merge patch 更新 Deployment pod-template 注解。
// 变更 pod template → 触发滚动重建（等价 kubectl rollout restart）。
func (c *k8sClient) patchDeploymentPodAnnotations(ctx context.Context, name string, ann map[string]string) error {
	body := map[string]any{
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{"annotations": ann},
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/apis/apps/v1/namespaces/%s/deployments/%s", c.ns, name)
	_, err = c.do(ctx, http.MethodPatch, path, "application/merge-patch+json", b)
	return err
}
