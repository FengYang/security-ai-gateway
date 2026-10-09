// P1-2 全链路 tracing：Collector allow-list 渲染与热更编排（方案 B3）。
//
// 事实源：Collector ConfigMap 中 `tail_sampling` 的 `values: &tenant_allowlist [...]`
// （唯一锚点；另两处为该列表的 YAML 别名 `*tenant_allowlist`，不参与替换）。
//
// 写入编排（全链 fail-closed，任一步失败即返回错误、端点 503，**不**改本地缓存）：
//
//	GET ConfigMap → 解析当前 allow-list → 增/删目标租户 → 渲染文本 → PATCH ConfigMap
//	→ （可选）PATCH otel-collector Deployment 注解触发滚动重建。
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const (
	// allowlistAnchor Collector 配置中 allow-list 的唯一定义锚点（替换点）。
	allowlistAnchor = "values: &tenant_allowlist"
	// allowlistRevAnnotation 记录本轮 allow-list 修订号（内容哈希前 12 hex），
	// 同时写 ConfigMap 与 Deployment pod-template，后者变化即触发滚动重建。
	allowlistRevAnnotation = "otpmask.io/allowlist-rev"

	defaultCollectorConfigMap  = "otel-collector-config"
	defaultCollectorConfigKey  = "otel-collector.yaml"
	defaultCollectorDeployment = "otel-collector"
)

// renderAllowlist 在 Collector 配置文本中替换 allow-list（唯一锚点）。
// 锚点缺失 → 返回 error（fail-closed：绝不静默 no-op 造成"API 成功但未生效"）。
func renderAllowlist(cfg string, tenants []string) (string, error) {
	vals, err := json.Marshal(append([]string{}, tenants...))
	if err != nil {
		return "", err
	}
	lines := strings.Split(cfg, "\n")
	for i, ln := range lines {
		pos := strings.Index(ln, allowlistAnchor)
		if pos < 0 {
			continue
		}
		indent := ln[:len(ln)-len(strings.TrimLeft(ln, " \t"))]
		lines[i] = indent + allowlistAnchor + " " + string(vals)
		return strings.Join(lines, "\n"), nil
	}
	return "", fmt.Errorf("allowlist: 未在 Collector 配置中找到锚点 %q", allowlistAnchor)
}

// parseAllowlist 解析当前 allow-list（与 renderAllowlist 同一锚点）。
func parseAllowlist(cfg string) ([]string, error) {
	for _, ln := range strings.Split(cfg, "\n") {
		pos := strings.Index(ln, allowlistAnchor)
		if pos < 0 {
			continue
		}
		rest := strings.TrimSpace(ln[pos+len(allowlistAnchor):])
		if rest == "" {
			return nil, nil
		}
		var out []string
		if err := json.Unmarshal([]byte(rest), &out); err != nil {
			return nil, fmt.Errorf("allowlist: 解析当前值失败（%q）: %w", rest, err)
		}
		return out, nil
	}
	return nil, fmt.Errorf("allowlist: 未找到锚点 %q", allowlistAnchor)
}

// allowlistRev 计算渲染后内容修订号（sha256 前 12 hex）。
func allowlistRev(rendered string) string {
	sum := sha256.Sum256([]byte(rendered))
	return hex.EncodeToString(sum[:])[:12]
}

// allowlistApplier Collector allow-list 应用器（事实源 = ConfigMap）。
type allowlistApplier struct {
	k8s        *k8sClient
	cmName     string
	cmKey      string
	deployName string
	restart    bool // 是否 PATCH Deployment 注解触发滚动（否则仅改配置，由外部 Reloader 生效）
}

// newAllowlistApplierFromEnv 按环境构建应用器；非 in-cluster → error（端点 fail-closed）。
func newAllowlistApplierFromEnv() (*allowlistApplier, error) {
	c, err := newInClusterK8sClient()
	if err != nil {
		return nil, err
	}
	cm := strings.TrimSpace(os.Getenv("ADMIN_OTEL_COLLECTOR_CONFIGMAP"))
	if cm == "" {
		cm = defaultCollectorConfigMap
	}
	key := strings.TrimSpace(os.Getenv("ADMIN_OTEL_COLLECTOR_KEY"))
	if key == "" {
		key = defaultCollectorConfigKey
	}
	dep := strings.TrimSpace(os.Getenv("ADMIN_OTEL_COLLECTOR_DEPLOYMENT"))
	if dep == "" {
		dep = defaultCollectorDeployment
	}
	return &allowlistApplier{
		k8s:        c,
		cmName:     cm,
		cmKey:      key,
		deployName: dep,
		restart:    os.Getenv("ADMIN_OTEL_COLLECTOR_RESTART") != "false",
	}, nil
}

// current 读取当前 allow-list（事实源）。
func (a *allowlistApplier) current(ctx context.Context) ([]string, error) {
	cfg, err := a.k8s.getConfigMapData(ctx, a.cmName, a.cmKey)
	if err != nil {
		return nil, err
	}
	return parseAllowlist(cfg)
}

// apply 增/删目标租户并落 ConfigMap（+ 触发滚动）。
// 返回：修订号、是否已触发滚动、应用后的完整 allow-list。
func (a *allowlistApplier) apply(ctx context.Context, tenant string, enabled bool) (rev string, restarted bool, tenants []string, err error) {
	cfg, err := a.k8s.getConfigMapData(ctx, a.cmName, a.cmKey)
	if err != nil {
		return "", false, nil, err
	}
	cur, err := parseAllowlist(cfg)
	if err != nil {
		return "", false, nil, err
	}
	next := setAllowList(cur, tenant, enabled)
	rendered, err := renderAllowlist(cfg, next)
	if err != nil {
		return "", false, nil, err
	}
	rev = allowlistRev(rendered)
	ann := map[string]string{allowlistRevAnnotation: rev}
	if err := a.k8s.patchConfigMapData(ctx, a.cmName, a.cmKey, rendered, ann); err != nil {
		return "", false, nil, err
	}
	if a.restart {
		// 变更 pod template 注解 → 滚动重建；失败即整体失败（配置已写但未生效，返回错误不掩盖）。
		if err := a.k8s.patchDeploymentPodAnnotations(ctx, a.deployName, ann); err != nil {
			return rev, false, next, fmt.Errorf("allowlist: 配置已更新但触发滚动失败（未生效）: %w", err)
		}
		restarted = true
	}
	return rev, restarted, next, nil
}
