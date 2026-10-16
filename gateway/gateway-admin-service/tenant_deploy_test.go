// C-18（M9）/N10（§4.3.10）/V-S3 部署约束验收（磁盘清单为准）：
//   - 管理面必须单副本（tenant store SQLite 多写者 + 进程内限流计数）→ replicas=1 + PDB maxUnavailable=0；
//   - 轴 A=untrusted 部署形态：机密 VM nodeSelector/toleration、TEE 加密 tenant store、镜像度量 annotation；
//   - Helm 与 k8s 清单双份 pin（Helm 侧开关注入，k8s 侧硬约束），任一漂移即失败。
//
// 路径解析先例：tenant_plugin_test.go（filepath.Join("..", "..", "deploy", ...)）。
package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// readDeployFile 读取仓库 deploy/ 下的部署文件。
func readDeployFile(t *testing.T, rel string) string {
	t.Helper()
	path := filepath.Join("..", "..", "deploy", rel)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取部署文件失败 %s: %v", path, err)
	}
	return string(b)
}

// mustMatchDeploy 断言正则命中（多行模式由 (?m) 声明）。
func mustMatchDeploy(t *testing.T, name, content, pattern string) {
	t.Helper()
	if !regexp.MustCompile(pattern).MatchString(content) {
		t.Errorf("%s 缺少约束: /%s/", name, pattern)
	}
}

// TestDeploy_K8sManifest_SingleReplicaAndHardening C-18/N10：k8s 清单硬约束。
func TestDeploy_K8sManifest_SingleReplicaAndHardening(t *testing.T) {
	content := readDeployFile(t, filepath.Join("k8s", "gateway-admin-service.yaml"))

	// C-18：Deployment 必须单副本；出现 replicas >= 2 即回归失败。
	mustMatchDeploy(t, "k8s Deployment replicas", content, `(?m)^  replicas: 1$`)
	if regexp.MustCompile(`(?m)^  replicas: ([2-9]|[1-9][0-9]+)$`).MatchString(content) {
		t.Error("C-18：管理面必须单副本（tenant store SQLite 多写者），发现 replicas >= 2")
	}

	// PDB 配套：maxUnavailable=0 → 驱逐须运维显式介入，防静默双副本。
	mustMatchDeploy(t, "k8s PDB 资源", content, `(?m)^kind: PodDisruptionBudget$`)
	mustMatchDeploy(t, "k8s PDB maxUnavailable", content, `(?m)^  maxUnavailable: 0$`)

	// N10：机密 VM 调度 + 镜像度量 annotation + 加密 tenant store 卷。
	mustMatchDeploy(t, "k8s 机密 VM nodeSelector", content, `(?m)^\s+otpmask\.io/confidential-vm: "true"$`)
	mustMatchDeploy(t, "k8s image-measurement annotation", content, `(?m)^\s+otpmask\.io/image-measurement:`)
	mustMatchDeploy(t, "k8s PVC 加密存储类", content, `(?m)^  storageClassName: tee-encrypted$`)
	mustMatchDeploy(t, "k8s PVC 名", content, `(?m)^  name: gateway-admin-tenant-store$`)
	mustMatchDeploy(t, "k8s tenant store PVC 引用", content, `(?m)^          claimName: gateway-admin-tenant-store$`)
	mustMatchDeploy(t, "k8s TENANT_STORE_PATH", content, `(?m)^          value: "/var/lib/otpmask-tenant/tenants\.db"$`)
	mustMatchDeploy(t, "k8s tenant store 挂载点", content, `(?m)^          mountPath: /var/lib/otpmask-tenant$`)
}

// TestDeploy_HelmValues_PortalHardeningDefaults Helm values：单副本/PDB/n10 默认值。
func TestDeploy_HelmValues_PortalHardeningDefaults(t *testing.T) {
	content := readDeployFile(t, filepath.Join("helm", "gateway-admin-service", "values.yaml"))

	mustMatchDeploy(t, "helm replicaCount", content, `(?m)^replicaCount: 1$`)
	mustMatchDeploy(t, "helm PDB 块", content, `(?m)^podDisruptionBudget:\n  enabled: true\n  maxUnavailable: 0$`)
	// n10 默认关闭（轴 A=trusted 不强制机密 VM；轴 A=untrusted 部署须显式启用）。
	mustMatchDeploy(t, "helm n10 开关", content, `(?m)^n10:\n  enabled: false$`)
	mustMatchDeploy(t, "helm n10 机密 VM 标签", content, `(?m)^\s+otpmask\.io/confidential-vm: "true"$`)
	mustMatchDeploy(t, "helm n10 加密存储类", content, `(?m)^    storageClassName: tee-encrypted$`)
	mustMatchDeploy(t, "helm n10 tenantStore 开关", content, `(?m)^  tenantStore:\n    enabled: false$`)
	mustMatchDeploy(t, "helm n10 镜像度量键", content, `(?m)^  imageMeasurement: ""$`)
}

// TestDeploy_HelmTemplates_GuardsPresent Helm 模板：开关注入与 fail-closed required。
func TestDeploy_HelmTemplates_GuardsPresent(t *testing.T) {
	pdb := readDeployFile(t, filepath.Join("helm", "gateway-admin-service", "templates", "pdb.yaml"))
	mustMatchDeploy(t, "pdb.yaml 开关", pdb, `(?m)^\{\{- if \.Values\.podDisruptionBudget\.enabled \}\}$`)
	mustMatchDeploy(t, "pdb.yaml maxUnavailable", pdb, `(?m)^  maxUnavailable: \{\{ \.Values\.podDisruptionBudget\.maxUnavailable \}\}$`)

	pvc := readDeployFile(t, filepath.Join("helm", "gateway-admin-service", "templates", "pvc.yaml"))
	mustMatchDeploy(t, "pvc.yaml 开关", pvc, `(?m)^\{\{- if \.Values\.n10\.tenantStore\.enabled \}\}$`)
	mustMatchDeploy(t, "pvc.yaml storageClassName", pvc, `storageClassName: \{\{ \.Values\.n10\.tenantStore\.storageClassName \| quote \}\}`)

	dep := readDeployFile(t, filepath.Join("helm", "gateway-admin-service", "templates", "deployment.yaml"))
	mustMatchDeploy(t, "deployment.yaml n10 nodeSelector 合并", dep, `merge \(dict\) \.Values\.n10\.nodeSelector`)
	mustMatchDeploy(t, "deployment.yaml image-measurement", dep, `otpmask\.io/image-measurement: \{\{ \.Values\.n10\.imageMeasurement`)
	// 门户启用 fail-closed：Secret（token-pepper）与 auth-service 地址必填。
	mustMatchDeploy(t, "deployment.yaml tokenPepper required", dep, `required "n10\.tenantStore\.existingSecret`)
	mustMatchDeploy(t, "deployment.yaml authServiceURL required", dep, `required "n10\.tenantStore\.authServiceURL`)
}
