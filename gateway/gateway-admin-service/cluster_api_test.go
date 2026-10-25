package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// P2-4 T-2.2 / T-2.4 / T-2.5 集群注册 API 与双签受理的端到端单测。

// clusterTestEnv 测试环境（注册表 + 审批登记 + 路由）。
type clusterTestEnv struct {
	mux   *http.ServeMux
	cfg   *config
	store *sqlClusterStore
	chain *adminAuditChain
}

func newClusterTestEnv(t *testing.T) *clusterTestEnv {
	t.Helper()
	cfg := testCfg()
	chain := newAuditTestChain(t, false)
	store := openTestClusterStore(t)
	api := newClusterAPI(store, newClusterApprovalRegistry(chain))
	mux := http.NewServeMux()
	registerClusterRoutes(mux, cfg, api)
	return &clusterTestEnv{mux: mux, cfg: cfg, store: store, chain: chain}
}

// adminToken 生成管理面 admin 会话令牌。
func (e *clusterTestEnv) adminToken(t *testing.T, sub string) string {
	t.Helper()
	return testSignToken(t, e.cfg.jwtSecret, claims{
		Sub: sub, Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience,
	})
}

// do 发起一次请求。
func (e *clusterTestEnv) do(t *testing.T, method, path, token, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, r)
	return rec
}

// registerCluster 注册集群并返回响应体中的凭证明文。
func (e *clusterTestEnv) registerCluster(t *testing.T, token, id string) clusterRegisterResponse {
	t.Helper()
	body := `{"id":"` + id + `","name":"集群 ` + id + `","endpoint":"https://` + id + `.example.com","form":"同城","capacity":{"rps":100,"concurrency":200}}`
	rec := e.do(t, http.MethodPost, "/v1/adminext/clusters", token, body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("注册集群失败：code=%d body=%s", rec.Code, rec.Body.String())
	}
	var out clusterRegisterResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析注册响应失败: %v", err)
	}
	return out
}

// approve 产生一条审批事件，返回审批 ID。
func (e *clusterTestEnv) approve(t *testing.T, token, id string) string {
	t.Helper()
	rec := e.do(t, http.MethodPost, "/v1/adminext/clusters/"+id+"/approval", token, "", nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("审批失败：code=%d body=%s", rec.Code, rec.Body.String())
	}
	var out clusterApprovalResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析审批响应失败: %v", err)
	}
	if out.ApprovalID == "" {
		t.Fatal("审批 ID 为空")
	}
	return out.ApprovalID
}

// 完整链路：注册 → 列表 → 心跳（带凭证）→ 双签摘除 → 凭证吊销。
func TestClusterAPI_EndToEnd(t *testing.T) {
	env := newClusterTestEnv(t)
	tok := env.adminToken(t, "admin1")

	reg := env.registerCluster(t, tok, "cluster-a")
	if reg.Credential == "" {
		t.Fatal("注册未返回集群身份凭证")
	}
	if reg.Cluster.Status != ClusterStatusActive {
		t.Errorf("注册后状态 = %q, want active", reg.Cluster.Status)
	}

	// 列表
	rec := env.do(t, http.MethodGet, "/v1/adminext/clusters", tok, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("列表失败：code=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "cluster-a") {
		t.Errorf("列表未含已注册集群：%s", rec.Body.String())
	}

	// 心跳（无凭证 → 403）
	rec = env.do(t, http.MethodPost, "/v1/adminext/clusters/cluster-a/heartbeat", "", `{"applied_config_version":"v1"}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("无凭证心跳应 403，实际 code=%d body=%s", rec.Code, rec.Body.String())
	}

	// 心跳（带凭证 → 200，且记录配置版本）
	rec = env.do(t, http.MethodPost, "/v1/adminext/clusters/cluster-a/heartbeat", "",
		`{"applied_config_version":"v1"}`, map[string]string{clusterCredentialHeader: reg.Credential})
	if rec.Code != http.StatusOK {
		t.Fatalf("心跳失败：code=%d body=%s", rec.Code, rec.Body.String())
	}
	stored, err := env.store.Get(t.Context(), "cluster-a")
	if err != nil {
		t.Fatalf("读取集群失败: %v", err)
	}
	if stored.Applied != "v1" {
		t.Errorf("应用配置版本 = %q, want v1", stored.Applied)
	}

	// 双签：两名不同授权人各审批一次
	idA := env.approve(t, env.adminToken(t, "admin1"), "cluster-a")
	idB := env.approve(t, env.adminToken(t, "admin2"), "cluster-a")

	// 摘除（缺双签 → 403）
	rec = env.do(t, http.MethodDelete, "/v1/adminext/clusters/cluster-a", tok, `{"tenant_disposition":"none"}`,
		map[string]string{clusterCredentialHeader: reg.Credential})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("缺双签摘除应 403，实际 code=%d body=%s", rec.Code, rec.Body.String())
	}

	// 摘除（双签齐全 → 204）
	removeBody := `{"dual_approval_ids":["` + idA + `","` + idB + `"],"tenant_disposition":"none"}`
	rec = env.do(t, http.MethodDelete, "/v1/adminext/clusters/cluster-a", tok, removeBody,
		map[string]string{clusterCredentialHeader: reg.Credential})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("摘除失败：code=%d body=%s", rec.Code, rec.Body.String())
	}
	stored, _ = env.store.Get(t.Context(), "cluster-a")
	if stored.Status != ClusterStatusRemoved {
		t.Errorf("摘除后状态 = %q, want removed", stored.Status)
	}

	// 凭证已吊销（心跳被拒）
	rec = env.do(t, http.MethodPost, "/v1/adminext/clusters/cluster-a/heartbeat", "",
		`{"applied_config_version":"v2"}`, map[string]string{clusterCredentialHeader: reg.Credential})
	if rec.Code != http.StatusForbidden {
		t.Errorf("摘除后凭证应失效，实际 code=%d", rec.Code)
	}
}

// 双签负向用例：同人自批、目标错绑、复用、过期。
func TestClusterAPI_DualApprovalNegative(t *testing.T) {
	t.Run("同一人自批双签无效", func(t *testing.T) {
		env := newClusterTestEnv(t)
		tok := env.adminToken(t, "admin1")
		reg := env.registerCluster(t, tok, "c1")
		idA := env.approve(t, tok, "c1")
		idB := env.approve(t, tok, "c1")
		body := `{"dual_approval_ids":["` + idA + `","` + idB + `"],"tenant_disposition":"none"}`
		rec := env.do(t, http.MethodDelete, "/v1/adminext/clusters/c1", tok, body,
			map[string]string{clusterCredentialHeader: reg.Credential})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("同人自批应 403，实际 code=%d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("审批目标错绑被拒", func(t *testing.T) {
		env := newClusterTestEnv(t)
		tok := env.adminToken(t, "admin1")
		reg := env.registerCluster(t, tok, "c1")
		env.registerCluster(t, tok, "c2")
		idA := env.approve(t, tok, "c1")
		idB := env.approve(t, env.adminToken(t, "admin2"), "c2")
		body := `{"dual_approval_ids":["` + idA + `","` + idB + `"],"tenant_disposition":"none"}`
		rec := env.do(t, http.MethodDelete, "/v1/adminext/clusters/c1", tok, body,
			map[string]string{clusterCredentialHeader: reg.Credential})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("目标错绑应 403，实际 code=%d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("审批一次性消费（复用被拒）", func(t *testing.T) {
		env := newClusterTestEnv(t)
		tok := env.adminToken(t, "admin1")
		reg := env.registerCluster(t, tok, "c1")
		idA := env.approve(t, tok, "c1")
		idB := env.approve(t, env.adminToken(t, "admin2"), "c1")
		body := `{"dual_approval_ids":["` + idA + `","` + idB + `"],"tenant_disposition":"none"}`
		rec := env.do(t, http.MethodDelete, "/v1/adminext/clusters/c1", tok, body,
			map[string]string{clusterCredentialHeader: reg.Credential})
		if rec.Code != http.StatusNoContent {
			t.Fatalf("首次摘除应成功：code=%d body=%s", rec.Code, rec.Body.String())
		}
		reg2 := env.registerCluster(t, tok, "c2")
		rec = env.do(t, http.MethodDelete, "/v1/adminext/clusters/c2", tok, body,
			map[string]string{clusterCredentialHeader: reg2.Credential})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("复用审批应 403，实际 code=%d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("审批超过 15min 失效", func(t *testing.T) {
		env := newClusterTestEnv(t)
		reg := newClusterApprovalRegistry(env.chain)
		idA, err := reg.RegisterApproval("admin1", "c1")
		if err != nil {
			t.Fatalf("审批失败: %v", err)
		}
		idB, err := reg.RegisterApproval("admin2", "c1")
		if err != nil {
			t.Fatalf("审批失败: %v", err)
		}
		ids := [2]string{idA, idB}
		if err := reg.ValidateDualApproval("admin3", "c1", ids, time.Now()); err != nil {
			t.Fatalf("新审批应有效: %v", err)
		}
		if err := reg.ValidateDualApproval("admin3", "c1", ids, time.Now().Add(clusterApprovalTTL+time.Minute)); err == nil {
			t.Fatal("超过有效期应拒绝")
		}
	})
}

// 摘除前置条件：必须声明租户处置；unreachable 走强制路径（需不可达声明 + 离线处置确认）。
func TestClusterAPI_RemovePreconditions(t *testing.T) {
	t.Run("缺租户处置声明被拒", func(t *testing.T) {
		env := newClusterTestEnv(t)
		tok := env.adminToken(t, "admin1")
		reg := env.registerCluster(t, tok, "c1")
		idA := env.approve(t, tok, "c1")
		idB := env.approve(t, env.adminToken(t, "admin2"), "c1")
		body := `{"dual_approval_ids":["` + idA + `","` + idB + `"]}`
		rec := env.do(t, http.MethodDelete, "/v1/adminext/clusters/c1", tok, body,
			map[string]string{clusterCredentialHeader: reg.Credential})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("缺 tenant_disposition 应 400，实际 code=%d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("unreachable 强制摘除需不可达声明与离线处置确认", func(t *testing.T) {
		env := newClusterTestEnv(t)
		tok := env.adminToken(t, "admin1")
		env.registerCluster(t, tok, "c1")
		if err := env.store.SetStatus(t.Context(), "c1", ClusterStatusUnreachable, time.Now()); err != nil {
			t.Fatalf("设置状态失败: %v", err)
		}
		idA := env.approve(t, tok, "c1")
		idB := env.approve(t, env.adminToken(t, "admin2"), "c1")
		body := `{"dual_approval_ids":["` + idA + `","` + idB + `"]}`
		rec := env.do(t, http.MethodDelete, "/v1/adminext/clusters/c1", tok, body, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("强制摘除缺声明应 400，实际 code=%d body=%s", rec.Code, rec.Body.String())
		}
		body = `{"dual_approval_ids":["` + idA + `","` + idB + `"],"unreachable_declaration":"集群不可达声明","tenant_offline_disposition":"租户离线处置确认"}`
		rec = env.do(t, http.MethodDelete, "/v1/adminext/clusters/c1", tok, body, nil)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("强制摘除应 204，实际 code=%d body=%s", rec.Code, rec.Body.String())
		}
		stored, _ := env.store.Get(t.Context(), "c1")
		if stored.Status != ClusterStatusQuarantined {
			t.Errorf("强制摘除终态 = %q, want quarantined", stored.Status)
		}
	})
}

// 审计先行：变更事件已落链（含双签引用），且链完整性未被破坏。
func TestClusterAPI_AuditChainEvidence(t *testing.T) {
	env := newClusterTestEnv(t)
	tok := env.adminToken(t, "admin1")
	reg := env.registerCluster(t, tok, "c1")
	idA := env.approve(t, tok, "c1")
	idB := env.approve(t, env.adminToken(t, "admin2"), "c1")
	body := `{"dual_approval_ids":["` + idA + `","` + idB + `"],"tenant_disposition":"none"}`
	rec := env.do(t, http.MethodDelete, "/v1/adminext/clusters/c1", tok, body,
		map[string]string{clusterCredentialHeader: reg.Credential})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("摘除失败：code=%d body=%s", rec.Code, rec.Body.String())
	}
	events, total := env.chain.list(100, 0)
	if total < 4 {
		t.Fatalf("链事件数 = %d, want ≥4（2 审批 + 注册 + 摘除）", total)
	}
	var sawApproval, sawChange bool
	for _, ev := range events {
		switch ev.Action {
		case auditActionClusterRegistryApproval:
			sawApproval = true
		case auditActionClusterRegistryChanged:
			sawChange = true
			if ev.Target != "c1" {
				t.Errorf("变更事件 target = %q, want c1", ev.Target)
			}
		}
	}
	if !sawApproval || !sawChange {
		t.Errorf("链上缺少审批/变更事件：approval=%v change=%v", sawApproval, sawChange)
	}
	if ok, broken := env.chain.verify(); !ok {
		t.Errorf("审计链校验失败（broken=%d）", broken)
	}
}
