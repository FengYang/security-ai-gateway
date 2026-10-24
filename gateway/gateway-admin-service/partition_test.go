// partition_test.go — T-4 租户分区编排端点单测（P2-3 §6.3/§7.2/§7.3）。
//
// 覆盖（T-4 验收：幂等 + 100% 拒绝跨区 + 一成员一登录域）：
//   - 鉴权：无令牌 401、auditor POST 403、auditor GET 200
//   - 入参：缺 Idempotency-Key 400、tenant/partition 命名非法 400、空 members 400、负 quota_qps 400、未知成员 400
//   - D-11：同成员归属其它分区 → 403 group_partition_mismatch（跨分区拒绝）
//   - 配额：quota_sessions 超成员 max_sessions 之和 → 429 group_quota_exceeded
//   - 幂等：同键同体回放 202、同键异体 → 409 group_idempotency_conflict
//   - 乐观并发：expected_version 不符 → 409 group_stale_epoch
//   - 删除守卫：缺 confirm 400、缺 drain 400、有活动 KeyRef → 409 group_partition_not_empty、drain+空 → 202
//   - GET 清单：返回分区；按 tenant 过滤
//   - 审计：落 cryptop.partition.changed 事件（tenant/target/action 摘要）
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newPartitionServer 组装分区端点测试服务器（挂鉴权中间件，与 main 同构）。
func newPartitionServer(t *testing.T, h *partitionHandler) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(cryptopPartitionPath, authMiddleware(testCfg(), h.handle))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// doPartitionPost 以指定角色发起 POST（idemKey 为空则不设置 Idempotency-Key）。
func doPartitionPost(t *testing.T, srvURL, sub, role, idemKey string, body partitionRequest) (int, partitionApplyResponse) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, srvURL+cryptopPartitionPath, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testSignToken(t, testSecret, claims{
		Sub: sub, Role: role, Iss: defaultIssuer, Aud: defaultAudience,
	}))
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got partitionApplyResponse
	_ = json.NewDecoder(resp.Body).Decode(&got)
	return resp.StatusCode, got
}

// doPartitionGet 以指定角色发起 GET（tenant 可选过滤）。
func doPartitionGet(t *testing.T, srvURL, sub, role, tenant string) (int, []partitionListItem) {
	t.Helper()
	u := srvURL + cryptopPartitionPath
	if tenant != "" {
		u += "?tenant=" + tenant
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testSignToken(t, testSecret, claims{
		Sub: sub, Role: role, Iss: defaultIssuer, Aud: defaultAudience,
	}))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got struct {
		Partitions []partitionListItem `json:"partitions"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&got)
	return resp.StatusCode, got.Partitions
}

// basePartitionReq 合法基础请求（调用方按用例覆写）。
func basePartitionReq() partitionRequest {
	return partitionRequest{
		Tenant:        "tenant-a",
		Partition:     "tenant-a",
		Members:       []string{"dc1-hsm-a", "dc2-hsm-a"},
		QuotaSessions: 24,
		QuotaQPS:      0,
		Action:        "update",
		Confirm:       true,
	}
}

// 默认成员注册表：两成员各属 tenant-a，max_sessions=16。
func defaultMembers() map[string]MemberInfo {
	return map[string]MemberInfo{
		"dc1-hsm-a": {Partition: "tenant-a", MaxSessions: 16},
		"dc2-hsm-a": {Partition: "tenant-a", MaxSessions: 16},
	}
}

func TestPartitionAuth(t *testing.T) {
	h := newPartitionHandler(newAuditTestChain(t, false), newPartitionStore(), newMemMemberRegistry(defaultMembers()), newMemKeyRefStore(nil), &memDesiredPublisher{})
	srv := newPartitionServer(t, h)

	t.Run("无令牌 → 401", func(t *testing.T) {
		raw, _ := json.Marshal(basePartitionReq())
		req, _ := http.NewRequest(http.MethodPost, srv.URL+cryptopPartitionPath, bytes.NewReader(raw))
		req.Header.Set("Idempotency-Key", "k1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("期望 401，实际 %d", resp.StatusCode)
		}
	})

	t.Run("auditor POST → 403", func(t *testing.T) {
		code, _ := doPartitionPostAs(t, srv.URL, "bob", roleAuditor, "k2", basePartitionReq())
		if code != http.StatusForbidden {
			t.Fatalf("期望 403，实际 %d", code)
		}
	})

	t.Run("auditor GET → 200", func(t *testing.T) {
		code, _ := doPartitionGet(t, srv.URL, "bob", roleAuditor, "")
		if code != http.StatusOK {
			t.Fatalf("期望 200，实际 %d", code)
		}
	})
}

// doPartitionPostAs 以指定 sub/role 发起 POST（post 写用）。
func doPartitionPostAs(t *testing.T, srvURL, sub, role, idemKey string, body partitionRequest) (int, partitionApplyResponse) {
	return doPartitionPost(t, srvURL, sub, role, idemKey, body)
}

func TestPartitionValidation(t *testing.T) {
	h := newPartitionHandler(newAuditTestChain(t, false), newPartitionStore(), newMemMemberRegistry(defaultMembers()), newMemKeyRefStore(nil), &memDesiredPublisher{})
	srv := newPartitionServer(t, h)

	cases := []struct {
		name     string
		mutate   func(*partitionRequest)
		wantCode int
		wantErr  string
		noKey    bool
	}{
		{"缺 Idempotency-Key", func(r *partitionRequest) {}, http.StatusBadRequest, "bad_request", true},
		{"tenant 命名非法", func(r *partitionRequest) { r.Tenant = "tenant/a" }, http.StatusBadRequest, "group_config_invalid", false},
		{"partition 命名非法", func(r *partitionRequest) { r.Partition = "-x" }, http.StatusBadRequest, "group_config_invalid", false},
		{"空 members", func(r *partitionRequest) { r.Members = nil }, http.StatusBadRequest, "group_config_invalid", false},
		{"负 quota_qps", func(r *partitionRequest) { r.QuotaQPS = -1 }, http.StatusBadRequest, "group_config_invalid", false},
		{"未知成员", func(r *partitionRequest) { r.Members = []string{"ghost"} }, http.StatusBadRequest, "group_config_invalid", false},
		{"action 非法", func(r *partitionRequest) { r.Action = "purge" }, http.StatusBadRequest, "bad_request", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := basePartitionReq()
			c.mutate(&req)
			key := "idem-" + c.name
			if c.noKey {
				key = ""
			}
			code, got := doPartitionPost(t, srv.URL, testAdminUser, roleAdmin, key, req)
			if code != c.wantCode {
				t.Fatalf("期望 %d，实际 %d（%+v）", c.wantCode, code, got)
			}
		})
	}
}

func TestPartitionD11OneMemberOnePartition(t *testing.T) {
	// 成员 dc1-hsm-a 已归属 tenant-a；尝试在 tenant-b 分区复用 → 403 group_partition_mismatch。
	members := map[string]MemberInfo{
		"dc1-hsm-a": {Partition: "tenant-a", MaxSessions: 16}, // 已归属
		"dc2-hsm-a": {Partition: "tenant-a", MaxSessions: 16},
		"dcX-hsm-b": {Partition: "tenant-b", MaxSessions: 16},
	}
	h := newPartitionHandler(newAuditTestChain(t, false), newPartitionStore(), newMemMemberRegistry(members), newMemKeyRefStore(nil), &memDesiredPublisher{})
	srv := newPartitionServer(t, h)

	// 先开 tenant-a（合法）。
	code, got := doPartitionPost(t, srv.URL, testAdminUser, roleAdmin, "open-a", basePartitionReq())
	if code != http.StatusAccepted {
		t.Fatalf("开通 tenant-a 期望 202，实际 %d %+v", code, got)
	}

	// 跨分区复用 dc1-hsm-a（属 tenant-a）→ 403。
	req := basePartitionReq()
	req.Tenant = "tenant-b"
	req.Partition = "tenant-b"
	req.Members = []string{"dc1-hsm-a", "dcX-hsm-b"}
	code, got = doPartitionPost(t, srv.URL, testAdminUser, roleAdmin, "cross", req)
	if code != http.StatusForbidden {
		t.Fatalf("跨分区复用成员期望 403，实际 %d %+v", code, got)
	}
}

func TestPartitionQuotaExceeded(t *testing.T) {
	// 两成员 max_sessions 各 16，合计 32；quota_sessions=40 → 429。
	h := newPartitionHandler(newAuditTestChain(t, false), newPartitionStore(), newMemMemberRegistry(defaultMembers()), newMemKeyRefStore(nil), &memDesiredPublisher{})
	srv := newPartitionServer(t, h)

	req := basePartitionReq()
	req.QuotaSessions = 40
	code, got := doPartitionPost(t, srv.URL, testAdminUser, roleAdmin, "quota", req)
	if code != http.StatusTooManyRequests {
		t.Fatalf("超配额期望 429，实际 %d %+v", code, got)
	}

	// quota_sessions=32 恰好等于合计 → 通过。
	req.QuotaSessions = 32
	code, got = doPartitionPost(t, srv.URL, testAdminUser, roleAdmin, "quota-ok", req)
	if code != http.StatusAccepted {
		t.Fatalf("配额边界 32 期望 202，实际 %d %+v", code, got)
	}
}

func TestPartitionIdempotency(t *testing.T) {
	h := newPartitionHandler(newAuditTestChain(t, false), newPartitionStore(), newMemMemberRegistry(defaultMembers()), newMemKeyRefStore(nil), &memDesiredPublisher{})
	srv := newPartitionServer(t, h)

	req := basePartitionReq()
	code1, got1 := doPartitionPost(t, srv.URL, testAdminUser, roleAdmin, "same-key", req)
	if code1 != http.StatusAccepted {
		t.Fatalf("首请求期望 202，实际 %d", code1)
	}
	// 同键同体 → 回放（仍 202，operation_id 一致）。
	code2, got2 := doPartitionPost(t, srv.URL, testAdminUser, roleAdmin, "same-key", req)
	if code2 != http.StatusAccepted || got2.OperationID != got1.OperationID {
		t.Fatalf("幂等回放期望相同 operation_id，实际 %d %+v vs %+v", code2, got2, got1)
	}
	// 同键异体 → 409。
	req.QuotaSessions = 10
	code3, _ := doPartitionPost(t, srv.URL, testAdminUser, roleAdmin, "same-key", req)
	if code3 != http.StatusConflict {
		t.Fatalf("同键异体期望 409，实际 %d", code3)
	}
}

func TestPartitionStaleEpoch(t *testing.T) {
	h := newPartitionHandler(newAuditTestChain(t, false), newPartitionStore(), newMemMemberRegistry(defaultMembers()), newMemKeyRefStore(nil), &memDesiredPublisher{})
	srv := newPartitionServer(t, h)

	// 开通得到版本 1。
	code, got := doPartitionPost(t, srv.URL, testAdminUser, roleAdmin, "open", basePartitionReq())
	if code != http.StatusAccepted || got.DesiredVersion != 1 {
		t.Fatalf("开通期望 202/版本1，实际 %d %+v", code, got)
	}
	// 带错误 expected_version（99）更新 → 409。
	req := basePartitionReq()
	req.ExpectedVersion = 99
	code, _ = doPartitionPost(t, srv.URL, testAdminUser, roleAdmin, "upd-bad", req)
	if code != http.StatusConflict {
		t.Fatalf("陈旧版本期望 409，实际 %d", code)
	}
	// 带正确 expected_version（1）更新 → 202。
	req.ExpectedVersion = 1
	code, got = doPartitionPost(t, srv.URL, testAdminUser, roleAdmin, "upd-ok", req)
	if code != http.StatusAccepted || got.DesiredVersion != 2 {
		t.Fatalf("正确版本更新期望 202/版本2，实际 %d %+v", code, got)
	}
}

func TestPartitionDeleteGuard(t *testing.T) {
	// 成员注册表 + 活动 KeyRef 计数 > 0 → 删除拦截。
	members := defaultMembers()
	keyRefs := newMemKeyRefStore(map[string]int{"tenant-a": 3})
	h := newPartitionHandler(newAuditTestChain(t, false), newPartitionStore(), newMemMemberRegistry(members), keyRefs, &memDesiredPublisher{})
	srv := newPartitionServer(t, h)

	if code, _ := doPartitionPost(t, srv.URL, testAdminUser, roleAdmin, "open", basePartitionReq()); code != http.StatusAccepted {
		t.Fatalf("开通期望 202，实际 %d", code)
	}

	del := partitionRequest{Tenant: "tenant-a", Partition: "tenant-a", Action: "delete", Confirm: true, Drain: true}

	// 有活动 KeyRef → 409 group_partition_not_empty。
	code, _ := doPartitionPost(t, srv.URL, testAdminUser, roleAdmin, "del", del)
	if code != http.StatusConflict {
		t.Fatalf("有活动 KeyRef 删除期望 409，实际 %d", code)
	}

	// 清空 KeyRef 后仍须 drain（已带）→ 202。
	keyRefs.mu.Lock()
	keyRefs.counts["tenant-a"] = 0
	keyRefs.mu.Unlock()
	code, got := doPartitionPost(t, srv.URL, testAdminUser, roleAdmin, "del2", del)
	if code != http.StatusAccepted {
		t.Fatalf("drain+空 KeyRef 删除期望 202，实际 %d %+v", code, got)
	}

	// 已删除再删 → 幂等 202（不存在视为成功）。
	code, _ = doPartitionPost(t, srv.URL, testAdminUser, roleAdmin, "del3", del)
	if code != http.StatusAccepted {
		t.Fatalf("重复删除期望 202，实际 %d", code)
	}
}

func TestPartitionDeleteRequiresConfirmAndDrain(t *testing.T) {
	h := newPartitionHandler(newAuditTestChain(t, false), newPartitionStore(), newMemMemberRegistry(defaultMembers()), newMemKeyRefStore(nil), &memDesiredPublisher{})
	srv := newPartitionServer(t, h)
	if code, _ := doPartitionPost(t, srv.URL, testAdminUser, roleAdmin, "open", basePartitionReq()); code != http.StatusAccepted {
		t.Fatalf("开通期望 202，实际 %d", code)
	}
	del := partitionRequest{Tenant: "tenant-a", Partition: "tenant-a", Action: "delete"}

	t.Run("缺 confirm → 400", func(t *testing.T) {
		code, _ := doPartitionPost(t, srv.URL, testAdminUser, roleAdmin, "d-noconf", del)
		if code != http.StatusBadRequest {
			t.Fatalf("期望 400，实际 %d", code)
		}
	})
	t.Run("缺 drain → 400", func(t *testing.T) {
		del.Confirm = true
		code, _ := doPartitionPost(t, srv.URL, testAdminUser, roleAdmin, "d-nodrain", del)
		if code != http.StatusBadRequest {
			t.Fatalf("期望 400，实际 %d", code)
		}
	})
}

func TestPartitionGetList(t *testing.T) {
	h := newPartitionHandler(newAuditTestChain(t, false), newPartitionStore(), newMemMemberRegistry(defaultMembers()), newMemKeyRefStore(nil), &memDesiredPublisher{})
	srv := newPartitionServer(t, h)

	if code, _ := doPartitionPost(t, srv.URL, testAdminUser, roleAdmin, "open", basePartitionReq()); code != http.StatusAccepted {
		t.Fatalf("开通期望 202，实际 %d", code)
	}
	// 第二个租户（独立成员 dc3-hsm-b，避免 D-11；单成员 max_sessions=16 故配额取 16）。
	req2 := basePartitionReq()
	req2.Tenant = "tenant-b"
	req2.Partition = "tenant-b"
	req2.Members = []string{"dc3-hsm-b"}
	req2.QuotaSessions = 16
	members2 := map[string]MemberInfo{"dc3-hsm-b": {Partition: "tenant-b", MaxSessions: 16}}
	h2 := newPartitionHandler(newAuditTestChain(t, false), newPartitionStore(), newMemMemberRegistry(members2), newMemKeyRefStore(nil), &memDesiredPublisher{})
	srv2 := newPartitionServer(t, h2)
	req2.Members = []string{"dc3-hsm-b"}
	if code, _ := doPartitionPost(t, srv2.URL, testAdminUser, roleAdmin, "open2", req2); code != http.StatusAccepted {
		t.Fatalf("开通 tenant-b 期望 202，实际 %d", code)
	}

	code, list := doPartitionGet(t, srv2.URL, testAdminUser, roleAdmin, "")
	if code != http.StatusOK {
		t.Fatalf("GET 期望 200，实际 %d", code)
	}
	if len(list) != 1 || list[0].Tenant != "tenant-b" {
		t.Fatalf("清单期望含 tenant-b，实际 %+v", list)
	}
	// 按不存在的 tenant 过滤 → 空。
	code, list = doPartitionGet(t, srv2.URL, testAdminUser, roleAdmin, "nope")
	if code != http.StatusOK || len(list) != 0 {
		t.Fatalf("过滤不存在 tenant 期望 200/空，实际 %d %+v", code, list)
	}
}

func TestPartitionAuditEvent(t *testing.T) {
	chain := newAuditTestChain(t, false)
	h := newPartitionHandler(chain, newPartitionStore(), newMemMemberRegistry(defaultMembers()), newMemKeyRefStore(nil), &memDesiredPublisher{})
	srv := newPartitionServer(t, h)

	if code, _ := doPartitionPost(t, srv.URL, testAdminUser, roleAdmin, "open", basePartitionReq()); code != http.StatusAccepted {
		t.Fatalf("开通期望 202，实际 %d", code)
	}
	events, _ := chain.list(100, 0)
	var found *adminAuditEvent
	for i := range events {
		if events[i].Action == auditActionCryptopPartition {
			found = &events[i]
			break
		}
	}
	if found == nil {
		t.Fatal("未找到 cryptop.partition.changed 审计事件")
	}
	if found.Tenant != "tenant-a" || found.Target != "tenant-a" || found.Result != "ok" {
		t.Fatalf("审计事件字段不符：%+v", found)
	}
}
