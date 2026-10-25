package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

// T-2.3 集群身份凭证（签发/校验/轮换/吊销）的单测。

func TestClusterCredential_IssueAndVerify(t *testing.T) {
	ctx := context.Background()
	st := openTestClusterStore(t)
	creds := st.Credentials()
	now := time.Now()

	token, rec, err := creds.Issue(ctx, "cluster-a", time.Hour, now)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	if token == "" || rec == nil {
		t.Fatalf("签发结果异常：token=%q rec=%+v", token, rec)
	}
	if rec.Status != CredentialActive {
		t.Errorf("凭证状态 = %q, want active", rec.Status)
	}
	if rec.ClusterID != "cluster-a" {
		t.Errorf("绑定集群 = %q, want cluster-a", rec.ClusterID)
	}
	if !rec.ExpiresAt.After(now) {
		t.Errorf("过期时间异常：%v", rec.ExpiresAt)
	}
	// 正确令牌可通过
	got, err := creds.Verify(ctx, "cluster-a", token, now)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	if got.ID != rec.ID {
		t.Errorf("校验返回的凭证 ID 不一致：%q vs %q", got.ID, rec.ID)
	}
}

// 令牌不得跨集群使用（哈希绑定 clusterID）。
func TestClusterCredential_TokenBoundToCluster(t *testing.T) {
	ctx := context.Background()
	st := openTestClusterStore(t)
	creds := st.Credentials()
	now := time.Now()

	token, _, err := creds.Issue(ctx, "cluster-a", time.Hour, now)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	if _, err := creds.Verify(ctx, "cluster-b", token, now); err == nil {
		t.Fatal("A 集群令牌在 B 集群处应校验失败")
	}
}

// 错误令牌 / 空令牌 / 未知集群一律拒绝（fail-closed）。
func TestClusterCredential_VerifyNegative(t *testing.T) {
	ctx := context.Background()
	st := openTestClusterStore(t)
	creds := st.Credentials()
	now := time.Now()

	token, _, err := creds.Issue(ctx, "cluster-a", time.Hour, now)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	cases := []struct {
		name      string
		clusterID string
		token     string
	}{
		{"令牌错误", "cluster-a", "wrong-token"},
		{"令牌为空", "cluster-a", ""},
		{"集群为空", "", token},
		{"集群未注册凭证", "cluster-zzz", token},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := creds.Verify(ctx, tc.clusterID, tc.token, now); err == nil {
				t.Fatal("期望校验失败")
			}
		})
	}
}

// 过期凭证失效。
func TestClusterCredential_Expired(t *testing.T) {
	ctx := context.Background()
	st := openTestClusterStore(t)
	creds := st.Credentials()
	now := time.Now()

	token, rec, err := creds.Issue(ctx, "cluster-a", time.Hour, now)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	if _, err := creds.Verify(ctx, "cluster-a", token, now.Add(59*time.Minute)); err != nil {
		t.Fatalf("未过期应通过: %v", err)
	}
	if _, err := creds.Verify(ctx, "cluster-a", token, now.Add(2*time.Hour)); err == nil {
		t.Fatal("过期凭证应校验失败")
	} else if !strings.Contains(err.Error(), "已过期") {
		t.Errorf("错误信息 = %q，未含过期语义", err.Error())
	}
	_ = rec
}

// 轮换：旧令牌立即失效，新令牌可用，且同一集群至多一条 active。
func TestClusterCredential_Rotate(t *testing.T) {
	ctx := context.Background()
	st := openTestClusterStore(t)
	creds := st.Credentials()
	now := time.Now()

	old, _, err := creds.Issue(ctx, "cluster-a", time.Hour, now)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	newTok, rec, err := creds.Rotate(ctx, "cluster-a", time.Hour, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("轮换失败: %v", err)
	}
	if old == newTok {
		t.Fatal("轮换后令牌未变化")
	}
	if rec.Status != CredentialActive {
		t.Errorf("新凭证状态 = %q, want active", rec.Status)
	}
	if _, err := creds.Verify(ctx, "cluster-a", old, now.Add(2*time.Minute)); err == nil {
		t.Fatal("轮换后旧令牌应失效")
	}
	if _, err := creds.Verify(ctx, "cluster-a", newTok, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("轮换后新令牌应可用: %v", err)
	}
	// 同一集群至多一条 active
	var activeCount int
	if err := st.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM cluster_credentials WHERE cluster_id = ? AND status = ?`,
		"cluster-a", string(CredentialActive)).Scan(&activeCount); err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if activeCount != 1 {
		t.Errorf("active 凭证数 = %d, want 1", activeCount)
	}
}

// 吊销：摘除集群时凭证立即失效。
func TestClusterCredential_RevokeAll(t *testing.T) {
	ctx := context.Background()
	st := openTestClusterStore(t)
	creds := st.Credentials()
	now := time.Now()

	token, _, err := creds.Issue(ctx, "cluster-a", time.Hour, now)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	n, err := creds.RevokeAll(ctx, "cluster-a", now)
	if err != nil {
		t.Fatalf("吊销失败: %v", err)
	}
	if n != 1 {
		t.Errorf("吊销数 = %d, want 1", n)
	}
	if _, err := creds.Verify(ctx, "cluster-a", token, now.Add(time.Minute)); err == nil {
		t.Fatal("吊销后令牌应失效")
	}
	// 幂等：重复吊销不再计数
	n2, err := creds.RevokeAll(ctx, "cluster-a", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("重复吊销失败: %v", err)
	}
	if n2 != 0 {
		t.Errorf("重复吊销数 = %d, want 0", n2)
	}
}

// TTL 上限：超过 24h 的申请按上限收敛（不签发超长有效期）。
func TestClusterCredential_TTLUpperBound(t *testing.T) {
	ctx := context.Background()
	st := openTestClusterStore(t)
	creds := st.Credentials()
	now := time.Now()

	_, rec, err := creds.Issue(ctx, "cluster-a", 30*24*time.Hour, now)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	if got := rec.ExpiresAt.Sub(now); got > DefaultClusterCredentialTTL {
		t.Errorf("有效期 = %v，超出上限 %v", got, DefaultClusterCredentialTTL)
	}
}

// 库内不得落明文令牌（只存哈希）。
func TestClusterCredential_NoPlaintextInStore(t *testing.T) {
	ctx := context.Background()
	st := openTestClusterStore(t)
	creds := st.Credentials()
	now := time.Now()

	token, _, err := creds.Issue(ctx, "cluster-a", time.Hour, now)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	var hash string
	if err := st.db.QueryRowContext(ctx,
		`SELECT secret_hash FROM cluster_credentials WHERE cluster_id = ?`, "cluster-a").Scan(&hash); err != nil {
		t.Fatalf("读取哈希失败: %v", err)
	}
	if hash == "" {
		t.Fatal("凭证哈希为空")
	}
	if strings.Contains(hash, token) {
		t.Fatal("库内疑似落明文令牌")
	}
}
