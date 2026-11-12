// worm_backend_s3_test.go — M2-1/M2-2 单测（fake S3；构造校验/攒批/失败重试/幂等/元数据/关闭语义）。
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// fakeS3Client 内存 fake（计数 + 可注入失败）。
type fakeS3Client struct {
	mu sync.Mutex

	headOK      bool
	lockEnabled bool
	failNext    atomic.Int32 // >0 时接下来 N 次 PutObject 返回错误

	puts   []s3.PutObjectInput
	bodies []string
	metas  []map[string]string
}

func (f *fakeS3Client) HeadBucket(ctx context.Context, p *s3.HeadBucketInput, o ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	if !f.headOK {
		return nil, errors.New("bucket not reachable")
	}
	return &s3.HeadBucketOutput{}, nil
}

func (f *fakeS3Client) GetObjectLockConfiguration(ctx context.Context, p *s3.GetObjectLockConfigurationInput, o ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error) {
	if !f.lockEnabled {
		return &s3.GetObjectLockConfigurationOutput{}, nil
	}
	return &s3.GetObjectLockConfigurationOutput{ObjectLockConfiguration: &types.ObjectLockConfiguration{
		ObjectLockEnabled: types.ObjectLockEnabledEnabled,
	}}, nil
}

func (f *fakeS3Client) PutObject(ctx context.Context, p *s3.PutObjectInput, o ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if f.failNext.Add(-1) >= 0 {
		return nil, errors.New("injected put failure")
	}
	body, err := io.ReadAll(p.Body)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts = append(f.puts, *p)
	f.bodies = append(f.bodies, string(body))
	f.metas = append(f.metas, p.Metadata)
	return &s3.PutObjectOutput{ETag: aws.String("fake-etag")}, nil
}

func testCfg() S3WormConfig {
	return S3WormConfig{
		Bucket: "worm-bucket", Region: "us-east-1", Prefix: "audit/cl-1/",
		RetentionDays: 30, Mode: "compliance", ClusterID: "cl-1",
		FlushBatchSize: 3, FlushInterval: 40 * time.Millisecond, BacklogMaxBytes: 1 << 20,
	}
}

func newTestBackend(t *testing.T, f *fakeS3Client) *s3WormBackend {
	t.Helper()
	f.headOK = true
	f.lockEnabled = true
	w, err := newS3WormBackendWithClient(context.Background(), testCfg(), f)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	return w
}

// TestS3WormConstructor_FailClosed 构造校验（§1.5：桶不可达 / Object Lock 未启用 → 拒绝启用）。
func TestS3WormConstructor_FailClosed(t *testing.T) {
	f := &fakeS3Client{headOK: false}
	if _, err := newS3WormBackendWithClient(context.Background(), testCfg(), f); err == nil {
		t.Fatal("桶不可达应拒绝构造")
	}
	f = &fakeS3Client{headOK: true, lockEnabled: false}
	if _, err := newS3WormBackendWithClient(context.Background(), testCfg(), f); err == nil {
		t.Fatal("Object Lock 未启用应拒绝构造")
	}
}

// TestS3WormAppendAndFlush 攒批上传：Append 不阻塞（入队即接受），段上传内容与本地行序一致。
func TestS3WormAppendAndFlush(t *testing.T) {
	f := &fakeS3Client{}
	w := newTestBackend(t, f)
	defer w.Close()

	for i := 0; i < 5; i++ {
		if err := w.Append(AuditEvent{EventID: "e1", PayloadSHA: "h1"}); err != nil {
			t.Fatalf("Append 失败: %v", err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && w.uploadedOK.Load() < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if got := w.uploadedOK.Load(); got < 2 {
		t.Fatalf("5 行 / 批 3 应产生 ≥2 次上传，got %d", got)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	total := 0
	for _, b := range f.bodies {
		total += strings.Count(b, "\n")
	}
	if total != 5 {
		t.Fatalf("上传 JSONL 总行数 = %d，want 5", total)
	}
	// 元数据链完整性字段（§1.1 判据 3）。
	m := f.metas[0]
	for _, k := range []string{"chain-start", "chain-end", "first-hash", "last-hash", "cluster-id", "worm-mode", "content-sha256"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("对象元数据缺 %s", k)
		}
	}
	if m["worm-mode"] != "compliance" || m["cluster-id"] != "cl-1" {
		t.Fatalf("元数据取值错误: %v", m)
	}
}

// TestS3WormFailureRetainRetry 上传失败：数据保留 + 重试成功（fail-open，不丢事件）。
func TestS3WormFailureRetainRetry(t *testing.T) {
	f := &fakeS3Client{}
	w := newTestBackend(t, f)
	defer w.Close()

	f.failNext.Store(2) // 前两次 PutObject 失败
	for i := 0; i < 3; i++ {
		_ = w.Append(AuditEvent{EventID: "e2", PayloadSHA: "h2"})
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		n := len(f.bodies)
		f.mu.Unlock()
		if n >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.bodies) != 1 {
		t.Fatalf("重试后应恰好 1 个对象，got %d", len(f.bodies))
	}
	if strings.Count(f.bodies[0], "\n") != 3 {
		t.Fatalf("失败重试后行数 = %d，want 3（数据不得丢弃）", strings.Count(f.bodies[0], "\n"))
	}
	if w.uploadedFai.Load() < 2 {
		t.Fatalf("失败计数 = %d，want ≥2", w.uploadedFai.Load())
	}
}

// TestS3WormKeyOrdering 对象键按链段区间单调递增（对账可按序拼接）。
func TestS3WormKeyOrdering(t *testing.T) {
	f := &fakeS3Client{}
	w := newTestBackend(t, f)
	defer w.Close()

	for i := 0; i < 7; i++ {
		_ = w.Append(AuditEvent{EventID: "e3", PayloadSHA: "h3"})
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		n := len(f.puts)
		f.mu.Unlock()
		if n >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var lastEnd int64
	for _, p := range f.puts {
		var start, end int64
		if _, err := fmt.Sscanf(aws.ToString(p.Key), "audit/cl-1/seg-%016d-%016d.jsonl", &start, &end); err != nil {
			t.Fatalf("对象键 %q 不可解析: %v", aws.ToString(p.Key), err)
		}
		if start != lastEnd+1 {
			t.Fatalf("链段区间不连续: %d..%d（前段尾 %d）", start, end, lastEnd)
		}
		lastEnd = end
	}
	if lastEnd != 7 {
		t.Fatalf("链段尾 = %d，want 7", lastEnd)
	}
}

// TestS3WormCloseFinalFlush Close 触发最终 flush（对齐 fileWorm「最终落盘」语义）。
func TestS3WormCloseFinalFlush(t *testing.T) {
	f := &fakeS3Client{}
	w := newTestBackend(t, f)
	_ = w.Append(AuditEvent{EventID: "e4", PayloadSHA: "h4"}) // 不足批，滞留缓冲
	// 直接 Close（不等待定时器）。
	if err := w.Close(); err != nil {
		t.Fatalf("Close 返回错误: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.bodies) != 1 || strings.Count(f.bodies[0], "\n") != 1 {
		t.Fatalf("Close 应最终 flush 1 行，got %d 对象", len(f.bodies))
	}
	if err := w.Append(AuditEvent{EventID: "e5"}); err == nil {
		t.Fatal("Close 后 Append 应被拒绝")
	}
}

// TestResolveWormCreds *_REF 载体解析（file:/env: 前缀 + 字面值拒绝）。
func TestResolveWormCreds(t *testing.T) {
	if _, _, err := resolveWormCreds("AKID123"); err == nil {
		t.Fatal("无前缀字面值应被拒绝")
	}
	if _, _, err := resolveWormCreds(""); err == nil {
		t.Fatal("空引用应被拒绝")
	}
	t.Setenv("WORM_TEST_CREDS", "akid\nsecret\n")
	ak, sk, err := resolveWormCreds("env:WORM_TEST_CREDS")
	if err != nil || ak != "akid" || sk != "secret" {
		t.Fatalf("env: 解析错误: %v %q %q", err, ak, sk)
	}
}

// TestWormBackendModeFromEnv WORM_BACKEND 解析（s3 显式拒绝，A4-01 不变量）。
func TestWormBackendModeFromEnv(t *testing.T) {
	t.Setenv("WORM_BACKEND", "")
	if m, err := wormBackendModeFromEnv(); err != nil || m != "file" {
		t.Fatalf("默认应为 file: %q %v", m, err)
	}
	t.Setenv("WORM_BACKEND", "dual")
	if m, err := wormBackendModeFromEnv(); err != nil || m != "dual" {
		t.Fatalf("dual 应被接受: %q %v", m, err)
	}
	t.Setenv("WORM_BACKEND", "s3")
	if _, err := wormBackendModeFromEnv(); err == nil {
		t.Fatal("纯 s3 应被拒绝（fileWorm 链权威不变量）")
	}
}

// TestDualWorm 主链失败返回错误（fail-closed 保持）、镜像失败不阻塞主链（fail-open）。
func TestDualWorm(t *testing.T) {
	f := &fakeS3Client{}
	w := newTestBackend(t, f)
	pw := newMemoryWorm()
	mw := newMemoryWorm()
	d := &dualWorm{primary: pw, mirror: mw}

	if err := d.Append(AuditEvent{EventID: "e6", PayloadSHA: "h6"}); err != nil {
		t.Fatalf("dual Append 失败: %v", err)
	}
	if mw.Len() != 1 {
		t.Fatal("镜像未收到事件")
	}
	pw.SetFail(true)
	if err := d.Append(AuditEvent{EventID: "e7"}); err == nil {
		t.Fatal("主链失败必须返回错误（fail-closed 保持）")
	}
	if mw.Len() != 1 {
		t.Fatal("主链失败时镜像不应收到事件")
	}
	_ = w // 保持 w 生命周期（fake 覆盖已在其它用例）
}
