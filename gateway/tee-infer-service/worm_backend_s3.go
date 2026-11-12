// worm_backend_s3.go — 审计链 WORM S3 后端（M2-1/M2-2，设计依据《网关侧缺口整改·技术实现方案》§1）。
//
// 架构位置（技术方案 §1.2）：
//
//	append()/appendOrFail() ──► WormBackend 接口 ──┬── fileWorm（现状，唯一写盘句柄，链序权威）
//	                                               └── s3WormBackend（本文件，合规留存层）
//	                                                     └── S3 Object Lock 桶（独立凭据/桶）
//	组合：dualWorm（fileWorm 为主 + s3Worm 异步镜像，失败策略 fail-open + 告警）
//
// 语义（§1.5 分层）：
//   - 主链（fileWorm）fail-closed 语义**保持现状**，S3 层故障**不得**阻塞主链 append；
//   - S3 层 fail-open：上传失败仅告警 + 重试 + 积压上限溢出告警（数据保留不丢弃）；
//   - 对象自 Append 攒批上传：每对象 = 一段 JSONL（与本地行序一致），单上传 goroutine 保序；
//   - 对象元数据携带链完整性信息（链段区间 + 边界事件哈希 + 集群 ID + 内容摘要），
//     供周期对账（对账脚本 build_tools/worm_reconcile.py 属取证环节，随 M2-3 另行交付）。
//
// 两仓边界：不涉 masked-infer。P1-8：不触碰 deploy/higress/*（env 样例放 deploy/audit/）。
// 国密红线：不涉 SM 系；传输签名沿用 SDK 标准 SigV4，不自研。
//
// 许可证：github.com/aws/aws-sdk-go-v2 全家桶 Apache-2.0（技术方案 §1.4 选型结论），
// 经自定义 Endpoint 对接 AWS S3 / 阿里云 OSS S3 兼容 / MinIO / Ceph RGW——不锁定单厂商。
//
// 安装期参数（参数名·默认值·覆写点·未填行为，§1.6）：
//   - WORM_BACKEND·file·env·未填=仅 fileWorm（现状）；`dual`=fileWorm 权威 + S3 镜像；
//     ⚠ 纯 `s3`（S3 单后端）**不支持**：与 A4-01「fileWorm 唯一写盘句柄/链序权威/启动恢复」
//     不变量冲突（auditChain.load 仅读本地文件），填 s3 → fail-closed 拒绝启动；
//   - WORM_S3_BUCKET·空·env·未填且 WORM_BACKEND=dual → 启动拒（fail-closed）；
//   - WORM_S3_ENDPOINT·空·env·未填=AWS 公有云默认端点（需配合 region）；
//   - WORM_S3_REGION·us-east-1·env·未填=默认值；
//   - WORM_S3_PREFIX·audit/·env·未填=默认值（对象键前缀）；
//   - WORM_S3_RETENTION_DAYS·365·env·未填=默认值；
//   - WORM_S3_MODE·compliance·env·未填=默认值（严格档；governance 为宽松档）；
//   - WORM_S3_CREDS_REF·空·env·未填且 dual → 启动拒；取值 `file:<路径>` 或 `env:<变量名>`
//     （沿用 MODULE_PIN_REF 的 R-S3-2 载体前缀语义；内容两行：AKID、SK；不落明文配置）；
//   - WORM_S3_CLUSTER_ID·default·env·未填=默认值（对象元数据 cluster-id）；
//   - WORM_S3_FLUSH_BATCH_SIZE·500·env·未填=默认值（攒批对象行数上限）；
//   - WORM_S3_FLUSH_INTERVAL·2s·env·未填=默认值（攒批最大时延）。
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// ---------- 配置 ----------

// S3WormConfig s3WormBackend 安装期配置（技术方案 §1.2 接口冻结基线）。
type S3WormConfig struct {
	Endpoint        string        // S3 兼容端点（安装期 WORM_S3_ENDPOINT；空=AWS 公有云默认）
	Region          string        // WORM_S3_REGION（默认 us-east-1）
	Bucket          string        // WORM_S3_BUCKET（须已开 Object Lock）
	Prefix          string        // 对象键前缀（默认 "audit/"）
	RetentionDays   int           // 合规保留天数（对象锁保留期，默认 365）
	Mode            string        // "compliance" | "governance"（默认 compliance）
	CredsRef        string        // 凭据引用（file:/env: 前缀，不落明文）
	ClusterID       string        // 对象元数据 cluster-id（默认 WORM_S3_CLUSTER_ID 或 "default"）
	FlushBatchSize  int           // 攒批上传对象行数（默认 500）
	FlushInterval   time.Duration // 攒批最大时延（默认 2s）
	BacklogMaxBytes int64         // 积压上限（默认 64MiB；仅溢出告警，不丢弃）
}

// normalize 修正零值/非法值为默认档。
func (c *S3WormConfig) normalize() error {
	c.Mode = strings.ToLower(strings.TrimSpace(c.Mode))
	if c.Mode == "" {
		c.Mode = "compliance"
	}
	if c.Mode != "compliance" && c.Mode != "governance" {
		return fmt.Errorf("WORM_S3_MODE=%q 非法（允许 compliance|governance）", c.Mode)
	}
	if c.RetentionDays <= 0 {
		c.RetentionDays = 365
	}
	if c.Prefix == "" {
		c.Prefix = "audit/"
	}
	if !strings.HasSuffix(c.Prefix, "/") {
		c.Prefix += "/"
	}
	if c.ClusterID == "" {
		c.ClusterID = "default"
	}
	if c.FlushBatchSize <= 0 {
		c.FlushBatchSize = 500
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = 2 * time.Second
	}
	if c.BacklogMaxBytes <= 0 {
		c.BacklogMaxBytes = 64 << 20
	}
	return nil
}

// s3WormConfigFromEnv 从安装期参数装配配置（缺省行为见文件头参数表）。
func s3WormConfigFromEnv() (S3WormConfig, error) {
	cfg := S3WormConfig{
		Endpoint:      os.Getenv("WORM_S3_ENDPOINT"),
		Region:        orDefault(os.Getenv("WORM_S3_REGION"), "us-east-1"),
		Bucket:        strings.TrimSpace(os.Getenv("WORM_S3_BUCKET")),
		Prefix:        os.Getenv("WORM_S3_PREFIX"),
		Mode:          orDefault(os.Getenv("WORM_S3_MODE"), "compliance"),
		CredsRef:      strings.TrimSpace(os.Getenv("WORM_S3_CREDS_REF")),
		ClusterID:     os.Getenv("WORM_S3_CLUSTER_ID"),
		RetentionDays: 365,
	}
	if v := os.Getenv("WORM_S3_RETENTION_DAYS"); v != "" {
		n, err := strconvAtoiPositive(v)
		if err != nil {
			return cfg, fmt.Errorf("WORM_S3_RETENTION_DAYS=%q 非法: %w", v, err)
		}
		cfg.RetentionDays = n
	}
	if v := os.Getenv("WORM_S3_FLUSH_BATCH_SIZE"); v != "" {
		n, err := strconvAtoiPositive(v)
		if err != nil {
			return cfg, fmt.Errorf("WORM_S3_FLUSH_BATCH_SIZE=%q 非法: %w", v, err)
		}
		cfg.FlushBatchSize = n
	}
	if v := os.Getenv("WORM_S3_FLUSH_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.FlushInterval = d
		}
	}
	if err := cfg.normalize(); err != nil {
		return cfg, err
	}
	// fail-closed（§1.6）：dual 模式下 bucket/creds_ref 未填 → 启动拒。
	if cfg.Bucket == "" {
		return cfg, errors.New("WORM_S3_BUCKET 未配置（fail-closed：S3 WORM 后端拒绝启用）")
	}
	if cfg.CredsRef == "" {
		return cfg, errors.New("WORM_S3_CREDS_REF 未配置（fail-closed：S3 WORM 后端拒绝启用）")
	}
	return cfg, nil
}

func strconvAtoiPositive(v string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("须为正整数")
	}
	return n, nil
}

// resolveWormCreds 按 *_REF 载体前缀解析 S3 凭据（语义对齐 cryptop/module R-S3-2）。
// 返回 (accessKeyID, secretAccessKey, error)；内容两行：AKID、SK。
func resolveWormCreds(credsRef string) (string, string, error) {
	ref := strings.TrimSpace(credsRef)
	if ref == "" {
		return "", "", errors.New("worm_s3_creds_ref 为空")
	}
	var raw string
	switch {
	case strings.HasPrefix(ref, "file:"):
		path := strings.TrimSpace(strings.TrimPrefix(ref, "file:"))
		if err := checkWormCredsFilePerm(path); err != nil {
			return "", "", fmt.Errorf("worm_s3_creds_ref: %w", err)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", "", fmt.Errorf("worm_s3_creds_ref 凭据文件 %s 读取失败: %w", path, err)
		}
		raw = string(b)
	case strings.HasPrefix(ref, "env:"):
		name := strings.TrimSpace(strings.TrimPrefix(ref, "env:"))
		raw = os.Getenv(name)
		if raw == "" {
			return "", "", fmt.Errorf("worm_s3_creds_ref 引用的环境变量 %s 未设置或为空", name)
		}
	default:
		return "", "", errors.New("worm_s3_creds_ref 须带载体前缀 file: 或 env:（禁止凭据字面值）")
	}
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(raw, "\r\n", "\n")), "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[0]) == "" || strings.TrimSpace(lines[1]) == "" {
		return "", "", errors.New("worm_s3_creds_ref 内容非法（须两行：access_key_id、secret_access_key）")
	}
	return strings.TrimSpace(lines[0]), strings.TrimSpace(lines[1]), nil
}

// ---------- S3 API 抽象（单测注入 fake；生产注入 *s3.Client） ----------

// s3APIClient 生产实现为 *s3.Client（aws-sdk-go-v2）；fake 实现见 worm_backend_s3_test.go。
type s3APIClient interface {
	HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	GetObjectLockConfiguration(ctx context.Context, params *s3.GetObjectLockConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// ---------- s3WormBackend ----------

// s3WormBackend S3 Object Lock WORM 后端（合规留存层）。
type s3WormBackend struct {
	cfg S3WormConfig
	cli s3APIClient

	// 攒批缓冲（mu 护；单上传 goroutine 保序）。
	// 段边界 = FlushBatchSize 行满（Append 时轮转）或 FlushInterval 到期（上传器轮转），
	// 保证「对象行数 = 批大小」语义成立（对象 ≠ 上传时刻的任意快照）。
	mu        sync.Mutex
	buf       bytes.Buffer   // 当前段 JSONL
	segLines  int            // 当前段行数
	segFirst  uint64         // 当前段首事件序号（自进程启动 1 起）
	segLast   uint64         // 当前段尾事件序号
	segFirstH string         // 首事件载荷摘要（元数据 first-hash）
	segLastH  string         // 尾事件载荷摘要（元数据 last-hash）
	seq       uint64         // 已接受事件总数
	pending   []*wormSegment // 待上传段队列（FIFO，保序）
	notify    chan struct{}
	stopped   bool
	closeOnce sync.Once

	// 上传 goroutine 生命周期
	wg   sync.WaitGroup
	stop chan struct{}

	// 指标（原子计数；供 /config 与对账脚本取数）
	uploadedOK  atomic.Uint64
	uploadedFai atomic.Uint64
	retried     atomic.Uint64
	backlogNow  atomic.Int64
	lastErr     atomic.Value // string
}

// wormSegment 一个待上传对象（一段 JSONL + 链段区间元数据）。
type wormSegment struct {
	body          []byte
	first, last   uint64
	firstH, lastH string
}

// newS3WormBackend 生产构造：按配置构建 SDK 客户端并 fail-closed 校验桶/对象锁。
func newS3WormBackend(ctx context.Context, cfg S3WormConfig) (*s3WormBackend, error) {
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	if cfg.Bucket == "" || cfg.CredsRef == "" {
		return nil, errors.New("worm-s3: bucket/creds_ref 未配置（fail-closed）")
	}
	ak, sk, err := resolveWormCreds(cfg.CredsRef)
	if err != nil {
		return nil, err
	}
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(cfg.Region)}
	if cfg.Endpoint != "" {
		opts = append(opts, awsconfig.WithBaseEndpoint(cfg.Endpoint))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("worm-s3: AWS 配置加载失败: %w", err)
	}
	cli := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.Credentials = credentials.NewStaticCredentialsProvider(ak, sk, "")
	})
	return newS3WormBackendWithClient(ctx, cfg, cli)
}

// newS3WormBackendWithClient 构造 + fail-closed 校验：
// HeadBucket（桶存在/可达）+ GetObjectLockConfiguration（Object Lock 已启用），不满足即拒绝启用（§1.5）。
func newS3WormBackendWithClient(ctx context.Context, cfg S3WormConfig, cli s3APIClient) (*s3WormBackend, error) {
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	if _, err := cli.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(cfg.Bucket)}); err != nil {
		return nil, fmt.Errorf("worm-s3: 桶 %s 不可达（fail-closed）: %w", cfg.Bucket, err)
	}
	lc, err := cli.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: aws.String(cfg.Bucket)})
	if err != nil {
		return nil, fmt.Errorf("worm-s3: 桶 %s Object Lock 配置查询失败（fail-closed：WORM 形同虚设即拒绝启用）: %w", cfg.Bucket, err)
	}
	if lc == nil || lc.ObjectLockConfiguration == nil || lc.ObjectLockConfiguration.ObjectLockEnabled != types.ObjectLockEnabledEnabled {
		return nil, fmt.Errorf("worm-s3: 桶 %s 未启用 Object Lock（fail-closed）", cfg.Bucket)
	}
	w := &s3WormBackend{
		cfg:    cfg,
		cli:    cli,
		notify: make(chan struct{}, 1),
		stop:   make(chan struct{}),
	}
	w.wg.Add(1)
	go w.uploaderLoop()
	return w, nil
}

// Append 追加一条事件到攒批队列（§1.2：进入持久化队列即视为接受，接口语义不变；
// 不做网络 I/O、不阻塞审计写路径；批满时轮转切段并通知上传器）。
func (w *s3WormBackend) Append(e AuditEvent) error {
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("worm-s3: 序列化审计事件失败: %w", err)
	}
	w.mu.Lock()
	if w.stopped {
		w.mu.Unlock()
		return errors.New("worm-s3: 后端已关闭，拒绝追加")
	}
	if w.segLines == 0 {
		w.segFirst = w.seq + 1
		w.segFirstH = e.PayloadSHA
	}
	w.buf.Write(line)
	w.buf.WriteByte('\n')
	w.segLines++
	w.seq++
	w.segLast = w.seq
	w.segLastH = e.PayloadSHA
	needFlush := false
	if w.segLines >= w.cfg.FlushBatchSize || int64(w.buf.Len()) >= w.cfg.BacklogMaxBytes {
		w.rotateLocked()
		needFlush = true
	}
	w.updateBacklogLocked()
	w.mu.Unlock()
	if needFlush {
		select {
		case w.notify <- struct{}{}:
		default:
		}
	}
	return nil
}

// rotateLocked 段轮转：当前缓冲快照入待上传队列并重置（调用方持锁）。
func (w *s3WormBackend) rotateLocked() {
	if w.segLines == 0 {
		return
	}
	w.pending = append(w.pending, &wormSegment{
		body:   append([]byte(nil), w.buf.Bytes()...),
		first:  w.segFirst,
		last:   w.segLast,
		firstH: w.segFirstH,
		lastH:  w.segLastH,
	})
	w.buf.Reset()
	w.segLines = 0
	w.segFirst, w.segLast = 0, 0
	w.segFirstH, w.segLastH = "", ""
}

// updateBacklogLocked 更新积压计数（调用方持锁）。
func (w *s3WormBackend) updateBacklogLocked() {
	total := int64(w.buf.Len())
	for _, s := range w.pending {
		total += int64(len(s.body))
	}
	w.backlogNow.Store(total)
}

// uploaderLoop 单上传 goroutine：notify 或定时触发（先轮转当前段再依序上传；保序）。
func (w *s3WormBackend) uploaderLoop() {
	defer w.wg.Done()
	t := time.NewTicker(w.cfg.FlushInterval)
	defer t.Stop()
	var overflowLogged bool
	for {
		select {
		case <-w.stop:
			return
		case <-w.notify:
		case <-t.C:
			w.mu.Lock()
			w.rotateLocked() // 定时兜底：静默期尾部事件亦按时延成段
			w.mu.Unlock()
		}
		for {
			ok, err := w.uploadOne()
			if err != nil {
				w.uploadedFai.Add(1)
				w.retried.Add(1)
				w.lastErr.Store(err.Error())
				// fail-open：告警 + 保留数据 + 下轮重试；积压溢出仅告警不丢弃（§1.5）。
				if w.backlogNow.Load() > w.cfg.BacklogMaxBytes && !overflowLogged {
					log.Printf("[audit] WORM S3 积压超上限 %d 字节（持续告警一次；数据保留，上传器持续重试）", w.cfg.BacklogMaxBytes)
					overflowLogged = true
				}
				break
			}
			overflowLogged = false
			if !ok {
				break
			}
		}
	}
}

// uploadOne 从待上传队列头取一段上传。返回 (false, nil)=队列已空；(true, nil)=上传成功；err=失败（段保留队头）。
func (w *s3WormBackend) uploadOne() (bool, error) {
	w.mu.Lock()
	if len(w.pending) == 0 {
		w.mu.Unlock()
		return false, nil
	}
	seg := w.pending[0]
	w.mu.Unlock()

	err := w.uploadSegment(seg)
	if err != nil {
		return true, err
	}
	w.mu.Lock()
	// 仅当队头未被并发改动时出队（单上传器下恒真，防御性判断）。
	if len(w.pending) > 0 && w.pending[0] == seg {
		w.pending = w.pending[1:]
	}
	w.updateBacklogLocked()
	w.mu.Unlock()
	w.uploadedOK.Add(1)
	return true, nil
}

// pendingBytes 当前积压字节数（测试与告警用）。
func (w *s3WormBackend) pendingBytes() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return int(w.backlogNow.Load())
}

// uploadSegment 上传单个段对象（对象锁保留期 + 链完整性元数据）。
func (w *s3WormBackend) uploadSegment(seg *wormSegment) error {
	sum := sha256.Sum256(seg.body)
	key := fmt.Sprintf("%sseg-%016d-%016d.jsonl", w.cfg.Prefix, seg.first, seg.last)
	retain := time.Now().UTC().AddDate(0, 0, w.cfg.RetentionDays)
	lockMode := types.ObjectLockModeCompliance
	if w.cfg.Mode == "governance" {
		lockMode = types.ObjectLockModeGovernance
	}
	_, err := w.cli.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket:                    aws.String(w.cfg.Bucket),
		Key:                       aws.String(key),
		Body:                      bytes.NewReader(seg.body),
		ContentType:               aws.String("application/x-ndjson"),
		ObjectLockMode:            lockMode,
		ObjectLockRetainUntilDate: aws.Time(retain),
		Metadata: map[string]string{
			"chain-start":    fmt.Sprintf("%d", seg.first),
			"chain-end":      fmt.Sprintf("%d", seg.last),
			"first-hash":     seg.firstH,
			"last-hash":      seg.lastH,
			"cluster-id":     w.cfg.ClusterID,
			"written-at":     time.Now().UTC().Format(time.RFC3339Nano),
			"worm-mode":      w.cfg.Mode,
			"content-sha256": hex.EncodeToString(sum[:]),
		},
	})
	if err != nil {
		return fmt.Errorf("worm-s3: 对象 %s 上传失败: %w", key, err)
	}
	return nil
}

// Close 停止上传器并做最终 flush（对齐 fileWorm.Close 的「最终落盘」语义）；
// 最终上传失败返回 error（数据保留在缓冲，进程退出前由调用方记日志）。
func (w *s3WormBackend) Close() error {
	w.closeOnce.Do(func() {
		w.mu.Lock()
		w.stopped = true
		w.rotateLocked() // 收尾段
		w.mu.Unlock()
		close(w.stop)
		w.wg.Wait()
	})
	// 最终上传余量（最多每段 3 次重试；失败数据保留并返回错误）。
	var lastErr error
	for {
		w.mu.Lock()
		if len(w.pending) == 0 {
			w.mu.Unlock()
			break
		}
		seg := w.pending[0]
		w.mu.Unlock()
		var err error
		for i := 0; i < 3; i++ {
			if err = w.uploadSegment(seg); err == nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if err != nil {
			lastErr = err
			w.lastErr.Store(err.Error())
			log.Printf("[audit] WORM S3 关闭前最终 flush 失败（数据保留在本地链，S3 镜像落后）: %v", err)
			break
		}
		w.mu.Lock()
		if len(w.pending) > 0 && w.pending[0] == seg {
			w.pending = w.pending[1:]
		}
		w.updateBacklogLocked()
		w.mu.Unlock()
		w.uploadedOK.Add(1)
	}
	return lastErr
}

// Name 返回后端标识。
func (w *s3WormBackend) Name() string {
	return "s3://" + w.cfg.Bucket + "/" + w.cfg.Prefix
}

// ---------- dualWorm（fileWorm 权威 + S3 镜像，§1.2/§1.5） ----------

// dualWorm 双后端组合：主链（fileWorm）fail-closed 语义保持；镜像层 fail-open + 告警。
type dualWorm struct {
	primary WormBackend // fileWorm：唯一写盘句柄，链序权威（A4-01 不变量）
	mirror  WormBackend // s3WormBackend：合规留存层
}

func (d *dualWorm) Append(e AuditEvent) error {
	if err := d.primary.Append(e); err != nil {
		return err // 主链失败 → 维持 fail-closed 语义（调用方按 auditFailClosed 处置）
	}
	if err := d.mirror.Append(e); err != nil {
		// S3 层 fail-open：仅告警（上传层错误在 uploaderLoop 内计数重试；此处仅攒批队列拒绝）。
		log.Printf("[audit] WORM S3 镜像接受失败（fail-open，主链不受影响）: %v", err)
	}
	return nil
}

func (d *dualWorm) Close() error {
	perr := d.primary.Close()
	merr := d.mirror.Close()
	if perr != nil {
		return perr
	}
	return merr
}

func (d *dualWorm) Name() string { return d.primary.Name() + "+mirror:" + d.mirror.Name() }

// ---------- main.go 装配辅助 ----------

// wormBackendModeFromEnv 解析 WORM_BACKEND（file|dual；s3 → 显式不支持，见文件头参数表）。
func wormBackendModeFromEnv() (string, error) {
	switch m := strings.ToLower(orDefault(os.Getenv("WORM_BACKEND"), "file")); m {
	case "file", "dual":
		return m, nil
	case "s3":
		return "", errors.New("WORM_BACKEND=s3 不支持（A4-01 不变量：fileWorm 唯一写盘句柄/链序权威/启动恢复；请用 dual）")
	default:
		return "", fmt.Errorf("WORM_BACKEND=%q 非法（允许 file|dual）", m)
	}
}

// unusedIO 防 io 包未使用告警占位（Body io.Reader 语义经 bytes.Reader 满足）。
var _ io.Reader = (*bytes.Reader)(nil)

// 权限校验辅助（对齐 readPINFile 的 0600 纪律；Linux 部署目标强制，Windows 开发机跳过）。
func checkWormCredsFilePerm(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("凭据文件 %s 权限 %04o 过宽，须 0600", path, fi.Mode().Perm())
	}
	return nil
}
