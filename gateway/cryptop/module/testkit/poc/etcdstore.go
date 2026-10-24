package poc

// EtcdControlStore 是 GroupControlStore 的 etcd v3.5 真机参考实现（V-2 / V-5）。
//
// 原子性设计（对应本体 §3.1.1 算法 2 / D-17）：
//
//	AcquireOwner 的全部写入条件放在**单个 etcd txn** 的 Compare 集合中：
//	  - epoch        比较 Value(epochKey) == ExpectedEpoch；
//	  - desired      比较 Value(desiredKey) == ExpectedDesiredVersion；
//	  - lease        比较 CreateRevision(leaseKey) == 0（租约不存在/已过期自动删除）；
//	  - 同 DC 自动   追加比较 Value(epochmetaKey) == req.DC（跨 DC 无 promotion 必然失败）；
//	  - promotion    追加比较审批键存在（CreateRevision>0，租约即有效期）且 Value == digest。
//	成功分支原子写 epoch+1 / epochmeta / claim / writer / lease（绑定 etcd Lease）/ leaseexp。
//	任一条件在窗口内变化 → txn 整体失败 → group_stale_epoch（fail-closed）。
//
// CAS 语义用"伴生比较键"表达，使 etcd 原生 Compare 可判定：
//	claim   "<owner>|<epoch>"           KeyOp claim（ClaimOwner/ClaimEpoch）
//	writer  "<epoch>|<bootID>"         目录写者身份（writer_epoch/writer_boot_id）
//	opvs    "<version>|<status>"       KeyOp 版本+状态
//	dirvs   "<version>"                目录项版本
//	目录写 additionally 要求 lease 键存在（CreateRevision>0），租约过期即失去写权。

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// 键布局（前缀 /cryptop，与本体 §6.2.2 控制存储表一致）。
const (
	kEpoch     = "epoch"
	kEpochMeta = "epochmeta"
	kClaim     = "claim"
	kWriter    = "writer"
	kLease     = "lease"
	kLeaseExp  = "leaseexp"
	kDesired   = "desired"
	kApprovals = "approvals"
	kOps       = "ops"
	kOpVS      = "opvs"
	kKeys      = "keys"
	kDirVS     = "dirvs"
)

// EtcdControlStore etcd 版控制存储（POC 参考实现）。
type EtcdControlStore struct {
	cli *clientv3.Client
	gid string
}

// NewEtcdControlStore 连接 etcd 并清空本组前缀（保证用例可重复执行）。
func NewEtcdControlStore(ctx context.Context, endpoints []string, gid string) (*EtcdControlStore, error) {
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("poc: 连接 etcd 失败: %w", err)
	}
	s := &EtcdControlStore{cli: cli, gid: gid}
	if err := s.Reset(ctx); err != nil {
		cli.Close()
		return nil, err
	}
	// desired 初始版本 0（bootstrap 路径据此比较）。
	if _, err := cli.Put(ctx, s.k(kDesired), "0"); err != nil {
		cli.Close()
		return nil, fmt.Errorf("poc: 初始化 desired 失败: %w", err)
	}
	return s, nil
}

// NewEtcdControlStoreAuth 以指定身份连接 etcd（V-5 RBAC 用例：按成员身份建客户端）。
func NewEtcdControlStoreAuth(ctx context.Context, endpoints []string, gid, user, pass string) (*EtcdControlStore, error) {
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: 5 * time.Second,
		Username:    user,
		Password:    pass,
	})
	if err != nil {
		return nil, fmt.Errorf("poc: 以 %s 连接 etcd 失败: %w", user, err)
	}
	s := &EtcdControlStore{cli: cli, gid: gid}
	return s, nil
}

func (s *EtcdControlStore) Close() error { return s.cli.Close() }

// CurrentRevision 返回 etcd 当前 revision（Watch 起点用）。
func (s *EtcdControlStore) CurrentRevision(ctx context.Context) (int64, error) {
	resp, err := s.cli.Get(ctx, s.groupPrefix())
	if err != nil {
		return 0, err
	}
	return resp.Header.Revision, nil
}

// Reset 删除本组全部键（用例前置）。
func (s *EtcdControlStore) Reset(ctx context.Context) error {
	_, err := s.cli.Delete(ctx, s.groupPrefix(), clientv3.WithPrefix())
	if err != nil {
		return fmt.Errorf("poc: 清理组前缀失败: %w", err)
	}
	// Reset 会连 desired 一起删，调用方负责重新初始化。
	return nil
}

func (s *EtcdControlStore) groupPrefix() string {
	return fmt.Sprintf("%s/groups/%s/", TestPrefix, s.gid)
}

func (s *EtcdControlStore) k(parts ...string) string {
	return s.groupPrefix() + strings.Join(parts, "/")
}

func u64(v uint64) string { return strconv.FormatUint(v, 10) }

func i64(v int64) string { return strconv.FormatInt(v, 10) }

// GetOwnerState 读取持久 epoch 与当前租约（只读观测）。
func (s *EtcdControlStore) GetOwnerState(ctx context.Context) (OwnerState, error) {
	resp, err := s.cli.Get(ctx, s.groupPrefix(), clientv3.WithPrefix())
	if err != nil {
		return OwnerState{}, fmt.Errorf("poc: 读取组状态失败: %w", err)
	}
	kv := map[string]string{}
	for _, ev := range resp.Kvs {
		kv[string(ev.Key)] = string(ev.Value)
	}
	st := OwnerState{StoreRevision: resp.Header.Revision}
	if v, ok := kv[s.k(kEpoch)]; ok {
		st.Epoch, _ = strconv.ParseUint(v, 10, 64)
	}
	if v, ok := kv[s.k(kEpochMeta)]; ok {
		st.LastDC = v
	}
	if v, ok := kv[s.k(kDesired)]; ok {
		st.DesiredVersion, _ = strconv.ParseUint(v, 10, 64)
	}
	if v, ok := kv[s.k(kLease)]; ok {
		// "<holder>|<bootID>|<epoch>|<leaseID>"
		p := strings.Split(v, "|")
		if len(p) == 4 {
			ls := &LeaseStatus{
				Holder: p[0], HolderBootID: p[1], DC: st.LastDC,
				StoreRevision: resp.Header.Revision,
			}
			ls.Epoch, _ = strconv.ParseUint(p[2], 10, 64)
			if expv, ok2 := kv[s.k(kLeaseExp)]; ok2 {
				if ms, err3 := strconv.ParseInt(expv, 10, 64); err3 == nil {
					ls.ExpiresAt = time.UnixMilli(ms)
				}
			}
			st.Lease = ls
			st.LastOwner, st.LastOwnerBootID = p[0], p[1]
		}
	}
	if st.LastOwner == "" {
		if v, ok := kv[s.k(kClaim)]; ok {
			if p := strings.SplitN(v, "|", 2); len(p) == 2 {
				st.LastOwner = p[0]
			}
		}
	}
	return st, nil
}

// AcquireOwner 单 txn 获取组主租约（§3.1.1 算法 2 / D-17）。
func (s *EtcdControlStore) AcquireOwner(ctx context.Context, req OwnerAcquireRequest) (LeaseStatus, error) {
	if req.Promotion != nil && req.Promotion.TargetMember != req.Member {
		return LeaseStatus{}, fmt.Errorf("%w: promotion 目标 %s 不是本成员 %s",
			ErrGroupStaleEpoch, req.Promotion.TargetMember, req.Member)
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	lg, err := s.cli.Grant(ctx, int64(ttl/time.Second))
	if err != nil {
		return LeaseStatus{}, fmt.Errorf("poc: 申请 etcd 租约失败: %w", err)
	}

	// 路径选择基于只读探测；**权威判定全部在 txn Compare 内**，探测过期只会导致
	// txn 失败（fail-closed），不会导致错误放行。
	st, err := s.GetOwnerState(ctx)
	if err != nil {
		return LeaseStatus{}, err
	}

	newEpoch := req.ExpectedEpoch + 1
	leaseVal := fmt.Sprintf("%s|%s|%d|%d", req.Member, req.BootID, newEpoch, lg.ID)
	expMs := time.Now().Add(ttl).UnixMilli()

	var cmp []clientv3.Cmp
	switch {
	case req.Promotion != nil:
		cmp = []clientv3.Cmp{
			clientv3.Compare(clientv3.Value(s.k(kEpoch)), "=", u64(req.ExpectedEpoch)),
			clientv3.Compare(clientv3.CreateRevision(s.k(kLease)), "=", 0),
			clientv3.Compare(clientv3.Value(s.k(kDesired)), "=", u64(req.ExpectedDesiredVersion)),
			clientv3.Compare(clientv3.CreateRevision(s.k(kApprovals, req.Promotion.ApprovalID)), ">", 0),
			clientv3.Compare(clientv3.Value(s.k(kApprovals, req.Promotion.ApprovalID)), "=", req.Promotion.Digest),
		}
	case st.Epoch > 0 && st.Lease == nil:
		// 同 DC 自动接管（epochmeta 参与比较 ⇒ 跨 DC 无 promotion 必然失败）。
		if !req.AllowAutoIntraDC {
			return LeaseStatus{}, fmt.Errorf("%w: 未开启同 DC 自动接管", ErrGroupStaleEpoch)
		}
		cmp = []clientv3.Cmp{
			clientv3.Compare(clientv3.Value(s.k(kEpoch)), "=", u64(req.ExpectedEpoch)),
			clientv3.Compare(clientv3.Value(s.k(kEpochMeta)), "=", req.DC),
			clientv3.Compare(clientv3.CreateRevision(s.k(kLease)), "=", 0),
			clientv3.Compare(clientv3.Value(s.k(kDesired)), "=", u64(req.ExpectedDesiredVersion)),
		}
	default:
		// 首次建主（尚无 epoch）。
		if !req.AllowBootstrap {
			return LeaseStatus{}, fmt.Errorf("%w: 首次建主需 AllowBootstrap", ErrGroupStaleEpoch)
		}
		if req.BootstrapOwner == "" || req.BootstrapOwner != req.Member {
			return LeaseStatus{}, fmt.Errorf("%w: bootstrap_owner 必须是本成员", ErrGroupStaleEpoch)
		}
		cmp = []clientv3.Cmp{
			clientv3.Compare(clientv3.CreateRevision(s.k(kEpoch)), "=", 0),
			clientv3.Compare(clientv3.CreateRevision(s.k(kLease)), "=", 0),
			clientv3.Compare(clientv3.Value(s.k(kDesired)), "=", u64(req.ExpectedDesiredVersion)),
		}
	}

	puts := []clientv3.Op{
		clientv3.OpPut(s.k(kEpoch), u64(newEpoch)),
		clientv3.OpPut(s.k(kEpochMeta), req.DC),
		clientv3.OpPut(s.k(kClaim), fmt.Sprintf("%s|%d", req.Member, newEpoch)),
		clientv3.OpPut(s.k(kWriter), fmt.Sprintf("%d|%s", newEpoch, req.BootID)),
		clientv3.OpPut(s.k(kLease), leaseVal, clientv3.WithLease(lg.ID)),
		clientv3.OpPut(s.k(kLeaseExp), i64(expMs)),
	}
	// Else 分支回读现状，便于诊断是哪一项条件不成立。
	elseOps := []clientv3.Op{
		clientv3.OpGet(s.k(kEpoch)), clientv3.OpGet(s.k(kLease)),
		clientv3.OpGet(s.k(kEpochMeta)), clientv3.OpGet(s.k(kDesired)),
	}

	resp, err := s.cli.Txn(ctx).If(cmp...).Then(puts...).Else(elseOps...).Commit()
	if err != nil {
		return LeaseStatus{}, fmt.Errorf("poc: AcquireOwner txn 失败: %w", err)
	}
	if !resp.Succeeded {
		diag := s.diagnose(resp)
		// txn 失败 ⇒ 租约无用，撤销以免泄漏。
		_, _ = s.cli.Revoke(ctx, lg.ID)
		return LeaseStatus{}, fmt.Errorf("%w: %s", ErrGroupStaleEpoch, diag)
	}

	return LeaseStatus{
		Holder: req.Member, HolderBootID: req.BootID, DC: req.DC,
		Epoch: newEpoch, ExpiresAt: time.UnixMilli(expMs),
		StoreRevision: resp.Header.Revision,
	}, nil
}

// diagnose 从 Else 分支回读结果构造诊断信息。
func (s *EtcdControlStore) diagnose(resp *clientv3.TxnResponse) string {
	get := func(i int) string {
		if i < len(resp.Responses) {
			if r := resp.Responses[i].GetResponseRange(); r != nil && len(r.Kvs) > 0 {
				return string(r.Kvs[0].Value)
			}
		}
		return "<不存在>"
	}
	return fmt.Sprintf("epoch=%s lease=%s epochmeta=%s desired=%s",
		get(0), get(1), get(2), get(3))
}

// RenewOwner 续租：boot_id 与 epoch 必须同时匹配（D-17）。
func (s *EtcdControlStore) RenewOwner(ctx context.Context, member, bootID string, epoch uint64, ttl time.Duration) error {
	resp, err := s.cli.Get(ctx, s.k(kLease))
	if err != nil {
		return fmt.Errorf("poc: 读取租约失败: %w", err)
	}
	if len(resp.Kvs) == 0 {
		return fmt.Errorf("%w: 无组主租约", ErrGroupFenced)
	}
	p := strings.Split(string(resp.Kvs[0].Value), "|")
	if len(p) != 4 {
		return fmt.Errorf("%w: 租约值损坏", ErrGroupFenced)
	}
	if p[0] != member || p[1] != bootID || p[2] != u64(epoch) {
		return fmt.Errorf("%w: 持有者/boot_id/epoch 不匹配（期望 %s/%s/%d，实际 %s/%s/%s）",
			ErrGroupFenced, member, bootID, epoch, p[0], p[1], p[2])
	}
	leaseID, err := strconv.ParseInt(p[3], 10, 64)
	if err != nil {
		return fmt.Errorf("%w: 租约 ID 损坏", ErrGroupFenced)
	}
	// KeepAliveOnce：租约已过期（etcd 已删键/lease 已失效）即失败。
	if _, err := s.cli.KeepAliveOnce(ctx, clientv3.LeaseID(leaseID)); err != nil {
		return fmt.Errorf("%w: 租约已失效: %v", ErrGroupFenced, err)
	}
	// leaseexp 仅为观测镜像，best-effort 刷新。
	if tl, err := s.cli.TimeToLive(ctx, clientv3.LeaseID(leaseID)); err == nil && tl.TTL > 0 {
		_, _ = s.cli.Put(ctx, s.k(kLeaseExp), i64(time.Now().Add(time.Duration(tl.TTL)*time.Second).UnixMilli()))
	}
	return nil
}

// ReleaseOwner 主动释放（撤销 etcd 租约 ⇒ lease 键随之删除）。
func (s *EtcdControlStore) ReleaseOwner(ctx context.Context, member, bootID string, epoch uint64) error {
	resp, err := s.cli.Get(ctx, s.k(kLease))
	if err != nil {
		return fmt.Errorf("poc: 读取租约失败: %w", err)
	}
	if len(resp.Kvs) == 0 {
		return fmt.Errorf("%w: 无组主租约", ErrGroupFenced)
	}
	p := strings.Split(string(resp.Kvs[0].Value), "|")
	if len(p) != 4 || p[0] != member || p[1] != bootID || p[2] != u64(epoch) {
		return fmt.Errorf("%w: 非持有者或 boot_id/epoch 不匹配", ErrGroupFenced)
	}
	leaseID, err := strconv.ParseInt(p[3], 10, 64)
	if err != nil {
		return fmt.Errorf("%w: 租约 ID 损坏", ErrGroupFenced)
	}
	if _, err := s.cli.Revoke(ctx, clientv3.LeaseID(leaseID)); err != nil {
		return fmt.Errorf("poc: 撤销租约失败: %w", err)
	}
	return nil
}

// SetDesired 由 admin 写入期望状态（版本 +1）。
func (s *EtcdControlStore) SetDesired(ctx context.Context) (uint64, error) {
	resp, err := s.cli.Get(ctx, s.k(kDesired))
	if err != nil {
		return 0, err
	}
	cur := uint64(0)
	if len(resp.Kvs) > 0 {
		cur, _ = strconv.ParseUint(string(resp.Kvs[0].Value), 10, 64)
	}
	next := cur + 1
	if _, err := s.cli.Put(ctx, s.k(kDesired), u64(next)); err != nil {
		return 0, err
	}
	return next, nil
}

// CreateApproval 创建双签审批；**审批键绑定 etcd 租约，租约即有效期**
// （过期自动删除 ⇒ AcquireOwner 的 CreateRevision>0 比较天然拒绝过期审批）。
func (s *EtcdControlStore) CreateApproval(ctx context.Context, a Approval) error {
	if a.ApprovalID == "" || a.Digest == "" {
		return fmt.Errorf("%w: 审批缺 ID 或 digest", ErrApprovalDigestBad)
	}
	ttl := time.Until(a.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("%w: 审批已过期", ErrApprovalNotFound)
	}
	lg, err := s.cli.Grant(ctx, int64(ttl/time.Second))
	if err != nil {
		return err
	}
	blob, err := json.Marshal(a)
	if err != nil {
		return err
	}
	// 值为 digest（比较基准）；完整结构另行存储于 approvals/full/{id} 供审计读取。
	resp, err := s.cli.Txn(ctx).
		If(clientv3.Compare(clientv3.CreateRevision(s.k(kApprovals, a.ApprovalID)), "=", 0)).
		Then(
			clientv3.OpPut(s.k(kApprovals, a.ApprovalID), a.Digest, clientv3.WithLease(lg.ID)),
			clientv3.OpPut(s.k(kApprovals, "full", a.ApprovalID), string(blob)),
		).
		Else(clientv3.OpGet(s.k(kApprovals, a.ApprovalID))).Commit()
	if err != nil {
		return err
	}
	if !resp.Succeeded {
		// 已存在：同 digest 则刷新租约（幂等复跑），digest 不同则拒绝（禁止改签）。
		existing := ""
		if r := resp.Responses[0].GetResponseRange(); r != nil && len(r.Kvs) > 0 {
			existing = string(r.Kvs[0].Value)
		}
		if existing != a.Digest {
			return fmt.Errorf("%w: 审批 %s 已存在且 digest 不同", ErrApprovalDigestBad, a.ApprovalID)
		}
		if _, err := s.cli.Put(ctx, s.k(kApprovals, a.ApprovalID), a.Digest, clientv3.WithLease(lg.ID)); err != nil {
			return err
		}
	}
	return nil
}

// GetApproval 读取完整审批（审计/诊断用）。
func (s *EtcdControlStore) GetApproval(ctx context.Context, approvalID string) (Approval, error) {
	resp, err := s.cli.Get(ctx, s.k(kApprovals, "full", approvalID))
	if err != nil {
		return Approval{}, err
	}
	if len(resp.Kvs) == 0 {
		return Approval{}, fmt.Errorf("%w: %s", ErrApprovalNotFound, approvalID)
	}
	var a Approval
	if err := json.Unmarshal(resp.Kvs[0].Value, &a); err != nil {
		return Approval{}, err
	}
	return a, nil
}

// CreateKeyOp 创建 KeyOp（版本从 1 开始）。
func (s *EtcdControlStore) CreateKeyOp(ctx context.Context, op KeyOp) (int64, error) {
	op.Version = 1
	blob, err := json.Marshal(op)
	if err != nil {
		return 0, err
	}
	resp, err := s.cli.Txn(ctx).
		If(clientv3.Compare(clientv3.CreateRevision(s.k(kOps, op.OpID)), "=", 0)).
		Then(
			clientv3.OpPut(s.k(kOps, op.OpID), string(blob)),
			clientv3.OpPut(s.k(kOpVS, op.OpID), fmt.Sprintf("1|%s", op.Status)),
		).
		Else(clientv3.OpGet(s.k(kOps, op.OpID))).Commit()
	if err != nil {
		return 0, err
	}
	if !resp.Succeeded {
		return 0, fmt.Errorf("%w: KeyOp %s 已存在", ErrGroupCASConflict, op.OpID)
	}
	return resp.Header.Revision, nil
}

// CASKeyOp 比较并交换：expectedVersion/expectedStatus 任一不符即失败；
// claim 必须是**当前**组主（owner+epoch）且租约未过期——旧主不得覆盖新终态。
func (s *EtcdControlStore) CASKeyOp(ctx context.Context, opID string, expectedVersion int64, expectedStatus string, op KeyOp) (int64, error) {
	resp, err := s.cli.Get(ctx, s.k(kOps, opID))
	if err != nil {
		return 0, err
	}
	if len(resp.Kvs) == 0 {
		return 0, fmt.Errorf("%w: KeyOp %s 不存在", ErrGroupCASConflict, opID)
	}
	op.Version = expectedVersion + 1
	blob, err := json.Marshal(op)
	if err != nil {
		return 0, err
	}
	txnResp, err := s.cli.Txn(ctx).If(
		clientv3.Compare(clientv3.Value(s.k(kOpVS, opID)), "=", fmt.Sprintf("%d|%s", expectedVersion, expectedStatus)),
		clientv3.Compare(clientv3.Value(s.k(kClaim)), "=", fmt.Sprintf("%s|%d", op.ClaimOwner, op.ClaimEpoch)),
		clientv3.Compare(clientv3.CreateRevision(s.k(kLease)), ">", 0),
	).Then(
		clientv3.OpPut(s.k(kOps, opID), string(blob)),
		clientv3.OpPut(s.k(kOpVS, opID), fmt.Sprintf("%d|%s", op.Version, op.Status)),
	).Commit()
	if err != nil {
		return 0, err
	}
	if !txnResp.Succeeded {
		return 0, fmt.Errorf("%w: KeyOp %s 版本/状态不匹配或 claim 失效（期望 v%d/%s claim=%s/%d）",
			ErrGroupCASConflict, opID, expectedVersion, expectedStatus, op.ClaimOwner, op.ClaimEpoch)
	}
	return txnResp.Header.Revision, nil
}

// GetKeyOp 读取 KeyOp。
func (s *EtcdControlStore) GetKeyOp(ctx context.Context, opID string) (KeyOp, int64, error) {
	resp, err := s.cli.Get(ctx, s.k(kOps, opID))
	if err != nil {
		return KeyOp{}, 0, err
	}
	if len(resp.Kvs) == 0 {
		return KeyOp{}, 0, fmt.Errorf("%w: KeyOp %s 不存在", ErrGroupCASConflict, opID)
	}
	var op KeyOp
	if err := json.Unmarshal(resp.Kvs[0].Value, &op); err != nil {
		return KeyOp{}, 0, err
	}
	op.StoreRevision = resp.Kvs[0].ModRevision
	return op, op.Version, nil
}

// WatchKeyOps 从 fromRevision 之后开始监听 KeyOp（切换窗口续传，不丢不重）。
func (s *EtcdControlStore) WatchKeyOps(ctx context.Context, fromRevision int64) (<-chan KeyOp, error) {
	ch := make(chan KeyOp, 64)
	wctx, cancel := context.WithCancel(ctx)
	go func() {
		defer close(ch)
		defer cancel()
		wc := s.cli.Watch(wctx, s.k(kOps), clientv3.WithPrefix(), clientv3.WithRev(fromRevision+1))
		for wresp := range wc {
			if err := wresp.Err(); err != nil {
				// 监听错误（如 revision 被压缩）：关闭信道，由调用方感知事件缺失。
				return
			}
			for _, ev := range wresp.Events {
				if ev.Type != clientv3.EventTypePut {
					continue
				}
				var op KeyOp
				if err := json.Unmarshal(ev.Kv.Value, &op); err != nil {
					continue
				}
				op.StoreRevision = ev.Kv.ModRevision
				select {
				case ch <- op:
				case <-wctx.Done():
					return
				}
			}
		}
	}()
	return ch, nil
}

// PutKeyDirectory 写入目录项（含 MAC），版本 +1；写者身份随值持久化。
func (s *EtcdControlStore) PutKeyDirectory(ctx context.Context, keyID string, kd KeyDirectory, macKey []byte) (int64, error) {
	verResp, err := s.cli.Get(ctx, s.k(kDirVS, keyID))
	if err != nil {
		return 0, err
	}
	curVer := int64(0)
	if len(verResp.Kvs) > 0 {
		curVer, _ = strconv.ParseInt(string(verResp.Kvs[0].Value), 10, 64)
	}
	kd.Version = curVer + 1
	if kd.MAC == "" {
		mac, err := DirectoryMAC(kd, macKey)
		if err != nil {
			return 0, err
		}
		kd.MAC = hex.EncodeToString(mac)
	}
	blob, err := CanonicalJSON(kd)
	if err != nil {
		return 0, err
	}
	resp, err := s.cli.Put(ctx, s.k(kKeys, keyID), string(blob))
	if err != nil {
		return 0, err
	}
	if _, err := s.cli.Put(ctx, s.k(kDirVS, keyID), i64(kd.Version)); err != nil {
		return 0, err
	}
	return resp.Header.Revision, nil
}

// CASKeyDirectory 目录 CAS 写：版本 + 写者身份（epoch+boot_id）+ 租约存在，三重校验。
func (s *EtcdControlStore) CASKeyDirectory(ctx context.Context, keyID string, expectedVersion int64,
	writerEpoch uint64, writerBootID string, kd KeyDirectory) (int64, error) {

	kd.Version = expectedVersion + 1
	mac, err := DirectoryMAC(kd, s.macKeyForTest(keyID))
	if err != nil {
		return 0, err
	}
	kd.MAC = hex.EncodeToString(mac)
	blob, err := CanonicalJSON(kd)
	if err != nil {
		return 0, err
	}
	// 首写时 dirvs 键不存在（等价版本 0）：用 CreateRevision 比较；
	// 非首写用 Value 比较。两者都保证"键在窗口内被他人改动即失败"。
	var verCmp clientv3.Cmp
	if expectedVersion == 0 {
		verCmp = clientv3.Compare(clientv3.CreateRevision(s.k(kDirVS, keyID)), "=", 0)
	} else {
		verCmp = clientv3.Compare(clientv3.Value(s.k(kDirVS, keyID)), "=", i64(expectedVersion))
	}
	resp, err := s.cli.Txn(ctx).If(
		verCmp,
		clientv3.Compare(clientv3.Value(s.k(kWriter)), "=", fmt.Sprintf("%d|%s", writerEpoch, writerBootID)),
		clientv3.Compare(clientv3.CreateRevision(s.k(kLease)), ">", 0),
	).Then(
		clientv3.OpPut(s.k(kKeys, keyID), string(blob)),
		clientv3.OpPut(s.k(kDirVS, keyID), i64(kd.Version)),
	).Commit()
	if err != nil {
		return 0, err
	}
	if !resp.Succeeded {
		return 0, fmt.Errorf("%w: 目录 %s 版本/写者身份/租约校验失败（期望 v%d writer=%d/%s）",
			ErrGroupCASConflict, keyID, expectedVersion, writerEpoch, writerBootID)
	}
	return resp.Header.Revision, nil
}

// macKeyForTest 目录 MAC 测试密钥（真实环境取自 HSM 内 directory_mac_key_ref）。
func (s *EtcdControlStore) macKeyForTest(keyID string) []byte {
	return []byte("p2-3-poc-directory-mac-key-32b")
}

// GetKeyDirectory 读取并**校验 MAC**（读者侧；校验失败返回 ErrDirectoryMACInvalid）。
func (s *EtcdControlStore) GetKeyDirectory(ctx context.Context, keyID string) (KeyDirectory, int64, error) {
	resp, err := s.cli.Get(ctx, s.k(kKeys, keyID))
	if err != nil {
		return KeyDirectory{}, 0, err
	}
	if len(resp.Kvs) == 0 {
		return KeyDirectory{}, 0, fmt.Errorf("%w: 目录 %s 不存在", ErrGroupNoLeader, keyID)
	}
	var kd KeyDirectory
	if err := DecodeStrict(resp.Kvs[0].Value, &kd); err != nil {
		return KeyDirectory{}, 0, fmt.Errorf("%w: 目录 %s 反序列化失败（未知字段/格式错误）: %v",
			ErrDirectoryMACInvalid, keyID, err)
	}
	if err := VerifyDirectoryMAC(kd, s.macKeyForTest(keyID)); err != nil {
		return KeyDirectory{}, 0, err
	}
	verResp, err := s.cli.Get(ctx, s.k(kDirVS, keyID))
	if err != nil {
		return KeyDirectory{}, 0, err
	}
	ver := int64(0)
	if len(verResp.Kvs) > 0 {
		ver, _ = strconv.ParseInt(string(verResp.Kvs[0].Value), 10, 64)
	}
	return kd, ver, nil
}

// GetKeyDirectoryRaw 读取目录项**不做 MAC 校验**（仅供测试构造"已篡改但格式合法"的值）。
func (s *EtcdControlStore) GetKeyDirectoryRaw(ctx context.Context, keyID string) (KeyDirectory, error) {
	resp, err := s.cli.Get(ctx, s.k(kKeys, keyID))
	if err != nil {
		return KeyDirectory{}, err
	}
	if len(resp.Kvs) == 0 {
		return KeyDirectory{}, fmt.Errorf("目录 %s 不存在", keyID)
	}
	var kd KeyDirectory
	if err := json.Unmarshal(resp.Kvs[0].Value, &kd); err != nil {
		return KeyDirectory{}, err
	}
	return kd, nil
}

// PutKeyDirectoryRaw 原样写入目录项字节（测试用：制造 MAC 不匹配的篡改值）。
func (s *EtcdControlStore) PutKeyDirectoryRaw(ctx context.Context, keyID string, blob []byte) error {
	_, err := s.cli.Put(ctx, s.k(kKeys, keyID), string(blob))
	return err
}
