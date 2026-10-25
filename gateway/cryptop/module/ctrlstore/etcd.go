// Package ctrlstore 是 P2-3 组控制存储的 **etcd 产品实现**（U-6：生产 etcd v3 全量、单 txn）。
//
// 来源：由 testkit/poc/etcdstore.go（真机 POC 参考实现）提升为主模块产品代码，
// 类型与工具统一改用 testkit 契约（原 POC 自带一套同构重复类型）。**产品实现以本包为准**，
// POC 继续作为真机验证基线；两者键布局一致（/cryptop 前缀，本体 §6.2.2 控制存储表），
// 由同一组真机测试共同约束。
//
// 原子性设计（本体 §3.1.1 算法 2 / D-17）：租约抢占、目录 CAS 等写路径的**全部条件**
// 放在单个 etcd txn 的 Compare 集合中，不存在"读后写"竞态窗口。
//
// 与 POC 的差异（有意为之）：
//   - 目录 MAC 密钥由构造函数**注入**（生产取自 HSM 内 directory_mac_key_ref），
//     不再硬编码测试密钥；
//   - 不含审批（Approval）方法——审批属 backup.ApprovalStore 契约（§7.2 T-2），
//     其 etcd 实现随 T-4 协作者一并落地；
//   - 删除仅供测试的 Reset / PutKeyDirectory / GetKeyDirectoryRaw / PutKeyDirectoryRaw。
package ctrlstore

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
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"security-ai-gateway/gateway/cryptop/module/testkit"
)

// ErrDirectoryMACInvalid 目录 MAC 校验失败（读者侧；写入侧由 DirectoryMAC 保证非空密钥）。
var ErrDirectoryMACInvalid = errors.New("ctrlstore: directory_mac_invalid")

// KeyPrefix 控制存储键前缀（与本体 §6.2.2 控制存储表一致）。
//
// 与 POC 侧 TestPrefix 同值（"/cryptop"）：两者键布局必须一致，
// 才能用同一组真机测试同时约束产品实现与 POC 参考实现。
const KeyPrefix = "/cryptop"

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

// EtcdControlStore etcd 版控制存储（产品实现，U-6）。
type EtcdControlStore struct {
	cli *clientv3.Client
	gid string
	// dirMACKey 目录 MAC 密钥：生产取自 HSM 内 directory_mac_key_ref，经构造函数注入。
	// 不得硬编码——testkit.DirectoryMAC 对空密钥一律报错（§6.2.2 禁止退化为无 MAC 目录）。
	dirMACKey []byte
}

// NewEtcdControlStore 连接 etcd 并初始化组前缀。
//
// dirMACKey 为目录 MAC 密钥（生产取自 HSM 内 directory_mac_key_ref），**不得为空**。
// 与 POC 版的差异：本函数**不清理既有数据**（Reset 语义只适用于可重复执行的测试用例，
// 生产绝不能在连接时清空控制面）；desired 仅在键不存在时初始化为 0，不覆盖既有值。
func NewEtcdControlStore(ctx context.Context, endpoints []string, gid string, dirMACKey []byte) (*EtcdControlStore, error) {
	if len(dirMACKey) == 0 {
		return nil, errors.New("ctrlstore: 目录 MAC 密钥为空（§6.2.2：无 MAC 密钥时目录写入一律失败）")
	}
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("ctrlstore: 连接 etcd 失败: %w", err)
	}
	s := &EtcdControlStore{cli: cli, gid: gid, dirMACKey: dirMACKey}
	// desired 初始版本 0（仅当键不存在时；bootstrap 路径据此比较）。不覆盖既有值。
	if _, err := cli.Txn(ctx).
		If(clientv3.Compare(clientv3.CreateRevision(s.k(kDesired)), "=", 0)).
		Then(clientv3.OpPut(s.k(kDesired), "0")).
		Commit(); err != nil {
		cli.Close()
		return nil, fmt.Errorf("ctrlstore: 初始化 desired 失败: %w", err)
	}
	return s, nil
}

// NewEtcdControlStoreAuth 以指定身份连接 etcd（RBAC：按成员身份建客户端，实现最小权限）。
func NewEtcdControlStoreAuth(ctx context.Context, endpoints []string, gid, user, pass string, dirMACKey []byte) (*EtcdControlStore, error) {
	if len(dirMACKey) == 0 {
		return nil, errors.New("ctrlstore: 目录 MAC 密钥为空（§6.2.2：无 MAC 密钥时目录写入一律失败）")
	}
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: 5 * time.Second,
		Username:    user,
		Password:    pass,
	})
	if err != nil {
		return nil, fmt.Errorf("ctrlstore: 以 %s 连接 etcd 失败: %w", user, err)
	}
	s := &EtcdControlStore{cli: cli, gid: gid, dirMACKey: dirMACKey}
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

func (s *EtcdControlStore) groupPrefix() string {
	return fmt.Sprintf("%s/groups/%s/", KeyPrefix, s.gid)
}

func (s *EtcdControlStore) k(parts ...string) string {
	return s.groupPrefix() + strings.Join(parts, "/")
}

func u64(v uint64) string { return strconv.FormatUint(v, 10) }

func i64(v int64) string { return strconv.FormatInt(v, 10) }

// GetOwnerState 读取持久 epoch 与当前租约（只读观测）。
func (s *EtcdControlStore) GetOwnerState(ctx context.Context) (testkit.OwnerState, error) {
	resp, err := s.cli.Get(ctx, s.groupPrefix(), clientv3.WithPrefix())
	if err != nil {
		return testkit.OwnerState{}, fmt.Errorf("ctrlstore: 读取组状态失败: %w", err)
	}
	kv := map[string]string{}
	for _, ev := range resp.Kvs {
		kv[string(ev.Key)] = string(ev.Value)
	}
	st := testkit.OwnerState{StoreRevision: resp.Header.Revision}
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
			ls := &testkit.LeaseStatus{
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
func (s *EtcdControlStore) AcquireOwner(ctx context.Context, req testkit.OwnerAcquireRequest) (testkit.LeaseStatus, error) {
	if req.Promotion != nil && req.Promotion.TargetMember != req.Member {
		return testkit.LeaseStatus{}, fmt.Errorf("%w: promotion 目标 %s 不是本成员 %s",
			testkit.ErrGroupStaleEpoch, req.Promotion.TargetMember, req.Member)
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	lg, err := s.cli.Grant(ctx, int64(ttl/time.Second))
	if err != nil {
		return testkit.LeaseStatus{}, fmt.Errorf("ctrlstore: 申请 etcd 租约失败: %w", err)
	}

	// 路径选择基于只读探测；**权威判定全部在 txn Compare 内**，探测过期只会导致
	// txn 失败（fail-closed），不会导致错误放行。
	st, err := s.GetOwnerState(ctx)
	if err != nil {
		return testkit.LeaseStatus{}, err
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
			return testkit.LeaseStatus{}, fmt.Errorf("%w: 未开启同 DC 自动接管", testkit.ErrGroupStaleEpoch)
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
			return testkit.LeaseStatus{}, fmt.Errorf("%w: 首次建主需 AllowBootstrap", testkit.ErrGroupStaleEpoch)
		}
		if req.BootstrapOwner == "" || req.BootstrapOwner != req.Member {
			return testkit.LeaseStatus{}, fmt.Errorf("%w: bootstrap_owner 必须是本成员", testkit.ErrGroupStaleEpoch)
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
		return testkit.LeaseStatus{}, fmt.Errorf("ctrlstore: AcquireOwner txn 失败: %w", err)
	}
	if !resp.Succeeded {
		diag := s.diagnose(resp)
		// txn 失败 ⇒ 租约无用，撤销以免泄漏。
		_, _ = s.cli.Revoke(ctx, lg.ID)
		return testkit.LeaseStatus{}, fmt.Errorf("%w: %s", testkit.ErrGroupStaleEpoch, diag)
	}

	return testkit.LeaseStatus{
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
		return fmt.Errorf("ctrlstore: 读取租约失败: %w", err)
	}
	if len(resp.Kvs) == 0 {
		return fmt.Errorf("%w: 无组主租约", testkit.ErrGroupFenced)
	}
	p := strings.Split(string(resp.Kvs[0].Value), "|")
	if len(p) != 4 {
		return fmt.Errorf("%w: 租约值损坏", testkit.ErrGroupFenced)
	}
	if p[0] != member || p[1] != bootID || p[2] != u64(epoch) {
		return fmt.Errorf("%w: 持有者/boot_id/epoch 不匹配（期望 %s/%s/%d，实际 %s/%s/%s）",
			testkit.ErrGroupFenced, member, bootID, epoch, p[0], p[1], p[2])
	}
	leaseID, err := strconv.ParseInt(p[3], 10, 64)
	if err != nil {
		return fmt.Errorf("%w: 租约 ID 损坏", testkit.ErrGroupFenced)
	}
	// KeepAliveOnce：租约已过期（etcd 已删键/lease 已失效）即失败。
	if _, err := s.cli.KeepAliveOnce(ctx, clientv3.LeaseID(leaseID)); err != nil {
		return fmt.Errorf("%w: 租约已失效: %v", testkit.ErrGroupFenced, err)
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
		return fmt.Errorf("ctrlstore: 读取租约失败: %w", err)
	}
	if len(resp.Kvs) == 0 {
		return fmt.Errorf("%w: 无组主租约", testkit.ErrGroupFenced)
	}
	p := strings.Split(string(resp.Kvs[0].Value), "|")
	if len(p) != 4 || p[0] != member || p[1] != bootID || p[2] != u64(epoch) {
		return fmt.Errorf("%w: 非持有者或 boot_id/epoch 不匹配", testkit.ErrGroupFenced)
	}
	leaseID, err := strconv.ParseInt(p[3], 10, 64)
	if err != nil {
		return fmt.Errorf("%w: 租约 ID 损坏", testkit.ErrGroupFenced)
	}
	if _, err := s.cli.Revoke(ctx, clientv3.LeaseID(leaseID)); err != nil {
		return fmt.Errorf("ctrlstore: 撤销租约失败: %w", err)
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

// CreateKeyOp 创建 testkit.KeyOp（版本从 1 开始）。
func (s *EtcdControlStore) CreateKeyOp(ctx context.Context, op testkit.KeyOp) (int64, error) {
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
		return 0, fmt.Errorf("%w: testkit.KeyOp %s 已存在", testkit.ErrGroupCASConflict, op.OpID)
	}
	return resp.Header.Revision, nil
}

// CASKeyOp 比较并交换：expectedVersion/expectedStatus 任一不符即失败；
// claim 必须是**当前**组主（owner+epoch）且租约未过期——旧主不得覆盖新终态。
func (s *EtcdControlStore) CASKeyOp(ctx context.Context, opID string, expectedVersion int64, expectedStatus string, op testkit.KeyOp) (int64, error) {
	resp, err := s.cli.Get(ctx, s.k(kOps, opID))
	if err != nil {
		return 0, err
	}
	if len(resp.Kvs) == 0 {
		return 0, fmt.Errorf("%w: testkit.KeyOp %s 不存在", testkit.ErrGroupCASConflict, opID)
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
		return 0, fmt.Errorf("%w: testkit.KeyOp %s 版本/状态不匹配或 claim 失效（期望 v%d/%s claim=%s/%d）",
			testkit.ErrGroupCASConflict, opID, expectedVersion, expectedStatus, op.ClaimOwner, op.ClaimEpoch)
	}
	return txnResp.Header.Revision, nil
}

// GetKeyOp 读取 testkit.KeyOp。
func (s *EtcdControlStore) GetKeyOp(ctx context.Context, opID string) (testkit.KeyOp, int64, error) {
	resp, err := s.cli.Get(ctx, s.k(kOps, opID))
	if err != nil {
		return testkit.KeyOp{}, 0, err
	}
	if len(resp.Kvs) == 0 {
		return testkit.KeyOp{}, 0, fmt.Errorf("%w: testkit.KeyOp %s 不存在", testkit.ErrGroupCASConflict, opID)
	}
	var op testkit.KeyOp
	if err := json.Unmarshal(resp.Kvs[0].Value, &op); err != nil {
		return testkit.KeyOp{}, 0, err
	}
	op.StoreRevision = resp.Kvs[0].ModRevision
	return op, op.Version, nil
}

// WatchKeyOps 从 fromRevision 之后开始监听 testkit.KeyOp（切换窗口续传，不丢不重）。
func (s *EtcdControlStore) WatchKeyOps(ctx context.Context, fromRevision int64) (<-chan testkit.KeyOp, error) {
	ch := make(chan testkit.KeyOp, 64)
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
				var op testkit.KeyOp
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

// ListKeyOps 返回 KeyOp **快照**（供无 context / 非流式消费侧使用）。
//
// 与 WatchKeyOps 的区别：WatchKeyOps 是长连接流式订阅（返回信道），
// 而 group.ControlStore 契约是快照语义（返回切片），故需本方法桥接。
// 仅返回 ModRevision > fromRevision 的项（fromRevision<=0 时返回全部）。
func (s *EtcdControlStore) ListKeyOps(ctx context.Context, fromRevision int64) ([]testkit.KeyOp, error) {
	resp, err := s.cli.Get(ctx, s.k(kOps), clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}
	out := make([]testkit.KeyOp, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		if kv.ModRevision <= fromRevision {
			continue
		}
		var op testkit.KeyOp
		if err := json.Unmarshal(kv.Value, &op); err != nil {
			continue
		}
		op.StoreRevision = kv.ModRevision
		out = append(out, op)
	}
	return out, nil
}

// CASKeyDirectory 目录 CAS 写：版本 + 写者身份（epoch+boot_id）+ 租约存在，三重校验。
func (s *EtcdControlStore) CASKeyDirectory(ctx context.Context, keyID string, expectedVersion int64,
	writerEpoch uint64, writerBootID string, kd testkit.KeyDirectory) (int64, error) {

	kd.Version = expectedVersion + 1
	mac, err := testkit.DirectoryMAC(kd, s.dirMACKey)
	if err != nil {
		return 0, err
	}
	kd.MAC = hex.EncodeToString(mac)
	blob, err := testkit.CanonicalJSON(kd)
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
			testkit.ErrGroupCASConflict, keyID, expectedVersion, writerEpoch, writerBootID)
	}
	return resp.Header.Revision, nil
}

// GetKeyDirectory 读取并**校验 MAC**（读者侧；校验失败返回 ErrDirectoryMACInvalid）。
func (s *EtcdControlStore) GetKeyDirectory(ctx context.Context, keyID string) (testkit.KeyDirectory, int64, error) {
	resp, err := s.cli.Get(ctx, s.k(kKeys, keyID))
	if err != nil {
		return testkit.KeyDirectory{}, 0, err
	}
	if len(resp.Kvs) == 0 {
		return testkit.KeyDirectory{}, 0, fmt.Errorf("%w: 目录 %s 不存在", testkit.ErrGroupNoLeader, keyID)
	}
	var kd testkit.KeyDirectory
	if err := testkit.DecodeStrict(resp.Kvs[0].Value, &kd); err != nil {
		return testkit.KeyDirectory{}, 0, fmt.Errorf("%w: 目录 %s 反序列化失败（未知字段/格式错误）: %v",
			ErrDirectoryMACInvalid, keyID, err)
	}
	if err := testkit.VerifyDirectoryMAC(kd, s.dirMACKey); err != nil {
		// 包装为本包错误：① 调用方可 errors.Is 判定；② 不把 testkit 内部错误
		// （带 "testkit:" 前缀）直接透传到产品链路。
		return testkit.KeyDirectory{}, 0, fmt.Errorf("%w: 目录 %s MAC 校验失败（疑似被篡改或键序/格式不符合 canonical）: %v",
			ErrDirectoryMACInvalid, keyID, err)
	}
	verResp, err := s.cli.Get(ctx, s.k(kDirVS, keyID))
	if err != nil {
		return testkit.KeyDirectory{}, 0, err
	}
	ver := int64(0)
	if len(verResp.Kvs) > 0 {
		ver, _ = strconv.ParseInt(string(verResp.Kvs[0].Value), 10, 64)
	}
	return kd, ver, nil
}
