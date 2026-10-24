package group

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"security-ai-gateway/gateway/cryptop/module/testkit"
)

// 本文件承载 P2-3 **T-3 跨机房容灾**的骨架（§16.2：硬件依赖「中」→「骨架可先，真机 Wave B」）。
//
// 口径依据：G-2 / D-3 / D-8 / R-5 / §7.2 T-3：
//   - **同 DC 允许自动接管，跨 DC 只能人工 promotion + 双签审批**（D-8）；
//   - 跨 DC **禁止自动紧急切换**，不计入 V-1（V-1 原文）；
//   - 旧主 fencing 双重：租约过期 + `PartitionRevoke`/网络隔离（D-8）；
//   - 延时预算按 R2-07 扩展跨 DC RTT，**禁止对网络形态套用 50ms localhost 口径**（R-5）；
//   - `vendor_admin.endpoint` 仅用于 `PartitionRevoke`/会话清理，**不得用于数据面**；
//     能力探测失败按"不支持"降级并告警，**不得静默当作支持**（L453）。
//
// **边界**：本文件只交付 DC 拓扑、promotion 编排、预算判据与撤销接口骨架；
// RTO 实测、真机切换演练、跨 DC 网络联调均属 Wave B（需借测硬件/真实 DC 环境），
// 因此本骨架**不宣称跨机房容灾已具备、不宣称 V-2/V-7 通过**。

// 跨机房容灾相关错误。
var (
	// ErrPromotionApprovalRequired 跨 DC promotion 缺双签审批单（D-8 强制）。
	ErrPromotionApprovalRequired = errors.New("group_promotion_approval_required")
	// ErrCrossDCAutoForbidden 跨 DC 禁止自动切换（D-8 / V-1）。
	ErrCrossDCAutoForbidden = errors.New("group_cross_dc_auto_forbidden")
	// ErrLatencyBudgetExceeded 实测 RTT 超延时预算（R-5 / D-3）。
	ErrLatencyBudgetExceeded = errors.New("group_latency_budget_exceeded")
	// ErrLocalhostCaliberOnNetwork 网络形态套用了 localhost 口径（R-5 明令禁止）。
	ErrLocalhostCaliberOnNetwork = errors.New("group_localhost_caliber_on_network")
	// ErrVendorAdminUnsupported 厂商管理面不支持 PartitionRevoke：调用方须转降级+告警。
	ErrVendorAdminUnsupported = errors.New("group_vendor_admin_unsupported")
)

// ---------------------------------------------------------------------------
// DC 拓扑
// ---------------------------------------------------------------------------

// DCTopology 模块组的机房拓扑：成员 → 机房（DC）映射。
type DCTopology struct {
	memberDC map[string]string
}

// NewDCTopology 构造拓扑（内部拷贝，防止调用方后续修改影响判定）。
func NewDCTopology(memberDC map[string]string) *DCTopology {
	cp := make(map[string]string, len(memberDC))
	for m, dc := range memberDC {
		cp[m] = dc
	}
	return &DCTopology{memberDC: cp}
}

// DC 返回成员所在机房；未知成员返回空串。
func (t *DCTopology) DC(member string) string { return t.memberDC[member] }

// IsCrossDC 判定两个成员是否跨机房。
//
// 任一方 DC 未知时返回 false（保守口径：拓扑不完整时不走 promotion 路径，
// 避免在信息缺失下误判为"可跨 DC 切换"）。
func (t *DCTopology) IsCrossDC(a, b string) bool {
	da, db := t.memberDC[a], t.memberDC[b]
	if da == "" || db == "" {
		return false
	}
	return da != db
}

// DCs 返回全部机房名（去重、升序，保证输出稳定可测）。
func (t *DCTopology) DCs() []string {
	seen := map[string]bool{}
	var out []string
	for _, dc := range t.memberDC {
		if dc == "" || seen[dc] {
			continue
		}
		seen[dc] = true
		out = append(out, dc)
	}
	sort.Strings(out)
	return out
}

// MembersIn 返回指定机房下的全部成员（升序）。
func (t *DCTopology) MembersIn(dc string) []string {
	var out []string
	for m, d := range t.memberDC {
		if d == dc {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// 延时预算（R-5 / D-3 / R2-07）
// ---------------------------------------------------------------------------

// AccessForm 访问形态：沿用 P1-5 D-5 二分，不重定义（D-3）。
type AccessForm string

const (
	AccessLocal   AccessForm = "local"   // 本机设备
	AccessNetwork AccessForm = "network" // 网络密码机 / 云服务
)

// LatencyBudget 延时预算：分形态配置，跨 DC 叠加附加 RTT。
type LatencyBudget struct {
	LocalRTT   time.Duration // 本机形态预算（P1-5 既有机内口径）
	NetworkRTT time.Duration // 网络形态预算（须按部署实测；不得等于/小于 localhost 口径）
	CrossDCRTT time.Duration // 跨 DC 附加 RTT（D-3：按 R2-07 扩展）
}

// DefaultLatencyBudget 默认预算：网络形态与跨 DC 均为占位值，
// 生产必须按部署实测覆盖（R-5：以实测替换标称）。
func DefaultLatencyBudget() LatencyBudget {
	return LatencyBudget{
		LocalRTT:   50 * time.Millisecond,
		NetworkRTT: 200 * time.Millisecond,
		CrossDCRTT: 100 * time.Millisecond,
	}
}

// BudgetFor 返回该形态（含是否跨 DC）的端到端 RTT 预算。
func (b LatencyBudget) BudgetFor(form AccessForm, crossDC bool) time.Duration {
	base := b.LocalRTT
	if form == AccessNetwork {
		base = b.NetworkRTT
	}
	if crossDC {
		base += b.CrossDCRTT
	}
	return base
}

// Validate 校验延时口径：
//  1. 网络形态不得套用 localhost 50ms 口径（R-5 明令禁止）—— 配置层硬伤直接拒；
//  2. 实测 RTT 不得超该形态（含跨 DC 附加）的预算。
func (b LatencyBudget) Validate(form AccessForm, crossDC bool, measuredRTT time.Duration) error {
	if form == AccessNetwork && b.NetworkRTT <= 50*time.Millisecond {
		return fmt.Errorf("%w: network 形态预算 %v 不应沿用 localhost 50ms 口径",
			ErrLocalhostCaliberOnNetwork, b.NetworkRTT)
	}
	budget := b.BudgetFor(form, crossDC)
	if measuredRTT > budget {
		return fmt.Errorf("%w: 实测 %v 超预算 %v（form=%s crossDC=%v）",
			ErrLatencyBudgetExceeded, measuredRTT, budget, form, crossDC)
	}
	return nil
}

// ---------------------------------------------------------------------------
// 跨 DC 人工 promotion（D-8）
// ---------------------------------------------------------------------------

// Promote 跨 DC 人工 promotion：本成员接管组主。
//
// 语义（D-8 / V-1）：
//   - 必须携带双签审批单（approvalID + digest），缺一即拒；
//   - **跨 DC 永远不自动切换**——本方法只应被管理面在人工确认后调用；
//   - 成功后本成员成为新组主，epoch 递增；失败（epoch 变化/审批不符/已有租约）
//     返回错误并保持非组主。
func (c *Coordinator) Promote(approvalID, digest string) (testkit.LeaseStatus, error) {
	if approvalID == "" || digest == "" {
		return testkit.LeaseStatus{}, ErrPromotionApprovalRequired
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	st := c.store.GetOwnerState()
	promo := &testkit.Promotion{
		TargetMember:  c.self,
		ExpectedEpoch: st.Epoch,
		ApprovalID:    approvalID,
		Digest:        digest,
	}
	return c.acquireLocked(false, promo)
}

// ---------------------------------------------------------------------------
// 厂商管理面：PartitionRevoke（旧主 fencing 第二重，D-8 / L382 / L453）
// ---------------------------------------------------------------------------

// PartitionRevoker 厂商管理面能力：仅用于 PartitionRevoke / 会话清理，
// **不得用于数据面**（L382）。
type PartitionRevoker interface {
	// RevokePartition 撤销指定成员/分区的厂商侧会话。
	// member/partition 均为空表示"仅探测可达性"，实现应返回 nil。
	RevokePartition(member, partition string) error
}

// VendorAdminConfig 厂商管理面配置。
type VendorAdminConfig struct {
	Endpoint      string // 空 = 不支持，按降级登记（V-7）
	CredentialRef string
}

// VendorAdmin 封装 PartitionRevoke 能力探测与调用。
//
// L453 要求：启动时探测能力，**探测失败按"不支持"降级并告警，不得静默当作支持**。
type VendorAdmin struct {
	cfg       VendorAdminConfig
	revoker   PartitionRevoker
	probed    bool
	supported bool
}

// NewVendorAdmin 构造厂商管理面封装。
func NewVendorAdmin(cfg VendorAdminConfig, r PartitionRevoker) *VendorAdmin {
	return &VendorAdmin{cfg: cfg, revoker: r}
}

// Probe 探测 PartitionRevoke 能力：endpoint 为空 / 无实现 / 探测失败 → 不支持。
func (v *VendorAdmin) Probe() bool {
	v.probed = true
	v.supported = false
	if v.cfg.Endpoint == "" || v.revoker == nil {
		return false
	}
	// 以空参数调用实现，仅探测可达性。
	if err := v.revoker.RevokePartition("", ""); err != nil {
		return false
	}
	v.supported = true
	return true
}

// Supported 返回探测结果；**未探测前一律 false**（保守，避免未探测即当支持）。
func (v *VendorAdmin) Supported() bool { return v.probed && v.supported }

// Revoke 撤销旧主会话。不支持时返回 ErrVendorAdminUnsupported，
// 调用方必须转为"降级 + 告警"，**不得静默当作撤销成功**（D-8 双重 fencing 要求）。
func (v *VendorAdmin) Revoke(member, partition string) error {
	if !v.Supported() {
		return ErrVendorAdminUnsupported
	}
	return v.revoker.RevokePartition(member, partition)
}

// ---------------------------------------------------------------------------
// RTO 口径（G-2 / G-0②：RTO≤30s，RPO=0）
// ---------------------------------------------------------------------------

// RTOBudget 跨机房切换的 RTO 口径与实测记录。
//
// **边界**：骨架只提供计时与判据；RTO **实测值须由真机演练（T-7/Wave B）登记**，
// 未取得真实演练数据前 `WithinRTO()` 恒为 false——不得宣称达标。
type RTOBudget struct {
	MaxRTO     time.Duration
	Measured   time.Duration
	HasMeasure bool
}

// DefaultRTOBudget 默认 RTO 预算（G-0② 闭合时确定：RTO≤30s / RPO=0）。
func DefaultRTOBudget() RTOBudget { return RTOBudget{MaxRTO: 30 * time.Second} }

// Record 记录一次切换的实测耗时。
func (b *RTOBudget) Record(start, end time.Time) {
	b.Measured = end.Sub(start)
	b.HasMeasure = true
}

// WithinRTO 判定实测是否达标；**未实测返回 false**（不得宣称达标）。
func (b RTOBudget) WithinRTO() bool {
	return b.HasMeasure && b.Measured <= b.MaxRTO
}
