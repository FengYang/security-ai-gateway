// P2-4 T-1.7：**内容级版本判据**（防"配置静默回退"的主防线）。
//
// 背景（QA 实跑取证，P2）：纯 revision 判据**发现不了**内容回退——覆盖方写出的
// revision 仍是单调递增的（rev=7 > rev=6），只是内容退回到了旧版本
// （路由表 v9 → v3）。后果：新策略在下次重启后静默丢失，且**零告警**
// （那次覆盖是一次"正常成功写"）。纯时钟判据同样无效。
//
// 判据（**按表逐个比较；各表版本号互不可比，禁止跨表比大小**）：
//
//	磁盘版本 > 本地版本 ⇒ 拒绝写入（磁盘更新 ⇒ 本地陈旧，回写即内容回退）；
//	本地缺该表而磁盘有 ⇒ 拒绝写入（写出会抹掉磁盘上更新的内容）；
//	版本相同但内容不同 ⇒ 拒绝写入并告警（**版本契约被破坏**：同版本内容漂移 ⇒
//	  版本号已不可信 ⇒ 保守拒绝；该契约由核心 API 层保证"变更必递增版本"
//	  ——限流表/ACL 表下发时"同版本"直接被拒，路由表变更则自动 +1）；
//	其余（本地更新 / 磁盘缺该表 / 版本与内容均相同）⇒ 放行。
//
// ⚠️ 关于"本地版本 ≤ 磁盘版本 ⇒ 一律拒绝"的字面读法：**不可实现**。
// 单写者路径下，绝大多数域的本地版本与磁盘版本**相同**（本进程并未变更该表），
// 按字面读法会让**任何一次写盘都被拒** ⇒ 快照永久停写（与 QA P2-新 同类的
// 停滞缺陷）。故本实现取"**内容不回退**"语义：**只有当本次写盘会让磁盘上某个
// 域退步时才拒绝**（磁盘更新 / 本地缺失该表 / 同版本内容漂移）。
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// contentDomain 内容级判据的一个域（**一个策略表 = 一个域**）。
type contentDomain struct {
	// name 域名（告警文案；与快照载荷字段一一对应）。
	name string
	// payload 对应的快照载荷字段名（用于与覆盖清单交叉核对，防漏判）。
	payload string
	// version 取该域的自报版本与存在性（ok=false ⇒ 该域在快照中不存在）。
	version func(*snapshotPayload) (int, bool)
	// content 取该域的规范化内容字节（用于"同版本内容比对"）。
	content func(*snapshotPayload) ([]byte, error)
}

// contentDomains 参与内容级判据的域（**各表版本互不可比，只能逐表比较**）。
//
// 覆盖的域 = 快照载荷中**带自报版本号**的全部表；处方集合与 MCP 后端集合
// 无版本号 ⇒ 登记为"不参与内容判据"（见 nonVersionedDomains）。
var contentDomains = []contentDomain{
	{
		name:    "route_table",
		payload: "RouteTable",
		version: func(p *snapshotPayload) (int, bool) {
			if p.RouteTable == nil {
				return 0, false
			}
			return p.RouteTable.Version, true
		},
		content: func(p *snapshotPayload) ([]byte, error) {
			return json.Marshal(p.RouteTable)
		},
	},
	{
		name:    "rate_limit_table",
		payload: "RateLimitTable",
		version: func(p *snapshotPayload) (int, bool) {
			if p.RateLimitTable == nil {
				return 0, false
			}
			return p.RateLimitTable.Version, true
		},
		content: func(p *snapshotPayload) ([]byte, error) {
			return json.Marshal(p.RateLimitTable)
		},
	},
	{
		name:    "acl_table",
		payload: "ACLTable",
		version: func(p *snapshotPayload) (int, bool) {
			if p.ACLTable == nil {
				return 0, false
			}
			return p.ACLTable.Version, true
		},
		content: func(p *snapshotPayload) ([]byte, error) {
			return json.Marshal(p.ACLTable)
		},
	},
	{
		name:    "a2a_rate_limit_table",
		payload: "A2ARateLimitTable",
		version: func(p *snapshotPayload) (int, bool) {
			if p.A2ARateLimitTable == nil {
				return 0, false
			}
			return p.A2ARateLimitTable.Version, true
		},
		content: func(p *snapshotPayload) ([]byte, error) {
			return json.Marshal(p.A2ARateLimitTable)
		},
	},
	{
		name:    "tool_catalog",
		payload: "ToolCatalog",
		version: func(p *snapshotPayload) (int, bool) {
			if p.ToolCatalog == nil {
				return 0, false
			}
			return p.ToolCatalog.Version, true
		},
		content: func(p *snapshotPayload) ([]byte, error) {
			return json.Marshal(p.ToolCatalog)
		},
	},
	{
		name:    "rbac_policy",
		payload: "RBACPolicy",
		version: func(p *snapshotPayload) (int, bool) {
			if p.RBACPolicy == nil {
				return 0, false
			}
			return p.RBACPolicy.Version, true
		},
		content: func(p *snapshotPayload) ([]byte, error) {
			return json.Marshal(p.RBACPolicy)
		},
	},
}

// nonVersionedDomain 不参与内容判据的域登记（**必须显式登记，不允许默认漏判**）。
type nonVersionedDomain struct {
	// Name 域名（与快照载荷字段对应）。
	Name string
	// payload 对应的快照载荷字段名（用于与覆盖清单交叉核对，防漏判）。
	payload string
	// Reason 不参与内容判据的理由（评审检查点）。
	Reason string
}

// nonVersionedDomains **明确登记**为"不参与内容判据"的域。
//
// 理由（两类，均为"无法用版本号区分磁盘更新与本地合法变更"）：
//   - 处方集合：条目无自报版本；且"本地删除"是**合法业务**（吊销处方必须能
//     落盘），无法用集合大小区分"磁盘更新"与"本地合法删除"⇒ 保守比较会误拒
//     正常的吊销操作（业务不可接受）；
//   - MCP 后端集合：条目无自报版本；本地摘除后端是合法运维动作，同上。
//
// ⇒ 这两个域的"陈旧写者覆盖新内容"风险由**写者锁（lockfile）**兜底：
// 写者锁保证同一时刻只有一个写者，从而消除"判据比较与写盘之间"的 TOCTOU 窗口。
var nonVersionedDomains = []nonVersionedDomain{
	{
		Name:    "prescriptions",
		payload: "Prescriptions",
		Reason:  "处方条目无自报版本；本地吊销是合法业务（必须能落盘），无法用集合大小区分“磁盘更新”与“本地合法删除”⇒ 不参与内容判据，由写者锁兜底",
	},
	{
		Name:    "mcp_servers",
		payload: "MCPServers",
		Reason:  "MCP 后端条目无自报版本；本地摘除是合法运维动作，同上⇒ 不参与内容判据，由写者锁兜底",
	},
}

// contentConflict 一个内容级冲突（本次写盘会让磁盘上某个域退步）。
type contentConflict struct {
	// Domain 域名。
	Domain string
	// DiskVersion 磁盘侧版本（域不存在时为 0）。
	DiskVersion int
	// LocalVersion 本地侧版本（域不存在时为 0）。
	LocalVersion int
	// Reason 冲突原因（告警文案）。
	Reason string
}

// String 冲突的单行描述。
func (c contentConflict) String() string {
	return fmt.Sprintf("域=%s 磁盘版本=%d 本地版本=%d（%s）", c.Domain, c.DiskVersion, c.LocalVersion, c.Reason)
}

// contentBlockError 内容回退拦截错误（**独立于防回退拒绝错误**，独立告警文案）。
//
// 语义：本次写盘被**主动放弃**（磁盘内容逐字节不变），且**不重试**、
// **不推进本地基线**（推进基线只对 revision 判据的拒绝生效，见 rollbackRejectError）。
type contentBlockError struct {
	// conflicts 冲突明细（按域逐个列出）。
	conflicts []contentConflict
}

// Error 实现 error 接口（文案与"防回退拒绝"**刻意不同**，便于告警分流与归因）。
func (e *contentBlockError) Error() string {
	return "内容回退拦截: " + contentConflictSummary(e.conflicts)
}

// contentConflictSummary 冲突清单的单行摘要（告警文案与错误文案共用）。
func contentConflictSummary(conflicts []contentConflict) string {
	parts := make([]string, 0, len(conflicts))
	for _, c := range conflicts {
		parts = append(parts, c.String())
	}
	return strings.Join(parts, "; ")
}

// isContentBlock 判定错误是否为内容回退拦截（用类型判定，不用文案匹配）。
func isContentBlock(err error) bool {
	var cbe *contentBlockError
	return errors.As(err, &cbe)
}

// compareContent 逐域比较磁盘与本地的内容版本，返回冲突清单（空 = 允许写入）。
//
// ⚠️ 调用前置条件：disk 与 local 必须来自**同一临界区**（写者锁内），
// 否则比较结果可能基于过时的磁盘视图（TOCTOU）。
func compareContent(disk, local *snapshotPayload) []contentConflict {
	if disk == nil || local == nil {
		return nil
	}
	var conflicts []contentConflict
	for _, d := range contentDomains {
		dv, dok := d.version(disk)
		lv, lok := d.version(local)
		switch {
		case dok && !lok:
			// 本地缺该表：写出会把磁盘上已有的（更新的）该表抹掉 ⇒ 拒绝。
			conflicts = append(conflicts, contentConflict{
				Domain:       d.name,
				DiskVersion:  dv,
				LocalVersion: lv,
				Reason:       "本地缺少该表，写入会抹掉磁盘上已有的内容",
			})
		case dok && lok && dv > lv:
			// 磁盘更新：本地陈旧，回写即内容回退 ⇒ 拒绝。
			conflicts = append(conflicts, contentConflict{
				Domain:       d.name,
				DiskVersion:  dv,
				LocalVersion: lv,
				Reason:       "磁盘版本更新（本地陈旧，回写即内容回退）",
			})
		case dok && lok && dv == lv:
			// 版本相同：内容必须一致（版本契约：变更必递增版本）。
			// 内容不一致 ⇒ 版本号已不可信 ⇒ 保守拒绝 + 告警。
			db, derr := d.content(disk)
			lb, lerr := d.content(local)
			switch {
			case derr != nil || lerr != nil:
				conflicts = append(conflicts, contentConflict{
					Domain:       d.name,
					DiskVersion:  dv,
					LocalVersion: lv,
					Reason:       "同版本内容比对失败（无法确认内容一致，保守拒绝）",
				})
			case !bytes.Equal(db, lb):
				conflicts = append(conflicts, contentConflict{
					Domain:       d.name,
					DiskVersion:  dv,
					LocalVersion: lv,
					Reason:       "同版本内容不一致（版本契约被破坏：同版本内容漂移）",
				})
			}
		}
	}
	return conflicts
}

// contentConflictKey 冲突集合的稳定标识（用于告警去重：同一冲突集合不重复刷屏）。
func contentConflictKey(conflicts []contentConflict) string {
	parts := make([]string, 0, len(conflicts))
	for _, c := range conflicts {
		parts = append(parts, c.String())
	}
	return strings.Join(parts, "|")
}
