// Package main — 跨集群流量调度配置模型（P2-4 T-5.1）。
//
// 口径来源：《GA-AI 网关能力补齐方案 · P2-4 多集群管理》§6.4 调度配置模型（北向）。
//
// 定位（**不自研 GSLB/LB**，D-5）：本产品数据面仍为"每集群一套标准单集群形态"，
// 本模型只描述"北向入口该往哪切、切多少、健康信号从哪来"，
// **执行点在客户既有 DNS / 云 LB / 北向网关**；本服务不实现自动紧急切换
// （switch_policy 默认 manual，健康触发只给建议，人工确认后执行）。
//
// 承载格式：Go 侧以 JSON 承载（避免为管理面引入 yaml 依赖）；
// SOP 附件（docs 侧）为 YAML 示例，由运维侧工具转换为 JSON 后装载。
//
// 校验取向：**fail-closed**——任何不自洽的调度配置一律拒绝装载并返回错误，
// 杜绝"半合法的调度计划"被下发到北向入口。
package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// ---------- 枚举 ----------

// ClusterRole 集群在北向调度中的角色。
type ClusterRole string

const (
	// RolePrimary 主集群：北向流量默认全部指向它。
	RolePrimary ClusterRole = "primary"
	// RoleStandby 备集群：默认不接流量，仅在切流目标。
	RoleStandby ClusterRole = "standby"
	// RoleWeighted 权重集群：按 weight 比例分摊流量（双活形态）。
	RoleWeighted ClusterRole = "weighted"
)

// 合法角色集合（校验用）。
var validClusterRoles = map[ClusterRole]bool{
	RolePrimary:  true,
	RoleStandby:  true,
	RoleWeighted: true,
}

// SwitchPolicy 切流策略。
type SwitchPolicy string

const (
	// SwitchManual 人工确认执行（默认；D-5：不做自动紧急切换）。
	SwitchManual SwitchPolicy = "manual"
	// SwitchSemiAuto 健康触发只给切换建议，仍需人工确认执行。
	SwitchSemiAuto SwitchPolicy = "semi-auto"
)

// 合法切流策略集合（校验用）。
var validSwitchPolicies = map[SwitchPolicy]bool{
	SwitchManual:   true,
	SwitchSemiAuto: true,
}

// ---------- 模型 ----------

// ScheduleCluster 单个集群的调度参数。
type ScheduleCluster struct {
	ID     string      `json:"id"`            // 集群 ID（与集群注册表一致，必填且唯一）
	Role   ClusterRole `json:"role"`          // primary | standby | weighted
	Weight int         `json:"weight"`        // 权重（primary/weighted 必为正；standby 必为 0）
	Health string      `json:"health_source"` // 健康信号源，可空（空=以集群注册心跳状态为准）
}

// TrafficSchedule 跨集群流量调度配置（§6.4）。
type TrafficSchedule struct {
	Clusters     []ScheduleCluster `json:"clusters"`      // 参与调度的集群列表
	SwitchPolicy SwitchPolicy      `json:"switch_policy"` // manual | semi-auto（空按 manual）
}

// ---------- 解析 ----------

// ParseTrafficSchedule 解析并校验调度配置。
// 解析失败、字段非法、配置不自洽一律返回错误（fail-closed），不返回半合法配置。
func ParseTrafficSchedule(raw []byte) (TrafficSchedule, error) {
	var s TrafficSchedule
	if err := json.Unmarshal(raw, &s); err != nil {
		return TrafficSchedule{}, fmt.Errorf("traffic_schedule: 解析失败: %w", err)
	}
	if err := s.Validate(); err != nil {
		return TrafficSchedule{}, err
	}
	return s, nil
}

// ---------- 校验 ----------

// Validate 校验调度配置的自洽性。
//
// 规则（逐条 fail-closed）：
//  1. 集群列表非空；
//  2. 集群 ID 非空且唯一；
//  3. role 必须是 primary | standby | weighted；
//  4. weight 不得为负；primary/weighted 的 weight 必须为正；standby 的 weight 必须为 0；
//  5. primary 至多一个（多主不合法：北向入口单写入口，避免双写漂移）；
//  6. 至少存在一个可承接流量的集群（primary 或 weighted），否则调度无意义；
//  7. switch_policy 必须是 manual | semi-auto（空按 manual）。
//
// 健康信号源（health_source）不参与上述必填校验：留空表示"以集群注册心跳状态为准"，
// 但**一旦填写就必须是可解析的健康源**（probe:<url> 或 registry:<表达式>），
// 防止把拼错的健康地址下发到北向（健康探活失败会表现为误判不可用）。
func (s TrafficSchedule) Validate() error {
	if len(s.Clusters) == 0 {
		return fmt.Errorf("traffic_schedule: clusters 为空（至少需要一个集群）")
	}
	seen := make(map[string]struct{}, len(s.Clusters))
	var primaryCount, activeCount int
	for i, c := range s.Clusters {
		if strings.TrimSpace(c.ID) == "" {
			return fmt.Errorf("traffic_schedule: clusters[%d].id 为空", i)
		}
		if _, dup := seen[c.ID]; dup {
			return fmt.Errorf("traffic_schedule: 集群 ID 重复：%q", c.ID)
		}
		seen[c.ID] = struct{}{}

		if !validClusterRoles[c.Role] {
			return fmt.Errorf("traffic_schedule: 集群 %q 的 role 非法：%q（合法值 primary|standby|weighted）", c.ID, c.Role)
		}
		if c.Weight < 0 {
			return fmt.Errorf("traffic_schedule: 集群 %q 的 weight 为负：%d", c.ID, c.Weight)
		}
		switch c.Role {
		case RolePrimary:
			primaryCount++
			activeCount++
			if c.Weight <= 0 {
				return fmt.Errorf("traffic_schedule: primary 集群 %q 的 weight 必须为正（当前 %d）", c.ID, c.Weight)
			}
		case RoleWeighted:
			activeCount++
			if c.Weight <= 0 {
				return fmt.Errorf("traffic_schedule: weighted 集群 %q 的 weight 必须为正（当前 %d）", c.ID, c.Weight)
			}
		case RoleStandby:
			if c.Weight != 0 {
				return fmt.Errorf("traffic_schedule: standby 集群 %q 的 weight 必须为 0（当前 %d）", c.ID, c.Weight)
			}
		}
		if err := validateHealthSource(c.ID, c.Health); err != nil {
			return err
		}
	}
	if primaryCount > 1 {
		return fmt.Errorf("traffic_schedule: primary 集群数 %d > 1（北向单写入口，多主不合法）", primaryCount)
	}
	if activeCount == 0 {
		return fmt.Errorf("traffic_schedule: 无可承接流量的集群（至少一个 primary 或 weighted）")
	}
	if s.SwitchPolicy == "" {
		s.SwitchPolicy = SwitchManual
	}
	if !validSwitchPolicies[s.SwitchPolicy] {
		return fmt.Errorf("traffic_schedule: switch_policy 非法：%q（合法值 manual|semi-auto）", s.SwitchPolicy)
	}
	return nil
}

// validateHealthSource 校验健康信号源。
// 允许为空（以集群注册心跳状态为准）；非空时必须形如 "probe:<url>" 或 "registry:<表达式>"。
func validateHealthSource(clusterID, src string) error {
	if strings.TrimSpace(src) == "" {
		return nil
	}
	scheme, rest, ok := strings.Cut(src, ":")
	if !ok || scheme == "" || rest == "" {
		return fmt.Errorf("traffic_schedule: 集群 %q 的 health_source 格式非法：%q（应为 probe:<url> 或 registry:<表达式>）", clusterID, src)
	}
	switch scheme {
	case "probe":
		u, err := url.Parse(rest)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("traffic_schedule: 集群 %q 的 probe 健康地址非法：%q（须为 http/https 绝对 URL）", clusterID, rest)
		}
	case "registry":
		// 注册表表达式：允许任意非空串（由健康汇总侧解释），此处只做非空与长度兜底。
		if len(rest) > 512 {
			return fmt.Errorf("traffic_schedule: 集群 %q 的 registry 健康表达式过长（%d > 512）", clusterID, len(rest))
		}
	default:
		return fmt.Errorf("traffic_schedule: 集群 %q 的 health_source 协议非法：%q（合法值 probe|registry）", clusterID, scheme)
	}
	return nil
}

// ---------- 查询辅助 ----------

// RoleOf 返回指定集群的角色；不存在返回空串。
func (s TrafficSchedule) RoleOf(clusterID string) ClusterRole {
	for _, c := range s.Clusters {
		if c.ID == clusterID {
			return c.Role
		}
	}
	return ""
}

// EffectivePolicy 返回生效的切流策略（空按 manual）。
func (s TrafficSchedule) EffectivePolicy() SwitchPolicy {
	if s.SwitchPolicy == "" {
		return SwitchManual
	}
	return s.SwitchPolicy
}

// ActiveClusters 返回当前承接流量的集群（primary + weighted），保持配置顺序。
func (s TrafficSchedule) ActiveClusters() []ScheduleCluster {
	out := make([]ScheduleCluster, 0, len(s.Clusters))
	for _, c := range s.Clusters {
		if c.Role == RolePrimary || c.Role == RoleWeighted {
			out = append(out, c)
		}
	}
	return out
}

// StandbyClusters 返回备集群（standby），保持配置顺序。
func (s TrafficSchedule) StandbyClusters() []ScheduleCluster {
	out := make([]ScheduleCluster, 0, len(s.Clusters))
	for _, c := range s.Clusters {
		if c.Role == RoleStandby {
			out = append(out, c)
		}
	}
	return out
}

// TotalActiveWeight 返回承接流量集群的权重总和（无承接集群时返回 0）。
func (s TrafficSchedule) TotalActiveWeight() int {
	sum := 0
	for _, c := range s.ActiveClusters() {
		sum += c.Weight
	}
	return sum
}

// WeightRatio 返回指定集群在承接流量集群中的权重占比（0~1）。
// 非承接流量集群（standby）或未知集群返回 0。
func (s TrafficSchedule) WeightRatio(clusterID string) float64 {
	total := s.TotalActiveWeight()
	if total <= 0 {
		return 0
	}
	for _, c := range s.ActiveClusters() {
		if c.ID == clusterID {
			return float64(c.Weight) / float64(total)
		}
	}
	return 0
}
