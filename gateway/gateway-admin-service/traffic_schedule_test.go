package main

import (
	"strings"
	"testing"
)

// T-5.1 调度配置模型 + 校验 的模型单测。

func TestTrafficSchedule_ParseValid(t *testing.T) {
	raw := `{
	  "clusters": [
	    {"id":"cluster-a","role":"primary","weight":100,"health_source":"probe:https://gateway-a.example.com/healthz"},
	    {"id":"cluster-b","role":"standby","weight":0,"health_source":"registry:heartbeat"},
	    {"id":"cluster-c","role":"weighted","weight":50}
	  ],
	  "switch_policy": "semi-auto"
	}`
	s, err := ParseTrafficSchedule([]byte(raw))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(s.Clusters) != 3 {
		t.Fatalf("集群数 = %d, want 3", len(s.Clusters))
	}
	if s.EffectivePolicy() != SwitchSemiAuto {
		t.Errorf("切流策略 = %q, want semi-auto", s.EffectivePolicy())
	}
	if got := s.RoleOf("cluster-b"); got != RoleStandby {
		t.Errorf("cluster-b 角色 = %q, want standby", got)
	}
	if got := s.RoleOf("cluster-zzz"); got != "" {
		t.Errorf("未知集群角色 = %q, want 空", got)
	}
	if n := len(s.ActiveClusters()); n != 2 {
		t.Errorf("承接流量集群数 = %d, want 2", n)
	}
	if n := len(s.StandbyClusters()); n != 1 {
		t.Errorf("备集群数 = %d, want 1", n)
	}
	if total := s.TotalActiveWeight(); total != 150 {
		t.Errorf("承接流量权重和 = %d, want 150", total)
	}
	if r := s.WeightRatio("cluster-a"); r < 0.66 || r > 0.67 {
		t.Errorf("cluster-a 权重占比 = %v, want ≈0.667", r)
	}
	if r := s.WeightRatio("cluster-b"); r != 0 {
		t.Errorf("standby 权重占比 = %v, want 0", r)
	}
}

func TestTrafficSchedule_DefaultPolicyIsManual(t *testing.T) {
	raw := `{"clusters":[{"id":"a","role":"primary","weight":1}]}`
	s, err := ParseTrafficSchedule([]byte(raw))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if s.EffectivePolicy() != SwitchManual {
		t.Errorf("缺省切流策略 = %q, want manual（D-5：不做自动紧急切换）", s.EffectivePolicy())
	}
}

func TestTrafficSchedule_Invalid(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string // 期望错误信息包含的片段
	}{
		{
			name: "非法 JSON",
			raw:  `{not json`,
			want: "解析失败",
		},
		{
			name: "集群列表为空",
			raw:  `{"clusters":[]}`,
			want: "clusters 为空",
		},
		{
			name: "集群 ID 为空",
			raw:  `{"clusters":[{"id":"  ","role":"primary","weight":1}]}`,
			want: "id 为空",
		},
		{
			name: "集群 ID 重复",
			raw:  `{"clusters":[{"id":"a","role":"primary","weight":1},{"id":"a","role":"standby","weight":0}]}`,
			want: "重复",
		},
		{
			name: "role 非法",
			raw:  `{"clusters":[{"id":"a","role":"backup","weight":1}]}`,
			want: "role 非法",
		},
		{
			name: "weight 为负",
			raw:  `{"clusters":[{"id":"a","role":"primary","weight":-1}]}`,
			want: "weight 为负",
		},
		{
			name: "primary 权重为零",
			raw:  `{"clusters":[{"id":"a","role":"primary","weight":0}]}`,
			want: "weight 必须为正",
		},
		{
			name: "weighted 权重为零",
			raw:  `{"clusters":[{"id":"a","role":"weighted","weight":0}]}`,
			want: "weight 必须为正",
		},
		{
			name: "standby 权重非零",
			raw:  `{"clusters":[{"id":"a","role":"primary","weight":1},{"id":"b","role":"standby","weight":5}]}`,
			want: "weight 必须为 0",
		},
		{
			name: "多主",
			raw:  `{"clusters":[{"id":"a","role":"primary","weight":1},{"id":"b","role":"primary","weight":1}]}`,
			want: "primary 集群数",
		},
		{
			name: "无可承接流量集群（仅 standby）",
			raw:  `{"clusters":[{"id":"a","role":"standby","weight":0}]}`,
			want: "无可承接流量的集群",
		},
		{
			name: "switch_policy 非法",
			raw:  `{"clusters":[{"id":"a","role":"primary","weight":1}],"switch_policy":"auto"}`,
			want: "switch_policy 非法",
		},
		{
			name: "health_source 格式非法",
			raw:  `{"clusters":[{"id":"a","role":"primary","weight":1,"health_source":"gateway-a/healthz"}]}`,
			want: "health_source 格式非法",
		},
		{
			name: "health_source 协议非法",
			raw:  `{"clusters":[{"id":"a","role":"primary","weight":1,"health_source":"http://a/healthz"}]}`,
			want: "协议非法",
		},
		{
			name: "probe 健康地址非法",
			raw:  `{"clusters":[{"id":"a","role":"primary","weight":1,"health_source":"probe:gateway-a/healthz"}]}`,
			want: "probe 健康地址非法",
		},
		{
			name: "probe 健康地址非 http 协议",
			raw:  `{"clusters":[{"id":"a","role":"primary","weight":1,"health_source":"probe:ftp://a/healthz"}]}`,
			want: "probe 健康地址非法",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := ParseTrafficSchedule([]byte(tc.raw))
			if err == nil {
				t.Fatalf("期望报错，实际通过：%+v", s)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("错误信息 = %q，未包含期望片段 %q", err.Error(), tc.want)
			}
		})
	}
}

// 校验失败必须 fail-closed：不得返回半合法配置。
func TestTrafficSchedule_InvalidReturnsZeroValue(t *testing.T) {
	s, err := ParseTrafficSchedule([]byte(`{"clusters":[{"id":"a","role":"primary","weight":0}]}`))
	if err == nil {
		t.Fatal("期望报错")
	}
	if len(s.Clusters) != 0 {
		t.Errorf("失败时返回了非零值配置：%+v", s)
	}
}

// health_source 留空 = 以集群注册心跳状态为准（合法）。
func TestTrafficSchedule_EmptyHealthSourceAllowed(t *testing.T) {
	raw := `{"clusters":[{"id":"a","role":"primary","weight":1}]}`
	if _, err := ParseTrafficSchedule([]byte(raw)); err != nil {
		t.Fatalf("health_source 留空应合法：%v", err)
	}
}

// 双活形态：全部 weighted。
func TestTrafficSchedule_AllWeighted(t *testing.T) {
	raw := `{"clusters":[
	  {"id":"a","role":"weighted","weight":70},
	  {"id":"b","role":"weighted","weight":30}
	]}`
	s, err := ParseTrafficSchedule([]byte(raw))
	if err != nil {
		t.Fatalf("双活形态应合法：%v", err)
	}
	if r := s.WeightRatio("a"); r < 0.69 || r > 0.71 {
		t.Errorf("a 占比 = %v, want ≈0.7", r)
	}
	if r := s.WeightRatio("b"); r < 0.29 || r > 0.31 {
		t.Errorf("b 占比 = %v, want ≈0.3", r)
	}
}
