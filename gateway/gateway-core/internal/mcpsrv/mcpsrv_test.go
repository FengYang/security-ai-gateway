package mcpsrv

import "testing"

func TestValidateNormalizesAndDefaults(t *testing.T) {
	s := &Server{ID: "mcp-public-demo", BaseURL: "http://Demo.Example.com:8080/", Prefix: "demo"}
	if err := Validate(s); err != nil {
		t.Fatalf("合法条目应通过: %v", err)
	}
	if s.BaseURL != "http://demo.example.com:8080" {
		t.Fatalf("base_url 规范化不符: %q", s.BaseURL)
	}
	if s.Health != HealthUnknown {
		t.Fatalf("health 缺省应为 unknown，got %q", s.Health)
	}
	if s.EffectiveTrack() != TrackSecure {
		t.Fatalf("track 空值有效轨应为 secure，got %q", s.EffectiveTrack())
	}
	if s.EffectiveNamespace() != "demo" {
		t.Fatalf("生效命名空间缺省应为 prefix，got %q", s.EffectiveNamespace())
	}
	if s.EffectiveNamespace() != "demo" || (&Server{Namespace: "fin", Prefix: "demo"}).EffectiveNamespace() != "fin" {
		t.Fatal("显式 namespace 应优先于 prefix")
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		s    Server
	}{
		{"id 非法", Server{ID: "Bad!", BaseURL: "http://h", Prefix: "p"}},
		{"scheme 非法", Server{ID: "ok", BaseURL: "ftp://h", Prefix: "p"}},
		{"userinfo 拒绝", Server{ID: "ok", BaseURL: "http://u:pw@h", Prefix: "p"}},
		{"query 拒绝", Server{ID: "ok", BaseURL: "http://h/x?a=1", Prefix: "p"}},
		{"fragment 拒绝", Server{ID: "ok", BaseURL: "http://h/x#f", Prefix: "p"}},
		{"缺主机", Server{ID: "ok", BaseURL: "http://", Prefix: "p"}},
		{"prefix 非法", Server{ID: "ok", BaseURL: "http://h", Prefix: "P_1"}},
		{"namespace 非法", Server{ID: "ok", BaseURL: "http://h", Prefix: "p", Namespace: "N!"}},
		{"track 非法", Server{ID: "ok", BaseURL: "http://h", Prefix: "p", Track: "internal"}},
		{"health 非法", Server{ID: "ok", BaseURL: "http://h", Prefix: "p", Health: "meh"}},
	}
	for _, tc := range cases {
		s := tc.s
		if err := Validate(&s); err == nil {
			t.Fatalf("%s 应被拒绝: %+v", tc.name, s)
		}
	}
}

func TestCheckConflicts(t *testing.T) {
	list := []*Server{{ID: "a", Prefix: "fin"}}
	cases := []struct {
		name string
		cand *Server
		want bool // true = 应冲突
	}{
		{"prefix 撞车", &Server{ID: "b", Prefix: "fin"}, true},
		{"生效命名空间撞车", &Server{ID: "b", Prefix: "ops", Namespace: "fin"}, true},
		{"自身更新放行", &Server{ID: "a", Prefix: "fin"}, false},
		{"无冲突", &Server{ID: "b", Prefix: "ops"}, false},
	}
	for _, tc := range cases {
		err := CheckConflicts(list, tc.cand)
		if (err != nil) != tc.want {
			t.Fatalf("%s: err=%v want conflict=%v", tc.name, err, tc.want)
		}
	}
}

func TestSummariesSortedAndMapped(t *testing.T) {
	list := []*Server{
		{ID: "s2", BaseURL: "http://b:2", Track: TrackSecure, Prefix: "ops"},
		{ID: "s1", BaseURL: "http://a:1", Track: TrackPublic, Prefix: "fin"},
	}
	out := Summaries(list)
	if len(out) != 2 || out[0].ID != "s1" || out[1].ID != "s2" {
		t.Fatalf("摘要应按 id 字典序: %+v", out)
	}
	if out[0].BaseURL != "http://a:1" || out[0].Track != TrackPublic || out[0].Prefix != "fin" {
		t.Fatalf("摘要字段映射不符: %+v", out[0])
	}
}
