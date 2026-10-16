package routeengine

// engine_ttft_test.go — P1-6 M6.1：引擎延迟配置/TTFT 通道访问器与端点状态快照用例
// （LatencyConfigOf / TTFTStatsUnreachable / SetTTFTStatsUnreachable / EndpointStates 副本语义）。

import "testing"

func TestEngineTTFTAccessorsAndStateSnapshot(t *testing.T) {
	lat := DefaultLatencyConfig()
	lat.StaleSec = 75
	eng := NewEngine(Config{
		Endpoints: []EndpointConfig{
			{Name: "a", URL: "http://a", Enabled: true, Weight: 1},
			{Name: "b", URL: "http://b", Enabled: true, Weight: 1},
		},
		Latency: lat,
	})

	if got := eng.LatencyConfigOf(); got.StaleSec != 75 || got.Quantile != lat.Quantile ||
		got.WindowSec != lat.WindowSec || got.MinSamples != lat.MinSamples {
		t.Fatalf("LatencyConfigOf 不符：%+v", got)
	}

	if eng.TTFTStatsUnreachable() {
		t.Fatal("初始不应为不可达")
	}
	eng.SetTTFTStatsUnreachable(true)
	if !eng.TTFTStatsUnreachable() {
		t.Fatal("置位后应不可达（R2-19 序 1）")
	}
	eng.SetTTFTStatsUnreachable(false)
	if eng.TTFTStatsUnreachable() {
		t.Fatal("清除后应可达")
	}

	states := eng.EndpointStates()
	if len(states) != 2 {
		t.Fatalf("端点数不符：%d", len(states))
	}
	states[0].Name = "mutated"
	for _, st := range eng.EndpointStates() {
		if st.Name == "mutated" {
			t.Fatal("EndpointStates 应返回副本（外部改动不得回写引擎内部）")
		}
	}
}
