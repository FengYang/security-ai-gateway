//go:build pkcs11

// randtest_live_test.go —— 随机数质量启动自检真机用例（M4-2，R-S3-12）。
//
// 运行前提同 pkcs11_live_test.go（SoftHSMv2 token + P11_LIVE=1）。
// SoftHSM 熵源为 OpenSSL RAND_Bytes（DRBG），quick 与 power-on 全量档均应通过。
package cryptopmodule

import (
	"testing"
)

// liveRandReader 从已初始化 backend 流式读取 C_GenerateRandom 输出
// （自检取样源；等价生产 Init 内 p11RandReader 路径，但走会话池）。
type liveRandReader struct {
	b *PKCS11Backend
}

func (r *liveRandReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	out, err := r.b.randRaw(len(p))
	if err != nil {
		return 0, err
	}
	return copy(p, out), nil
}

// TestPKCS11LiveRandSelfCheckQuick M4-2 主链路：Init 启动自检（quick 档）
// → RandHealth=1 → Rand 输出可用。
func TestPKCS11LiveRandSelfCheckQuick(t *testing.T) {
	cfg := p11LiveConfig(t, []string{MechRand})
	backend, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend(pkcs11): %v", err)
	}
	defer func() { _ = backend.Close() }()
	pb, ok := backend.(*PKCS11Backend)
	if !ok {
		t.Fatalf("backend 类型 %T，应為 *PKCS11Backend", backend)
	}

	// Init 已执行 quick 自检（R-S3-12 失败即启动拒，能到这即已通过）。
	if got := pb.RandHealth(); got != RandHealthPassed {
		t.Fatalf("RandHealth=%d（%v），应为 RandHealthPassed", int(got), got)
	}
	if pb.RandHealth().Int() != 1 {
		t.Fatalf("RandHealth.Int()=%d，指标值应为 1（附录 B cryptop_module_rand_health）", pb.RandHealth().Int())
	}

	out, err := pb.Rand(32)
	if err != nil {
		t.Fatalf("Rand(32): %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("Rand(32) 长度 %d", len(out))
	}
	if isAllSame(out) {
		t.Fatal("Rand 输出全同值，熵源可疑")
	}

	// 幂等复跑：健康态保持。
	if _, err := pb.Rand(64); err != nil {
		t.Fatalf("二次 Rand(64): %v", err)
	}
	if got := pb.RandHealth(); got != RandHealthPassed {
		t.Fatalf("二次调用后 RandHealth=%d，应保持 Passed", int(got))
	}
}

// TestPKCS11LiveRandSelfCheckPowerOn M4-2 全量档：对 SoftHSM C_GenerateRandom
// 输出执行 GM/T 0062-2018 E 类上电检测（15 项×20 组×10^6 bit ≈ 2.5MB）。
// 该档用于 S3-a 厂商到货验收与密评留档，启动路径不启用。
func TestPKCS11LiveRandSelfCheckPowerOn(t *testing.T) {
	cfg := p11LiveConfig(t, []string{MechRand})
	backend, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend(pkcs11): %v", err)
	}
	defer func() { _ = backend.Close() }()
	pb := backend.(*PKCS11Backend)

	rep, err := RunRandSelfCheck(&liveRandReader{b: pb}, RandCheckPowerOn)
	if err != nil {
		t.Fatalf("power-on 自检过程失败: %v", err)
	}
	if !rep.Passed {
		t.Fatalf("SoftHSM 上电检测应通过: %s", rep)
	}
	if rep.Alpha != 0.0001 {
		t.Fatalf("power-on 档 Alpha=%g，应为 0.0001", rep.Alpha)
	}
	// 健康态不被全量档降级（全量档仅验收用，不改运行态健康）。
	if got := pb.RandHealth(); got != RandHealthPassed {
		t.Fatalf("全量档后 RandHealth=%d，应保持 Passed", int(got))
	}
}

// TestPKCS11LiveRandSelfCheckBackendReport M4-2：直接执行 quick 档并核对
// 报告要素（R-S3-12 留档：样本量/显著水平/逐项 P/结论）。
//
// 取样走流式 liveRandReader（不预缓冲单样本）——与生产 Init 路径一致，
// 使误拒率对策重试能够重新采样（M4-3 修正：预缓冲单样本时复检只能
// 吃到 EOF，重试形同虚设）。
func TestPKCS11LiveRandSelfCheckBackendReport(t *testing.T) {
	cfg := p11LiveConfig(t, []string{MechRand})
	backend, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend(pkcs11): %v", err)
	}
	defer func() { _ = backend.Close() }()
	pb := backend.(*PKCS11Backend)

	rep, err := RunRandSelfCheck(&liveRandReader{b: pb}, RandCheckQuick)
	if err != nil {
		t.Fatalf("quick 自检: %v", err)
	}
	if !rep.Passed {
		t.Fatalf("SoftHSM quick 自检应通过: %s", rep)
	}
	if len(rep.Items) != 3 {
		t.Fatalf("quick 档应 3 项，实际 %d: %s", len(rep.Items), rep)
	}
	for _, it := range rep.Items {
		if !it.Pass {
			t.Fatalf("单项 %s 未通过（P=%g）: %s", it.Name, it.P, rep)
		}
	}
	t.Logf("留档摘要: %s", rep)
}

// TestPKCS11LiveRandFailClosedAfterClose M4-2 边界：Close 后 Rand fail-closed
// （自检守卫在 closed 检查之后不会放行输出）。
func TestPKCS11LiveRandFailClosedAfterClose(t *testing.T) {
	cfg := p11LiveConfig(t, []string{MechRand})
	backend, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend(pkcs11): %v", err)
	}
	if err := backend.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	pb := backend.(*PKCS11Backend)
	if _, err := pb.Rand(16); err == nil {
		t.Fatal("Close 后 Rand 应 fail-closed 报错")
	}
}

// isAllSame 判断输出是否所有字节相同（熵源明显失效的粗筛）。
func isAllSame(b []byte) bool {
	for _, v := range b {
		if v != b[0] {
			return false
		}
	}
	return true
}
