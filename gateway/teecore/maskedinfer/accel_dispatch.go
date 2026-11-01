//go:build cgo

// accel_dispatch.go — 掩码线性加速后端（CUDA / 华为昇腾）运行时派发。
//
// 设计（路线2 步骤③ 多后端统一架构）：
//   - 网关侧不感知硬件厂商；仅按部署环境（env ACCEL_BACKEND_LIB，逗号分隔候选路径）
//     用 dlopen 加载对应 .so（libaccel_cuda.so / libaccel_ascend.so），
//     并解析统一的 C ABI 符号 accel_cipher_linear_int128（见 accel_linear_int128.h）。
//   - 后端不可用（未配置 / 加载失败 / 调用失败）时，AccelLinearInt128 返回
//     ErrAccelUnavailable，调用方应回退到 CPU 路径 CipherLinearInt128（int128_linear.go）。
//   - 算法正确性已由 CipherLinearInt128 与 math/big 神谕逐位对拍锁定，各加速后端仅替换执行后端。
//
// 本文件仅在 CGO 可用时编译；无 CGO 时由 accel_dispatch_nocgo.go 提供恒回退桩。

package maskedinfer

/*
#include <stdint.h>
#include <dlfcn.h>
#include <stdlib.h>

typedef int (*accel_fn_t)(const int8_t* W, const int64_t* bias, const uint64_t* V, int rows, int cols, uint64_t* out, int batch);
typedef int (*abi_fn_t)(void);

static void* g_accel_handle = NULL;
static accel_fn_t g_accel_fn = NULL;
static int g_accel_loaded = 0; // 0=未尝试, 1=已加载可用, -1=不可用

// 尝试从给定路径加载加速后端 .so，解析统一符号 accel_cipher_linear_int128，
// 并校验 ABI 版本（required_abi 为网关侧期望版本，须与后端 accel_cipher_linear_int128_abi_version 一致）。
// 返回 0 成功；-1 dlopen 失败；-2 主符号缺失；-3 路径为空；-4 ABI 版本符号缺失；-5 ABI 版本不匹配。
static int maskedinfer_load_accel(const char* path, int required_abi) {
    if (path == NULL || *path == '\0') return -3;
    void* h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (h == NULL) return -1;
    void* sym = dlsym(h, "accel_cipher_linear_int128");
    if (sym == NULL) { dlclose(h); return -2; }
    abi_fn_t abi_fn = (abi_fn_t)dlsym(h, "accel_cipher_linear_int128_abi_version");
    if (abi_fn == NULL) { dlclose(h); return -4; }
    if (abi_fn() != required_abi) { dlclose(h); return -5; }
    g_accel_handle = h;
    g_accel_fn = (accel_fn_t)sym;
    g_accel_loaded = 1;
    return 0;
}

// 调用加速后端；若未加载返回 -9。
static int maskedinfer_call_accel(const int8_t* W, const int64_t* bias, const uint64_t* V, int rows, int cols, uint64_t* out, int batch) {
    if (g_accel_loaded != 1 || g_accel_fn == NULL) return -9;
    return g_accel_fn(W, bias, V, rows, cols, out, batch);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"
)

// ErrAccelUnavailable 表示加速后端不可用（未配置 .so / 加载失败 / 调用失败 / 权重越界 / ABI 版本不匹配），
// 调用方应回退到 CPU 路径 CipherLinearInt128。
var ErrAccelUnavailable = errors.New("maskedinfer: 加速后端不可用，请回退 CPU 路径 CipherLinearInt128")

// accelLinearInt128ABIVersion 是网关侧要求的加速后端 ABI 版本，须与
// accel_linear_int128.h 中 ACCEL_LINEAR_INT128_ABI_VERSION 保持一致。
const accelLinearInt128ABIVersion = 1

var (
	accelOnce    sync.Once
	accelLoadErr error
)

// resetAccelStateForTest 仅供测试：重置一次性加载状态，使「未配置后端 → 回退」分支
// 在单进程内可重复验证（生产路径不调用）。
func resetAccelStateForTest() {
	accelOnce = sync.Once{}
	accelLoadErr = nil
}

// loadAccelOnce 执行一次后端加载（candidates 为候选 .so 路径；空则回退 env ACCEL_BACKEND_LIB）。
// 注意：本函数自身不得再调用 accelOnce.Do，否则会与外层 Once 形成不可重入死锁
// （sync.Once 非可重入，嵌套 Do 同一 Once 会自锁）。仅由 accelOnce.Do 包一层。
func loadAccelOnce(candidates []string) {
	if len(candidates) == 0 {
		if env := os.Getenv("ACCEL_BACKEND_LIB"); env != "" {
			candidates = strings.Split(env, ",")
		}
	}
	var lastErr error
	for _, p := range candidates {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// 安全校验（Sec-C1）：拒绝任意 env 注入路径，仅允许受信绝对路径，
		// 且必须是普通文件、非符号链接、不被 group/other 写入，以防 TEE 进程内代码注入。
		if err := validateAccelLibPath(p); err != nil {
			lastErr = fmt.Errorf("后端路径 %q 校验失败: %w", p, err)
			continue
		}
		rc := C.maskedinfer_load_accel(C.CString(p), C.int(accelLinearInt128ABIVersion))
		if rc == 0 {
			accelLoadErr = nil
			return
		}
		lastErr = fmt.Errorf("后端路径 %q 加载失败 rc=%d（-1 dlopen/-2 主符号缺失/-4 ABI符号缺失/-5 版本不匹配）", p, int(rc))
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("未配置加速后端 .so（候选 0 个）")
	}
	accelLoadErr = lastErr
}

// validateAccelLibPath 对受信后端 .so 路径做最小安全校验（防 TEE 进程内任意代码注入）：
//   - 必须是绝对路径；
//   - 不得是符号链接（防 TOCTOU / 重定向到攻击者可控文件）；
//   - 必须是普通文件；
//   - 不得被 group/other 写入（防被替换）。
func validateAccelLibPath(p string) error {
	if !filepath.IsAbs(p) {
		return fmt.Errorf("非绝对路径（拒绝：仅允许受信绝对路径）")
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("Lstat 失败: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("拒绝符号链接（防 TOCTOU/重定向）")
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("非普通文件")
	}
	if fi.Mode().Perm()&0o022 != 0 { // 0o022 = group-write | other-write
		return fmt.Errorf("权限过宽（group/other 可写，存在被替换风险）")
	}
	return nil
}

// InitAccelBackend 由网关在启动时显式调用：加载指定/环境给定的后端 .so。
// 传入候选路径列表（按序尝试）；为空时回退到环境变量 ACCEL_BACKEND_LIB（逗号分隔）。
// 加载失败不致命：仅记录，后续 AccelLinearInt128 会返回 ErrAccelUnavailable 由调用方回退。
// 多次调用只有首次生效（sync.Once）。返回首次加载的结果（nil 表示成功加载一个）。
func InitAccelBackend(paths ...string) error {
	accelOnce.Do(func() { loadAccelOnce(paths) })
	return accelLoadErr
}

// ensureAccelLoaded 惰性触发加载（仅在尚未尝试过时）：优先用显式/环境变量候选。
func ensureAccelLoaded() {
	accelOnce.Do(func() { loadAccelOnce(nil) })
}

// AccelLinearInt128 经加速后端（CUDA / 昇腾 Ascend）计算掩码线性层。
// 后端不可用或调用失败时返回 ErrAccelUnavailable，调用方应回退 CipherLinearInt128。
//
// 算术语义与 CipherLinearInt128（int128_linear.go）逐位一致：
//
//	y[b][i] = ( Σ_j W[i*cols+j] · V[b*cols+j] + bias[i] ) mod 2^64
func (m *QuantizedMatrix) AccelLinearInt128(V [][]uint64) ([][]uint64, error) {
	ensureAccelLoaded()
	if accelLoadErr != nil {
		return nil, ErrAccelUnavailable
	}
	// 后端仅支持 int8 量化权重：超出 [-128,127] 时 int8 截断会失真，
	// 返回 ErrAccelUnavailable 由调用方回退到 CPU 路径（CipherLinearInt128 用全 int64）。
	for _, v := range m.Data {
		if v < -128 || v > 127 {
			return nil, ErrAccelUnavailable
		}
	}
	batch := len(V)
	if batch == 0 {
		return [][]uint64{}, nil
	}
	for b, vec := range V {
		if len(vec) != m.Cols {
			return nil, fmt.Errorf("maskedinfer: 向量[%d]长度 %d != 列数 %d", b, len(vec), m.Cols)
		}
	}
	// 权重 int32 → int8（量化位宽 8，值必落在 [-128,127]）
	w8 := make([]int8, len(m.Data))
	for i, v := range m.Data {
		w8[i] = int8(v)
	}
	// 偏置 int32 → int64
	bias64 := make([]int64, m.Rows)
	if m.Bias != nil {
		for i := range bias64 {
			bias64[i] = int64(m.Bias[i])
		}
	}
	// 展平 V 为 [batch*cols]，与内核布局 V[b*cols+j] 一致
	flatV := make([]uint64, batch*m.Cols)
	for b := 0; b < batch; b++ {
		copy(flatV[b*m.Cols:(b+1)*m.Cols], V[b])
	}
	flatOut := make([]uint64, batch*m.Rows)

	rc := C.maskedinfer_call_accel(
		(*C.int8_t)(unsafe.Pointer(&w8[0])),
		(*C.int64_t)(unsafe.Pointer(&bias64[0])),
		(*C.uint64_t)(unsafe.Pointer(&flatV[0])),
		C.int(m.Rows), C.int(m.Cols),
		(*C.uint64_t)(unsafe.Pointer(&flatOut[0])),
		C.int(batch),
	)
	if rc != 0 {
		return nil, fmt.Errorf("maskedinfer: 加速后端调用失败 rc=%d: %w", int(rc), ErrAccelUnavailable)
	}
	out := make([][]uint64, batch)
	for b := 0; b < batch; b++ {
		row := make([]uint64, m.Rows)
		for i := 0; i < m.Rows; i++ {
			v := flatOut[b*m.Rows+i]
			if m.ModBits == Mod32 {
				// 后端按 mod 2^64 写入；Mod32 矩阵再按 2^32 归约（2^32 | 2^64，低 32 位即精确）。
				row[i] = v & 0xFFFFFFFF
			} else {
				row[i] = v
			}
		}
		out[b] = row
	}
	return out, nil
}
