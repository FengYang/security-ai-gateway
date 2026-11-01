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

static void* g_accel_handle = NULL;
static accel_fn_t g_accel_fn = NULL;
static int g_accel_loaded = 0; // 0=未尝试, 1=已加载可用, -1=不可用

// 尝试从给定路径加载加速后端 .so，并解析统一符号 accel_cipher_linear_int128。
// 返回 0 成功；-1 dlopen 失败；-2 符号缺失；-3 路径为空。
static int maskedinfer_load_accel(const char* path) {
    if (path == NULL || *path == '\0') return -3;
    void* h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (h == NULL) return -1;
    void* sym = dlsym(h, "accel_cipher_linear_int128");
    if (sym == NULL) { dlclose(h); return -2; }
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
	"strings"
	"sync"
	"unsafe"
)

// ErrAccelUnavailable 表示加速后端不可用（未配置 .so / 加载失败 / 调用失败），
// 调用方应回退到 CPU 路径 CipherLinearInt128。
var ErrAccelUnavailable = errors.New("maskedinfer: 加速后端不可用，请回退 CPU 路径 CipherLinearInt128")

var (
	accelOnce    sync.Once
	accelLoadErr error
)

// loadAccelOnce 执行一次后端加载（candidates 为候选 .so 路径；空则回退 env ACCEL_BACKEND_LIB）。
// 注意：本函数自身不得再调用 accelOnce.Do，否则会与外层 Once 形成不可重入死锁
// （sync.Once 非可重入，嵌套 Do 同一 Once 会自锁）。仅由 accelOnce.Do 包一层。
func loadAccelOnce(candidates []string) {
	if len(candidates) == 0 {
		if env := os.Getenv("ACCEL_BACKEND_LIB"); env != "" {
			candidates = strings.Split(env, ",")
		}
	}
	for _, p := range candidates {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		rc := C.maskedinfer_load_accel(C.CString(p))
		if rc == 0 {
			accelLoadErr = nil
			return
		}
	}
	accelLoadErr = fmt.Errorf("未找到可用加速后端 .so（候选 %d 个）", len(candidates))
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
//   y[b][i] = ( Σ_j W[i*cols+j] · V[b*cols+j] + bias[i] ) mod 2^64
func (m *QuantizedMatrix) AccelLinearInt128(V [][]uint64) ([][]uint64, error) {
	ensureAccelLoaded()
	if accelLoadErr != nil {
		return nil, ErrAccelUnavailable
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
		return nil, fmt.Errorf("maskedinfer: 加速后端调用失败 rc=%d", int(rc))
	}
	out := make([][]uint64, batch)
	for b := 0; b < batch; b++ {
		row := make([]uint64, m.Rows)
		copy(row, flatOut[b*m.Rows:(b+1)*m.Rows])
		out[b] = row
	}
	return out, nil
}
