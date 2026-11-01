// cipher_linear_int128_ascend.cpp — 路线2 掩码线性【华为昇腾 Ascend 后端】。
//
// 本文件实现与 NVIDIA CUDA 后端（cipher_linear_int128.cu）同一后端无关符号
//   accel_cipher_linear_int128（见 accel_linear_int128.h），
// 网关侧按部署环境加载 libaccel_ascend.so 即可，不关心硬件厂商。
//
// ⚠ 状态：🖥 待环境就绪 —— 本机无 CANN 工具链 / 昇腾硬件，NPU 路径无法编译与运行。
//   本文件提供：
//   (1)【可移植 CPU 参考实现】—— 任意机器（含 x86_64 构建机）可编译验证，语义与
//       Go 侧 CipherLinearInt128 逐位一致；用于在本机建立"ABI + 语义"对拍基线。
//   (2)【目标 NPU 路径骨架】—— Ascend C 算子 + AscendCL 启动封装（见文件末尾，
//       默认以 #if 0 包裹，需 CANN 工具链启用），是真实打上昇腾 NPU 的落点。
//
// 昇腾特殊性：Ascend C 无原生 __int128，128 位累加须用两 uint64 (hi/lo) 仿真
//   （与 Go 侧 add128 同构）；这也正是 §10.5"老架构两 int64 仿真"路线的真机落点。
//
// 编译（可移植参考路径，任意机器）：
//   g++ -shared -fPIC cipher_linear_int128_ascend.cpp -o libaccel_ascend.so
// 编译（目标 NPU 路径，需 CANN 工具链；启用末尾 #if 1 段并链接 -lascendcl）：
//   g++ -shared -fPIC -DHAVE_CANN cipher_linear_int128_ascend.cpp -o libaccel_ascend.so -lascendcl

#include "accel_linear_int128.h"

#include <cstddef>
#include <cstdint>

// ----------------------------------------------------------------------------
// (1) 可移植 CPU 参考实现（语义正确，任何机器可编译 / 测试）
//     用原生 __int128（gcc/clang 在 x86_64 与 aarch64 均支持）做中间累加，
//     与 CUDA 后端、Go CPU 路径逐位一致；仅作为参考/基线，不占用 NPU。
// ----------------------------------------------------------------------------
extern "C" int accel_cipher_linear_int128(const int8_t* W, const int64_t* bias,
                                          const uint64_t* V, int rows, int cols,
                                          uint64_t* out, int batch) {
  if (rows <= 0 || cols <= 0 || batch <= 0) return -2;

#if defined(HAVE_CANN)
  // === 目标 NPU 路径（待 CANN 工具链编译，🖥 待环境就绪）===
  // 见文件末尾 AscendC 算子 + acl 启动封装。真实编译时应在此改走 NPU 启动，
  // 并移除下方 CPU 回退。为保持"可编译即正确"，默认仍走 CPU 参考实现。
  // TODO(ascend): 替换为 acl 启动 AscendC 算子，移除 CPU 回退分支。
#endif

  for (int b = 0; b < batch; b++) {
    for (int i = 0; i < rows; i++) {
      __int128 acc = 0;
      const int8_t* Wrow = W + (size_t)i * cols;
      const uint64_t* Vrow = V + (size_t)b * cols;
      for (int j = 0; j < cols; j++) {
        // 有符号 128 位乘积：(__int128)(int64_t)W * (__int128)(uint64_t)V
        // （负权重时乘积为负，等价于二进制补码低 64 位；严禁无符号乘积）
        acc += (__int128)(int64_t)Wrow[j] * (__int128)(uint64_t)Vrow[j];
      }
      acc += (__int128)bias[i];                 // 有符号偏置
      out[(size_t)b * rows + i] = (uint64_t)acc; // 低 64 位 = mod 2^64
    }
  }
  return 0;
}

// ABI 版本握手符号（见 accel_linear_int128.h）。
extern "C" int accel_cipher_linear_int128_abi_version(void) {
  return ACCEL_LINEAR_INT128_ABI_VERSION;
}

// ----------------------------------------------------------------------------
// (2) 目标 NPU 路径骨架（Ascend C 算子 + AscendCL 启动封装）
//     默认以 #if 0 包裹：此处是"打上昇腾 NPU"的真实落点，需 CANN 工具链编译，
//     且须在带昇腾硬件的环境运行；当前本机无 CANN / 硬件，标记 🖥 待环境就绪。
//
//     关键点：
//       - Ascend C 无原生 __int128，128 位累加用两 uint64 (lo/hi) 仿真：
//           mul64(W, V) -> (plo, phi)；符号位由 W<0 决定（W<0 时 hi 加 ~0 等价补码）；
//           累加用 add128（同 Go add128）：l=lo+pl; c=(l<lo); h=hi+ph+c。
//       - 算子按 (b, i) 分核，逐 j 做有符号 128 位乘加，写回 out[b*rows+i] 低 64 位。
//       - host 侧用 acl 分配 Device 内存、拷贝 W/V/bias、LaunchKernel、回拷 out。
//     以下为示意骨架，未含完整 acl 资源管理/错误码处理，待 CANN 环境补全。
// ----------------------------------------------------------------------------
#if 0  // ← 启用需 CANN：改为 #if 1 并链接 -lascendcl
#include "acl/acl.h"
#include "acl/ops/acl_cipher_linear.h"  // 假设算子已注册；实际路径随 CANN 版本

// Ascend C 算子内核骨架（在 .cpp 同包或独立 .cpp 内以 __aicore__ 实现）：
//   template <typename T> class CipherLinearAscend {
//     __aicore__ inline void Compute(int i, int cols,
//         GlobalTensor<int8_t>& Wg, GlobalTensor<uint64_t>& Vg,
//         GlobalTensor<int64_t>& Bg, GlobalTensor<uint64_t>& Og, int rows, int batch, int b) {
//       uint64_t lo = 0, hi = 0;
//       for (int j = 0; j < cols; j++) {
//         int64_t w = (int64_t)Wg.GetValue(i * cols + j);
//         uint64_t v = Vg.GetValue(b * cols + j);
//         // 无符号 64x64 -> 128，hi/lo 仿真；负权重时 hi 加 ~0 等价二进制补码
//         uint64_t pl, phi; Mul64((uint64_t)(int8_t)w, v, pl, phi);
//         if (w < 0) phi += ~0ull;
//         uint64_t l = lo + pl; uint64_t c = (l < lo) ? 1u : 0u;
//         uint64_t h = hi + phi + c; lo = l; hi = h;
//       }
//       int64_t bias = Bg.GetValue(i);
//       uint64_t blo = (uint64_t)bias, bhi = (bias < 0) ? ~0ull : 0ull;
//       uint64_t l = lo + blo; uint64_t c = (l < lo) ? 1u : 0u;
//       uint64_t h = hi + bhi + c;
//       Og.SetValue((uint64_t)(b * rows + i), (uint64_t)l);  // 低 64 位 = mod 2^64
//     }
//   };
//
// host 启动封装（替换上方 CPU 参考实现体）：
//   aclInit(nullptr); aclrtSetDevice(0);
//   // 分配 Device 内存 devW/devV/devB/devOut，aclMemcpy H2D；
//   // aclCipherLinearLaunch(devW, devB, devV, rows, cols, devOut, batch, stream);
//   // aclMemcpy D2H(devOut -> out)；aclrtSynchronizeStream；释放资源；aclFinalize。
#endif
