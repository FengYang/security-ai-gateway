// accel_linear_int128.h — 路线2 掩码线性加速后端【统一 C ABI 契约】。
//
// 后端无关：NVIDIA CUDA 与华为昇腾（Ascend / CANN）各自实现同一符号
//   int accel_cipher_linear_int128(...)
// 网关侧按部署环境（env ACCEL_BACKEND_LIB 指向对应 .so）加载并调用本符号；
// 加载失败 / 未配置时回退到 Go CPU 路径 CipherLinearInt128
// （gateway/teecore/maskedinfer/int128_linear.go）。
//
// ⚠ 算法正确性已由 Go 侧 CipherLinearInt128（与 math/big 神谕逐位一致）对拍锁定；
//   各后端仅为"执行后端替换"，必须严格保持下列语义，否则 TEE 侧 Unmask 解掩码失配。
//
// 语义： y[b][i] = ( Σ_j W[i*cols+j] · V[b*cols+j] + bias[i] )  mod 2^64
//   - W  : int8 量化权重（行优先），符号扩展 int64 参与乘积；
//   - V  : uint64 掩码域向量（= ToMaskDomain(x) + r，mod 2^64），无符号参与；
//   - 乘积按"有符号 128 位"累加：对负权重 W，乘积须为负
//        （等价 (int64)W × (uint64)V 的二进制补码低 64 位）；
//        严禁用无符号乘积（会使负权重系统性偏差）；
//   - 单乘积 W(int8)·V(uint64) 幅值可达 ~2^71，C 维累加可达 ~2^83，超出 64 位，
//        故必须 128 位中间累加（原生 __int128，或两 uint64 hi/lo 仿真）；
//   - 最终 (uint64)acc 取低 64 位 = mod 2^64；真值 < 2^84 << 2^127，128 位无溢出，低 64 位精确；
//   - bias : 有符号 int64，累加进 128 位和再取低 64 位；
//   - out : [batch][rows]，布局 out[b*rows + i]。
//
// 返回：0 成功；非 0 失败（含不支持的硬件 / 维度非法）。
//
// 编译示例（CUDA，需 nvcc + compute capability >= 7.0）：
//   nvcc -O3 -arch=sm_70 -c cipher_linear_int128.cu -o cipher_linear_int128.o
//   g++ -shared -fPIC accel_linear_int128.o -o libaccel_cuda.so -lcudart
// 编译示例（昇腾，可移植参考路径，任意机器可编译验证）：
//   g++ -shared -fPIC cipher_linear_int128_ascend.cpp -o libaccel_ascend.so
// 编译示例（昇腾，目标 NPU 路径，需 CANN 工具链）：
//   g++ -shared -fPIC -DHAVE_CANN cipher_linear_int128_ascend.cpp -o libaccel_ascend.so -lascendcl

#include <cstdint>

#ifndef ACCEL_LINEAR_INT128_H
#define ACCEL_LINEAR_INT128_H

// 注意（网关加载侧必读）：
//   - 后端按 mod 2^64 计算并写入 out（低 64 位）；Go 侧 AccelLinearInt128 会再按矩阵
//     ModBits（Mod32→低 32 位 / Mod64→低 64 位）归约，从而与 CipherLinear(math/big) 逐位一致。
//   - 加载须为受信绝对路径：网关仅从受信安装目录 dlopen，并校验文件为普通文件、group/other 不可写、
//     且 ABI 版本匹配（见 accel_cipher_linear_int128_abi_version），拒绝任意 env 路径以防范代码注入。

// 加速后端 ABI 版本号：网关加载侧（accel_dispatch.go 的 accelLinearInt128ABIVersion）
// 与后端实现（accel_cipher_linear_int128_abi_version()）必须一致，否则拒绝加载并回退 CPU。
#define ACCEL_LINEAR_INT128_ABI_VERSION 1

#ifdef __cplusplus
extern "C" {
#endif

// 在加速器件上计算掩码线性层。
//   W     : int8 权重，行优先 [rows][cols]
//   bias  : int64 偏置 [rows]（单位已为 b·S/scale，与内核侧一致）
//   V     : uint64 掩码域输入 [batch][cols]
//   out   : uint64 输出 [batch][rows]，布局 out[b*rows + i]
//   rows/cols/batch : 维度
// 返回 0 成功，非 0 失败。
int accel_cipher_linear_int128(const int8_t* W, const int64_t* bias,
                               const uint64_t* V, int rows, int cols,
                               uint64_t* out, int batch);

// ABI 版本握手符号：返回本后端实现的 ABI 版本（见 ACCEL_LINEAR_INT128_ABI_VERSION）。
// 网关加载侧据此校验版本，不匹配则拒绝加载、回退 CPU 路径。
int accel_cipher_linear_int128_abi_version(void);

#ifdef __cplusplus
}
#endif

#endif // ACCEL_LINEAR_INT128_H
