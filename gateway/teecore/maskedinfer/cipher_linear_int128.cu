// cipher_linear_int128.cu — 路线2 步骤③ 不可信加速器线性内核【NVIDIA CUDA 后端】。
//
// 本文件实现一个后端无关的 C ABI 符号 accel_cipher_linear_int128（见 accel_linear_int128.h），
// 与华为昇腾后端 cipher_linear_int128_ascend.cpp 共用同一符号与语义；网关侧按部署环境
// 加载对应 .so（libaccel_cuda.so / libaccel_ascend.so），不关心具体硬件。
//
// ⚠ 状态：🖥 待环境就绪 —— 本机无 CUDA 工具链 / GPU，未编译未运行。
//   内核算术语义与已真机验证的 Go `CipherLinearInt128` 逐位一致（见 int128_linear.go）。
//
// 编译（需 nvcc + CUDA GPU，compute capability >= 7.0 以原生支持 __int128）：
//   nvcc -O3 -arch=sm_70 -c cipher_linear_int128.cu -o cipher_linear_int128.o
//   g++ -shared -fPIC cipher_linear_int128.o -o libaccel_cuda.so -lcudart
//
// 正确性要点（务必与 int128_linear.go / accel_linear_int128.h 保持一致）：
//   - 乘积为"有符号 128 位"：(__int128)(int64_t)W * (__int128)(uint64_t)V
//     （不可写成 (uint64_t)W * V —— 那会变成无符号乘积，对负权重错误）
//   - 128 位累加，最终 (uint64_t)acc 取低 64 位 = mod 2^64（与 math/big.reduce 等价）
//   - 偏置作为有符号 int64 累加进 128 位和

#include "accel_linear_int128.h"

#include <cuda_runtime.h>

#define CL_CHECK(call)                                                        \
  do {                                                                       \
    cudaError_t _e = (call);                                                 \
    if (_e != cudaSuccess) return -1;                                        \
  } while (0)

// 每个 block 负责一个 (batch b, row i) 的输出；块内线程按 stride 分摊 cols 维，
// 局部 __int128 累加后做块内归约，线程 0 写回 (uint64_t)acc（低 64 位 = mod 2^64）。
__global__ void cipherLinearKernel(const int8_t* __restrict__ W,
                                   const int64_t* __restrict__ bias,
                                   const uint64_t* __restrict__ V, int rows,
                                   int cols, uint64_t* __restrict__ out,
                                   int batch) {
  int b = blockIdx.x / rows;
  int i = blockIdx.x % rows;
  int tid = threadIdx.x;

  // 共享内存存放每线程的 128 位部分和（这里用原生 __int128；compute cap >= 7.0 支持）
  extern __shared__ __int128 shared_acc[];

  __int128 acc = 0;
  // stride 遍历 cols
  for (int j = tid; j < cols; j += blockDim.x) {
    int64_t w = (int64_t)W[(size_t)i * cols + j];          // 符号扩展 int8→int64
    uint64_t v = V[(size_t)b * cols + j];                  // 无符号掩码域
    acc += (__int128)w * (__int128)v;                      // 有符号 128 位乘积
  }
  shared_acc[tid] = acc;
  __syncthreads();

  // 块内归约（树形）
  for (int stride = blockDim.x / 2; stride > 0; stride >>= 1) {
    if (tid < stride) {
      shared_acc[tid] += shared_acc[tid + stride];
    }
    __syncthreads();
  }

  if (tid == 0) {
    acc = shared_acc[0];
    acc += (__int128)bias[i];                 // 有符号偏置
    out[(size_t)b * rows + i] = (uint64_t)acc; // 低 64 位 = mod 2^64
  }
}

// 统一加速后端符号：CUDA 实现。
int accel_cipher_linear_int128(const int8_t* W, const int64_t* bias,
                               const uint64_t* V, int rows, int cols,
                               uint64_t* out, int batch) {
  if (rows <= 0 || cols <= 0 || batch <= 0) return -2;
  int blocks = batch * rows;
  int threads = 128; // 每 block 线程数；cols 较大时自动 stride 分摊
  size_t shm = (size_t)threads * sizeof(__int128);

  cipherLinearKernel<<<blocks, threads, shm>>>(W, bias, V, rows, cols, out, batch);
  CL_CHECK(cudaGetLastError());
  CL_CHECK(cudaDeviceSynchronize());
  return 0;
}
