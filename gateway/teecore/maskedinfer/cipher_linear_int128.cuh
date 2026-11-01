// cipher_linear_int128.cuh — 路线2 步骤③ 不可信加速器线性内核（GPU int128）对外接口。
//
// ⚠ 状态：🖥 待环境就绪 —— 本机无 CUDA 工具链 / GPU，无法编译与运行。
//   内核算术语义与已真机验证的 Go `CipherLinearInt128`
//   （gateway/teecore/maskedinfer/int128_linear.go，逐位对齐 math/big 神谕）完全一致，
//   故算法正确性已由 Go 侧 200+50 组随机/真实对拍证明；此处仅替换执行后端。
//
// 语义：y[b][i] = ( Σ_j W[i*cols+j] * V[b*cols+j] + bias[i] )  mod 2^64
//   - W：int8 量化权重（行优先，已 round(W_real/scale)），符号扩展为 int64 参与乘积；
//   - V：uint64 掩码域向量（= ToMaskDomain(x) + r，mod 2^64），按无符号参与乘积；
//   - 乘积按"有符号 128 位"累加（W 为负时乘积为负），最终取低 64 位 = mod 2^64；
//   - 偏置 bias 为有符号 int64，累加进 128 位和后再取低 64 位。
// 关键：单乘积 W(int8)·V(uint64) 幅值可达 ~2^71，C 维累加可达 ~2^83，远超 64 位，
//       故必须用 128 位（或两 int64 hi/lo 仿真）中间累加，再 mod 2^64。

#ifndef CIPHER_LINEAR_INT128_CUH
#define CIPHER_LINEAR_INT128_CUH

#ifdef __cplusplus
extern "C" {
#endif

// 在 GPU 上计算掩码线性层。
//   W     : 设备指针，int8 权重，行优先 [rows][cols]
//   bias  : 设备指针，int64 偏置 [rows]（单位已为 b·S/scale，与内核侧一致）
//   V     : 设备指针，uint64 掩码域输入 [batch][cols]
//   out   : 设备指针，uint64 输出 [batch][rows]
//   rows/cols/batch : 维度
// 返回 0 成功，非 0 失败（含不支持的 compute capability）。
int cipher_linear_int128(const int8_t* W, const int64_t* bias,
                         const uint64_t* V, int rows, int cols,
                         uint64_t* out, int batch);

#ifdef __cplusplus
}
#endif

#endif // CIPHER_LINEAR_INT128_CUH
