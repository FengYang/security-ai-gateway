// Package main — 决策门 PoC（M4-4）：固定 r + TEE 掩码像预计算的单层线性正确性验证
//
// 验证技术方案 形式化方案的核心数学性质：
//
//	网关加密：   c = x + r                    （r 为 TEE 生成的掩码）
//	vLLM 密态线性（不知道 r）：y_cipher = W·c + b = W·x + b + W·r
//	TEE 补算：   用预计算掩码像 W·r 解密：y = y_cipher - W·r = W·x + b ✅
//	（本 PoC 非线性层取恒等；GELU/softmax 的 TEE 补算为 M6 NonLinearService）
//
// 结论标准：若 y == W·x + b (mod R)，则"固定 r + 掩码像"方案数学闭合，
// 路径 B（密态线性 + TEE 补算）具备可行性，决策门通过。
//
// 运行：go run ./gateway/poc/linear-mask-poc
package main

import (
	"fmt"
	"math/rand"

	"security-ai-gateway/cipher/mask"
)

// R 量化域（与 otpmask-plugin / secagg 对齐 2^32）。
const R uint64 = 1 << 32

func matMulVec(W [][]uint64, v []uint64) []uint64 {
	n := len(W)
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		var sum uint64
		for j := 0; j < len(v); j++ {
			sum = (sum + W[i][j]*v[j]) % R
		}
		out[i] = sum % R
	}
	return out
}

func vecAdd(a, b []uint64) []uint64 {
	out := make([]uint64, len(a))
	for i := range a {
		out[i] = (a[i] + b[i]) % R
	}
	return out
}

func vecSub(a, b []uint64) []uint64 {
	out := make([]uint64, len(a))
	for i := range a {
		out[i] = (a[i] + R - b[i]%R) % R
	}
	return out
}

func eq(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func main() {
	dim := 4

	// 1. TEE 生成掩码 r（256 位 seed 派生掩码流 → 掩码向量）
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(rand.Intn(256))
	}
	s, err := mask.NewStream(seed, R)
	if err != nil {
		panic(err)
	}
	r := make([]uint64, dim)
	for i := range r {
		r[i] = s.Next()
	}

	// 2. 明文输入 x（网关侧，企业内部）
	x := []uint64{100, 200, 300, 400}

	// 3. 模型权重 W、b（vLLM 持有，明文权重）
	W := [][]uint64{
		{1, 2, 3, 4},
		{5, 6, 7, 8},
		{9, 10, 11, 12},
		{13, 14, 15, 16},
	}
	b := []uint64{1, 2, 3, 4}

	// 4. 网关加密：c = x + r
	c := vecAdd(x, r)

	// 5. vLLM 密态线性（不知道 r）：y_cipher = W·c + b
	yCipher := vecAdd(matMulVec(W, c), b)

	// 6. TEE：预计算掩码像 W·r，解密 y = y_cipher - W·r
	wDotR := matMulVec(W, r)
	y := vecSub(yCipher, wDotR)

	// 7. 参照：明文线性 W·x + b
	want := vecAdd(matMulVec(W, x), b)

	fmt.Printf("x        = %v\n", x)
	fmt.Printf("r        = %v\n", r)
	fmt.Printf("c=x+r    = %v\n", c)
	fmt.Printf("y_cipher = %v  (vLLM 在密文域计算，未见明文)\n", yCipher)
	fmt.Printf("y        = %v  (TEE 用 W·r 解密)\n", y)
	fmt.Printf("want     = %v  (明文 W·x+b 参照)\n", want)
	if eq(y, want) {
		fmt.Println("\n[PASS] 决策门 PoC 通过：固定 r + TEE 掩码像方案数学闭合，路径 B 可行")
	} else {
		fmt.Println("\n[FAIL] 决策门 PoC 失败")
	}
}
