package secagg

import "context"

// PartyDriver 参与方协议执行接口（依赖倒置）。
//
// 本地实现为 *party（内存同步模型）；远程实现为 gRPC 客户端代理
// （每阶段一次 RPC，见 wire 包）。聚合服务器只依赖本接口，
// 从而实现"同一协议内核、两种部署形态"。
//
// 所有方法接受 context.Context，用于超时控制与取消传播。
type PartyDriver interface {
	// partyID 参与方 ID（0..n-1）。
	partyID() int
	// advertise Round 0：通告双公钥 + Ed25519 身份签名。
	advertise(ctx context.Context) (advertiseMsg, error)
	// shareSeeds Round 1：生成并加密所有份额包 + 种子承诺。
	shareSeeds(ctx context.Context, advertises map[int]advertiseMsg) ([]shareBundleCipher, seedCommitments, error)
	// receiveBundles 接收服务器路由的份额密文。
	receiveBundles(ctx context.Context, bundles []shareBundleCipher) error
	// maskedInput Round 2：计算双掩码后的输入。
	maskedInput(ctx context.Context, advertises map[int]advertiseMsg) ([]uint64, error)
	// unmask Round 4：按交付规则提交份额。
	unmask(ctx context.Context, online map[int]bool) (unmaskMsg, error)
	// dropped 从指定轮次起是否离线（测试注入与远程故障模拟）。
	dropped(round Round) bool
}
