//go:build pkcs11

// keyref.go —— PKCS#11 后端 KeyRef 编解码（M4-4a）。
//
// KeyRef（[]byte）在上层是模块内密钥对象的不透明引用；PKCS#11 后端的编码
// 形态为文本 token：
//
//	pk11:v1:<slot>:<partition>:<handle-hex>
//
// 设计约束：
//   - **不含密钥材料**：句柄是 token 对象的 PKCS#11 序号，泄露句柄不等于
//     泄露密钥（取用仍需登录态+会话；CKA_PRIVATE 对象仅登录后可见）。
//     KeyRef.String() 可直接进日志。
//   - **跨后端/跨槽/跨租户误用即拒**（fail-closed）：token 携带 backend
//     标识、槽位下标与 partition，decode 时逐项比对当前后端，不匹配返回
//     ErrKeyNotFound——防止 mock 后端的 ref、另一槽位/分区的句柄在本后端
//     被误用（R-S3-8 多租户隔离的引用层防线）。
//   - **slot 语义**同 Init：GetSlotList(tokenPresent=true) 的下标（token
//     重建后厂商 slot ID 会变，下标不变；见 pkcs11.go 包注释）。
//   - **partition 禁含冒号**：分区名作为分隔字段，含 ":" 会破坏 token
//     结构；encode 期拒绝（Config.Validate 亦应拦截，此处为内聚兜底）。
package cryptopmodule

import (
	"fmt"
	"strconv"
	"strings"
)

// keyRefPrefix/keyRefVersion KeyRef token 前缀与版本（升级编码时升版本号，
// 旧版本 token 一律拒而不解析，防止静默误读）。
const (
	keyRefPrefix  = "pk11"
	keyRefVersion = "v1"
)

// encodeKeyRef 构造 PKCS#11 KeyRef token。
// partition 含 ":" 返回错误（调用方配置层亦应拦截，此处 fail-closed 兜底）。
func encodeKeyRef(slot int, partition string, handle uint) (KeyRef, error) {
	if strings.Contains(partition, ":") {
		return nil, fmt.Errorf("pkcs11: partition=%q 含冒号（会破坏 KeyRef token 结构，禁止）", partition)
	}
	tok := strings.Join([]string{
		keyRefPrefix, keyRefVersion,
		strconv.Itoa(slot), partition,
		strconv.FormatUint(uint64(handle), 16),
	}, ":")
	return KeyRef(tok), nil
}

// decodeKeyRef 解析 KeyRef 并校验归属（当前后端的 slot 与 partition）。
// 任何格式错误或归属不匹配均返回 ErrKeyNotFound 包装错误（fail-closed）。
func decodeKeyRef(ref KeyRef, slot int, partition string) (uint, error) {
	if len(ref) == 0 {
		return 0, fmt.Errorf("%w: KeyRef 为空", ErrKeyNotFound)
	}
	parts := strings.Split(string(ref), ":")
	if len(parts) != 5 {
		return 0, fmt.Errorf("%w: KeyRef %q 结构非法（须为 %s:%s:<slot>:<partition>:<handle>）",
			ErrKeyNotFound, ref, keyRefPrefix, keyRefVersion)
	}
	if parts[0] != keyRefPrefix || parts[1] != keyRefVersion {
		return 0, fmt.Errorf("%w: KeyRef %q 不属于 PKCS#11 后端（前缀/版本不匹配；禁止跨后端误用）",
			ErrKeyNotFound, ref)
	}
	tokSlot, err := strconv.Atoi(parts[2])
	if err != nil || tokSlot < 0 {
		return 0, fmt.Errorf("%w: KeyRef %q slot 字段非法: %q", ErrKeyNotFound, ref, parts[2])
	}
	if tokSlot != slot {
		return 0, fmt.Errorf("%w: KeyRef %q 属于 slot=%d，当前后端 slot=%d（禁止跨槽误用）",
			ErrKeyNotFound, ref, tokSlot, slot)
	}
	if parts[3] != partition {
		return 0, fmt.Errorf("%w: KeyRef %q 属于 partition=%q，当前 partition=%q（禁止跨租户误用，R-S3-8）",
			ErrKeyNotFound, ref, parts[3], partition)
	}
	handle, err := strconv.ParseUint(parts[4], 16, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: KeyRef %q handle 字段非法: %q", ErrKeyNotFound, ref, parts[4])
	}
	return uint(handle), nil
}
