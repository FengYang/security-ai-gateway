//go:build !pkcs11

// pkcs11_stub.go —— PKCS#11 后端的 fail-closed 占位（未启用 pkcs11 tag 的构建）。
//
// 真实实现在 pkcs11.go（//go:build pkcs11，cgo + github.com/miekg/pkcs11）。
// 默认构建不引入 cgo 依赖；启用方式：
//
//	go build -tags pkcs11 ./...   # 需 cgo 与 PKCS#11 库（SoftHSM/厂商 HSM）
//
// 未启用时对 backend=pkcs11 返回明确错误（fail-closed 启动拒，C-3），
// 绝不静默回退 mock/软件实现冒充合规。
package cryptopmodule

import "fmt"

// newPKCS11Backend 见 pkcs11.go（启用 pkcs11 tag 时的真实构造入口）。
func newPKCS11Backend(cfg *Config) (ModuleBackend, error) {
	return nil, fmt.Errorf("%w: 本构建未启用 pkcs11 tag（go build -tags pkcs11；需 cgo 与 PKCS#11 库）；backend=pkcs11 不可用",
		ErrNotImplemented)
}
