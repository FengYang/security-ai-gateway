// Package archtest 架构边界门禁（方案 §6.3「边界强制」的机器可执行版本）。
//
// 本包没有生产代码，只有测试：用 `go/parser` 直接读源码的 import 声明，断言四层架构的
// 依赖方向不被破坏。
//
// 【为什么用 Go 测试，而不是只靠 golangci-lint 的 depguard】
// CI 的必过项是 `go vet` + `go test ./...`；golangci-lint 是否安装、版本与本仓
// `.golangci.yml` 是否兼容，都不在 CI 依赖清单里。把边界规则写成普通单测，等于让
// 「改坏依赖方向」直接表现为**单测红**，零额外工具链、本地与 CI 同一判据。
// `.golangci.yml` 里的 depguard 规则与之同源，作为开发者本地的更早反馈。
package archtest
