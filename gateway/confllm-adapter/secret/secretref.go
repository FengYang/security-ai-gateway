// Package secret 凭据引用与解析抽象（§1.4 / §7.3 / §7.7）。
//
// SecretRef 指向 broker .env 凭据库；Credential 解析后的凭据（绝不序列化/打印）。
// SecretResolver 由 admin-service 基于 broker 实现，confllm-adapter 仅依赖此接口（零硬依赖）。
package secret

import "context"

// SecretRef 凭据引用（仅存名称，绝不存明文）。
type SecretRef struct {
	Name string `json:"name" yaml:"name"`
}

// Credential 解析后的凭据。所有字段均 json:"-"（§7.2：绝不序列化/打印 Key）。
type Credential struct {
	Key             []byte   `json:"-"`
	Upstream        string   `json:"-"`
	AllowedPrefixes []string `json:"-"`
}

// SecretResolver 凭据解析接口（实现在 admin-service 基于 broker .env）。
type SecretResolver interface {
	Resolve(ctx context.Context, ref SecretRef) (*Credential, error)
}
