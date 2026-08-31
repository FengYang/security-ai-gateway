// Package main — Higress Wasm 插件：hello-plugin（M1 里程碑）
//
// 目标：验证 Go Wasm 插件在 Higress 中的完整生命周期
// - 插件加载与配置读取（wrapper.ParseConfigBy，支持热更新）
// - 请求/响应头拦截（ProcessRequestHeadersBy / ProcessResponseHeadersBy）
// - 日志输出（logs.Log）
//
// 编译（Go 1.24+ 原生 wasm，须加 -buildmode=c-shared）：
//
//	GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o main.wasm .
//
// 加载：将 main.wasm 打包为 OCI/Docker 镜像后通过 WasmPlugin CRD 或控制台关联路由。
package main

import (
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/higress-group/wasm-go/pkg/wrapper"
	logs "github.com/higress-group/wasm-go/pkg/log"
	"github.com/tidwall/gjson"
)

func main() {}

func init() {
	wrapper.SetCtx(
		"hello-plugin",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
		wrapper.ProcessResponseHeadersBy(onHttpResponseHeaders),
	)
}

// PluginConfig 插件配置（控制台 YAML 自动转 JSON 下发，可热更新）。
type PluginConfig struct {
	// Message 每次拦截时打印的消息（验证配置热加载）。
	Message string `json:"message"`
	// LogLevel 日志级别（debug/info/warn/error），预留。
	LogLevel string `json:"log_level"`
}

func parseConfig(json gjson.Result, config *PluginConfig, log logs.Log) error {
	config.Message = json.Get("message").String()
	config.LogLevel = json.Get("log_level").String()
	if config.Message == "" {
		config.Message = "hello from otpmask gateway"
	}
	log.Infof("hello-plugin: 配置已加载 message=%q log_level=%q", config.Message, config.LogLevel)
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config PluginConfig, log logs.Log) types.Action {
	log.Infof("hello-plugin: 收到请求头, message=%q", config.Message)
	if host, err := proxywasm.GetHttpRequestHeader("host"); err == nil {
		log.Infof("hello-plugin: host=%s", host)
	}
	if path, err := proxywasm.GetHttpRequestHeader(":path"); err == nil {
		log.Infof("hello-plugin: path=%s", path)
	}
	// 标记请求经过本插件（便于端到端验证）
	proxywasm.AddHttpRequestHeader("x-otpmask-hello", "true")
	return types.HeaderContinue
}

func onHttpResponseHeaders(ctx wrapper.HttpContext, config PluginConfig, log logs.Log) types.Action {
	log.Infof("hello-plugin: 收到响应头, message=%q", config.Message)
	proxywasm.AddHttpResponseHeader("x-otpmask-hello", "true")
	return types.HeaderContinue
}
