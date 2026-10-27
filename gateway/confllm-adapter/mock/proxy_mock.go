package mock

import (
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
)

// NewProxyMock 构造 proxy-mediated 形态 mock（Privatemode 本地 proxy 桩）。
//
// 实现为到 target（通常为 MockKernel.URL）的反向代理，模拟「客户端本地 proxy 在 prompt
// 离开本机前校验远程证明后再转发至机密 enclave」的拓扑。真实 proxy 的证明校验为 pending-doc，
// 此处仅做透明转发（X-Mock-Scenario 等请求头原样传递，便于契约测试选场景）。
func NewProxyMock(target string) *httptest.Server {
	u, err := url.Parse(target)
	if err != nil {
		panic("mock: 非法 proxy target: " + err.Error())
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	return httptest.NewServer(rp)
}
