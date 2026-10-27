package mock

import "time"

// 默认 fixture 响应体（OpenAI 兼容语义，L1 归一）。provider 参数用于模型名字段，便于断言。

const defaultChatOK = `{"id":"chatcmpl-mock-1","object":"chat.completion","model":"mock-model","choices":[{"index":0,"message":{"role":"assistant","content":"hello from mock"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}`

const defaultStream = `data: {"id":"chatcmpl-mock-1","object":"chat.completion.chunk","model":"mock-model","choices":[{"index":0,"delta":{"role":"assistant","content":"hello"},"finish_reason":null}]}

data: {"id":"chatcmpl-mock-1","object":"chat.completion.chunk","model":"mock-model","choices":[{"index":0,"delta":{"content":" world"},"finish_reason":"stop"}]}

data: [DONE]

`

const defaultList = `{"object":"list","data":[{"id":"mock-model","owned_by":"mock-provider"}]}`

const default401 = `{"error":{"message":"invalid api key","type":"invalid_request_error"}}`

const default429 = `{"error":{"message":"rate limit exceeded","type":"rate_limit_error"}}`

// ChatOKFixture 正常非流式响应 fixture。
func ChatOKFixture(provider string) Fixture {
	return Fixture{Scenario: "chat_ok", StatusCode: 200, Body: []byte(defaultChatOK)}
}

// StreamFixture 流式 SSE 响应 fixture。
func StreamFixture(provider string) Fixture {
	return Fixture{Scenario: "chat_stream", StatusCode: 200, Stream: true, Body: []byte(defaultStream)}
}

// ListFixture 模型列表 fixture。
func ListFixture(provider string) Fixture {
	return Fixture{Scenario: "list", StatusCode: 200, Body: []byte(defaultList)}
}

// Auth401Fixture 鉴权失败 fixture（401）。
func Auth401Fixture(provider string) Fixture {
	return Fixture{Scenario: "auth_401", StatusCode: 401, Body: []byte(default401)}
}

// Rate429Fixture 限流 fixture（429 + Retry-After）。
func Rate429Fixture(provider string) Fixture {
	return Fixture{Scenario: "rate_429", StatusCode: 429, RetryAfter: "1", Body: []byte(default429)}
}

// TimeoutFixture 超时 fixture（延迟 2s，配合短 context → upstream_timeout）。
func TimeoutFixture(provider string) Fixture {
	return Fixture{Scenario: "timeout", StatusCode: 200, Delay: 2 * time.Second, Body: []byte(defaultChatOK)}
}

// DefaultFixtures 返回 6 类缺省 fixture（契约测试用）。
func DefaultFixtures(provider string) []Fixture {
	return []Fixture{
		ChatOKFixture(provider),
		StreamFixture(provider),
		ListFixture(provider),
		Auth401Fixture(provider),
		Rate429Fixture(provider),
		TimeoutFixture(provider),
	}
}
