// Package testagent provides a small, runnable A2A v1.0 agent for local
// development and S-A2A-1 lifecycle tests.
//
// It deliberately lives outside the production registry path: the card is
// signed with an ephemeral Ed25519 key and the executor is in-memory only.
// Use the returned PinnedKeys with the gateway's verifier; do not ship this
// package as a production agent.
package testagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"strings"

	protocol "security-ai-gateway/gateway/a2a"

	sdk "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2acrypto"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
)

// Config controls the local test agent.
type Config struct {
	// PublicURL is the gateway-form interface URL, e.g.
	// http://127.0.0.1:9001/a2a.
	PublicURL string
	// Tenant is optional and is copied into supportedInterfaces[0].tenant.
	Tenant string
	// Name is optional; defaults to "A2A Test Agent".
	Name string
}

// Agent owns the signed card and HTTP handler.
type Agent struct {
	card    *sdk.AgentCard
	handler http.Handler
	key     protocol.PinnedKey
}

// New builds a signed v1.0 card and a JSON-RPC handler.
func New(cfg Config) (*Agent, error) {
	if strings.TrimSpace(cfg.PublicURL) == "" {
		return nil, errors.New("testagent: PublicURL is required")
	}
	if cfg.Name == "" {
		cfg.Name = "A2A Test Agent"
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("testagent: generate key: %w", err)
	}
	const kid = "testagent-ed25519-1"
	card := &sdk.AgentCard{
		Name:        cfg.Name,
		Description: "local A2A v1.0 test agent",
		Version:     "1.0.0",
		SupportedInterfaces: []*sdk.AgentInterface{{
			URL:             cfg.PublicURL,
			ProtocolBinding: sdk.TransportProtocolJSONRPC,
			ProtocolVersion: sdk.Version,
			Tenant:          cfg.Tenant,
		}},
		DefaultInputModes:  []string{"text/plain"},
		DefaultOutputModes: []string{"text/plain"},
		Skills: []sdk.AgentSkill{{
			ID:          "hello_world",
			Name:        "Hello World",
			Description: "returns a completed task",
			Tags:        []string{},
		}},
	}
	raw, err := json.Marshal(card)
	if err != nil {
		return nil, fmt.Errorf("testagent: marshal card: %w", err)
	}
	signer, err := a2acrypto.NewSigner(a2acrypto.SignerConfig{
		PrivateKey: priv,
		KeyID:      kid,
	})
	if err != nil {
		return nil, fmt.Errorf("testagent: signer: %w", err)
	}
	sig, err := signer.Sign(context.Background(), raw)
	if err != nil {
		return nil, fmt.Errorf("testagent: sign card: %w", err)
	}
	card.Signatures = []sdk.AgentCardSignature{*sig}
	if cardErr := protocol.ValidateAgentCard(card, protocol.CardValidationOptions{
		Tenant:    cfg.Tenant,
		PublicURL: cfg.PublicURL,
	}); cardErr != nil {
		return nil, fmt.Errorf("testagent: card validation: %w", cardErr)
	}

	requestHandler := a2asrv.NewHandler(executor{}, a2asrv.WithCallInterceptors(authInterceptor{}))
	mux := http.NewServeMux()
	mux.Handle("/a2a", a2asrv.NewJSONRPCHandler(requestHandler))
	mux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewStaticAgentCardHandler(card))

	return &Agent{
		card:    card,
		handler: mux,
		key: protocol.PinnedKey{
			Kid:       kid,
			Alg:       "EdDSA",
			PublicKey: pub,
		},
	}, nil
}

// authInterceptor marks every call as authenticated. The testagent is a
// fixture: the gateway terminates A2A governance authentication and the
// agent backend observes the gateway-verified caller. Without this the
// in-memory task store refuses ListTasks (-31401).
type authInterceptor struct{}

func (authInterceptor) Before(ctx context.Context, callCtx *a2asrv.CallContext, _ *a2asrv.Request) (context.Context, any, error) {
	if callCtx.User == nil {
		callCtx.User = &a2asrv.User{}
	}
	callCtx.User.Name = "gateway"
	callCtx.User.Authenticated = true
	return ctx, nil, nil
}

func (authInterceptor) After(ctx context.Context, _ *a2asrv.CallContext, _ *a2asrv.Response) error {
	return nil
}

// Handler returns the HTTP handler for the agent endpoint and card discovery.
func (a *Agent) Handler() http.Handler { return a.handler }

// Card returns the signed card served at the well-known path.
func (a *Agent) Card() *sdk.AgentCard { return a.card }

// PinnedKeys returns the verifier-side key for this ephemeral agent.
func (a *Agent) PinnedKeys() []protocol.PinnedKey {
	return []protocol.PinnedKey{a.key}
}

type executor struct{}

func (executor) Execute(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[sdk.Event, error] {
	return func(yield func(sdk.Event, error) bool) {
		if ec.StoredTask == nil {
			if !yield(sdk.NewSubmittedTask(ec, ec.Message), nil) {
				return
			}
		}
		if !yield(sdk.NewStatusUpdateEvent(ec, sdk.TaskStateWorking, nil), nil) {
			return
		}
		state := finalState(ec)
		if !yield(sdk.NewStatusUpdateEvent(ec, state, nil), nil) {
			return
		}
		// INPUT_REQUIRED / AUTH_REQUIRED 是「等待外部输入」的**可恢复中间态**：
		// agent 此时并未结束工作，而是挂起等待下一条消息。sdk 以「迭代器返回」
		// 作为执行结束信号并随即关闭该任务的执行队列，因此这里若直接返回，紧随
		// 其后的 CancelTask 就会命中已关闭队列，sdk 把它报成
		// -32603(INTERNAL_ERROR: cancelation failed: queue is closed) 而不是正常
		// 取消（KI#4 的剩余竞态：约 1/50 触发）。保持迭代器存活即可让队列不关，
		// 取消路径按 sdk 既有语义产出 CANCELED。释放由上下文结束承担（请求结束 /
		// 连接关闭 / 测试清理时 sdk 取消 ctx）。
		if state == sdk.TaskStateInputRequired || state == sdk.TaskStateAuthRequired {
			<-ctx.Done()
		}
	}
}

func (executor) Cancel(_ context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[sdk.Event, error] {
	return func(yield func(sdk.Event, error) bool) {
		yield(sdk.NewStatusUpdateEvent(ec, sdk.TaskStateCanceled, nil), nil)
	}
}

func finalState(ec *a2asrv.ExecutorContext) sdk.TaskState {
	if ec.Message != nil {
		if raw, ok := ec.Message.Metadata["ga.test.final_state"].(string); ok {
			switch sdk.TaskState(raw) {
			case sdk.TaskStateInputRequired, sdk.TaskStateAuthRequired, sdk.TaskStateFailed, sdk.TaskStateRejected:
				return sdk.TaskState(raw)
			}
		}
	}
	return sdk.TaskStateCompleted
}
