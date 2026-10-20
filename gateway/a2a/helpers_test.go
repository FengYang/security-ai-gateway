package a2a

import (
	"encoding/json"
	"testing"

	sdk "github.com/a2aproject/a2a-go/v2/a2a"
)

func testCard() *sdk.AgentCard {
	return &sdk.AgentCard{
		Name:        "Test Agent",
		Description: "test agent",
		Version:     "1.0.0",
		SupportedInterfaces: []*sdk.AgentInterface{{
			URL:             "https://agent.example.com/a2a",
			ProtocolBinding: sdk.TransportProtocolJSONRPC,
			ProtocolVersion: sdk.Version,
		}},
		DefaultInputModes:  []string{"text/plain"},
		DefaultOutputModes: []string{"text/plain"},
		Skills: []sdk.AgentSkill{{
			ID:          "hello_world",
			Name:        "Hello World",
			Description: "returns hello",
			Tags:        []string{},
		}},
		Signatures: []sdk.AgentCardSignature{{
			Protected: "eyJhbGciOiJFZERTQSJ9",
			Signature: "dGVzdA",
		}},
	}
}

func testCardJSON(t *testing.T, card *sdk.AgentCard) []byte {
	t.Helper()
	raw, err := json.Marshal(card)
	if err != nil {
		t.Fatalf("marshal card: %v", err)
	}
	return raw
}
