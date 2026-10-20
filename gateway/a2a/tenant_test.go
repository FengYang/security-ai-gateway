package a2a

import (
	"encoding/json"
	"testing"
)

func TestRequestTenant(t *testing.T) {
	tenant, ok, err := RequestTenant(json.RawMessage(`{"tenant":"tenant-a"}`))
	if err != nil || !ok || tenant != "tenant-a" {
		t.Fatalf("tenant=%q ok=%v err=%v", tenant, ok, err)
	}
	_, ok, err = RequestTenant(json.RawMessage(`{}`))
	if err != nil || ok {
		t.Fatalf("missing tenant: ok=%v err=%v", ok, err)
	}
	_, _, err = RequestTenant(json.RawMessage(`{"tenant":1}`))
	assertRPCCode(t, err, CodeInvalidParams)
}

func TestResolveTenant(t *testing.T) {
	got, err := ResolveTenant("tenant-a", "", "")
	if err != nil || got != "tenant-a" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	got, err = ResolveTenant("tenant-a", "tenant-a", "tenant-a")
	if err != nil || got != "tenant-a" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	_, err = ResolveTenant("tenant-a", "tenant-b", "")
	assertRPCCode(t, err, CodeUnauthorized)
	_, err = ResolveTenant("tenant-a", "", "tenant-b")
	assertRPCCode(t, err, CodeUnauthorized)
	_, err = ResolveTenant("", "", "")
	assertRPCCode(t, err, CodeUnauthenticated)
}

func TestResolveRouteTenant(t *testing.T) {
	if _, err := ResolveRouteTenant("tenant-a", "tenant-a"); err != nil {
		t.Fatalf("matching route: %v", err)
	}
	_, err := ResolveRouteTenant("tenant-a", "tenant-b")
	assertRPCCode(t, err, CodeUnauthorized)
}
