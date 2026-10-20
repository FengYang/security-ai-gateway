package a2a

import "testing"

func TestNegotiateVersion(t *testing.T) {
	for _, v := range []string{"1.0", "1.0.0", "1.0.1", " 1.0.2 "} {
		if err := NegotiateVersion(v); err != nil {
			t.Fatalf("%q: %v", v, err)
		}
	}
	for _, v := range []string{"", "0.3", "0.3.0", "1.1", "2.0"} {
		assertRPCCode(t, NegotiateVersion(v), CodeVersionNotSupported)
	}
	for _, v := range []string{"1", "1.0.", "1.0.0.0", "v1.0", "1.0,2.0"} {
		assertRPCCode(t, NegotiateVersion(v), CodeInvalidRequest)
	}
}

func TestCheckExtensions(t *testing.T) {
	if err := CheckExtensions(""); err != nil {
		t.Fatalf("empty: %v", err)
	}
	if err := CheckExtensions("https://example.com/ext"); err != nil {
		t.Fatalf("optional extension must pass through: %v", err)
	}
}
