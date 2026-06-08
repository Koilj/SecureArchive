package main

import (
	"testing"
)

func TestHasDisallowedChars(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"plain ascii", "asset_abc123", false},
		{"allowed whitespace", "hello\tworld\nfoo", false},
		{"ascii control 0x01", "bad\x01name", true},
		{"del char 0x7f", "bad\x7fname", true},
		{"zero-width space", "bad\u200Bname", true},
		{"right-to-left override", "bad\u202Ename", true},
		{"word joiner", "bad\u2060name", true},
		{"bom", "\ufeffbad", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasDisallowedChars(tc.in); got != tc.want {
				t.Fatalf("hasDisallowedChars(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestAgentAuthDisabled(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"", false},
		{"0", false},
		{"false", false},
		{"no", false},
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{"True", true},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("AGENT_DISABLE_AUTH", tc.value)
			if got := agentAuthDisabled(); got != tc.want {
				t.Fatalf("agentAuthDisabled(env=%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestValidateRPCEvalLimits(t *testing.T) {
	t.Run("function is required", func(t *testing.T) {
		err := validateRPC(&rpcRequest{Function: "", Args: []string{"a"}}, false)
		if err == nil {
			t.Fatal("expected error for empty function")
		}
	})

	t.Run("too many args", func(t *testing.T) {
		args := make([]string, maxRPCArgs+1)
		err := validateRPC(&rpcRequest{Function: "GetAllAssetsPublic", Args: args}, false)
		if err == nil {
			t.Fatal("expected error for too many args")
		}
	})

	t.Run("per-arg size cap", func(t *testing.T) {
		big := make([]byte, maxArgLenDefault+1)
		for i := range big {
			big[i] = 'a'
		}
		err := validateRPC(&rpcRequest{Function: "GetAsset", Args: []string{string(big)}}, false)
		if err == nil {
			t.Fatal("expected error for oversized arg")
		}
	})

	t.Run("disallowed chars in arg", func(t *testing.T) {
		err := validateRPC(&rpcRequest{Function: "GetAsset", Args: []string{"ok\x00name"}}, false)
		if err == nil {
			t.Fatal("expected error for control char in arg")
		}
	})

	t.Run("happy path", func(t *testing.T) {
		err := validateRPC(&rpcRequest{Function: "GetAsset", Args: []string{"asset_1"}}, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestValidateRPCSubmitPolicies(t *testing.T) {
	t.Run("unknown submit function rejected", func(t *testing.T) {
		err := validateRPC(&rpcRequest{Function: "DoEvilThing", Args: nil}, true)
		if err == nil {
			t.Fatal("expected error for unknown submit fn")
		}
	})

	t.Run("arg count enforced per policy", func(t *testing.T) {
		pol := submitPolicies["RegisterUser"]
		// RegisterUser wants 4 args; pass 3 -> reject.
		err := validateRPC(&rpcRequest{Function: "RegisterUser", Args: []string{"a", "b", "c"}}, true)
		if err == nil {
			t.Fatalf("expected error for too few args (policy=%+v)", pol)
		}
	})

	t.Run("per-arg cap for submit", func(t *testing.T) {
		pol := submitPolicies["ApproveCategory"]
		big := make([]byte, pol.MaxArg+1)
		for i := range big {
			big[i] = 'x'
		}
		err := validateRPC(&rpcRequest{Function: "ApproveCategory", Args: []string{string(big), "ok"}}, true)
		if err == nil {
			t.Fatal("expected error for oversized arg against submit policy")
		}
	})

	t.Run("BindServiceIdentity restricted to SecurityService", func(t *testing.T) {
		t.Setenv("AGENT_USER", "MLService")
		err := validateRPC(&rpcRequest{Function: "BindServiceIdentity", Args: []string{"a", "b"}}, true)
		if err == nil {
			t.Fatal("expected BindServiceIdentity to be rejected for MLService agent")
		}
		t.Setenv("AGENT_USER", "SecurityService")
		if err := validateRPC(&rpcRequest{Function: "BindServiceIdentity", Args: []string{"a", "b"}}, true); err != nil {
			t.Fatalf("expected BindServiceIdentity to pass for SecurityService agent, got %v", err)
		}
	})
}
