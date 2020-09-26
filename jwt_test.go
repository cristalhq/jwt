package jwt

import (
	"encoding/json"
	"testing"
)

func mustSigner(s Signer, err error) Signer {
	if err != nil {
		panic(err)
	}
	return s
}

func mustVerifier(v Verifier, err error) Verifier {
	if err != nil {
		panic(err)
	}
	return v
}

type customClaims struct {
	RegisteredClaims
	TestField string `json:"test_field"`
}

func TestMarshalHeader(t *testing.T) {
	f := func(h *Header, want string) {
		t.Helper()

		raw, err := json.Marshal(h)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if string(raw) != want {
			t.Errorf("got: %v, want %v", string(raw), want)
		}
	}

	f(
		&Header{Algorithm: RS256},
		`{"alg":"RS256"}`,
	)
	f(
		&Header{Algorithm: RS256, Type: "JWT"},
		`{"alg":"RS256","typ":"JWT"}`,
	)
	f(
		&Header{Algorithm: RS256, ContentType: "token"},
		`{"alg":"RS256","cty":"token"}`,
	)
	f(
		&Header{Algorithm: RS256, Type: "JWT", ContentType: "token"},
		`{"alg":"RS256","typ":"JWT","cty":"token"}`,
	)
	f(
		&Header{Algorithm: RS256, Type: "JwT", ContentType: "token"},
		`{"alg":"RS256","typ":"JwT","cty":"token"}`,
	)
}
