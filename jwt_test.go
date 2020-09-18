package jwt

import (
	"encoding/json"
	"strings"
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
	StandardClaims
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

func TestSecurePrint(t *testing.T) {
	signer, _ := NewSignerHS(HS256, []byte(`test-key`))
	claims := &StandardClaims{
		ID:       "test-id",
		Audience: Audience([]string{"test-user"}),
	}

	builder := NewBuilder(signer)
	token, err := builder.Build(claims)
	if err != nil {
		t.Fatal(err)
	}

	secure := token.SecureString()
	insecure := token.String()

	pos := strings.Index(secure, `.<signature>`)

	if secure[:pos] != insecure[:pos] {
		t.Fatalf("parts must be equal, got %v and %v", secure[:pos], insecure[:pos])
	}
	if secure[pos:] == insecure[pos:] {
		t.Fatalf("parts must not be equal, got %v and %v", secure[:pos], insecure[:pos])
	}
	if !strings.HasSuffix(secure, `.<signature>`) {
		t.Fatalf("must have safe suffix, got %v", secure)
	}
	if strings.HasSuffix(insecure, `.<signature>`) {
		t.Fatalf("must not have safe suffix, got %v", insecure)
	}
}
