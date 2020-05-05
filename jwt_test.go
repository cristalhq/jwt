package jwt

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustSigner(s Signer, _ error) Signer {
	return s
}

type customClaims struct {
	StandardClaims
	TestField string `json:"test_field"`
}

func (cs *customClaims) MarshalBinary() (data []byte, err error) {
	return json.Marshal(cs)
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
		`{"alg":"RS256","typ":"JWT"}`,
	)
	f(
		&Header{Algorithm: RS256, Type: "JWT"},
		`{"alg":"RS256","typ":"JWT"}`,
	)
}

func TestSecurePrint(t *testing.T) {
	sign, _ := NewHS256([]byte(`test-key`))
	claims := &StandardClaims{
		ID:       "test-id",
		Audience: Audience([]string{"test-user"}),
	}

	token, err := Build(sign, claims)
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
