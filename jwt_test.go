package jwt

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func TestDecodeClaims(t *testing.T) {
	tokenStr := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.jC1Ncd2FW0ZpoiHV9_Bk2eDWdfCqUIzfCgTHZfK0h_o`
	token, err := ParseNoVerify([]byte(tokenStr))
	if err != nil {
		t.Fatal(err)
	}

	claims := RegisteredClaims{}
	if err := token.DecodeClaims(&claims); err != nil {
		t.Fatal(err)
	}

	iat := asNumericDate(1516239022)
	wantClaims := RegisteredClaims{
		IssuedAt: &iat,
		Audience: Audience{"John Doe"},
		Subject:  "1234567890",
	}
	if !reflect.DeepEqual(claims, wantClaims) {
		t.Fatalf("want %v, got %v", wantClaims, claims)
	}
}

func TestMarshalHeader(t *testing.T) {
	f := func(h *Header, want string) {
		t.Helper()

		raw, err := h.MarshalJSON()
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
	f(
		&Header{Algorithm: RS256, Type: "JwT", ContentType: "token", KeyID: "test"},
		`{"alg":"RS256","typ":"JwT","cty":"token","kid":"test"}`,
	)
}

var bytesToBase64 = base64.RawURLEncoding.EncodeToString

func strToBase64(s string) string {
	return bytesToBase64([]byte(s))
}

func getSignerError(_ Signer, err error) error {
	return err
}

func getVerifierError(_ Verifier, err error) error {
	return err
}

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
