package jwt

import (
	"encoding/base64"
	"testing"
)

var bytesToBase64 = base64.RawURLEncoding.EncodeToString

func strToBase64(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func getSignerError(_ Signer, err error) error {
	return err
}

func getVerifierError(_ Verifier, err error) error {
	return err
}

func mustBuild(s Signer, p interface{}) *Token {
	t, err := NewBuilder(s).Build(p)
	if err != nil {
		panic(err)
	}
	return t
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
