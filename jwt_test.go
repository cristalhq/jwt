package jwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"reflect"
	"testing"
)

func TestDecodeClaims(t *testing.T) {
	tokenStr := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.jC1Ncd2FW0ZpoiHV9_Bk2eDWdfCqUIzfCgTHZfK0h_o`
	token, err := ParseNoVerify([]byte(tokenStr))
	mustOk(t, err)

	claims := RegisteredClaims{}
	mustOk(t, token.DecodeClaims(&claims))

	iat := asNumericDate(1516239022)
	wantClaims := RegisteredClaims{
		IssuedAt: &iat,
		Audience: Audience{"John Doe"},
		Subject:  "1234567890",
	}
	mustEqual(t, claims, wantClaims)
}

func TestMarshalHeader(t *testing.T) {
	f := func(h *Header, want string) {
		t.Helper()

		raw, err := h.MarshalJSON()
		mustOk(t, err)
		mustEqual(t, string(raw), want)
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

func TestNewKey(t *testing.T) {
	key, err := GenerateRandomBits(512)
	mustOk(t, err)

	// 8 bits to 1 byte
	const byteCount = int(512.0 / 8)
	mustEqual(t, len(key), byteCount)
}

var bytesToBase64 = base64.RawURLEncoding.EncodeToString

func base64ToBytes(s string) []byte {
	return must(base64.RawURLEncoding.DecodeString(s))
}

func getSignerError(_ Signer, err error) error {
	return err
}

func getVerifierError(_ Verifier, err error) error {
	return err
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func mustParseRSAKey(s string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		panic("invalid PEM")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return key
}

func mustParseECKey(s string) *ecdsa.PrivateKey {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		panic("invalid PEM")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return key
}

func mustOk(tb testing.TB, err error) {
	tb.Helper()
	if err != nil {
		tb.Fatal(err)
	}
}

func mustFail(tb testing.TB, err error) {
	tb.Helper()
	if err == nil {
		tb.Fatal()
	}
}

func mustEqual[T any](tb testing.TB, have, want T) {
	tb.Helper()
	if !reflect.DeepEqual(have, want) {
		tb.Fatalf("\nhave: %+v\nwant: %+v\n", have, want)
	}
}
