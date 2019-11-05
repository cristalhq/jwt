package jwt

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestBuild(t *testing.T) {
	signer := NewHS256([]byte(`secret`))
	builder := NewTokenBuilder(signer)

	claims := &StandardClaims{
		Audience: []string{"admin"},
		ID:       "random-unique-string",
	}
	token, _ := builder.Build(claims)

	fmt.Printf("Algorithm %v\n", token.Header().Algorithm)
	fmt.Printf("Type      %v\n", token.Header().Type)
	fmt.Printf("Claims    %v\n", string(token.RawClaims()))
	fmt.Printf("Payload   %v\n", string(token.Payload()))
	fmt.Printf("Token     %v\n", string(token.Raw()))
}

func TestBuildWithHeader(t *testing.T) {
	f := func(signer Signer, header Header, want string) {
		t.Helper()

		token, err := BuildWithHeader(signer, header, &StandardClaims{})
		if err != nil {
			t.Error(err)
		}

		want = toBase64(want)
		raw := string(token.RawHeader())
		if raw != want {
			t.Errorf("want %v, got %v", want, raw)
		}
	}

	f(
		NewHS256(nil),
		Header{Algorithm: HS256, Type: "JWT"},
		`{"alg":"HS256","typ":"JWT"}`,
	)
	f(
		NewHS512(nil),
		Header{Algorithm: HS512, Type: "jit"},
		`{"alg":"HS512","typ":"jit"}`,
	)
	f(
		NewHS512(nil),
		Header{Algorithm: Algorithm("OwO"), Type: "JWT"},
		`{"alg":"OwO","typ":"JWT"}`,
	)
	f(
		NewHS512(nil),
		Header{Algorithm: Algorithm("UwU"), Type: "jit"},
		`{"alg":"UwU","typ":"jit"}`,
	)
}

func toBase64(s string) string {
	buf := make([]byte, base64EncodedLen(len(s)))
	base64.RawURLEncoding.Encode(buf, []byte(s))
	return string(buf)
}
