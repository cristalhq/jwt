package jwt

import (
	"encoding/base64"
	"errors"
	"testing"
)

func TestBuild(t *testing.T) {
	f := func(signer Signer, claims interface{}, want string) {
		t.Helper()

		token, err := BuildBytes(signer, claims)
		if err != nil {
			t.Error(err)
		}

		raw := string(token)
		if raw != want {
			t.Errorf("want %v, got %v", want, raw)
		}
	}

	f(
		mustSigner(NewHS256([]byte("test-key-256"))),
		&StandardClaims{
			ID:       "just an id",
			Audience: Audience([]string{"audience"}),
		},
		`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqdXN0IGFuIGlkIiwiYXVkIjoiYXVkaWVuY2UifQ.t5oEdZGp0Qbth7lo5fZlV_o4-r9gMoYBSktXbarjWoo`,
	)
}

func TestBuildHeader(t *testing.T) {
	f := func(signer Signer, header Header, want string) {
		t.Helper()

		token, err := NewBuilder(signer).Build(&StandardClaims{})
		if err != nil {
			t.Error(err)
		}

		want = toBase64(want)
		raw := string(token.RawHeader())
		if raw != want {
			t.Errorf("want %v, got %v", want, raw)
		}
	}

	key := []byte("key")
	f(
		mustSigner(NewHS256(key)),
		Header{Algorithm: HS256, Type: "JWT"},
		`{"alg":"HS256","typ":"JWT"}`,
	)
	f(
		mustSigner(NewHS384(key)),
		Header{Algorithm: HS384, Type: "JWT"},
		`{"alg":"HS384","typ":"JWT"}`,
	)
	f(
		mustSigner(NewHS512(key)),
		Header{Algorithm: HS512, Type: "JWT"},
		`{"alg":"HS512","typ":"JWT"}`,
	)

	f(
		mustSigner(NewRS256(rsaPublicKey1, rsaPrivateKey1)),
		Header{Algorithm: RS256, Type: "JWT"},
		`{"alg":"RS256","typ":"JWT"}`,
	)
	f(
		mustSigner(NewRS384(rsaPublicKey1, rsaPrivateKey1)),
		Header{Algorithm: RS384, Type: "JWT"},
		`{"alg":"RS384","typ":"JWT"}`,
	)
	f(
		mustSigner(NewRS512(rsaPublicKey1, rsaPrivateKey1)),
		Header{Algorithm: RS512, Type: "JWT"},
		`{"alg":"RS512","typ":"JWT"}`,
	)
}

func TestBuildMalformed(t *testing.T) {
	f := func(signer Signer, claims interface{}) {
		t.Helper()

		_, err := BuildBytes(signer, claims)
		if err == nil {
			t.Error("want err, got nil")
		}
	}

	f(
		badSigner{},
		nil,
	)
	f(
		mustSigner(NewHS256([]byte("test-key"))),
		badSigner.Algorithm,
	)
}

func toBase64(s string) string {
	buf := make([]byte, base64EncodedLen(len(s)))
	base64.RawURLEncoding.Encode(buf, []byte(s))
	return string(buf)
}

var _ Signer = badSigner{}

type badSigner struct{}

func (badSigner) Algorithm() Algorithm {
	return "bad"
}
func (badSigner) Sign(payload []byte) ([]byte, error) {
	return nil, errors.New("error by design")
}
func (badSigner) Verify(payload, signature []byte) error {
	return errors.New("error by design")
}
