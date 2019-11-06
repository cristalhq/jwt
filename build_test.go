package jwt

import (
	"encoding/base64"
	"testing"
)

func TestBuild(t *testing.T) {
	f := func(signer Signer, claims BinaryMarshaler, want string) {
		t.Helper()

		token, err := NewTokenBuilder(signer).Build(claims)
		if err != nil {
			t.Error(err)
		}

		raw := string(token.InsecureString())
		if raw != want {
			t.Errorf("want %v, got %v", want, raw)
		}
	}

	f(
		NewNoEncrypt(),
		&StandardClaims{
			ID:       "just an id",
			Audience: Audience([]string{"audience"}),
		},
		`eyJhbGciOiJub25lIn0.eyJhdWQiOiJhdWRpZW5jZSIsImp0aSI6Imp1c3QgYW4gaWQifQ.`,
	)

	f(
		NewHS256([]byte("test-key-256")),
		&StandardClaims{
			ID:       "just an id",
			Audience: Audience([]string{"audience"}),
		},
		`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsImp0aSI6Imp1c3QgYW4gaWQifQ.6EWV4IFTyCqCUn-_R1AFRgJptvmV09Os57WAejPcf7Q`,
	)
	f(
		NewHS384([]byte("test-key-384")),
		&StandardClaims{
			ID:       "just an id",
			Audience: Audience([]string{"audience"}),
		},
		`eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsImp0aSI6Imp1c3QgYW4gaWQifQ.aWImRb5WxBvJCPlQcWxg6YXH2jriPBd4Z7vjBn0MjYY8ZBpdJXw8kgbkn6_9yeo6`,
	)
	f(
		NewHS512([]byte("test-key-512")),
		&StandardClaims{
			ID:       "just an id",
			Audience: Audience([]string{"audience"}),
		},
		`eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsImp0aSI6Imp1c3QgYW4gaWQifQ.cLQPM2tE9toJdvxN4HlAZXm7c3FTHMgTMw5M0Ba1AxRsU6-z_Ftiqik1IcscAXmi5v3bNRCan6qFNm1NKiDmJQ`,
	)

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

func TestBuildHeader(t *testing.T) {
	f := func(signer Signer, header Header, want string) {
		t.Helper()

		token, err := NewTokenBuilder(signer).Build(&StandardClaims{})
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
		NewNoEncrypt(), Header{Algorithm: NoEncryption, Type: "JWT"},
		`{"alg":"none"}`,
	)

	f(
		NewHS256(nil), Header{Algorithm: HS256, Type: "JWT"},
		`{"alg":"HS256","typ":"JWT"}`,
	)
	f(
		NewHS384(nil), Header{Algorithm: HS384, Type: "JWT"},
		`{"alg":"HS384","typ":"JWT"}`,
	)
	f(
		NewHS512(nil), Header{Algorithm: HS512, Type: "JWT"},
		`{"alg":"HS512","typ":"JWT"}`,
	)

	f(
		NewRS256(rsaPublicKey1, rsaPrivateKey1), Header{Algorithm: RS256, Type: "JWT"},
		`{"alg":"RS256","typ":"JWT"}`,
	)
	f(
		NewRS384(rsaPublicKey1, rsaPrivateKey1), Header{Algorithm: RS384, Type: "JWT"},
		`{"alg":"RS384","typ":"JWT"}`,
	)
	f(
		NewRS512(rsaPublicKey1, rsaPrivateKey1), Header{Algorithm: RS512, Type: "JWT"},
		`{"alg":"RS512","typ":"JWT"}`,
	)
}

func toBase64(s string) string {
	buf := make([]byte, base64EncodedLen(len(s)))
	base64.RawURLEncoding.Encode(buf, []byte(s))
	return string(buf)
}
