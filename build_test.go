package jwt

import (
	"encoding/base64"
	"testing"
)

func TestBuild(t *testing.T) {
	f := func(signer Signer, claims interface{}, want string) {
		t.Helper()

		token, err := NewBuilder(signer).Build(claims)
		if err != nil {
			t.Error(err)
		}

		raw := string(token.String())
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
		`eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJqdGkiOiJqdXN0IGFuIGlkIiwiYXVkIjoiYXVkaWVuY2UifQ.ZXlKaGJHY2lPaUp1YjI1bElpd2lkSGx3SWpvaVNsZFVJbjAuZXlKcWRHa2lPaUpxZFhOMElHRnVJR2xrSWl3aVlYVmtJam9pWVhWa2FXVnVZMlVpZlE`,
	)

	f(
		getSigner(NewHS256([]byte("test-key-256"))),
		&StandardClaims{
			ID:       "just an id",
			Audience: Audience([]string{"audience"}),
		},
		`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqdXN0IGFuIGlkIiwiYXVkIjoiYXVkaWVuY2UifQ.t5oEdZGp0Qbth7lo5fZlV_o4-r9gMoYBSktXbarjWoo`,
	)
	f(
		getSigner(NewHS384([]byte("test-key-384"))),
		&StandardClaims{
			ID:       "just an id",
			Audience: Audience([]string{"audience"}),
		},
		`eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqdXN0IGFuIGlkIiwiYXVkIjoiYXVkaWVuY2UifQ.l_Ric0QxkvqmGfBqr-f90dHsdBaiXQuYbKzlqC92eyNv3j1J3FHCeMjbiwB94q9S`,
	)
	f(
		getSigner(NewHS512([]byte("test-key-512"))),
		&StandardClaims{
			ID:       "just an id",
			Audience: Audience([]string{"audience"}),
		},
		`eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqdXN0IGFuIGlkIiwiYXVkIjoiYXVkaWVuY2UifQ.Um-OqqMOsmXQUqNoaIohIJQKbaYtY1rpBfyx46lh4vrXj1JFCahz5BIltASpYZJ-t4-yAyvaYfMZuUC7PHDhcA`,
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

	f(
		NewNoEncrypt(),
		Header{Algorithm: NoEncryption, Type: "JWT"},
		`{"alg":"none","typ":"JWT"}`,
	)

	key := []byte("key")
	f(
		getSigner(NewHS256(key)),
		Header{Algorithm: HS256, Type: "JWT"},
		`{"alg":"HS256","typ":"JWT"}`,
	)
	f(
		getSigner(NewHS384(key)),
		Header{Algorithm: HS384, Type: "JWT"},
		`{"alg":"HS384","typ":"JWT"}`,
	)
	f(
		getSigner(NewHS512(key)),
		Header{Algorithm: HS512, Type: "JWT"},
		`{"alg":"HS512","typ":"JWT"}`,
	)

	f(
		getSigner(NewRS256(rsaPublicKey1, rsaPrivateKey1)),
		Header{Algorithm: RS256, Type: "JWT"},
		`{"alg":"RS256","typ":"JWT"}`,
	)
	f(
		getSigner(NewRS384(rsaPublicKey1, rsaPrivateKey1)),
		Header{Algorithm: RS384, Type: "JWT"},
		`{"alg":"RS384","typ":"JWT"}`,
	)
	f(
		getSigner(NewRS512(rsaPublicKey1, rsaPrivateKey1)),
		Header{Algorithm: RS512, Type: "JWT"},
		`{"alg":"RS512","typ":"JWT"}`,
	)
}

func toBase64(s string) string {
	buf := make([]byte, base64EncodedLen(len(s)))
	base64.RawURLEncoding.Encode(buf, []byte(s))
	return string(buf)
}
