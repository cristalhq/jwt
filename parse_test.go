package jwt

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseNoVerifyString(t *testing.T) {
	f := func(token string, header Header, claims, signature string) {
		t.Helper()

		parts := strings.Split(token, ".")
		partHeader, _, _ := parts[0], parts[1], parts[2]

		tk, err := ParseNoVerifyString(token)
		if err != nil {
			t.Errorf("want nil, got %#v", err)
		}

		if gotHeader := string(tk.RawHeader()); partHeader != gotHeader {
			t.Errorf("want header %q, got %q", partHeader, gotHeader)
		}

		if tk.Header() != header {
			t.Errorf("want %#v, got %#v", header, tk.Header())
		}

		gotClaims := string(tk.RawClaims())
		if gotClaims != claims {
			t.Errorf("want claim %s, got %s", claims, gotClaims)
		}

		sign := bytesToBase64(tk.Signature())
		if sign != signature {
			t.Errorf("want signature %#v, got %#v", signature, sign)
		}
	}

	f(
		`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqdXN0IGFuIGlkIiwiYXVkIjoiYXVkaWVuY2UifQ.t5oEdZGp0Qbth7lo5fZlV_o4-r9gMoYBSktXbarjWoo`,
		Header{
			Algorithm: HS256,
			Type:      "JWT",
		},
		`{"jti":"just an id","aud":"audience"}`,
		"t5oEdZGp0Qbth7lo5fZlV_o4-r9gMoYBSktXbarjWoo",
	)
	f(
		`eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImN0eSI6InRva2VuIn0.eyJqdGkiOiJqdXN0IGFuIGlkIiwiYXVkIjoiYXVkaWVuY2UifQ.t5oEdZGp0Qbth7lo5fZlV_o4-r9gMoYBSktXbarjWoo`,
		Header{
			Algorithm:   HS512,
			Type:        "JWT",
			ContentType: "token",
		},
		`{"jti":"just an id","aud":"audience"}`,
		"t5oEdZGp0Qbth7lo5fZlV_o4-r9gMoYBSktXbarjWoo",
	)
}

func TestParseMalformed(t *testing.T) {
	f := func(got string) {
		t.Helper()

		_, err := ParseNoVerifyString(got)
		if err == nil {
			t.Error("got nil want err")
		}
	}

	f(`xyz.xyz`)
	f(`xyz.xyz.xyz.xyz`)
	f(`a.xyz.xyz`)
	f(`xyz.ab/c.xyz`)
	f(`xyz.abc.x/yz`)
	f(`x/z.ab_c.xyz`)
	f(`ab_c.xyz.xyz`)
	f(`e30.ab/c.xyz`) // `e30` is JSON `{}` in base64
	f(`e30.e30.ab/c`)
}

func bytesToBase64(b []byte) string {
	buf := make([]byte, b64EncodedLen(len(b)))
	base64.RawURLEncoding.Encode(buf, b)
	return string(buf)
}
