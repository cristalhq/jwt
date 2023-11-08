package jwt

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	f := func(token string, header Header, claims, signature string) {
		t.Helper()

		parts := strings.Split(token, ".")
		partHeader, _, _ := parts[0], parts[1], parts[2]

		tk, err := Parse([]byte(token), nopVerifier{})
		mustOk(t, err)
		mustEqual(t, string(tk.HeaderPart()), partHeader)
		mustEqual(t, tk.Header(), header)
		mustEqual(t, string(tk.Claims()), claims)
		mustEqual(t, bytesToBase64(tk.Signature()), signature)
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

func TestParseAnotherAlgorithm(t *testing.T) {
	const tokenHS256 = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqdXN0IGFuIGlkIiwiYXVkIjoiYXVkaWVuY2UifQ.t5oEdZGp0Qbth7lo5fZlV_o4-r9gMoYBSktXbarjWoo`
	verifier := must(NewVerifierHS(HS512, []byte("key")))

	_, err := Parse([]byte(tokenHS256), verifier)
	mustEqual(t, err, ErrAlgorithmMismatch)
}

func TestParseWrongType(t *testing.T) {
	const tokenHS256 = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkJPTUJPTSJ9.eyJqdGkiOiJqdXN0IGFuIGlkIiwiYXVkIjoiYXVkaWVuY2UifQ.t5oEdZGp0Qbth7lo5fZlV_o4-r9gMoYBSktXbarjWoo`
	verifier := must(NewVerifierHS(HS256, []byte("key")))

	token, err := Parse([]byte(tokenHS256), verifier)
	mustEqual(t, err, ErrNotJWTType)
	if token == nil {
		t.Fatal()
	}
}

func TestParseMalformed(t *testing.T) {
	f := func(got string) {
		t.Helper()

		_, err := Parse([]byte(got), nopVerifier{})
		mustEqual(t, err, ErrInvalidFormat)
	}

	f(`xyz.xyz`)
	f(`eyJ.xyz`)
	f(`eyJ!.x!yz.e30`)
	f(`eyJ.xyz.xyz`)
	f(`eyJhIjoxMjN9.x!yz.e30`) // `e30` is JSON `{}` in base64.
	f(`eyJhIjoxMjN9.e30.x!yz`)
}

type nopVerifier struct{}

func (nopVerifier) Algorithm() Algorithm      { return "nop" }
func (nopVerifier) Verify(token *Token) error { return nil }
