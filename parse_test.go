package jwt

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	testCases := []struct {
		token     string
		header    Header
		claims    string
		signature string
	}{
		{
			`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqdXN0IGFuIGlkIiwiYXVkIjoiYXVkaWVuY2UifQ.t5oEdZGp0Qbth7lo5fZlV_o4-r9gMoYBSktXbarjWoo`,
			Header{
				Algorithm: HS256,
				Type:      "JWT",
			},
			`{"jti":"just an id","aud":"audience"}`,
			"t5oEdZGp0Qbth7lo5fZlV_o4-r9gMoYBSktXbarjWoo",
		},
		{
			`eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImN0eSI6InRva2VuIn0.eyJqdGkiOiJqdXN0IGFuIGlkIiwiYXVkIjoiYXVkaWVuY2UifQ.t5oEdZGp0Qbth7lo5fZlV_o4-r9gMoYBSktXbarjWoo`,
			Header{
				Algorithm:   HS512,
				Type:        "JWT",
				ContentType: "token",
			},
			`{"jti":"just an id","aud":"audience"}`,
			"t5oEdZGp0Qbth7lo5fZlV_o4-r9gMoYBSktXbarjWoo",
		},
	}

	for _, tc := range testCases {
		parts := strings.Split(tc.token, ".")
		partHeader, _, _ := parts[0], parts[1], parts[2]

		tk, err := Parse([]byte(tc.token), nopVerifier{})
		mustOk(t, err)
		mustEqual(t, string(tk.HeaderPart()), partHeader)
		mustEqual(t, tk.Header(), tc.header)
		mustEqual(t, string(tk.Claims()), tc.claims)
		mustEqual(t, bytesToBase64(tk.Signature()), tc.signature)
	}
}

func TestParseAnotherAlgorithm(t *testing.T) {
	const tokenHS256 = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqdXN0IGFuIGlkIiwiYXVkIjoiYXVkaWVuY2UifQ.t5oEdZGp0Qbth7lo5fZlV_o4-r9gMoYBSktXbarjWoo`
	verifier := must(NewVerifierHS(HS512, []byte("key")))

	_, err := Parse([]byte(tokenHS256), verifier)
	mustEqual(t, err, ErrAlgorithmMismatch)
}

func TestParseMalformed(t *testing.T) {
	testCases := []struct {
		token string
	}{
		{`xyz.xyz`},
		{`eyJ.xyz`},
		{`eyJ!.x!yz.e30`},
		{`eyJ.xyz.xyz`},
		{`eyJhIjoxMjN9.x!yz.e30`}, // `e30` is JSON `{}` in base64.
		{`eyJhIjoxMjN9.e30.x!yz`},
	}

	for _, tc := range testCases {
		_, err := Parse([]byte(tc.token), nopVerifier{})
		mustEqual(t, err, ErrInvalidFormat)
	}
}

type nopVerifier struct{}

func (nopVerifier) Algorithm() Algorithm      { return "nop" }
func (nopVerifier) Verify(token *Token) error { return nil }
