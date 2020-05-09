package jwt

import (
	"testing"
)

func TestParseString(t *testing.T) {
	f := func(token string, header Header, payload, signature string) {
		t.Helper()

		tk, err := ParseString(token)
		if err != nil {
			t.Errorf("want nil, got %#v", err)
		}
		if tk.Header() != header {
			t.Errorf("want %#v, got %#v", header, tk.Header())
		}
		headerStr := toBase64(headerString(header))
		if string(tk.RawHeader()) != headerStr {
			t.Errorf("want %#v, got %#v", headerStr, string(tk.RawHeader()))
		}
		if string(tk.Payload()) != payload {
			t.Errorf("want %#v, got %#v", payload, string(tk.Payload()))
		}
		sign := toBase64(string(tk.Signature()))
		if sign != signature {
			t.Errorf("want %#v, got %#v", signature, sign)
		}
	}

	f(
		`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqdXN0IGFuIGlkIiwiYXVkIjoiYXVkaWVuY2UifQ.t5oEdZGp0Qbth7lo5fZlV_o4-r9gMoYBSktXbarjWoo`,
		Header{
			Algorithm: HS256,
			Type:      "JWT",
		},
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqdXN0IGFuIGlkIiwiYXVkIjoiYXVkaWVuY2UifQ",
		"t5oEdZGp0Qbth7lo5fZlV_o4-r9gMoYBSktXbarjWoo",
	)
	f(
		`eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImN0eSI6InRva2VuIn0.eyJqdGkiOiJqdXN0IGFuIGlkIiwiYXVkIjoiYXVkaWVuY2UifQ.t5oEdZGp0Qbth7lo5fZlV_o4-r9gMoYBSktXbarjWoo`,
		Header{
			Algorithm:   HS512,
			Type:        "JWT",
			ContentType: "token",
		},
		"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImN0eSI6InRva2VuIn0.eyJqdGkiOiJqdXN0IGFuIGlkIiwiYXVkIjoiYXVkaWVuY2UifQ",
		"t5oEdZGp0Qbth7lo5fZlV_o4-r9gMoYBSktXbarjWoo",
	)
}

func TestParseMalformed(t *testing.T) {
	f := func(got string) {
		t.Helper()

		_, err := ParseString(got)
		if err == nil {
			t.Error("got nil want nil")
		}
	}

	f(`xyz.xyz`)
	f(`a.xyz.xyz`)
	f(`xyz.ab/c.xyz`)
	f(`xyz.abc.x/yz`)
	f(`x/z.ab_c.xyz`)
	f(`ab_c.xyz.xyz`)
}

func headerString(header Header) string {
	raw, _ := header.MarshalJSON()
	return string(raw)
}
