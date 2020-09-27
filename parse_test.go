package jwt

import (
	"strings"
	"testing"
)

func TestParseString(t *testing.T) {
	f := func(token string, header Header, payload, signature string) {
		t.Helper()

		tk, err := ParseNoVerifyString(token)
		if err != nil {
			t.Errorf("want nil, got %#v", err)
		}
		if tk.Header() != header {
			t.Errorf("want %#v, got %#v", header, tk.Header())
		}
		headerStr := toBase64(header.String())
		if string(tk.HeaderPart()) != headerStr {
			t.Errorf("header: want %#v, got %#v", headerStr, string(tk.HeaderPart()))
		}
		if string(tk.PayloadPart()) != payload {
			t.Errorf("payload: want %#v, got %#v", payload, string(tk.PayloadPart()))
		}
		sign := toBase64(string(tk.Signature()))
		if sign != signature {
			t.Errorf("signature: want %#v, got %#v", signature, sign)
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

func TestParse(t *testing.T) {
	f := func(raw string, want *Token, wantError bool) {

		token, err := ParseNoVerifyString(raw)
		if err != nil && !wantError {
			t.Fatalf("unexpected err %v", err)
		}
		if err == nil && wantError {
			t.Fatal("expected error")
		}

		dot1 := strings.IndexByte(raw, '.')
		dot2 := strings.LastIndexByte(raw, '.')
		if dot2 <= dot1 {
			return
		}
		gotHeader := raw[:dot1]
		// gotClaims := raw[dot1+1 : dot2]
		gotSignature := raw[dot2+1:]
		gotPayload := raw[:dot2]
		// t.Logf("head %#v\nclaims %#v\nsign %#v\npay %#v", gotHeader, gotClaims, gotSignature, gotPayload)

		if string(token.HeaderPart()) != gotHeader {
			t.Errorf("raw header: got %v, want %v", string(token.HeaderPart()), gotHeader)
		}
		if token.header != want.header {
			t.Errorf("header: got %v, want %v", token.header, want.header)
		}

		if string(token.PayloadPart()) != gotPayload {
			t.Errorf("payload: got %v, want %v", string(token.PayloadPart()), gotPayload)
		}

		if toBase64(string(token.Signature())) != gotSignature {
			t.Errorf("signature: got %v, want %v", toBase64(string(token.Signature())), (gotSignature))
		}
	}

	f(
		``,
		&Token{},
		true,
	)
	f(
		`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbiIsImp0aSI6InJhbmRvbS11bmlxdWUtc3RyaW5nIn0.dv9-XpY9P8ypm1uWQwB6eKvq3jeyodLA7brhjsf4JVs`,
		&Token{
			header: Header{
				Algorithm: HS256,
				Type:      "JWT",
			},
		},
		false,
	)
	f(
		`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbiIsImp0aSI6InJhbmRvbS11bmlxdWUtc3RyaW5nIn0`,
		&Token{},
		true,
	)
	f(
		`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbi_LL_IsImp0aSI6InJhbmRvbS11bmlxdWUtc3RyaW5nIn0.dv9-XpY9P8ypm1uWQwB6eKvq3jeyodLA7brhjsf4JVs`,
		&Token{
			header: Header{
				Algorithm: HS256,
				Type:      "JWT",
			},
		},
		false,
	)
}

func TestParseString2(t *testing.T) {
	verifier, _ := NewVerifierHS(HS256, []byte(`test-key-256`))
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsImp0aSI6Imp1c3QgYW4gaWQifQ.6EWV4IFTyCqCUn-_R1AFRgJptvmV09Os57WAejPcf7Q"

	if _, err := ParseString(token, verifier); err != nil {
		t.Fatal(err)
	}
}

func TestParseMalformed(t *testing.T) {
	f := func(got string) {
		t.Helper()

		_, err := ParseNoVerifyString(got)
		if err == nil {
			t.Error("got nil want nil")
		}
	}

	f(`xyz.xyz`)
	f(`xyz.xyz.xyz.xyz`)
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
