package jwt

import (
	"testing"
)

func TestHMAC(t *testing.T) {
	f := func(signer Signer, verifier Verifier, claims interface{}) {
		t.Helper()

		tokenBuilder := NewBuilder(signer)
		token, err := tokenBuilder.Build(claims)
		if err != nil {
			t.Errorf("want nil, got %#v", err)
		}

		err = verifier.Verify(token.PayloadPart(), token.Signature())
		if err != nil {
			t.Errorf("want no err, got: %#v", err)
		}
	}
	f(
		mustSigner(NewSignerHS(HS256, []byte("key1"))),
		mustVerifier(NewVerifierHS(HS256, []byte("key1"))),
		&RegisteredClaims{},
	)
	f(
		mustSigner(NewSignerHS(HS384, []byte("key2"))),
		mustVerifier(NewVerifierHS(HS384, []byte("key2"))),
		&RegisteredClaims{},
	)
	f(
		mustSigner(NewSignerHS(HS512, []byte("key3"))),
		mustVerifier(NewVerifierHS(HS512, []byte("key3"))),
		&RegisteredClaims{},
	)

	f(
		mustSigner(NewSignerHS(HS256, []byte("key1"))),
		mustVerifier(NewVerifierHS(HS256, []byte("key1"))),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		mustSigner(NewSignerHS(HS384, []byte("key2"))),
		mustVerifier(NewVerifierHS(HS384, []byte("key2"))),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		mustSigner(NewSignerHS(HS512, []byte("key3"))),
		mustVerifier(NewVerifierHS(HS512, []byte("key3"))),
		&customClaims{
			TestField: "baz",
		},
	)
}

func TestHMAC_InvalidSignature(t *testing.T) {
	f := func(signer Signer, verifier Verifier, claims interface{}) {
		t.Helper()

		tokenBuilder := NewBuilder(signer)
		token, err := tokenBuilder.Build(claims)
		if err != nil {
			t.Errorf("want nil, got %#v", err)
		}

		err = verifier.Verify(token.PayloadPart(), token.Signature())
		if err == nil {
			t.Errorf("want %#v, got nil", ErrInvalidSignature)
		}
	}
	f(
		mustSigner(NewSignerHS(HS256, []byte("key1"))),
		mustVerifier(NewVerifierHS(HS256, []byte("1key"))),
		&RegisteredClaims{},
	)
	f(
		mustSigner(NewSignerHS(HS384, []byte("key2"))),
		mustVerifier(NewVerifierHS(HS384, []byte("2key"))),
		&RegisteredClaims{},
	)
	f(
		mustSigner(NewSignerHS(HS512, []byte("key3"))),
		mustVerifier(NewVerifierHS(HS512, []byte("3key"))),
		&RegisteredClaims{},
	)

	f(
		mustSigner(NewSignerHS(HS256, []byte("key1"))),
		mustVerifier(NewVerifierHS(HS256, []byte("1key"))),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		mustSigner(NewSignerHS(HS384, []byte("key2"))),
		mustVerifier(NewVerifierHS(HS384, []byte("2key"))),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		mustSigner(NewSignerHS(HS512, []byte("key3"))),
		mustVerifier(NewVerifierHS(HS512, []byte("3key"))),
		&customClaims{
			TestField: "baz",
		},
	)
}
