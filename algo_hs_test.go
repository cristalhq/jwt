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

		err = verifier.Verify(token.Payload(), token.Signature())
		if err != nil {
			t.Errorf("want no err, got: %#v", err)
		}
	}
	f(
		mustSigner(NewSignerHMAC(HS256, []byte("key1"))),
		mustVerifier(NewVerifierHMAC(HS256, []byte("key1"))),
		&StandardClaims{},
	)
	f(
		mustSigner(NewSignerHMAC(HS384, []byte("key2"))),
		mustVerifier(NewVerifierHMAC(HS384, []byte("key2"))),
		&StandardClaims{},
	)
	f(
		mustSigner(NewSignerHMAC(HS512, []byte("key3"))),
		mustVerifier(NewVerifierHMAC(HS512, []byte("key3"))),
		&StandardClaims{},
	)

	f(
		mustSigner(NewSignerHMAC(HS256, []byte("key1"))),
		mustVerifier(NewVerifierHMAC(HS256, []byte("key1"))),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		mustSigner(NewSignerHMAC(HS384, []byte("key2"))),
		mustVerifier(NewVerifierHMAC(HS384, []byte("key2"))),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		mustSigner(NewSignerHMAC(HS512, []byte("key3"))),
		mustVerifier(NewVerifierHMAC(HS512, []byte("key3"))),
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

		err = verifier.Verify(token.Payload(), token.Signature())
		if err == nil {
			t.Errorf("want %#v, got nil", ErrInvalidSignature)
		}
	}
	f(
		mustSigner(NewSignerHMAC(HS256, []byte("key1"))),
		mustVerifier(NewVerifierHMAC(HS256, []byte("1key"))),
		&StandardClaims{},
	)
	f(
		mustSigner(NewSignerHMAC(HS384, []byte("key2"))),
		mustVerifier(NewVerifierHMAC(HS384, []byte("2key"))),
		&StandardClaims{},
	)
	f(
		mustSigner(NewSignerHMAC(HS512, []byte("key3"))),
		mustVerifier(NewVerifierHMAC(HS512, []byte("3key"))),
		&StandardClaims{},
	)

	f(
		mustSigner(NewSignerHMAC(HS256, []byte("key1"))),
		mustVerifier(NewVerifierHMAC(HS256, []byte("1key"))),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		mustSigner(NewSignerHMAC(HS384, []byte("key2"))),
		mustVerifier(NewVerifierHMAC(HS384, []byte("2key"))),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		mustSigner(NewSignerHMAC(HS512, []byte("key3"))),
		mustVerifier(NewVerifierHMAC(HS512, []byte("3key"))),
		&customClaims{
			TestField: "baz",
		},
	)
}
