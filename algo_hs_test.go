package jwt

import (
	"testing"
)

func TestHMAC(t *testing.T) {
	f := func(signer Signer, claims interface{}) {
		t.Helper()

		tokenBuilder := NewBuilder(signer)
		token, err := tokenBuilder.Build(claims)
		if err != nil {
			t.Errorf("want nil, got %#v", err)
		}

		err = signer.Verify(token.Payload(), token.Signature())
		if err != nil {
			t.Errorf("want no err, got: %#v", err)
		}
	}
	f(
		mustSigner(NewHS256([]byte("key1"))),
		&StandardClaims{},
	)
	f(
		mustSigner(NewHS384([]byte("key2"))),
		&StandardClaims{},
	)
	f(
		mustSigner(NewHS512([]byte("key3"))),
		&StandardClaims{},
	)

	f(
		mustSigner(NewHS256([]byte("key1"))),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		mustSigner(NewHS384([]byte("key2"))),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		mustSigner(NewHS512([]byte("key3"))),
		&customClaims{
			TestField: "baz",
		},
	)
}

func TestHMAC_InvalidSignature(t *testing.T) {
	f := func(signer, verifier Signer, claims interface{}) {
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
		mustSigner(NewHS256([]byte("key1"))),
		mustSigner(NewHS256([]byte("1key"))),
		&StandardClaims{},
	)
	f(
		mustSigner(NewHS384([]byte("key2"))),
		mustSigner(NewHS384([]byte("2key"))),
		&StandardClaims{},
	)
	f(
		mustSigner(NewHS512([]byte("key3"))),
		mustSigner(NewHS512([]byte("3key"))),
		&StandardClaims{},
	)

	f(
		mustSigner(NewHS256([]byte("key1"))),
		mustSigner(NewHS256([]byte("1key"))),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		mustSigner(NewHS384([]byte("key2"))),
		mustSigner(NewHS384([]byte("2key"))),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		mustSigner(NewHS512([]byte("key3"))),
		mustSigner(NewHS512([]byte("3key"))),
		&customClaims{
			TestField: "baz",
		},
	)
}
