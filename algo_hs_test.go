package jwt

import (
	"testing"
)

func TestHMAC(t *testing.T) {
	f := func(signer Signer, claims BinaryMarshaler) {
		t.Helper()

		tokenBuilder := NewTokenBuilder(signer)
		token, err := tokenBuilder.Build(claims)
		if err != nil {
			t.Errorf("want nil, got %#v", err)
		}

		err = signer.Verify(token.Payload(), token.Signature())
		if err != nil {
			t.Errorf("want no err, got: `%v`", err)
		}
	}
	f(
		NewHS256([]byte("key1")),
		&StandardClaims{},
	)
	f(
		NewHS384([]byte("key2")),
		&StandardClaims{},
	)
	f(
		NewHS512([]byte("key3")),
		&StandardClaims{},
	)

	f(
		NewHS256([]byte("key1")),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		NewHS384([]byte("key2")),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		NewHS512([]byte("key3")),
		&customClaims{
			TestField: "baz",
		},
	)
}

func TestHMAC_InvalidSignature(t *testing.T) {
	f := func(signer, verifier Signer, claims BinaryMarshaler) {
		t.Helper()

		tokenBuilder := NewTokenBuilder(signer)
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
		NewHS256([]byte("key1")),
		NewHS256([]byte("1key")),
		&StandardClaims{},
	)
	f(
		NewHS384([]byte("key2")),
		NewHS384([]byte("2key")),
		&StandardClaims{},
	)
	f(
		NewHS512([]byte("key3")),
		NewHS512([]byte("3key")),
		&StandardClaims{},
	)

	f(
		NewHS256([]byte("key1")),
		NewHS256([]byte("1key")),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		NewHS384([]byte("key2")),
		NewHS384([]byte("2key")),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		NewHS512([]byte("key3")),
		NewHS512([]byte("3key")),
		&customClaims{
			TestField: "baz",
		},
	)
}
