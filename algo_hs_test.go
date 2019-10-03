package jwt

import (
	"encoding"
	"testing"
)

func TestHS_WithValidSignature(t *testing.T) {
	f := func(signer Signer, claims encoding.BinaryMarshaler) {
		tokenBuilder := NewTokenBuilder(signer)
		token, _ := tokenBuilder.Build(claims)

		err := signer.Verify(token.Signature(), token.Payload())
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
}

func TestHS_WithValidSignature_CustomClaims(t *testing.T) {
	f := func(signer Signer, claims encoding.BinaryMarshaler) {
		tokenBuilder := NewTokenBuilder(signer)
		token, _ := tokenBuilder.Build(claims)

		err := signer.Verify(token.Signature(), token.Payload())
		if err != nil {
			t.Errorf("want no err, got: `%v`", err)
		}
	}
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

func TestHS_WithInvalidSignature(t *testing.T) {
	f := func(signer, verifier Signer, claims encoding.BinaryMarshaler) {
		tokenBuilder := NewTokenBuilder(signer)
		token, _ := tokenBuilder.Build(claims)

		err := verifier.Verify(token.Signature(), token.Payload())
		if err == nil {
			t.Errorf("want %v, got nil", ErrInvalidSignature)
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
}

func TestHS_WithInvalidSignature_CustomClaims(t *testing.T) {
	f := func(signer, verifier Signer, claims encoding.BinaryMarshaler) {
		tokenBuilder := NewTokenBuilder(signer)
		token, _ := tokenBuilder.Build(claims)

		err := verifier.Verify(token.Signature(), token.Payload())
		if err == nil {
			t.Errorf("want %v, got nil", ErrInvalidSignature)
		}
	}
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
