package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

var ecdsaPublicKey256 *ecdsa.PublicKey
var ecdsaPublicKey384 *ecdsa.PublicKey
var ecdsaPublicKey521 *ecdsa.PublicKey
var ecdsaPrivateKey256 *ecdsa.PrivateKey
var ecdsaPrivateKey384 *ecdsa.PrivateKey
var ecdsaPrivateKey521 *ecdsa.PrivateKey

var ecdsaOtherPublicKey256 *ecdsa.PublicKey
var ecdsaOtherPublicKey384 *ecdsa.PublicKey
var ecdsaOtherPublicKey521 *ecdsa.PublicKey
var ecdsaOtherPrivateKey256 *ecdsa.PrivateKey
var ecdsaOtherPrivateKey384 *ecdsa.PrivateKey
var ecdsaOtherPrivateKey521 *ecdsa.PrivateKey

func init() {
	ecdsaPrivateKey256, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaPublicKey256 = &ecdsaPrivateKey256.PublicKey

	ecdsaPrivateKey384, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecdsaPublicKey384 = &ecdsaPrivateKey384.PublicKey

	ecdsaPrivateKey521, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	ecdsaPublicKey521 = &ecdsaPrivateKey521.PublicKey

	ecdsaOtherPrivateKey256, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaOtherPublicKey256 = &ecdsaOtherPrivateKey256.PublicKey

	ecdsaOtherPrivateKey384, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecdsaOtherPublicKey384 = &ecdsaOtherPrivateKey384.PublicKey

	ecdsaOtherPrivateKey521, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	ecdsaOtherPublicKey521 = &ecdsaOtherPrivateKey521.PublicKey
}

func TestES256_WithValidSignature(t *testing.T) {
	f := func(signer Signer, claims BinaryMarshaler) {
		t.Helper()

		tokenBuilder := NewBuilder(signer)
		token, _ := tokenBuilder.Build(claims)

		err := signer.Verify(token.Payload(), token.Signature())
		if err != nil {
			t.Errorf("want no err, got: `%v`", err)
		}
	}

	f(
		getSigner(NewES256(ecdsaPublicKey256, ecdsaPrivateKey256)),
		&StandardClaims{},
	)
	f(
		getSigner(NewES384(ecdsaPublicKey384, ecdsaPrivateKey384)),
		&StandardClaims{},
	)
	f(
		getSigner(NewES512(ecdsaPublicKey521, ecdsaPrivateKey521)),
		&StandardClaims{},
	)

	f(
		getSigner(NewES256(ecdsaPublicKey256, ecdsaPrivateKey256)),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		getSigner(NewES384(ecdsaPublicKey384, ecdsaPrivateKey384)),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		getSigner(NewES512(ecdsaPublicKey521, ecdsaPrivateKey521)),
		&customClaims{
			TestField: "baz",
		},
	)
}

func TestES384_WithInvalidSignature(t *testing.T) {
	f := func(signer, verifier Signer, claims BinaryMarshaler) {
		t.Helper()

		tokenBuilder := NewBuilder(signer)
		token, _ := tokenBuilder.Build(claims)

		err := verifier.Verify(token.Payload(), token.Signature())
		if err == nil {
			t.Errorf("want %v, got nil", ErrInvalidSignature)
		}
	}
	f(
		getSigner(NewES256(ecdsaPublicKey256, ecdsaPrivateKey256)),
		getSigner(NewES256(ecdsaOtherPublicKey256, ecdsaOtherPrivateKey256)),
		&StandardClaims{},
	)
	f(
		getSigner(NewES384(ecdsaPublicKey384, ecdsaPrivateKey384)),
		getSigner(NewES384(ecdsaOtherPublicKey384, ecdsaOtherPrivateKey384)),
		&StandardClaims{},
	)
	f(
		getSigner(NewES512(ecdsaPublicKey521, ecdsaPrivateKey521)),
		getSigner(NewES512(ecdsaOtherPublicKey521, ecdsaOtherPrivateKey521)),
		&StandardClaims{},
	)

	f(
		getSigner(NewES256(ecdsaPublicKey256, ecdsaPrivateKey256)),
		getSigner(NewES256(ecdsaOtherPublicKey256, ecdsaOtherPrivateKey256)),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		getSigner(NewES384(ecdsaPublicKey384, ecdsaPrivateKey384)),
		getSigner(NewES384(ecdsaOtherPublicKey384, ecdsaOtherPrivateKey384)),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		getSigner(NewES512(ecdsaPublicKey521, ecdsaPrivateKey521)),
		getSigner(NewES512(ecdsaOtherPublicKey521, ecdsaOtherPrivateKey521)),
		&customClaims{
			TestField: "baz",
		},
	)
}
