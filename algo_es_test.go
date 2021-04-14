package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
)

var (
	ecdsaPublicKey256, ecdsaPublicKey384, ecdsaPublicKey521    *ecdsa.PublicKey
	ecdsaPrivateKey256, ecdsaPrivateKey384, ecdsaPrivateKey521 *ecdsa.PrivateKey

	ecdsaPublicKey256Another, ecdsaPublicKey384Another, ecdsaPublicKey521Another    *ecdsa.PublicKey
	ecdsaPrivateKey256Another, ecdsaPrivateKey384Another, ecdsaPrivateKey521Another *ecdsa.PrivateKey
)

func init() {
	f := func(f func() elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
		privKey, err := ecdsa.GenerateKey(f(), rand.Reader)
		if err != nil {
			panic(err)
		}
		return privKey, &privKey.PublicKey
	}

	ecdsaPrivateKey256, ecdsaPublicKey256 = f(elliptic.P256)
	ecdsaPrivateKey384, ecdsaPublicKey384 = f(elliptic.P384)
	ecdsaPrivateKey521, ecdsaPublicKey521 = f(elliptic.P521)

	ecdsaPrivateKey256Another, ecdsaPublicKey256Another = f(elliptic.P256)
	ecdsaPrivateKey384Another, ecdsaPublicKey384Another = f(elliptic.P384)
	ecdsaPrivateKey521Another, ecdsaPublicKey521Another = f(elliptic.P521)
}

func TestES(t *testing.T) {
	f := func(alg Algorithm, privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey, isCorrectSign bool) {
		t.Helper()

		const payload = `simple-string-payload`

		sign := esSign(t, alg, privateKey, payload)

		err := esVerify(t, alg, publicKey, payload, sign)
		if err != nil && isCorrectSign {
			t.Fatal(err)
		}
		if err == nil && !isCorrectSign {
			t.Fatal("must be not nil")
		}
	}

	f(ES256, ecdsaPrivateKey256, ecdsaPublicKey256, true)
	f(ES384, ecdsaPrivateKey384, ecdsaPublicKey384, true)
	f(ES512, ecdsaPrivateKey521, ecdsaPublicKey521, true)

	f(ES256, ecdsaPrivateKey256, ecdsaPublicKey256Another, false)
	f(ES384, ecdsaPrivateKey384, ecdsaPublicKey384Another, false)
	f(ES512, ecdsaPrivateKey521, ecdsaPublicKey521Another, false)

	f(ES256, ecdsaPrivateKey256Another, ecdsaPublicKey256, false)
	f(ES384, ecdsaPrivateKey384Another, ecdsaPublicKey384, false)
	f(ES512, ecdsaPrivateKey521Another, ecdsaPublicKey521, false)
}

func TestES_BadKeys(t *testing.T) {
	f := func(err, wantErr error) {
		t.Helper()

		if !errors.Is(err, wantErr) {
			t.Fatalf("expected %v, got %v", wantErr, err)
		}
	}

	f(getSignerError(NewSignerES(ES256, nil)), ErrNilKey)
	f(getSignerError(NewSignerES(ES384, nil)), ErrNilKey)
	f(getSignerError(NewSignerES(ES512, nil)), ErrNilKey)

	f(getSignerError(NewSignerES("foo", ecdsaPrivateKey384)), ErrUnsupportedAlg)

	f(getSignerError(NewSignerES(ES256, ecdsaPrivateKey384)), ErrInvalidKey)
	f(getSignerError(NewSignerES(ES256, ecdsaPrivateKey521)), ErrInvalidKey)
	f(getSignerError(NewSignerES(ES384, ecdsaPrivateKey256)), ErrInvalidKey)
	f(getSignerError(NewSignerES(ES384, ecdsaPrivateKey521)), ErrInvalidKey)
	f(getSignerError(NewSignerES(ES512, ecdsaPrivateKey256)), ErrInvalidKey)
	f(getSignerError(NewSignerES(ES512, ecdsaPrivateKey384)), ErrInvalidKey)

	f(getVerifierError(NewVerifierES(ES256, nil)), ErrNilKey)
	f(getVerifierError(NewVerifierES(ES384, nil)), ErrNilKey)
	f(getVerifierError(NewVerifierES(ES512, nil)), ErrNilKey)

	f(getVerifierError(NewVerifierES("boo", ecdsaPublicKey384)), ErrUnsupportedAlg)

	f(getVerifierError(NewVerifierES(ES256, ecdsaPublicKey384)), ErrInvalidKey)
	f(getVerifierError(NewVerifierES(ES256, ecdsaPublicKey521)), ErrInvalidKey)
	f(getVerifierError(NewVerifierES(ES384, ecdsaPublicKey256)), ErrInvalidKey)
	f(getVerifierError(NewVerifierES(ES384, ecdsaPublicKey521)), ErrInvalidKey)
	f(getVerifierError(NewVerifierES(ES512, ecdsaPublicKey256)), ErrInvalidKey)
	f(getVerifierError(NewVerifierES(ES512, ecdsaPublicKey384)), ErrInvalidKey)
}

func esSign(t *testing.T, alg Algorithm, privateKey *ecdsa.PrivateKey, payload string) []byte {
	t.Helper()

	signer, errSigner := NewSignerES(alg, privateKey)
	if errSigner != nil {
		t.Fatalf("NewSignerES %v", errSigner)
	}

	sign, errSign := signer.Sign([]byte(payload))
	if errSign != nil {
		t.Fatalf("SignES %v", errSign)
	}
	return sign
}

func esVerify(t *testing.T, alg Algorithm, publicKey *ecdsa.PublicKey, payload string, sign []byte) error {
	t.Helper()

	verifier, errVerifier := NewVerifierES(alg, publicKey)
	if errVerifier != nil {
		t.Fatalf("NewVerifierES %v", errVerifier)
	}
	return verifier.Verify([]byte(payload), sign)
}
