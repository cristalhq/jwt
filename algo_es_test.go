package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
)

var (
	ecdsaPublicKey256, ecdsaPublicKey384, ecdsaPublicKey521    *ecdsa.PublicKey
	ecdsaPrivateKey256, ecdsaPrivateKey384, ecdsaPrivateKey521 *ecdsa.PrivateKey

	ecdsaPublicKey256Another, ecdsaPublicKey384Another, ecdsaPublicKey521Another    *ecdsa.PublicKey
	ecdsaPrivateKey256Another, ecdsaPrivateKey384Another, ecdsaPrivateKey521Another *ecdsa.PrivateKey
)

var initESKeysOnce sync.Once

func initESKeys() {
	initESKeysOnce.Do(func() {
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
	})
}

func TestES(t *testing.T) {
	initESKeys()

	f := func(alg Algorithm, privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey, wantErr error) {
		t.Helper()

		signer, errSigner := NewSignerES(alg, privateKey)
		if errSigner != nil {
			t.Fatalf("NewSignerES %v", errSigner)
		}
		verifier, errVerifier := NewVerifierES(alg, publicKey)
		if errVerifier != nil {
			t.Fatalf("NewVerifierES %v", errVerifier)
		}

		token, err := NewBuilder(signer).Build(simplePayload)
		if err != nil {
			t.Fatalf("Build %v", errVerifier)
		}

		errVerify := verifier.Verify(token)
		if !errors.Is(errVerify, wantErr) {
			t.Errorf("want %v, got %v", wantErr, errVerify)
		}
	}

	f(ES256, ecdsaPrivateKey256, ecdsaPublicKey256, nil)
	f(ES384, ecdsaPrivateKey384, ecdsaPublicKey384, nil)
	f(ES512, ecdsaPrivateKey521, ecdsaPublicKey521, nil)

	f(ES256, ecdsaPrivateKey256, ecdsaPublicKey256Another, ErrInvalidSignature)
	f(ES384, ecdsaPrivateKey384, ecdsaPublicKey384Another, ErrInvalidSignature)
	f(ES512, ecdsaPrivateKey521, ecdsaPublicKey521Another, ErrInvalidSignature)

	f(ES256, ecdsaPrivateKey256Another, ecdsaPublicKey256, ErrInvalidSignature)
	f(ES384, ecdsaPrivateKey384Another, ecdsaPublicKey384, ErrInvalidSignature)
	f(ES512, ecdsaPrivateKey521Another, ecdsaPublicKey521, ErrInvalidSignature)
}

func TestES_BadKeys(t *testing.T) {
	initESKeys()

	f := func(err, wantErr error) {
		t.Helper()

		if !errors.Is(err, wantErr) {
			t.Errorf("expected %v, got %v", wantErr, err)
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
