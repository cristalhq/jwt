package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync"
	"testing"
)

var (
	rsaPublicKey256, rsaPublicKey384, rsaPublicKey512, rsaPublicKey512Other     *rsa.PublicKey
	rsaPrivateKey256, rsaPrivateKey384, rsaPrivateKey512, rsaPrivateKey512Other *rsa.PrivateKey

	rsaPublicKey256Another, rsaPublicKey384Another, rsaPublicKey512Another    *rsa.PublicKey
	rsaPrivateKey256Another, rsaPrivateKey384Another, rsaPrivateKey512Another *rsa.PrivateKey
)

var initRSKeysOnce sync.Once

func initRSKeys() {
	initRSKeysOnce.Do(func() {
		f := func(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
			privKey, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				panic(err)
			}
			return privKey, &privKey.PublicKey
		}

		rsaPrivateKey256, rsaPublicKey256 = f(256 * 8)
		rsaPrivateKey384, rsaPublicKey384 = f(384 * 8)
		rsaPrivateKey512, rsaPublicKey512 = f(512 * 8)
		rsaPrivateKey512Other, rsaPublicKey512Other = f(256 * 8) // 256 just for the example

		rsaPrivateKey256Another, rsaPublicKey256Another = f(256 * 8)
		rsaPrivateKey384Another, rsaPublicKey384Another = f(384 * 8)
		rsaPrivateKey512Another, rsaPublicKey512Another = f(512 * 8)
	})
}

func TestRS(t *testing.T) {
	initRSKeys()

	f := func(alg Algorithm, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, wantErr error) {
		t.Helper()

		signer, errSigner := NewSignerRS(alg, privateKey)
		if errSigner != nil {
			t.Fatalf("NewSignerRS %v", errSigner)
		}
		verifier, errVerifier := NewVerifierRS(alg, publicKey)
		if errVerifier != nil {
			t.Fatalf("NewVerifierRS %v", errVerifier)
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

	f(RS256, rsaPrivateKey256, rsaPublicKey256, nil)
	f(RS384, rsaPrivateKey384, rsaPublicKey384, nil)
	f(RS512, rsaPrivateKey512, rsaPublicKey512, nil)
	f(RS512, rsaPrivateKey512Other, rsaPublicKey512Other, nil)

	f(RS256, rsaPrivateKey256, rsaPublicKey256Another, ErrInvalidSignature)
	f(RS384, rsaPrivateKey384, rsaPublicKey384Another, ErrInvalidSignature)
	f(RS512, rsaPrivateKey512, rsaPublicKey512Another, ErrInvalidSignature)

	f(RS256, rsaPrivateKey256Another, rsaPublicKey256, ErrInvalidSignature)
	f(RS384, rsaPrivateKey384Another, rsaPublicKey384, ErrInvalidSignature)
	f(RS512, rsaPrivateKey512Another, rsaPublicKey512, ErrInvalidSignature)
	f(RS512, rsaPrivateKey512Other, rsaPublicKey512, ErrInvalidSignature)
}

func TestRS_BadKeys(t *testing.T) {
	initRSKeys()

	f := func(err, wantErr error) {
		t.Helper()

		if !errors.Is(err, wantErr) {
			t.Errorf("expected %v, got %v", wantErr, err)
		}
	}

	f(getSignerError(NewSignerRS(RS256, nil)), ErrNilKey)
	f(getSignerError(NewSignerRS(RS384, nil)), ErrNilKey)
	f(getSignerError(NewSignerRS(RS512, nil)), ErrNilKey)
	f(getSignerError(NewSignerRS("foo", rsaPrivateKey384)), ErrUnsupportedAlg)

	f(getVerifierError(NewVerifierRS(RS256, nil)), ErrNilKey)
	f(getVerifierError(NewVerifierRS(RS384, nil)), ErrNilKey)
	f(getVerifierError(NewVerifierRS(RS512, nil)), ErrNilKey)
	f(getVerifierError(NewVerifierRS("boo", rsaPublicKey384)), ErrUnsupportedAlg)
}
