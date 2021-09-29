package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync"
	"testing"
)

var (
	rsapsPublicKey256, rsapsPublicKey384, rsapsPublicKey512, rsapsPublicKey512Other     *rsa.PublicKey
	rsapsPrivateKey256, rsapsPrivateKey384, rsapsPrivateKey512, rsapsPrivateKey512Other *rsa.PrivateKey

	rsapsPublicKey256Another, rsapsPublicKey384Another, rsapsPublicKey512Another    *rsa.PublicKey
	rsapsPrivateKey256Another, rsapsPrivateKey384Another, rsapsPrivateKey512Another *rsa.PrivateKey
)

var initPSKeysOnce sync.Once

func initPSKeys() {
	initPSKeysOnce.Do(func() {
		f := func(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
			privKey, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				panic(err)
			}
			return privKey, &privKey.PublicKey
		}

		rsapsPrivateKey256, rsapsPublicKey256 = f(256 * 8)
		rsapsPrivateKey384, rsapsPublicKey384 = f(384 * 8)
		rsapsPrivateKey512, rsapsPublicKey512 = f(512 * 8)
		rsapsPrivateKey512Other, rsapsPublicKey512Other = f(256 * 8)

		rsapsPrivateKey256Another, rsapsPublicKey256Another = f(256 * 8)
		rsapsPrivateKey384Another, rsapsPublicKey384Another = f(384 * 8)
		rsapsPrivateKey512Another, rsapsPublicKey512Another = f(512 * 8)
	})
}

func TestPS(t *testing.T) {
	initPSKeys()

	f := func(alg Algorithm, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, wantErr error) {
		t.Helper()

		signer, errSigner := NewSignerPS(alg, privateKey)
		if errSigner != nil {
			t.Fatalf("NewSignerPS %v", errSigner)
		}
		verifier, errVerifier := NewVerifierPS(alg, publicKey)
		if errVerifier != nil {
			t.Fatalf("NewVerifierPS %v", errVerifier)
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

	f(PS256, rsapsPrivateKey256, rsapsPublicKey256, nil)
	f(PS384, rsapsPrivateKey384, rsapsPublicKey384, nil)
	f(PS512, rsapsPrivateKey512, rsapsPublicKey512, nil)
	f(PS512, rsapsPrivateKey512Other, rsapsPublicKey512Other, nil)

	f(PS256, rsapsPrivateKey256, rsapsPublicKey256Another, ErrInvalidSignature)
	f(PS384, rsapsPrivateKey384, rsapsPublicKey384Another, ErrInvalidSignature)
	f(PS512, rsapsPrivateKey512, rsapsPublicKey512Another, ErrInvalidSignature)

	f(PS256, rsapsPrivateKey256Another, rsapsPublicKey256, ErrInvalidSignature)
	f(PS384, rsapsPrivateKey384Another, rsapsPublicKey384, ErrInvalidSignature)
	f(PS512, rsapsPrivateKey512Another, rsapsPublicKey512, ErrInvalidSignature)
	f(PS512, rsapsPrivateKey512Another, rsapsPublicKey512Other, ErrInvalidSignature)
}

func TestPS_BadKeys(t *testing.T) {
	initPSKeys()

	f := func(err, wantErr error) {
		t.Helper()

		if !errors.Is(err, wantErr) {
			t.Errorf("expected %v, got %v", wantErr, err)
		}
	}

	f(getSignerError(NewSignerPS(PS256, nil)), ErrNilKey)
	f(getSignerError(NewSignerPS(PS384, nil)), ErrNilKey)
	f(getSignerError(NewSignerPS(PS512, nil)), ErrNilKey)
	f(getSignerError(NewSignerPS("foo", rsapsPrivateKey384)), ErrUnsupportedAlg)

	f(getVerifierError(NewVerifierPS(PS256, nil)), ErrNilKey)
	f(getVerifierError(NewVerifierPS(PS384, nil)), ErrNilKey)
	f(getVerifierError(NewVerifierPS(PS512, nil)), ErrNilKey)
	f(getVerifierError(NewVerifierPS("boo", rsapsPublicKey384)), ErrUnsupportedAlg)
}
