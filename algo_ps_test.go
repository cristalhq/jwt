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

	f := func(alg Algorithm, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, isCorrectSign bool) {
		t.Helper()

		signer := mustSigner(NewSignerPS(alg, privateKey))
		token := mustBuild(signer, simplePayload)
		verifier := mustVerifier(NewVerifierPS(alg, publicKey))

		err := verifier.Verify(token)
		if err == nil && !isCorrectSign {
			t.Error("must be not nil")
		}
	}

	f(PS256, rsapsPrivateKey256, rsapsPublicKey256, true)
	f(PS384, rsapsPrivateKey384, rsapsPublicKey384, true)
	f(PS512, rsapsPrivateKey512, rsapsPublicKey512, true)
	f(PS512, rsapsPrivateKey512Other, rsapsPublicKey512Other, true)

	f(PS256, rsapsPrivateKey256, rsapsPublicKey256Another, false)
	f(PS384, rsapsPrivateKey384, rsapsPublicKey384Another, false)
	f(PS512, rsapsPrivateKey512, rsapsPublicKey512Another, false)

	f(PS256, rsapsPrivateKey256Another, rsapsPublicKey256, false)
	f(PS384, rsapsPrivateKey384Another, rsapsPublicKey384, false)
	f(PS512, rsapsPrivateKey512Another, rsapsPublicKey512, false)
	f(PS512, rsapsPrivateKey512Another, rsapsPublicKey512Other, false)
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
