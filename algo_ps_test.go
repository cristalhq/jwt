package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
)

var (
	rsapsPublicKey256, rsapsPublicKey384, rsapsPublicKey512    *rsa.PublicKey
	rsapsPrivateKey256, rsapsPrivateKey384, rsapsPrivateKey512 *rsa.PrivateKey

	rsapsPublicKey256Another, rsapsPublicKey384Another, rsapsPublicKey512Another    *rsa.PublicKey
	rsapsPrivateKey256Another, rsapsPrivateKey384Another, rsapsPrivateKey512Another *rsa.PrivateKey
)

func init() {
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

	rsapsPrivateKey256Another, rsapsPublicKey256Another = f(256 * 8)
	rsapsPrivateKey384Another, rsapsPublicKey384Another = f(384 * 8)
	rsapsPrivateKey512Another, rsapsPublicKey512Another = f(512 * 8)
}
func TestPS(t *testing.T) {
	f := func(alg Algorithm, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, isCorrectSign bool) {
		t.Helper()

		const payload = `simple-string-payload`

		sign := psSign(t, alg, privateKey, payload)

		err := psVerify(t, alg, publicKey, payload, sign)
		if err != nil && isCorrectSign {
			t.Fatal(err)
		}
		if err == nil && !isCorrectSign {
			t.Fatal("must be not nil")
		}
	}

	f(PS256, rsapsPrivateKey256, rsapsPublicKey256, true)
	f(PS384, rsapsPrivateKey384, rsapsPublicKey384, true)
	f(PS512, rsapsPrivateKey512, rsapsPublicKey512, true)

	f(PS256, rsapsPrivateKey256, rsapsPublicKey256Another, false)
	f(PS384, rsapsPrivateKey384, rsapsPublicKey384Another, false)
	f(PS512, rsapsPrivateKey512, rsapsPublicKey512Another, false)

	f(PS256, rsapsPrivateKey256Another, rsapsPublicKey256, false)
	f(PS384, rsapsPrivateKey384Another, rsapsPublicKey384, false)
	f(PS512, rsapsPrivateKey512Another, rsapsPublicKey512, false)
}

func TestPS_BadKeys(t *testing.T) {
	f := func(err, wantErr error) {
		t.Helper()

		if !errors.Is(err, wantErr) {
			t.Fatalf("expected %v, got %v", wantErr, err)
		}
	}

	f(getSignerError(NewSignerPS(PS256, nil)), ErrNilKey)
	f(getSignerError(NewSignerPS(PS384, nil)), ErrNilKey)
	f(getSignerError(NewSignerPS(PS512, nil)), ErrNilKey)

	f(getSignerError(NewSignerPS("foo", rsapsPrivateKey384)), ErrUnsupportedAlg)

	f(getSignerError(NewSignerPS(PS256, rsapsPrivateKey384)), ErrInvalidKey)
	f(getSignerError(NewSignerPS(PS256, rsapsPrivateKey512)), ErrInvalidKey)
	f(getSignerError(NewSignerPS(PS384, rsapsPrivateKey256)), ErrInvalidKey)
	f(getSignerError(NewSignerPS(PS384, rsapsPrivateKey512)), ErrInvalidKey)
	f(getSignerError(NewSignerPS(PS512, rsapsPrivateKey256)), ErrInvalidKey)
	f(getSignerError(NewSignerPS(PS512, rsapsPrivateKey384)), ErrInvalidKey)

	f(getVerifierError(NewVerifierPS(PS256, nil)), ErrNilKey)
	f(getVerifierError(NewVerifierPS(PS384, nil)), ErrNilKey)
	f(getVerifierError(NewVerifierPS(PS512, nil)), ErrNilKey)

	f(getVerifierError(NewVerifierPS("boo", rsapsPublicKey384)), ErrUnsupportedAlg)

	f(getVerifierError(NewVerifierPS(PS256, rsapsPublicKey384)), ErrInvalidKey)
	f(getVerifierError(NewVerifierPS(PS256, rsapsPublicKey512)), ErrInvalidKey)
	f(getVerifierError(NewVerifierPS(PS384, rsapsPublicKey256)), ErrInvalidKey)
	f(getVerifierError(NewVerifierPS(PS384, rsapsPublicKey512)), ErrInvalidKey)
	f(getVerifierError(NewVerifierPS(PS512, rsapsPublicKey256)), ErrInvalidKey)
	f(getVerifierError(NewVerifierPS(PS512, rsapsPublicKey384)), ErrInvalidKey)
}

func psSign(t *testing.T, alg Algorithm, privateKey *rsa.PrivateKey, payload string) []byte {
	t.Helper()

	signer, errSigner := NewSignerPS(alg, privateKey)
	if errSigner != nil {
		t.Fatalf("NewSignerPS %v", errSigner)
	}

	sign, errSign := signer.Sign([]byte(payload))
	if errSign != nil {
		t.Fatalf("SignPS %v", errSign)
	}
	return sign
}

func psVerify(t *testing.T, alg Algorithm, publicKey *rsa.PublicKey, payload string, sign []byte) error {
	t.Helper()

	verifier, errVerifier := NewVerifierPS(alg, publicKey)
	if errVerifier != nil {
		t.Fatalf("NewVerifierPS %v", errVerifier)
	}
	return verifier.Verify([]byte(payload), sign)
}
