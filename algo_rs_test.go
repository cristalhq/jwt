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

	f := func(alg Algorithm, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, isCorrectSign bool) {
		t.Helper()

		const payload = `simple-string-payload`

		sign := rsSign(t, alg, privateKey, payload)

		err := rsVerify(t, alg, publicKey, payload, sign)
		if err != nil && isCorrectSign {
			t.Error(err)
		}
		if err == nil && !isCorrectSign {
			t.Error("must be not nil")
		}
	}

	f(RS256, rsaPrivateKey256, rsaPublicKey256, true)
	f(RS384, rsaPrivateKey384, rsaPublicKey384, true)
	f(RS512, rsaPrivateKey512, rsaPublicKey512, true)
	f(RS512, rsaPrivateKey512Other, rsaPublicKey512Other, true)

	f(RS256, rsaPrivateKey256, rsaPublicKey256Another, false)
	f(RS384, rsaPrivateKey384, rsaPublicKey384Another, false)
	f(RS512, rsaPrivateKey512, rsaPublicKey512Another, false)

	f(RS256, rsaPrivateKey256Another, rsaPublicKey256, false)
	f(RS384, rsaPrivateKey384Another, rsaPublicKey384, false)
	f(RS512, rsaPrivateKey512Another, rsaPublicKey512, false)
	f(RS512, rsaPrivateKey512Other, rsaPublicKey512, false)
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

func rsSign(t *testing.T, alg Algorithm, privateKey *rsa.PrivateKey, payload string) []byte {
	t.Helper()

	signer, errSigner := NewSignerRS(alg, privateKey)
	if errSigner != nil {
		t.Fatalf("NewSignerRS %v", errSigner)
	}

	sign, errSign := signer.Sign([]byte(payload))
	if errSign != nil {
		t.Fatalf("SignRS %v", errSign)
	}
	return sign
}

func rsVerify(t *testing.T, alg Algorithm, publicKey *rsa.PublicKey, payload string, sign []byte) error {
	t.Helper()

	verifier, errVerifier := NewVerifierRS(alg, publicKey)
	if errVerifier != nil {
		t.Fatalf("NewVerifierRS %v", errVerifier)
	}
	return verifier.Verify([]byte(payload), sign)
}
