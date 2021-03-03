package jwt

import (
	"crypto/rsa"
	"errors"
	"testing"
)

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

	f(PS256, rsaPrivateKey256, rsaPublicKey256, true)
	f(PS384, rsaPrivateKey384, rsaPublicKey384, true)
	f(PS512, rsaPrivateKey512, rsaPublicKey512, true)

	f(PS256, rsaPrivateKey256, rsaOtherPublicKey256, false)
	f(PS384, rsaPrivateKey384, rsaOtherPublicKey384, false)
	f(PS512, rsaPrivateKey512, rsaOtherPublicKey512, false)

	f(PS256, rsaOtherPrivateKey256, rsaPublicKey256, false)
	f(PS384, rsaOtherPrivateKey384, rsaPublicKey384, false)
	f(PS512, rsaOtherPrivateKey512, rsaPublicKey512, false)
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

	f(getSignerError(NewSignerPS("foo", rsaPrivateKey384)), ErrUnsupportedAlg)

	f(getSignerError(NewSignerPS(PS256, rsaPrivateKey384)), ErrInvalidKey)
	f(getSignerError(NewSignerPS(PS256, rsaPrivateKey512)), ErrInvalidKey)
	f(getSignerError(NewSignerPS(PS384, rsaPrivateKey256)), ErrInvalidKey)
	f(getSignerError(NewSignerPS(PS384, rsaPrivateKey512)), ErrInvalidKey)
	f(getSignerError(NewSignerPS(PS512, rsaPrivateKey256)), ErrInvalidKey)
	f(getSignerError(NewSignerPS(PS512, rsaPrivateKey384)), ErrInvalidKey)

	f(getVerifierError(NewVerifierPS(PS256, nil)), ErrNilKey)
	f(getVerifierError(NewVerifierPS(PS384, nil)), ErrNilKey)
	f(getVerifierError(NewVerifierPS(PS512, nil)), ErrNilKey)

	f(getVerifierError(NewVerifierPS("boo", rsaPublicKey384)), ErrUnsupportedAlg)

	f(getVerifierError(NewVerifierPS(PS256, rsaPublicKey384)), ErrInvalidKey)
	f(getVerifierError(NewVerifierPS(PS256, rsaPublicKey512)), ErrInvalidKey)
	f(getVerifierError(NewVerifierPS(PS384, rsaPublicKey256)), ErrInvalidKey)
	f(getVerifierError(NewVerifierPS(PS384, rsaPublicKey512)), ErrInvalidKey)
	f(getVerifierError(NewVerifierPS(PS512, rsaPublicKey256)), ErrInvalidKey)
	f(getVerifierError(NewVerifierPS(PS512, rsaPublicKey384)), ErrInvalidKey)
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
