package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
)

var (
	rsaPublicKey256, rsaPublicKey384, rsaPublicKey512    *rsa.PublicKey
	rsaPrivateKey256, rsaPrivateKey384, rsaPrivateKey512 *rsa.PrivateKey

	rsaOtherPublicKey256, rsaOtherPublicKey384, rsaOtherPublicKey512    *rsa.PublicKey
	rsaOtherPrivateKey256, rsaOtherPrivateKey384, rsaOtherPrivateKey512 *rsa.PrivateKey
)

func init() {
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

	rsaOtherPrivateKey256, rsaOtherPublicKey256 = f(256 * 8)
	rsaOtherPrivateKey384, rsaOtherPublicKey384 = f(384 * 8)
	rsaOtherPrivateKey512, rsaOtherPublicKey512 = f(512 * 8)
}

func TestRS(t *testing.T) {
	f := func(alg Algorithm, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, isCorrectSign bool) {
		t.Helper()

		const payload = `simple-string-payload`

		sign := rsSign(t, alg, privateKey, payload)

		err := rsVerify(t, alg, publicKey, payload, sign)
		if err != nil && isCorrectSign {
			t.Fatal(err)
		}
		if err == nil && !isCorrectSign {
			t.Fatal("must be not nil")
		}
	}

	f(RS256, rsaPrivateKey256, rsaPublicKey256, true)
	f(RS384, rsaPrivateKey384, rsaPublicKey384, true)
	f(RS512, rsaPrivateKey512, rsaPublicKey512, true)

	f(RS256, rsaPrivateKey256, rsaOtherPublicKey256, false)
	f(RS384, rsaPrivateKey384, rsaOtherPublicKey384, false)
	f(RS512, rsaPrivateKey512, rsaOtherPublicKey512, false)

	f(RS256, rsaOtherPrivateKey256, rsaPublicKey256, false)
	f(RS384, rsaOtherPrivateKey384, rsaPublicKey384, false)
	f(RS512, rsaOtherPrivateKey512, rsaPublicKey512, false)
}

func TestRS_BadKeys(t *testing.T) {
	f := func(err, wantErr error) {
		t.Helper()

		if !errors.Is(err, wantErr) {
			t.Fatalf("expected %v, got %v", wantErr, err)
		}
	}

	f(getSignerError(NewSignerRS(RS256, nil)), ErrNilKey)
	f(getSignerError(NewSignerRS(RS384, nil)), ErrNilKey)
	f(getSignerError(NewSignerRS(RS512, nil)), ErrNilKey)

	f(getSignerError(NewSignerRS("foo", rsaPrivateKey384)), ErrUnsupportedAlg)

	f(getSignerError(NewSignerRS(RS256, rsaPrivateKey384)), ErrInvalidKey)
	f(getSignerError(NewSignerRS(RS256, rsaPrivateKey512)), ErrInvalidKey)
	f(getSignerError(NewSignerRS(RS384, rsaPrivateKey256)), ErrInvalidKey)
	f(getSignerError(NewSignerRS(RS384, rsaPrivateKey512)), ErrInvalidKey)
	f(getSignerError(NewSignerRS(RS512, rsaPrivateKey256)), ErrInvalidKey)
	f(getSignerError(NewSignerRS(RS512, rsaPrivateKey384)), ErrInvalidKey)

	f(getVerifierError(NewVerifierRS(RS256, nil)), ErrNilKey)
	f(getVerifierError(NewVerifierRS(RS384, nil)), ErrNilKey)
	f(getVerifierError(NewVerifierRS(RS512, nil)), ErrNilKey)

	f(getVerifierError(NewVerifierRS("boo", rsaPublicKey384)), ErrUnsupportedAlg)

	f(getVerifierError(NewVerifierRS(RS256, rsaPublicKey384)), ErrInvalidKey)
	f(getVerifierError(NewVerifierRS(RS256, rsaPublicKey512)), ErrInvalidKey)
	f(getVerifierError(NewVerifierRS(RS384, rsaPublicKey256)), ErrInvalidKey)
	f(getVerifierError(NewVerifierRS(RS384, rsaPublicKey512)), ErrInvalidKey)
	f(getVerifierError(NewVerifierRS(RS512, rsaPublicKey256)), ErrInvalidKey)
	f(getVerifierError(NewVerifierRS(RS512, rsaPublicKey384)), ErrInvalidKey)
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
