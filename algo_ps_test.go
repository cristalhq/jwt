package jwt

import (
	"crypto/rsa"
	"testing"
)

func TestPS(t *testing.T) {
	f := func(alg Algorithm, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, isCorrectSign bool) {
		t.Helper()

		const payload = `simple-string-payload`

		sign := psSign(t, alg, privateKey, payload)

		err := psVerify(t, alg, publicKey, payload, sign)
		if err != nil {
			if isCorrectSign {
				t.Fatal(err)
			}
		}
	}

	f(
		PS256, rsaPrivateKey1, rsaPublicKey1, true,
	)
	f(
		PS384, rsaPrivateKey1, rsaPublicKey1, true,
	)
	f(
		PS512, rsaPrivateKey1, rsaPublicKey1, true,
	)

	f(
		PS256, rsaPrivateKey1, rsaPublicKey2, false,
	)
	f(
		PS384, rsaPrivateKey1, rsaPublicKey2, false,
	)
	f(
		PS512, rsaPrivateKey1, rsaPublicKey2, false,
	)
}

func psSign(t *testing.T, alg Algorithm, privateKey *rsa.PrivateKey, payload string) []byte {
	t.Helper()

	signer, errSigner := NewSignerPS(alg, privateKey)
	if errSigner != nil {
		t.Fatal(errSigner)
	}

	sign, errSign := signer.Sign([]byte(payload))
	if errSign != nil {
		t.Fatal(errSign)
	}
	return sign
}

func psVerify(t *testing.T, alg Algorithm, publicKey *rsa.PublicKey, payload string, sign []byte) error {
	t.Helper()

	verifier, errVerifier := NewVerifierPS(alg, publicKey)
	if errVerifier != nil {
		t.Fatal(errVerifier)
	}
	return verifier.Verify([]byte(payload), sign)
}
