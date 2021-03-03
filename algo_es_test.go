package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

var (
	ecdsaPublicKey256, ecdsaPublicKey384, ecdsaPublicKey521    *ecdsa.PublicKey
	ecdsaPrivateKey256, ecdsaPrivateKey384, ecdsaPrivateKey521 *ecdsa.PrivateKey

	ecdsaOtherPublicKey256, ecdsaOtherPublicKey384, ecdsaOtherPublicKey521    *ecdsa.PublicKey
	ecdsaOtherPrivateKey256, ecdsaOtherPrivateKey384, ecdsaOtherPrivateKey521 *ecdsa.PrivateKey
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

	ecdsaOtherPrivateKey256, ecdsaOtherPublicKey256 = f(elliptic.P256)
	ecdsaOtherPrivateKey384, ecdsaOtherPublicKey384 = f(elliptic.P384)
	ecdsaOtherPrivateKey521, ecdsaOtherPublicKey521 = f(elliptic.P521)
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

	f(ES256, ecdsaPrivateKey256, ecdsaOtherPublicKey256, false)
	f(ES384, ecdsaPrivateKey384, ecdsaOtherPublicKey384, false)
	f(ES512, ecdsaPrivateKey521, ecdsaOtherPublicKey521, false)

	f(ES256, ecdsaOtherPrivateKey256, ecdsaPublicKey256, false)
	f(ES384, ecdsaOtherPrivateKey384, ecdsaPublicKey384, false)
	f(ES512, ecdsaOtherPrivateKey521, ecdsaPublicKey521, false)
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
