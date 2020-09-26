package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

var ecdsaPubKey256 *ecdsa.PublicKey
var ecdsaPubKey384 *ecdsa.PublicKey
var ecdsaPubKey521 *ecdsa.PublicKey
var ecdsaPrivKey256 *ecdsa.PrivateKey
var ecdsaPrivKey384 *ecdsa.PrivateKey
var ecdsaPrivKey521 *ecdsa.PrivateKey

var ecdsaOtherPublicKey256 *ecdsa.PublicKey
var ecdsaOtherPublicKey384 *ecdsa.PublicKey
var ecdsaOtherPublicKey521 *ecdsa.PublicKey
var ecdsaOtherPrivateKey256 *ecdsa.PrivateKey
var ecdsaOtherPrivateKey384 *ecdsa.PrivateKey
var ecdsaOtherPrivateKey521 *ecdsa.PrivateKey

func init() {
	ecdsaPrivKey256, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaPubKey256 = &ecdsaPrivKey256.PublicKey

	ecdsaPrivKey384, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecdsaPubKey384 = &ecdsaPrivKey384.PublicKey

	ecdsaPrivKey521, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	ecdsaPubKey521 = &ecdsaPrivKey521.PublicKey

	ecdsaOtherPrivateKey256, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaOtherPublicKey256 = &ecdsaOtherPrivateKey256.PublicKey

	ecdsaOtherPrivateKey384, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecdsaOtherPublicKey384 = &ecdsaOtherPrivateKey384.PublicKey

	ecdsaOtherPrivateKey521, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	ecdsaOtherPublicKey521 = &ecdsaOtherPrivateKey521.PublicKey
}

func TestES(t *testing.T) {
	f := func(alg Algorithm, privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey, isCorrectSign bool) {
		t.Helper()

		const payload = `simple-string-payload`

		sign := esSign(t, alg, privateKey, payload)

		err := esVerify(t, alg, publicKey, payload, sign)
		if err != nil {
			if isCorrectSign {
				t.Fatal(err)
			}
		}
	}

	f(
		ES256, ecdsaPrivKey256, ecdsaPubKey256, true,
	)
	f(
		ES384, ecdsaPrivKey384, ecdsaPubKey384, true,
	)
	f(
		ES512, ecdsaPrivKey521, ecdsaPubKey521, true,
	)

	f(
		ES256, ecdsaPrivKey256, ecdsaPubKey256, false,
	)
	f(
		ES384, ecdsaPrivKey384, ecdsaPubKey384, false,
	)
	f(
		ES512, ecdsaPrivKey521, ecdsaPubKey521, false,
	)
}

func esSign(t *testing.T, alg Algorithm, privateKey *ecdsa.PrivateKey, payload string) []byte {
	t.Helper()

	signer, errSigner := NewSignerES(alg, privateKey)
	if errSigner != nil {
		t.Fatal(errSigner)
	}

	sign, errSign := signer.Sign([]byte(payload))
	if errSign != nil {
		t.Fatal(errSign)
	}
	return sign
}

func esVerify(t *testing.T, alg Algorithm, publicKey *ecdsa.PublicKey, payload string, sign []byte) error {
	t.Helper()

	verifier, errVerifier := NewVerifierES(alg, publicKey)
	if errVerifier != nil {
		t.Fatal(errVerifier)
	}
	return verifier.Verify([]byte(payload), sign)
}
