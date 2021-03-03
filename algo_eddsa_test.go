package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

var (
	ed25519PrivateKey ed25519.PrivateKey
	ed25519PublicKey  ed25519.PublicKey

	ed25519OtherPrivateKey ed25519.PrivateKey
	ed25519OtherPublicKey  ed25519.PublicKey
)

func init() {
	f := func() (ed25519.PrivateKey, ed25519.PublicKey) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		return privKey, pubKey
	}

	ed25519PrivateKey, ed25519PublicKey = f()
	ed25519OtherPrivateKey, ed25519OtherPublicKey = f()
}

func TestEdDSA(t *testing.T) {
	f := func(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey, isCorrectSign bool) {
		t.Helper()

		const payload = `simple-string-payload`

		sign := ed25519Sign(t, privateKey, payload)

		err := ed25519Verify(t, publicKey, payload, sign)
		if err != nil && isCorrectSign {
			t.Fatal(err)
		}
		if err == nil && !isCorrectSign {
			t.Fatal("must be not nil")
		}
	}

	f(ed25519PrivateKey, ed25519PublicKey, true)
	f(ed25519PrivateKey, ed25519OtherPublicKey, false)
	f(ed25519OtherPrivateKey, ed25519PublicKey, false)
}

func ed25519Sign(t *testing.T, privateKey ed25519.PrivateKey, payload string) []byte {
	t.Helper()

	signer, errSigner := NewSignerEdDSA(privateKey)
	if errSigner != nil {
		t.Fatalf("NewSignerEdDSA %v", errSigner)
	}

	sign, errSign := signer.Sign([]byte(payload))
	if errSign != nil {
		t.Fatalf("SignEdDSA %v", errSign)
	}
	return sign
}

func ed25519Verify(t *testing.T, publicKey ed25519.PublicKey, payload string, sign []byte) error {
	t.Helper()

	verifier, errVerifier := NewVerifierEdDSA(publicKey)
	if errVerifier != nil {
		t.Fatalf("NewVerifierEdDSA %v", errVerifier)
	}
	return verifier.Verify([]byte(payload), sign)
}
