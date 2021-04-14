package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

var (
	ed25519PrivateKey ed25519.PrivateKey
	ed25519PublicKey  ed25519.PublicKey

	ed25519PrivateKeyAnother ed25519.PrivateKey
	ed25519PublicKeyAnother  ed25519.PublicKey
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
	ed25519PrivateKeyAnother, ed25519PublicKeyAnother = f()
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
	f(ed25519PrivateKey, ed25519PublicKeyAnother, false)
	f(ed25519PrivateKeyAnother, ed25519PublicKey, false)
}

func TestEdDSA_BadKeys(t *testing.T) {
	f := func(err, wantErr error) {
		if !errors.Is(err, wantErr) {
			t.Fatalf("expected %v, got %v", wantErr, err)
		}
	}

	f(getSignerError(NewSignerEdDSA(nil)), ErrNilKey)
	priv := ed25519.PrivateKey(make([]byte, 72))
	f(getSignerError(NewSignerEdDSA(priv)), ErrInvalidKey)

	f(getVerifierError(NewVerifierEdDSA(nil)), ErrNilKey)
	pub := ed25519.PublicKey(make([]byte, 72))
	f(getVerifierError(NewVerifierEdDSA(pub)), ErrInvalidKey)
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
