package jwt

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestEdDSA(t *testing.T) {
	f := func(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey, wantErr error) {
		t.Helper()

		signer, errSigner := NewSignerEdDSA(privateKey)
		if errSigner != nil {
			t.Fatalf("NewSignerEdDSA %v", errSigner)
		}
		verifier, errVerifier := NewVerifierEdDSA(publicKey)
		if errVerifier != nil {
			t.Fatalf("NewVerifierEdDSA %v", errVerifier)
		}

		token, err := NewBuilder(signer).Build(simplePayload)
		if err != nil {
			t.Fatalf("Build %v", errVerifier)
		}

		errVerify := verifier.Verify(token)
		if !errors.Is(errVerify, wantErr) {
			t.Errorf("want %v, got %v", wantErr, errVerify)
		}
	}

	f(ed25519PrivateKey, ed25519PublicKey, nil)
	f(ed25519PrivateKey, ed25519PublicKeyAnother, ErrInvalidSignature)
	f(ed25519PrivateKeyAnother, ed25519PublicKey, ErrInvalidSignature)
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

var (
	// See: RFC 8037, appendix A.1
	ed25519PrivateKey = ed25519.PrivateKey([]byte{
		0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
		0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
		0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
		0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
		0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
		0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
		0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
		0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
	})
	ed25519PublicKey = ed25519PrivateKey.Public().(ed25519.PublicKey)

	ed25519PrivateKeyAnother ed25519.PrivateKey = base64ToBytes("eJGvQDFFiaYHaZU2sfRhPrGKlgZcHBT8CPY3Fx2zhQEjlzQ5-3qTgKZ5wCmIRqL4sbNhWvpPx5Y_PqmSEg3oYg")
	ed25519PublicKeyAnother  ed25519.PublicKey  = base64ToBytes("I5c0Oft6k4CmecApiEai-LGzYVr6T8eWPz6pkhIN6GI")
)
