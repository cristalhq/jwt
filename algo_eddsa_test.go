package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
)

var (
	ed25519PrivateKey ed25519.PrivateKey
	ed25519PublicKey  ed25519.PublicKey

	ed25519PrivateKeyAnother ed25519.PrivateKey
	ed25519PublicKeyAnother  ed25519.PublicKey
)

var initEdDSAKeysOnce sync.Once

func initEdDSAKeys() {
	initEdDSAKeysOnce.Do(func() {
		f := func() (ed25519.PrivateKey, ed25519.PublicKey) {
			pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				panic(err)
			}
			return privKey, pubKey
		}

		ed25519PrivateKey, ed25519PublicKey = f()
		ed25519PrivateKeyAnother, ed25519PublicKeyAnother = f()
	})
}

func TestEdDSA(t *testing.T) {
	initEdDSAKeys()

	f := func(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey, wantErr error) {
		t.Helper()

		signer := mustSigner(NewSignerEdDSA(privateKey))
		verifier := mustVerifier(NewVerifierEdDSA(publicKey))
		token := mustBuild(signer, simplePayload)

		err := verifier.Verify(token)
		if !errors.Is(err, wantErr) {
			t.Errorf("want %v, got %v", wantErr, err)
		}
	}

	f(ed25519PrivateKey, ed25519PublicKey, nil)
	f(ed25519PrivateKey, ed25519PublicKeyAnother, ErrInvalidSignature)
	f(ed25519PrivateKeyAnother, ed25519PublicKey, ErrInvalidSignature)
}

func TestEdDSA_BadKeys(t *testing.T) {
	initEdDSAKeys()

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
