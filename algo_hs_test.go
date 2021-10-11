package jwt

import (
	"errors"
	"testing"
)

func TestHS(t *testing.T) {
	f := func(alg Algorithm, signKey, verifyKey []byte, wantErr error) {
		t.Helper()

		signer, errSigner := NewSignerHS(alg, signKey)
		if errSigner != nil {
			t.Fatalf("NewSignerHS %v", errSigner)
		}
		verifier, errVerifier := NewVerifierHS(alg, verifyKey)
		if errVerifier != nil {
			t.Fatalf("NewVerifierHS %v", errVerifier)
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

	f(HS256, hsKey256, hsKey256, nil)
	f(HS384, hsKey384, hsKey384, nil)
	f(HS512, hsKey512, hsKey512, nil)

	f(HS256, hsKey256, hsKeyAnother256, ErrInvalidSignature)
	f(HS384, hsKey384, hsKeyAnother384, ErrInvalidSignature)
	f(HS512, hsKey512, hsKeyAnother512, ErrInvalidSignature)

	f(HS256, hsKey256, hsKeyAnother256, ErrInvalidSignature)
}

var (
	hsKey256 = []byte("hmac-secret-key-256")
	hsKey384 = []byte("hmac-secret-key-384")
	hsKey512 = []byte("hmac-secret-key-512")

	hsKeyAnother256 = []byte("hmac-secret-key-256-another")
	hsKeyAnother384 = []byte("hmac-secret-key-384-another")
	hsKeyAnother512 = []byte("hmac-secret-key-512-another")
)
