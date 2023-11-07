package jwt

import (
	"testing"
)

func TestHS(t *testing.T) {
	f := func(alg Algorithm, signKey, verifyKey []byte, wantErr error) {
		t.Helper()

		signer, err := NewSignerHS(alg, signKey)
		mustOk(t, err)

		verifier, err := NewVerifierHS(alg, verifyKey)
		mustOk(t, err)

		token, err := NewBuilder(signer).Build(simplePayload)
		mustOk(t, err)

		err = verifier.Verify(token)
		mustEqual(t, err, wantErr)
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
