package jwt

import (
	"testing"
)

var (
	hsKey256 = []byte("hmac-secret-key-256")
	hsKey384 = []byte("hmac-secret-key-384")
	hsKey512 = []byte("hmac-secret-key-512")

	hsKeyAnother256 = []byte("hmac-secret-key-256-another")
	hsKeyAnother384 = []byte("hmac-secret-key-384-another")
	hsKeyAnother512 = []byte("hmac-secret-key-512-another")
)

func TestHS(t *testing.T) {
	f := func(alg Algorithm, signKey, verifyKey []byte, isCorrectSign bool) {
		t.Helper()

		signer := mustSigner(NewSignerHS(alg, signKey))
		token := mustBuild(signer, simplePayload)
		verifier := mustVerifier(NewVerifierHS(alg, verifyKey))

		err := verifier.Verify(token)
		if err == nil && !isCorrectSign {
			t.Fatal("must be not nil")
		}
	}

	f(HS256, hsKey256, hsKey256, true)
	f(HS384, hsKey384, hsKey384, true)
	f(HS512, hsKey512, hsKey512, true)

	f(HS256, hsKey256, hsKeyAnother256, false)
	f(HS384, hsKey384, hsKeyAnother384, false)
	f(HS512, hsKey512, hsKeyAnother512, false)

	f(HS256, hsKey256, hsKeyAnother256, false)
}
