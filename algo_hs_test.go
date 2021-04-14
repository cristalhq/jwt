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

		const payload = `simple-string-payload`

		sign := hsSign(t, alg, signKey, payload)

		err := hsVerify(t, alg, verifyKey, payload, sign)
		if err != nil && isCorrectSign {
			t.Fatal(err)
		}
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

func hsSign(t *testing.T, alg Algorithm, key []byte, payload string) []byte {
	t.Helper()

	signer, errSigner := NewSignerHS(alg, key)
	if errSigner != nil {
		t.Fatalf("NewSignerHS %v", errSigner)
	}

	sign, errSign := signer.Sign([]byte(payload))
	if errSign != nil {
		t.Fatalf("SignHS %v", errSign)
	}
	return sign
}

func hsVerify(t *testing.T, alg Algorithm, key []byte, payload string, sign []byte) error {
	t.Helper()

	verifier, errVerifier := NewVerifierHS(alg, key)
	if errVerifier != nil {
		t.Fatalf("NewVerifierHS %v", errVerifier)
	}
	return verifier.Verify([]byte(payload), sign)
}
