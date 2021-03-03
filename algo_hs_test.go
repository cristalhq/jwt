package jwt

import (
	"testing"
)

func TestHS(t *testing.T) {
	f := func(alg Algorithm, signKey, verifyKey string, isCorrectSign bool) {
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

	f(HS256, `hmac-secret-key`, `hmac-secret-key`, true)
	f(HS384, `hmac-secret-key`, `hmac-secret-key`, true)
	f(HS512, `hmac-secret-key`, `hmac-secret-key`, true)

	f(HS256, `key_1`, `1_key`, false)
	f(HS384, `key_1`, `1_key`, false)
	f(HS512, `key_1`, `1_key`, false)

	f(HS256, `hmac-secret-key`, `key_1`, false)
}

func hsSign(t *testing.T, alg Algorithm, key, payload string) []byte {
	t.Helper()

	signer, errSigner := NewSignerHS(alg, []byte(key))
	if errSigner != nil {
		t.Fatalf("NewSignerHS %v", errSigner)
	}

	sign, errSign := signer.Sign([]byte(payload))
	if errSign != nil {
		t.Fatalf("SignHS %v", errSign)
	}
	return sign
}

func hsVerify(t *testing.T, alg Algorithm, key, payload string, sign []byte) error {
	t.Helper()

	verifier, errVerifier := NewVerifierHS(alg, []byte(key))
	if errVerifier != nil {
		t.Fatalf("NewVerifierHS %v", errVerifier)
	}
	return verifier.Verify([]byte(payload), sign)
}
