package jwt

import (
	"encoding/base64"
	"testing"
)

func TestHS(t *testing.T) {
	f := func(alg Algorithm, signKey, verifyKey string, isCorrectSign bool, wantSign string) {
		t.Helper()

		const payload = `simple-string-payload`

		sign := hsSign(t, alg, signKey, payload)

		got := base64.StdEncoding.EncodeToString(sign)
		if got != wantSign {
			t.Fatalf("want %q, got %q", wantSign, got)
		}

		err := hsVerify(t, alg, verifyKey, payload, sign)
		if err != nil {
			if isCorrectSign {
				t.Fatal(err)
			}
		}
	}

	f(
		HS256, `hmac-secret-key`, `hmac-secret-key`,
		true,
		`G2xzjtj5WspiEGLeMJVVfOwgolPAvVs52sztKOYObH0=`,
	)
	f(
		HS384, `hmac-secret-key`, `hmac-secret-key`,
		true,
		`FjCo36x0lvZ9R/aqVHGPktG/xjoo+1H9P2Uisnb9/tn8JOvuFlMDPYQGwul4hQdq`,
	)
	f(
		HS512, `hmac-secret-key`, `hmac-secret-key`,
		true,
		`3i3eSP90Cyepul8FyuB31g/kNw+AWEJlIa/Qz4VGLCut+fsWZ+t6Ww9QXiKBMKqoAIZw7nQXwaLnL+2p96uMiw==`,
	)

	f(
		HS256, `key_1`, `1_key`,
		false,
		`HiGp5jorfcJ+XKJiw4WJwCHx6Oy3BpOCEDV+VZKmQR8=`,
	)
	f(
		HS384, `key_1`, `1_key`,
		false,
		`eq4MaXQP+FB4pksWLu5I+aM/26hLNaDXbpI39bY/Y0e3YwLw/JdkTgxJ3+7KDlwO`,
	)
	f(
		HS512, `key_1`, `1_key`,
		false,
		`jxnpkrW1c0cIOsOzfBqrSucjx9j7TTQL7BrtKc4522bev7bo42qbgbgfBKZr7o8jChZaQ3J/T2rX05SD+YUaCQ==`,
	)
}

func hsSign(t *testing.T, alg Algorithm, key, payload string) []byte {
	t.Helper()

	signer, errSigner := NewSignerHS(alg, []byte(key))
	if errSigner != nil {
		t.Fatal(errSigner)
	}

	sign, errSign := signer.Sign([]byte(payload))
	if errSign != nil {
		t.Fatal(errSign)
	}
	return sign
}

func hsVerify(t *testing.T, alg Algorithm, key, payload string, sign []byte) error {
	t.Helper()

	verifier, errVerifier := NewVerifierHS(alg, []byte(key))
	if errVerifier != nil {
		t.Fatal(errVerifier)
	}
	return verifier.Verify([]byte(payload), sign)
}
