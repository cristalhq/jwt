package jwt

import (
	"testing"
)

func TestHS(t *testing.T) {
	testCases := []struct {
		alg       Algorithm
		signKey   []byte
		verifyKey []byte
		wantErr   error
	}{
		{HS256, hsKey256, hsKey256, nil},
		{HS384, hsKey384, hsKey384, nil},
		{HS512, hsKey512, hsKey512, nil},

		{HS256, hsKey256, hsKeyAnother256, ErrInvalidSignature},
		{HS384, hsKey384, hsKeyAnother384, ErrInvalidSignature},
		{HS512, hsKey512, hsKeyAnother512, ErrInvalidSignature},

		{HS256, hsKey256, hsKeyAnother256, ErrInvalidSignature},
	}

	for _, tc := range testCases {
		signer, err := NewSignerHS(tc.alg, tc.signKey)
		mustOk(t, err)

		verifier, err := NewVerifierHS(tc.alg, tc.verifyKey)
		mustOk(t, err)

		token, err := NewBuilder(signer).Build(simplePayload)
		mustOk(t, err)

		err = verifier.Verify(token)
		mustEqual(t, err, tc.wantErr)
	}
}

var (
	hsKey256 = []byte("hmac-secret-key-256")
	hsKey384 = []byte("hmac-secret-key-384")
	hsKey512 = []byte("hmac-secret-key-512")

	hsKeyAnother256 = []byte("hmac-secret-key-256-another")
	hsKeyAnother384 = []byte("hmac-secret-key-384-another")
	hsKeyAnother512 = []byte("hmac-secret-key-512-another")
)
