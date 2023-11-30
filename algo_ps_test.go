package jwt

import (
	"crypto/rsa"
	"testing"
)

func TestPS(t *testing.T) {
	testCases := []struct {
		alg        Algorithm
		privateKey *rsa.PrivateKey
		publicKey  *rsa.PublicKey
		wantErr    error
	}{
		{PS256, rsapsPrivateKey256, rsapsPublicKey256, nil},
		{PS384, rsapsPrivateKey384, rsapsPublicKey384, nil},
		{PS512, rsapsPrivateKey512, rsapsPublicKey512, nil},
		{PS512, rsapsPrivateKey512Other, rsapsPublicKey512Other, nil},

		{PS256, rsapsPrivateKey256, rsapsPublicKey256Another, ErrInvalidSignature},
		{PS384, rsapsPrivateKey384, rsapsPublicKey384Another, ErrInvalidSignature},
		{PS512, rsapsPrivateKey512, rsapsPublicKey512Another, ErrInvalidSignature},

		{PS256, rsapsPrivateKey256Another, rsapsPublicKey256, ErrInvalidSignature},
		{PS384, rsapsPrivateKey384Another, rsapsPublicKey384, ErrInvalidSignature},
		{PS512, rsapsPrivateKey512Another, rsapsPublicKey512, ErrInvalidSignature},
		{PS512, rsapsPrivateKey512Another, rsapsPublicKey512Other, ErrInvalidSignature},
	}

	for _, tc := range testCases {
		signer, errSigner := NewSignerPS(tc.alg, tc.privateKey)
		mustOk(t, errSigner)

		verifier, errVerifier := NewVerifierPS(tc.alg, tc.publicKey)
		mustOk(t, errVerifier)

		token, err := NewBuilder(signer).Build(simplePayload)
		mustOk(t, err)

		err = verifier.Verify(token)
		mustEqual(t, err, tc.wantErr)
	}
}

func TestPS_BadKeys(t *testing.T) {
	testCases := []struct {
		err     error
		wantErr error
	}{
		{getErr(NewSignerPS(PS256, nil)), ErrNilKey},
		{getErr(NewSignerPS(PS384, nil)), ErrNilKey},
		{getErr(NewSignerPS(PS512, nil)), ErrNilKey},
		{getErr(NewSignerPS("foo", rsapsPrivateKey384)), ErrUnsupportedAlg},

		{getErr(NewVerifierPS(PS256, nil)), ErrNilKey},
		{getErr(NewVerifierPS(PS384, nil)), ErrNilKey},
		{getErr(NewVerifierPS(PS512, nil)), ErrNilKey},
		{getErr(NewVerifierPS("boo", rsapsPublicKey384)), ErrUnsupportedAlg},
	}

	for _, tc := range testCases {
		mustEqual(t, tc.err, tc.wantErr)
	}
}

var (
	rsapsPrivateKey256      = mustParseRSAKey(testKeyRSA1024)
	rsapsPrivateKey384      = mustParseRSAKey(testKeyRSA2048)
	rsapsPrivateKey512      = mustParseRSAKey(testKeyRSA4096)
	rsapsPrivateKey512Other = mustParseRSAKey(testKeyRSA4096Other)

	rsapsPublicKey256      = &rsapsPrivateKey256.PublicKey
	rsapsPublicKey384      = &rsapsPrivateKey384.PublicKey
	rsapsPublicKey512      = &rsapsPrivateKey512.PublicKey
	rsapsPublicKey512Other = &rsapsPrivateKey512Other.PublicKey

	rsapsPrivateKey256Another = mustParseRSAKey(testKeyRSA1024Another)
	rsapsPrivateKey384Another = mustParseRSAKey(testKeyRSA2048Another)
	rsapsPrivateKey512Another = mustParseRSAKey(testKeyRSA4096Another)

	rsapsPublicKey256Another = &rsapsPrivateKey256Another.PublicKey
	rsapsPublicKey384Another = &rsapsPrivateKey384Another.PublicKey
	rsapsPublicKey512Another = &rsapsPrivateKey512Another.PublicKey
)
