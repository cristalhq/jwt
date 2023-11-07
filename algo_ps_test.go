package jwt

import (
	"crypto/rsa"
	"testing"
)

func TestPS(t *testing.T) {
	f := func(alg Algorithm, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, wantErr error) {
		t.Helper()

		signer, errSigner := NewSignerPS(alg, privateKey)
		mustOk(t, errSigner)

		verifier, errVerifier := NewVerifierPS(alg, publicKey)
		mustOk(t, errVerifier)

		token, err := NewBuilder(signer).Build(simplePayload)
		mustOk(t, err)

		err = verifier.Verify(token)
		mustEqual(t, err, wantErr)
	}

	f(PS256, rsapsPrivateKey256, rsapsPublicKey256, nil)
	f(PS384, rsapsPrivateKey384, rsapsPublicKey384, nil)
	f(PS512, rsapsPrivateKey512, rsapsPublicKey512, nil)
	f(PS512, rsapsPrivateKey512Other, rsapsPublicKey512Other, nil)

	f(PS256, rsapsPrivateKey256, rsapsPublicKey256Another, ErrInvalidSignature)
	f(PS384, rsapsPrivateKey384, rsapsPublicKey384Another, ErrInvalidSignature)
	f(PS512, rsapsPrivateKey512, rsapsPublicKey512Another, ErrInvalidSignature)

	f(PS256, rsapsPrivateKey256Another, rsapsPublicKey256, ErrInvalidSignature)
	f(PS384, rsapsPrivateKey384Another, rsapsPublicKey384, ErrInvalidSignature)
	f(PS512, rsapsPrivateKey512Another, rsapsPublicKey512, ErrInvalidSignature)
	f(PS512, rsapsPrivateKey512Another, rsapsPublicKey512Other, ErrInvalidSignature)
}

func TestPS_BadKeys(t *testing.T) {
	f := func(err, wantErr error) {
		t.Helper()
		mustEqual(t, err, wantErr)
	}

	f(getSignerError(NewSignerPS(PS256, nil)), ErrNilKey)
	f(getSignerError(NewSignerPS(PS384, nil)), ErrNilKey)
	f(getSignerError(NewSignerPS(PS512, nil)), ErrNilKey)
	f(getSignerError(NewSignerPS("foo", rsapsPrivateKey384)), ErrUnsupportedAlg)

	f(getVerifierError(NewVerifierPS(PS256, nil)), ErrNilKey)
	f(getVerifierError(NewVerifierPS(PS384, nil)), ErrNilKey)
	f(getVerifierError(NewVerifierPS(PS512, nil)), ErrNilKey)
	f(getVerifierError(NewVerifierPS("boo", rsapsPublicKey384)), ErrUnsupportedAlg)
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
