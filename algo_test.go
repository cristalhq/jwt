package jwt

import (
	"testing"
)

const simplePayload = `simple-string-payload`

func TestSignerAlg(t *testing.T) {
	f := func(s Signer, want Algorithm) {
		t.Helper()
		mustEqual(t, s.Algorithm(), want)
	}

	f(must(NewSignerHS(HS256, hsKey256)), HS256)
	f(must(NewSignerHS(HS384, hsKey384)), HS384)
	f(must(NewSignerHS(HS512, hsKey512)), HS512)

	f(must(NewSignerRS(RS256, rsaPrivateKey256)), RS256)
	f(must(NewSignerRS(RS384, rsaPrivateKey384)), RS384)
	f(must(NewSignerRS(RS512, rsaPrivateKey512)), RS512)

	f(must(NewSignerPS(PS256, rsapsPrivateKey256)), PS256)
	f(must(NewSignerPS(PS384, rsapsPrivateKey384)), PS384)
	f(must(NewSignerPS(PS512, rsapsPrivateKey512)), PS512)

	f(must(NewSignerES(ES256, ecdsaPrivateKey256)), ES256)
	f(must(NewSignerES(ES384, ecdsaPrivateKey384)), ES384)
	f(must(NewSignerES(ES512, ecdsaPrivateKey521)), ES512)
}

func TestVerifierAlg(t *testing.T) {
	f := func(v Verifier, want Algorithm) {
		t.Helper()
		mustEqual(t, v.Algorithm(), want)
	}

	f(must(NewVerifierHS(HS256, hsKey256)), HS256)
	f(must(NewVerifierHS(HS384, hsKey384)), HS384)
	f(must(NewVerifierHS(HS512, hsKey512)), HS512)

	f(must(NewVerifierRS(RS256, rsaPublicKey256)), RS256)
	f(must(NewVerifierRS(RS384, rsaPublicKey384)), RS384)
	f(must(NewVerifierRS(RS512, rsaPublicKey512)), RS512)

	f(must(NewVerifierPS(PS256, rsapsPublicKey256)), PS256)
	f(must(NewVerifierPS(PS384, rsapsPublicKey384)), PS384)
	f(must(NewVerifierPS(PS512, rsapsPublicKey512)), PS512)

	f(must(NewVerifierES(ES256, ecdsaPublicKey256)), ES256)
	f(must(NewVerifierES(ES384, ecdsaPublicKey384)), ES384)
	f(must(NewVerifierES(ES512, ecdsaPublicKey521)), ES512)
}

func TestSignerBadParams(t *testing.T) {
	f := func(_ Signer, err error) {
		t.Helper()
		mustFail(t, err)
	}

	f(NewSignerEdDSA(nil))
	f(NewSignerEdDSA([]byte{}))

	f(NewSignerHS(HS256, nil))
	f(NewSignerHS(HS256, []byte{}))

	f(NewSignerRS(RS256, nil))
	f(NewSignerPS(PS256, nil))
	f(NewSignerES(ES256, nil))

	f(NewSignerHS("xxx", []byte("key")))
	f(NewSignerRS("xxx", rsaPrivateKey256))
	f(NewSignerPS("xxx", rsaPrivateKey256))
	f(NewSignerES("xxx", ecdsaPrivateKey256))
}

func TestVerifierBadParams(t *testing.T) {
	f := func(_ Verifier, err error) {
		t.Helper()
		mustFail(t, err)
	}

	f(NewVerifierEdDSA(nil))
	f(NewVerifierEdDSA([]byte{}))

	f(NewVerifierHS(HS256, nil))
	f(NewVerifierHS(HS256, []byte{}))

	f(NewVerifierRS(RS256, nil))
	f(NewVerifierPS(PS256, nil))
	f(NewVerifierES(ES256, nil))

	f(NewVerifierHS("xxx", []byte("key")))
	f(NewVerifierRS("xxx", rsaPublicKey256))
	f(NewVerifierPS("xxx", rsaPublicKey256))
	f(NewVerifierES("xxx", ecdsaPublicKey256))
}
