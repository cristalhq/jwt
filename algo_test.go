package jwt

import (
	"testing"
)

const simplePayload = `simple-string-payload`

func TestSignerAlg(t *testing.T) {
	testCases := []struct {
		s    Signer
		want Algorithm
	}{
		{must(NewSignerHS(HS256, hsKey256)), HS256},
		{must(NewSignerHS(HS384, hsKey384)), HS384},
		{must(NewSignerHS(HS512, hsKey512)), HS512},

		{must(NewSignerRS(RS256, rsaPrivateKey256)), RS256},
		{must(NewSignerRS(RS384, rsaPrivateKey384)), RS384},
		{must(NewSignerRS(RS512, rsaPrivateKey512)), RS512},

		{must(NewSignerPS(PS256, rsapsPrivateKey256)), PS256},
		{must(NewSignerPS(PS384, rsapsPrivateKey384)), PS384},
		{must(NewSignerPS(PS512, rsapsPrivateKey512)), PS512},

		{must(NewSignerES(ES256, ecdsaPrivateKey256)), ES256},
		{must(NewSignerES(ES384, ecdsaPrivateKey384)), ES384},
		{must(NewSignerES(ES512, ecdsaPrivateKey521)), ES512},
	}

	for _, tc := range testCases {
		mustEqual(t, tc.s.Algorithm(), tc.want)
	}
}

func TestVerifierAlg(t *testing.T) {
	testCases := []struct {
		v    Verifier
		want Algorithm
	}{
		{must(NewVerifierHS(HS256, hsKey256)), HS256},
		{must(NewVerifierHS(HS384, hsKey384)), HS384},
		{must(NewVerifierHS(HS512, hsKey512)), HS512},

		{must(NewVerifierRS(RS256, rsaPublicKey256)), RS256},
		{must(NewVerifierRS(RS384, rsaPublicKey384)), RS384},
		{must(NewVerifierRS(RS512, rsaPublicKey512)), RS512},

		{must(NewVerifierPS(PS256, rsapsPublicKey256)), PS256},
		{must(NewVerifierPS(PS384, rsapsPublicKey384)), PS384},
		{must(NewVerifierPS(PS512, rsapsPublicKey512)), PS512},

		{must(NewVerifierES(ES256, ecdsaPublicKey256)), ES256},
		{must(NewVerifierES(ES384, ecdsaPublicKey384)), ES384},
		{must(NewVerifierES(ES512, ecdsaPublicKey521)), ES512},
	}

	for _, tc := range testCases {
		mustEqual(t, tc.v.Algorithm(), tc.want)
	}
}

func TestSignerBadParams(t *testing.T) {
	testCases := []struct {
		err error
	}{
		{getErr(NewSignerEdDSA(nil))},
		{getErr(NewSignerEdDSA([]byte{}))},

		{getErr(NewSignerHS(HS256, nil))},
		{getErr(NewSignerHS(HS256, []byte{}))},

		{getErr(NewSignerRS(RS256, nil))},
		{getErr(NewSignerPS(PS256, nil))},
		{getErr(NewSignerES(ES256, nil))},

		{getErr(NewSignerHS("xxx", []byte("key")))},
		{getErr(NewSignerRS("xxx", rsaPrivateKey256))},
		{getErr(NewSignerPS("xxx", rsaPrivateKey256))},
		{getErr(NewSignerES("xxx", ecdsaPrivateKey256))},
	}

	for _, tc := range testCases {
		mustFail(t, tc.err)
	}
}

func TestVerifierBadParams(t *testing.T) {
	testCases := []struct {
		err error
	}{
		{getErr(NewVerifierEdDSA(nil))},
		{getErr(NewVerifierEdDSA([]byte{}))},

		{getErr(NewVerifierHS(HS256, nil))},
		{getErr(NewVerifierHS(HS256, []byte{}))},

		{getErr(NewVerifierRS(RS256, nil))},
		{getErr(NewVerifierPS(PS256, nil))},
		{getErr(NewVerifierES(ES256, nil))},

		{getErr(NewVerifierHS("xxx", []byte("key")))},
		{getErr(NewVerifierRS("xxx", rsaPublicKey256))},
		{getErr(NewVerifierPS("xxx", rsaPublicKey256))},
		{getErr(NewVerifierES("xxx", ecdsaPublicKey256))},
	}

	for _, tc := range testCases {
		mustFail(t, tc.err)
	}
}
