package jwt

import (
	"testing"
)

func TestSignerAlg(t *testing.T) {
	f := func(s Signer, want Algorithm) {
		t.Helper()
		if alg := s.Algorithm(); alg != want {
			t.Errorf("got %#v, want %#v", alg, want)
		}
	}

	hmacKey := []byte("key")
	f(mustSigner(NewSignerHS(HS256, hmacKey)), HS256)
	f(mustSigner(NewSignerHS(HS384, hmacKey)), HS384)
	f(mustSigner(NewSignerHS(HS512, hmacKey)), HS512)

	f(mustSigner(NewSignerRS(RS256, rsaPrivateKey256)), RS256)
	f(mustSigner(NewSignerRS(RS384, rsaPrivateKey384)), RS384)
	f(mustSigner(NewSignerRS(RS512, rsaPrivateKey512)), RS512)

	f(mustSigner(NewSignerPS(PS256, rsaPrivateKey256)), PS256)
	f(mustSigner(NewSignerPS(PS384, rsaPrivateKey384)), PS384)
	f(mustSigner(NewSignerPS(PS512, rsaPrivateKey512)), PS512)

	f(mustSigner(NewSignerES(ES256, ecdsaPrivateKey256)), ES256)
	f(mustSigner(NewSignerES(ES384, ecdsaPrivateKey384)), ES384)
	// f(mustSigner(NewSignerES(ES512, ecdsaPrivateKey521)), ES512)
}

func TestVerifierAlg(t *testing.T) {
	f := func(v Verifier, want Algorithm) {
		t.Helper()
		if alg := v.Algorithm(); alg != want {
			t.Errorf("got %#v, want %#v", alg, want)
		}
	}

	hmacKey := []byte("key")
	f(mustVerifier(NewVerifierHS(HS256, hmacKey)), HS256)
	f(mustVerifier(NewVerifierHS(HS384, hmacKey)), HS384)
	f(mustVerifier(NewVerifierHS(HS512, hmacKey)), HS512)

	f(mustVerifier(NewVerifierRS(RS256, rsaPublicKey256)), RS256)
	f(mustVerifier(NewVerifierRS(RS384, rsaPublicKey384)), RS384)
	f(mustVerifier(NewVerifierRS(RS512, rsaPublicKey512)), RS512)

	f(mustVerifier(NewVerifierPS(PS256, rsaPublicKey256)), PS256)
	f(mustVerifier(NewVerifierPS(PS384, rsaPublicKey384)), PS384)
	f(mustVerifier(NewVerifierPS(PS512, rsaPublicKey512)), PS512)

	f(mustVerifier(NewVerifierES(ES256, ecdsaPublicKey256)), ES256)
	f(mustVerifier(NewVerifierES(ES384, ecdsaPublicKey384)), ES384)
	f(mustVerifier(NewVerifierES(ES512, ecdsaPublicKey521)), ES512)
}

func TestSignerBadParams(t *testing.T) {
	f := func(_ Signer, err error) {
		t.Helper()
		if err == nil {
			t.Error("should have an error")
		}
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
		if err == nil {
			t.Error("should have an error")
		}
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
