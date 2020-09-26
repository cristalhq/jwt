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

	rsaPriv := rsaPrivateKey1
	f(mustSigner(NewSignerRS(RS256, rsaPriv)), RS256)
	f(mustSigner(NewSignerRS(RS384, rsaPriv)), RS384)
	f(mustSigner(NewSignerRS(RS512, rsaPriv)), RS512)

	f(mustSigner(NewSignerPS(PS256, rsaPriv)), PS256)
	f(mustSigner(NewSignerPS(PS384, rsaPriv)), PS384)
	f(mustSigner(NewSignerPS(PS512, rsaPriv)), PS512)

	ecdsaPriv := ecdsaPrivKey256
	f(mustSigner(NewSignerES(ES256, ecdsaPriv)), ES256)
	f(mustSigner(NewSignerES(ES384, ecdsaPriv)), ES384)
	f(mustSigner(NewSignerES(ES512, ecdsaPriv)), ES512)
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

	rsaPub := rsaPublicKey1
	f(mustVerifier(NewVerifierRS(RS256, rsaPub)), RS256)
	f(mustVerifier(NewVerifierRS(RS384, rsaPub)), RS384)
	f(mustVerifier(NewVerifierRS(RS512, rsaPub)), RS512)

	f(mustVerifier(NewVerifierPS(PS256, rsaPub)), PS256)
	f(mustVerifier(NewVerifierPS(PS384, rsaPub)), PS384)
	f(mustVerifier(NewVerifierPS(PS512, rsaPub)), PS512)

	ecdsaPub := ecdsaPubKey256
	f(mustVerifier(NewVerifierES(ES256, ecdsaPub)), ES256)
	f(mustVerifier(NewVerifierES(ES384, ecdsaPub)), ES384)
	f(mustVerifier(NewVerifierES(ES512, ecdsaPub)), ES512)
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
	f(NewSignerRS("xxx", rsaPrivateKey1))
	f(NewSignerPS("xxx", rsaPrivateKey1))
	f(NewSignerES("xxx", ecdsaPrivKey256))
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
	f(NewVerifierRS("xxx", rsaPublicKey1))
	f(NewVerifierPS("xxx", rsaPublicKey1))
	f(NewVerifierES("xxx", ecdsaPubKey256))
}
