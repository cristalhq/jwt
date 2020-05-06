package jwt

import "testing"

func TestSignerAlg(t *testing.T) {
	f := func(s Signer, want Algorithm) {
		t.Helper()
		if alg := s.Algorithm(); alg != want {
			t.Errorf("got %#v, want %#v", alg, want)
		}
	}

	hmacKey := []byte("key")
	f(mustSigner(NewSignerHMAC(HS256, hmacKey)), HS256)
	f(mustSigner(NewSignerHMAC(HS384, hmacKey)), HS384)
	f(mustSigner(NewSignerHMAC(HS512, hmacKey)), HS512)

	rsaPriv := rsaPrivateKey1
	f(mustSigner(NewSignerRSA(RS256, rsaPriv)), RS256)
	f(mustSigner(NewSignerRSA(RS384, rsaPriv)), RS384)
	f(mustSigner(NewSignerRSA(RS512, rsaPriv)), RS512)

	f(mustSigner(NewSignerPS(PS256, rsaPriv)), PS256)
	f(mustSigner(NewSignerPS(PS384, rsaPriv)), PS384)
	f(mustSigner(NewSignerPS(PS512, rsaPriv)), PS512)

	ecdsaPriv := ecdsaPrivateKey256
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
	f(mustVerifier(NewVerifierHMAC(HS256, hmacKey)), HS256)
	f(mustVerifier(NewVerifierHMAC(HS384, hmacKey)), HS384)
	f(mustVerifier(NewVerifierHMAC(HS512, hmacKey)), HS512)

	rsaPub := rsaPublicKey1
	f(mustVerifier(NewVerifierRSA(RS256, rsaPub)), RS256)
	f(mustVerifier(NewVerifierRSA(RS384, rsaPub)), RS384)
	f(mustVerifier(NewVerifierRSA(RS512, rsaPub)), RS512)

	f(mustVerifier(NewVerifierPS(PS256, rsaPub)), PS256)
	f(mustVerifier(NewVerifierPS(PS384, rsaPub)), PS384)
	f(mustVerifier(NewVerifierPS(PS512, rsaPub)), PS512)

	ecdsaPub := ecdsaPublicKey256
	f(mustVerifier(NewVerifierES(ES256, ecdsaPub)), ES256)
	f(mustVerifier(NewVerifierES(ES384, ecdsaPub)), ES384)
	f(mustVerifier(NewVerifierES(ES512, ecdsaPub)), ES512)
}

func TestSignerErrOnNilKey(t *testing.T) {
	f := func(_ Signer, err error) {
		t.Helper()
		if err == nil {
			t.Error("should have an error")
		}
	}

	f(NewSignerEdDSA(nil))

	f(NewSignerHMAC(HS256, nil))
	f(NewSignerHMAC(HS384, nil))
	f(NewSignerHMAC(HS512, nil))

	f(NewSignerRSA(RS256, nil))
	f(NewSignerRSA(RS384, nil))
	f(NewSignerRSA(RS512, nil))

	f(NewSignerES(ES256, nil))
	f(NewSignerES(ES384, nil))
	f(NewSignerES(ES512, nil))

	f(NewSignerPS(PS256, nil))
	f(NewSignerPS(PS384, nil))
	f(NewSignerPS(PS512, nil))
}

func TestVerifierErrOnNilKey(t *testing.T) {
	f := func(_ Verifier, err error) {
		t.Helper()
		if err == nil {
			t.Error("should have an error")
		}
	}

	f(NewVerifierEdDSA(nil))

	f(NewVerifierHMAC(HS256, nil))
	f(NewVerifierHMAC(HS384, nil))
	f(NewVerifierHMAC(HS512, nil))

	f(NewVerifierRSA(RS256, nil))
	f(NewVerifierRSA(RS384, nil))
	f(NewVerifierRSA(RS512, nil))

	f(NewVerifierES(ES256, nil))
	f(NewVerifierES(ES384, nil))
	f(NewVerifierES(ES512, nil))

	f(NewVerifierPS(PS256, nil))
	f(NewVerifierPS(PS384, nil))
	f(NewVerifierPS(PS512, nil))
}
