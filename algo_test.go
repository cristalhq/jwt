package jwt

import "testing"

func TestCorrectAlgorithm(t *testing.T) {
	f := func(s Signer, want Algorithm) {
		t.Helper()
		if alg := s.Algorithm(); alg != want {
			t.Errorf("got %#v, want %#v", alg, want)
		}
	}

	hmacKey := []byte("key")
	f(mustSigner(NewHS256(hmacKey)), HS256)
	f(mustSigner(NewHS384(hmacKey)), HS384)
	f(mustSigner(NewHS512(hmacKey)), HS512)

	rsaPub, rsaPriv := rsaPublicKey1, rsaPrivateKey1
	f(mustSigner(NewRS256(rsaPub, rsaPriv)), RS256)
	f(mustSigner(NewRS384(rsaPub, rsaPriv)), RS384)
	f(mustSigner(NewRS512(rsaPub, rsaPriv)), RS512)

	f(mustSigner(NewPS256(rsaPub, rsaPriv)), PS256)
	f(mustSigner(NewPS384(rsaPub, rsaPriv)), PS384)
	f(mustSigner(NewPS512(rsaPub, rsaPriv)), PS512)

	// ecdsaPub, ecdsaPriv := nil, nil
	// f(mustSigner(NewES256(ecdsaPub, ecdsaPriv)), ES256)
	// f(mustSigner(NewES384(ecdsaPub, ecdsaPriv)), ES384)
	// f(mustSigner(NewES512(ecdsaPub, ecdsaPriv)), ES512)
}

func TestPanicOnNilKey(t *testing.T) {
	f := func(_ Signer, err error) {
		t.Helper()
		if err == nil {
			t.Error("should have an error")
		}
	}

	f(NewEdDSA(nil, nil))

	f(NewHS256(nil))
	f(NewHS384(nil))
	f(NewHS512(nil))

	f(NewRS256(nil, nil))
	f(NewRS384(nil, nil))
	f(NewRS512(nil, nil))

	f(NewES256(nil, nil))
	f(NewES384(nil, nil))
	f(NewES512(nil, nil))

	f(NewPS256(nil, nil))
	f(NewPS384(nil, nil))
	f(NewPS512(nil, nil))
}
