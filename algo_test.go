package jwt

import "testing"

func TestCorrectAlgorithm(t *testing.T) {
	f := func(s Signer, want Algorithm) {
		if alg := s.Algorithm(); alg != want {
			t.Errorf("got %#v, want %#v", alg, want)
		}
	}

	hmacKey := []byte("key")
	f(getSigner(NewHS256(hmacKey)), HS256)
	f(getSigner(NewHS384(hmacKey)), HS384)
	f(getSigner(NewHS512(hmacKey)), HS512)

	rsaPub, rsaPriv := rsaPublicKey1, rsaPrivateKey1
	f(getSigner(NewRS256(rsaPub, rsaPriv)), RS256)
	f(getSigner(NewRS384(rsaPub, rsaPriv)), RS384)
	f(getSigner(NewRS512(rsaPub, rsaPriv)), RS512)

	f(getSigner(NewPS256(rsaPub, rsaPriv)), PS256)
	f(getSigner(NewPS384(rsaPub, rsaPriv)), PS384)
	f(getSigner(NewPS512(rsaPub, rsaPriv)), PS512)

	// ecdsaPub, ecdsaPriv := nil, nil
	// f(getSigner(NewES256(ecdsaPub, ecdsaPriv)), ES256)
	// f(getSigner(NewES384(ecdsaPub, ecdsaPriv)), ES384)
	// f(getSigner(NewES512(ecdsaPub, ecdsaPriv)), ES512)
}

func TestPanicOnNilKey(t *testing.T) {
	f := func(_ Signer, err error) {
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
