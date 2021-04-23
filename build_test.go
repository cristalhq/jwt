package jwt

import (
	"errors"
	"testing"
)

func TestBuild(t *testing.T) {
	f := func(signer Signer, verifier Verifier, claims interface{}) {
		t.Helper()

		token, err := Build(signer, claims)
		if err != nil {
			t.Error(err)
		}

		errVerify := verifier.Verify(token.Payload(), token.Signature())
		if errVerify != nil {
			t.Error(errVerify)
		}
	}

	f(
		mustSigner(NewSignerEdDSA(ed25519PrivateKey)),
		mustVerifier(NewVerifierEdDSA(ed25519PublicKey)),
		"i-am-already-a-claims",
	)

	f(
		mustSigner(NewSignerHS(HS256, hsKey256)),
		mustVerifier(NewVerifierHS(HS256, hsKey256)),
		"i-am-already-a-claims",
	)
	f(
		mustSigner(NewSignerHS(HS384, hsKey384)),
		mustVerifier(NewVerifierHS(HS384, hsKey384)),
		"i-am-already-a-claims",
	)
	f(
		mustSigner(NewSignerHS(HS512, hsKey512)),
		mustVerifier(NewVerifierHS(HS512, hsKey512)),
		"i-am-already-a-claims",
	)

	f(
		mustSigner(NewSignerRS(RS256, rsaPrivateKey256)),
		mustVerifier(NewVerifierRS(RS256, rsaPublicKey256)),
		"i-am-already-a-claims",
	)
	f(
		mustSigner(NewSignerRS(RS384, rsaPrivateKey384)),
		mustVerifier(NewVerifierRS(RS384, rsaPublicKey384)),
		"i-am-already-a-claims",
	)
	f(
		mustSigner(NewSignerRS(RS512, rsaPrivateKey512)),
		mustVerifier(NewVerifierRS(RS512, rsaPublicKey512)),
		"i-am-already-a-claims",
	)

	f(
		mustSigner(NewSignerES(ES256, ecdsaPrivateKey256)),
		mustVerifier(NewVerifierES(ES256, ecdsaPublicKey256)),
		"i-am-already-a-claims",
	)
	f(
		mustSigner(NewSignerES(ES384, ecdsaPrivateKey384)),
		mustVerifier(NewVerifierES(ES384, ecdsaPublicKey384)),
		"i-am-already-a-claims",
	)
	f(
		mustSigner(NewSignerES(ES512, ecdsaPrivateKey521)),
		mustVerifier(NewVerifierES(ES512, ecdsaPublicKey521)),
		"i-am-already-a-claims",
	)

	f(
		mustSigner(NewSignerPS(PS256, rsaPrivateKey256)),
		mustVerifier(NewVerifierPS(PS256, rsaPublicKey256)),
		"i-am-already-a-claims",
	)
	f(
		mustSigner(NewSignerPS(PS384, rsaPrivateKey384)),
		mustVerifier(NewVerifierPS(PS384, rsaPublicKey384)),
		"i-am-already-a-claims",
	)
	f(
		mustSigner(NewSignerPS(PS512, rsaPrivateKey512)),
		mustVerifier(NewVerifierPS(PS512, rsaPublicKey512)),
		"i-am-already-a-claims",
	)
}

func TestBuildHeader(t *testing.T) {
	f := func(signer Signer, want string, opts ...BuilderOption) {
		t.Helper()

		token, err := NewBuilder(signer, opts...).Build(&StandardClaims{})
		if err != nil {
			t.Error(err)
		}

		want = strToBase64(want)
		raw := string(token.RawHeader())
		if raw != want {
			t.Errorf("\nwant %v,\n got %v", want, raw)
		}
	}

	key := []byte("key")
	f(
		mustSigner(NewSignerHS(HS256, key)),
		`{"alg":"HS256","typ":"JWT"}`,
	)
	f(
		mustSigner(NewSignerHS(HS384, key)),
		`{"alg":"HS384","typ":"JWT"}`,
	)
	f(
		mustSigner(NewSignerHS(HS512, key)),
		`{"alg":"HS512","typ":"JWT"}`,
	)

	f(
		mustSigner(NewSignerRS(RS256, rsaPrivateKey256)),
		`{"alg":"RS256","typ":"JWT"}`,
	)
	f(
		mustSigner(NewSignerRS(RS384, rsaPrivateKey384)),
		`{"alg":"RS384","typ":"JWT"}`,
	)
	f(
		mustSigner(NewSignerRS(RS512, rsaPrivateKey512)),
		`{"alg":"RS512","typ":"JWT"}`,
	)

	f(
		mustSigner(NewSignerHS(HS256, key)),
		`{"alg":"HS256","typ":"JWT","kid":"test"}`,
		WithKeyID("test"),
	)
	f(
		mustSigner(NewSignerHS(HS512, key)),
		`{"alg":"HS512","typ":"JWT","cty":"jwk+json"}`,
		WithContentType("jwk+json"),
	)

	f(
		mustSigner(NewSignerRS(RS256, rsaPrivateKey256)),
		`{"alg":"RS256","typ":"JWT","kid":"test"}`,
		WithKeyID("test"),
	)
	f(
		mustSigner(NewSignerRS(RS512, rsaPrivateKey512)),
		`{"alg":"RS512","typ":"JWT","cty":"jwk+json"}`,
		WithContentType("jwk+json"),
	)
}

func TestBuildClaims(t *testing.T) {
	key := []byte("somekey")
	s := mustSigner(NewSignerHS(HS256, key))
	v := mustVerifier(NewVerifierHS(HS256, key))

	f := func(claims interface{}, want string) {
		token, err := NewBuilder(s).Build(claims)
		if err != nil {
			t.Fatal(err)
		}

		errVerify := v.Verify(token.Payload(), token.Signature())
		if errVerify != nil {
			t.Fatal(errVerify)
		}

		if got := token.String(); got != want {
			t.Errorf("want %v, got %v", want, got)
		}
	}

	f(
		"i-am-already-a-claims",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aS1hbS1hbHJlYWR5LWEtY2xhaW1z.AXh-18zdRymq7HlsG7bweN5WSaM-KKaP2N5HNecuWys",
	)
	f(
		[]byte("i-am-also-a-claims"),
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aS1hbS1hbHNvLWEtY2xhaW1z._hc2MMMxkHFx3FqkEwEuhY78m7Jx-wKezbBSwrpnTug",
	)

	type myType string
	f(
		myType("custom-type-a-claims"),
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ImN1c3RvbS10eXBlLWEtY2xhaW1zIg.f8zbPF75mPfza6cHH6C_wm2tJh3_HyaPmqC12ZGuX0o",
	)

	myClaims := struct {
		Foo string
		Bar int64
	}{
		Foo: "foo",
		Bar: 42,
	}
	f(
		myClaims,
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJGb28iOiJmb28iLCJCYXIiOjQyfQ.Ac3O8UnAtnbjY681ZYE-XdgXN6tQgdcHuhk4mDfohdY",
	)
}

func TestBuildMalformed(t *testing.T) {
	f := func(signer Signer, claims interface{}) {
		t.Helper()

		_, err := Build(signer, claims)
		if err == nil {
			t.Error("want err, got nil")
		}
	}

	f(
		badSigner{},
		nil,
	)
	f(
		mustSigner(NewSignerHS(HS256, []byte("test-key"))),
		badSigner.Algorithm,
	)
}

type badSigner struct{}

func (badSigner) SignSize() int {
	return 0
}

func (badSigner) Algorithm() Algorithm {
	return "bad"
}

func (badSigner) Sign(payload []byte) ([]byte, error) {
	return nil, errors.New("error by design")
}

func (badSigner) Verify(payload, signature []byte) error {
	return errors.New("error by design")
}
