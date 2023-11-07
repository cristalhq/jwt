package jwt

import (
	"errors"
	"sync"
	"testing"
)

func TestBuild(t *testing.T) {
	f := func(signer Signer, verifier Verifier, claims any) {
		t.Helper()

		token, err := NewBuilder(signer).Build(claims)
		mustOk(t, err)

		err = verifier.Verify(token)
		mustOk(t, err)
	}

	f(
		must(NewSignerEdDSA(ed25519PrivateKey)),
		must(NewVerifierEdDSA(ed25519PublicKey)),
		"i-am-already-a-claims",
	)

	f(
		must(NewSignerHS(HS256, hsKey256)),
		must(NewVerifierHS(HS256, hsKey256)),
		"i-am-already-a-claims",
	)
	f(
		must(NewSignerHS(HS384, hsKey384)),
		must(NewVerifierHS(HS384, hsKey384)),
		"i-am-already-a-claims",
	)
	f(
		must(NewSignerHS(HS512, hsKey512)),
		must(NewVerifierHS(HS512, hsKey512)),
		"i-am-already-a-claims",
	)

	f(
		must(NewSignerRS(RS256, rsaPrivateKey256)),
		must(NewVerifierRS(RS256, rsaPublicKey256)),
		"i-am-already-a-claims",
	)
	f(
		must(NewSignerRS(RS384, rsaPrivateKey384)),
		must(NewVerifierRS(RS384, rsaPublicKey384)),
		"i-am-already-a-claims",
	)
	f(
		must(NewSignerRS(RS512, rsaPrivateKey512)),
		must(NewVerifierRS(RS512, rsaPublicKey512)),
		"i-am-already-a-claims",
	)

	f(
		must(NewSignerES(ES256, ecdsaPrivateKey256)),
		must(NewVerifierES(ES256, ecdsaPublicKey256)),
		"i-am-already-a-claims",
	)
	f(
		must(NewSignerES(ES384, ecdsaPrivateKey384)),
		must(NewVerifierES(ES384, ecdsaPublicKey384)),
		"i-am-already-a-claims",
	)
	f(
		must(NewSignerES(ES512, ecdsaPrivateKey521)),
		must(NewVerifierES(ES512, ecdsaPublicKey521)),
		"i-am-already-a-claims",
	)

	f(
		must(NewSignerPS(PS256, rsaPrivateKey256)),
		must(NewVerifierPS(PS256, rsaPublicKey256)),
		"i-am-already-a-claims",
	)
	f(
		must(NewSignerPS(PS384, rsaPrivateKey384)),
		must(NewVerifierPS(PS384, rsaPublicKey384)),
		"i-am-already-a-claims",
	)
	f(
		must(NewSignerPS(PS512, rsapsPrivateKey512)),
		must(NewVerifierPS(PS512, rsapsPublicKey512)),
		"i-am-already-a-claims",
	)
}

func TestBuildHeader(t *testing.T) {
	f := func(signer Signer, want string, opts ...BuilderOption) {
		t.Helper()

		token, err := NewBuilder(signer, opts...).Build(&RegisteredClaims{})
		mustOk(t, err)

		have := string(token.HeaderPart())
		want = bytesToBase64([]byte(want))
		mustEqual(t, have, want)
	}

	key := []byte("key")
	f(
		must(NewSignerHS(HS256, key)),
		`{"alg":"HS256","typ":"JWT"}`,
	)
	f(
		must(NewSignerHS(HS384, key)),
		`{"alg":"HS384","typ":"JWT"}`,
	)
	f(
		must(NewSignerHS(HS512, key)),
		`{"alg":"HS512","typ":"JWT"}`,
	)

	f(
		must(NewSignerRS(RS256, rsaPrivateKey256)),
		`{"alg":"RS256","typ":"JWT"}`,
	)
	f(
		must(NewSignerRS(RS384, rsaPrivateKey384)),
		`{"alg":"RS384","typ":"JWT"}`,
	)
	f(
		must(NewSignerRS(RS512, rsaPrivateKey512)),
		`{"alg":"RS512","typ":"JWT"}`,
	)

	f(
		must(NewSignerHS(HS256, key)),
		`{"alg":"HS256","typ":"JWT","kid":"test"}`,
		WithKeyID("test"),
	)
	f(
		must(NewSignerHS(HS512, key)),
		`{"alg":"HS512","typ":"JWT","cty":"jwk+json"}`,
		WithContentType("jwk+json"),
	)

	f(
		must(NewSignerRS(RS256, rsaPrivateKey256)),
		`{"alg":"RS256","typ":"JWT","kid":"test"}`,
		WithKeyID("test"),
	)
	f(
		must(NewSignerRS(RS512, rsaPrivateKey512)),
		`{"alg":"RS512","typ":"JWT","cty":"jwk+json"}`,
		WithContentType("jwk+json"),
	)
}

func TestBuildClaims(t *testing.T) {
	key := []byte("somekey")
	s := must(NewSignerHS(HS256, key))
	v := must(NewVerifierHS(HS256, key))

	f := func(claims any, want string) {
		token, err := NewBuilder(s).Build(claims)
		mustOk(t, err)

		err = v.Verify(token)
		mustOk(t, err)
		mustEqual(t, token.String(), want)
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
	f := func(signer Signer, claims any) {
		t.Helper()

		_, err := NewBuilder(signer).Build(claims)
		mustFail(t, err)
	}

	f(
		badSigner{},
		nil,
	)
	f(
		must(NewSignerHS(HS256, []byte("test-key"))),
		badSigner.Algorithm,
	)
}

func TestBuilderConcurrently(t *testing.T) {
	signer, err := NewSignerHS(HS256, []byte("test-key"))
	mustOk(t, err)

	builder := NewBuilder(signer)

	errCh := make(chan error, 10)
	claims := "string-claims"

	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()

			token, err := builder.Build(claims)
			errCh <- err

			if token.String() == "" {
				panic("should not be empty")
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		mustOk(t, err)
	}
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
