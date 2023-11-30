package jwt

import (
	"errors"
	"sync"
	"testing"
)

func TestBuild(t *testing.T) {
	testCases := []struct {
		signer   Signer
		verifier Verifier
		claims   any
	}{
		{
			must(NewSignerEdDSA(ed25519PrivateKey)),
			must(NewVerifierEdDSA(ed25519PublicKey)),
			"i-am-already-a-claims",
		},

		{
			must(NewSignerHS(HS256, hsKey256)),
			must(NewVerifierHS(HS256, hsKey256)),
			"i-am-already-a-claims",
		},
		{
			must(NewSignerHS(HS384, hsKey384)),
			must(NewVerifierHS(HS384, hsKey384)),
			"i-am-already-a-claims",
		},
		{
			must(NewSignerHS(HS512, hsKey512)),
			must(NewVerifierHS(HS512, hsKey512)),
			"i-am-already-a-claims",
		},

		{
			must(NewSignerRS(RS256, rsaPrivateKey256)),
			must(NewVerifierRS(RS256, rsaPublicKey256)),
			"i-am-already-a-claims",
		},
		{
			must(NewSignerRS(RS384, rsaPrivateKey384)),
			must(NewVerifierRS(RS384, rsaPublicKey384)),
			"i-am-already-a-claims",
		},
		{
			must(NewSignerRS(RS512, rsaPrivateKey512)),
			must(NewVerifierRS(RS512, rsaPublicKey512)),
			"i-am-already-a-claims",
		},

		{
			must(NewSignerES(ES256, ecdsaPrivateKey256)),
			must(NewVerifierES(ES256, ecdsaPublicKey256)),
			"i-am-already-a-claims",
		},
		{
			must(NewSignerES(ES384, ecdsaPrivateKey384)),
			must(NewVerifierES(ES384, ecdsaPublicKey384)),
			"i-am-already-a-claims",
		},
		{
			must(NewSignerES(ES512, ecdsaPrivateKey521)),
			must(NewVerifierES(ES512, ecdsaPublicKey521)),
			"i-am-already-a-claims",
		},

		{
			must(NewSignerPS(PS256, rsaPrivateKey256)),
			must(NewVerifierPS(PS256, rsaPublicKey256)),
			"i-am-already-a-claims",
		},
		{
			must(NewSignerPS(PS384, rsaPrivateKey384)),
			must(NewVerifierPS(PS384, rsaPublicKey384)),
			"i-am-already-a-claims",
		},
		{
			must(NewSignerPS(PS512, rsapsPrivateKey512)),
			must(NewVerifierPS(PS512, rsapsPublicKey512)),
			"i-am-already-a-claims",
		},
	}

	for _, tc := range testCases {
		token, err := NewBuilder(tc.signer).Build(tc.claims)
		mustOk(t, err)

		err = tc.verifier.Verify(token)
		mustOk(t, err)
	}
}

func TestBuildHeader(t *testing.T) {
	key := []byte("key")

	testCases := []struct {
		signer Signer
		opts   []BuilderOption
		want   string
	}{
		{
			must(NewSignerHS(HS256, key)),
			nil,
			`{"alg":"HS256","typ":"JWT"}`,
		},
		{
			must(NewSignerHS(HS384, key)),
			nil,
			`{"alg":"HS384","typ":"JWT"}`,
		},
		{
			must(NewSignerHS(HS512, key)),
			nil,
			`{"alg":"HS512","typ":"JWT"}`,
		},

		{
			must(NewSignerRS(RS256, rsaPrivateKey256)),
			nil,
			`{"alg":"RS256","typ":"JWT"}`,
		},
		{
			must(NewSignerRS(RS384, rsaPrivateKey384)),
			nil,
			`{"alg":"RS384","typ":"JWT"}`,
		},
		{
			must(NewSignerRS(RS512, rsaPrivateKey512)),
			nil,
			`{"alg":"RS512","typ":"JWT"}`,
		},

		{
			must(NewSignerHS(HS256, key)),
			[]BuilderOption{WithKeyID("test")},
			`{"alg":"HS256","typ":"JWT","kid":"test"}`,
		},
		{
			must(NewSignerHS(HS512, key)),
			[]BuilderOption{WithContentType("jwk+json")},
			`{"alg":"HS512","typ":"JWT","cty":"jwk+json"}`,
		},

		{
			must(NewSignerRS(RS256, rsaPrivateKey256)),
			[]BuilderOption{WithKeyID("test")},
			`{"alg":"RS256","typ":"JWT","kid":"test"}`,
		},
		{
			must(NewSignerRS(RS512, rsaPrivateKey512)),
			[]BuilderOption{WithContentType("jwk+json")},
			`{"alg":"RS512","typ":"JWT","cty":"jwk+json"}`,
		},
	}

	for _, tc := range testCases {
		token, err := NewBuilder(tc.signer, tc.opts...).Build(&RegisteredClaims{})
		mustOk(t, err)

		have := string(token.HeaderPart())
		want := bytesToBase64([]byte(tc.want))
		mustEqual(t, have, want)
	}
}

func TestBuildClaims(t *testing.T) {
	key := []byte("somekey")
	s := must(NewSignerHS(HS256, key))
	v := must(NewVerifierHS(HS256, key))

	type myType string
	myClaims := struct {
		Foo string
		Bar int64
	}{
		Foo: "foo",
		Bar: 42,
	}

	testCases := []struct {
		claims any
		want   string
	}{
		{
			"i-am-already-a-claims",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aS1hbS1hbHJlYWR5LWEtY2xhaW1z.AXh-18zdRymq7HlsG7bweN5WSaM-KKaP2N5HNecuWys",
		},
		{
			[]byte("i-am-also-a-claims"),
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aS1hbS1hbHNvLWEtY2xhaW1z._hc2MMMxkHFx3FqkEwEuhY78m7Jx-wKezbBSwrpnTug",
		},

		{
			myType("custom-type-a-claims"),
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ImN1c3RvbS10eXBlLWEtY2xhaW1zIg.f8zbPF75mPfza6cHH6C_wm2tJh3_HyaPmqC12ZGuX0o",
		},

		{
			myClaims,
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJGb28iOiJmb28iLCJCYXIiOjQyfQ.Ac3O8UnAtnbjY681ZYE-XdgXN6tQgdcHuhk4mDfohdY",
		},
	}

	for _, tc := range testCases {
		token, err := NewBuilder(s).Build(tc.claims)
		mustOk(t, err)

		err = v.Verify(token)
		mustOk(t, err)
		mustEqual(t, token.String(), tc.want)
	}
}

func TestBuildMalformed(t *testing.T) {
	testCases := []struct {
		signer Signer
		claims any
	}{
		{badSigner{}, nil},
		{
			must(NewSignerHS(HS256, []byte("test-key"))),
			badSigner.Algorithm,
		},
	}

	for _, tc := range testCases {
		_, err := NewBuilder(tc.signer).Build(tc.claims)
		mustFail(t, err)
	}
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
