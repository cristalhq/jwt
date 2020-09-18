package jwt

import (
	"testing"
)

func TestPS256_WithValidSignature(t *testing.T) {
	f := func(signer Signer, verifier Verifier, claims interface{}) {
		t.Helper()

		tokenBuilder := NewBuilder(signer)
		token, _ := tokenBuilder.Build(claims)

		err := verifier.Verify(token.Payload(), token.Signature())
		if err != nil {
			t.Errorf("want no err, got: %#v", err)
		}
	}

	f(
		mustSigner(NewSignerPS(PS256, rsaPrivateKey1)),
		mustVerifier(NewVerifierPS(PS256, rsaPublicKey1)),
		&RegisteredClaims{},
	)
	f(
		mustSigner(NewSignerPS(PS384, rsaPrivateKey1)),
		mustVerifier(NewVerifierPS(PS384, rsaPublicKey1)),
		&RegisteredClaims{},
	)
	f(
		mustSigner(NewSignerPS(PS512, rsaPrivateKey1)),
		mustVerifier(NewVerifierPS(PS512, rsaPublicKey1)),
		&RegisteredClaims{},
	)

	f(
		mustSigner(NewSignerPS(PS256, rsaPrivateKey1)),
		mustVerifier(NewVerifierPS(PS256, rsaPublicKey1)),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		mustSigner(NewSignerPS(PS384, rsaPrivateKey1)),
		mustVerifier(NewVerifierPS(PS384, rsaPublicKey1)),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		mustSigner(NewSignerPS(PS512, rsaPrivateKey1)),
		mustVerifier(NewVerifierPS(PS512, rsaPublicKey1)),
		&customClaims{
			TestField: "baz",
		},
	)
}

func TestPS384_WithInvalidSignature(t *testing.T) {
	f := func(signer Signer, verifier Verifier, claims interface{}) {
		t.Helper()

		tokenBuilder := NewBuilder(signer)
		token, _ := tokenBuilder.Build(claims)

		err := verifier.Verify(token.Payload(), token.Signature())
		if err == nil {
			t.Errorf("want %v, got nil", ErrInvalidSignature)
		}
	}
	f(
		mustSigner(NewSignerPS(PS256, rsaPrivateKey1)),
		mustVerifier(NewVerifierPS(PS256, rsaPublicKey2)),
		&RegisteredClaims{},
	)
	f(
		mustSigner(NewSignerPS(PS384, rsaPrivateKey1)),
		mustVerifier(NewVerifierPS(PS384, rsaPublicKey2)),
		&RegisteredClaims{},
	)
	f(
		mustSigner(NewSignerPS(PS512, rsaPrivateKey1)),
		mustVerifier(NewVerifierPS(PS512, rsaPublicKey2)),
		&RegisteredClaims{},
	)

	f(
		mustSigner(NewSignerPS(PS256, rsaPrivateKey1)),
		mustVerifier(NewVerifierPS(PS256, rsaPublicKey2)),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		mustSigner(NewSignerPS(PS384, rsaPrivateKey1)),
		mustVerifier(NewVerifierPS(PS384, rsaPublicKey2)),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		mustSigner(NewSignerPS(PS512, rsaPrivateKey1)),
		mustVerifier(NewVerifierPS(PS512, rsaPublicKey2)),
		&customClaims{
			TestField: "baz",
		},
	)
}
