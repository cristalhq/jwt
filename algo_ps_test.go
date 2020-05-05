package jwt

import (
	"testing"
)

func TestPS256_WithValidSignature(t *testing.T) {
	f := func(signer Signer, claims interface{}) {
		t.Helper()

		tokenBuilder := NewBuilder(signer)
		token, _ := tokenBuilder.Build(claims)

		err := signer.Verify(token.Payload(), token.Signature())
		if err != nil {
			t.Errorf("want no err, got: %#v", err)
		}
	}

	f(
		mustSigner(NewPS256(rsaPublicKey1, rsaPrivateKey1)),
		&StandardClaims{},
	)
	f(
		mustSigner(NewPS384(rsaPublicKey1, rsaPrivateKey1)),
		&StandardClaims{},
	)
	f(
		mustSigner(NewPS512(rsaPublicKey1, rsaPrivateKey1)),
		&StandardClaims{},
	)

	f(
		mustSigner(NewPS256(rsaPublicKey1, rsaPrivateKey1)),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		mustSigner(NewPS384(rsaPublicKey1, rsaPrivateKey1)),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		mustSigner(NewPS512(rsaPublicKey1, rsaPrivateKey1)),
		&customClaims{
			TestField: "baz",
		},
	)
}

func TestPS384_WithInvalidSignature(t *testing.T) {
	f := func(signer, verifier Signer, claims interface{}) {
		t.Helper()

		tokenBuilder := NewBuilder(signer)
		token, _ := tokenBuilder.Build(claims)

		err := verifier.Verify(token.Payload(), token.Signature())
		if err == nil {
			t.Errorf("want %v, got nil", ErrInvalidSignature)
		}
	}
	f(
		mustSigner(NewPS256(rsaPublicKey1, rsaPrivateKey1)),
		mustSigner(NewPS256(rsaPublicKey2, rsaPrivateKey2)),
		&StandardClaims{},
	)
	f(
		mustSigner(NewPS384(rsaPublicKey1, rsaPrivateKey1)),
		mustSigner(NewPS384(rsaPublicKey2, rsaPrivateKey2)),
		&StandardClaims{},
	)
	f(
		mustSigner(NewPS512(rsaPublicKey1, rsaPrivateKey1)),
		mustSigner(NewPS512(rsaPublicKey2, rsaPrivateKey2)),
		&StandardClaims{},
	)

	f(
		mustSigner(NewPS256(rsaPublicKey1, rsaPrivateKey1)),
		mustSigner(NewPS256(rsaPublicKey2, rsaPrivateKey2)),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		mustSigner(NewPS384(rsaPublicKey1, rsaPrivateKey1)),
		mustSigner(NewPS384(rsaPublicKey2, rsaPrivateKey2)),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		mustSigner(NewPS512(rsaPublicKey1, rsaPrivateKey1)),
		mustSigner(NewPS512(rsaPublicKey2, rsaPrivateKey2)),
		&customClaims{
			TestField: "baz",
		},
	)
}
