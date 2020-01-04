package jwt

import (
	"testing"
)

func TestPS256_WithValidSignature(t *testing.T) {
	f := func(signer Signer, claims BinaryMarshaler) {
		t.Helper()

		tokenBuilder := NewTokenBuilder(signer)
		token, _ := tokenBuilder.Build(claims)

		err := signer.Verify(token.Payload(), token.Signature())
		if err != nil {
			t.Errorf("want no err, got: `%v`", err)
		}
	}

	f(
		getSigner(NewPS256(rsaPublicKey1, rsaPrivateKey1)),
		&StandardClaims{},
	)
	f(
		getSigner(NewPS384(rsaPublicKey1, rsaPrivateKey1)),
		&StandardClaims{},
	)
	f(
		getSigner(NewPS512(rsaPublicKey1, rsaPrivateKey1)),
		&StandardClaims{},
	)

	f(
		getSigner(NewPS256(rsaPublicKey1, rsaPrivateKey1)),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		getSigner(NewPS384(rsaPublicKey1, rsaPrivateKey1)),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		getSigner(NewPS512(rsaPublicKey1, rsaPrivateKey1)),
		&customClaims{
			TestField: "baz",
		},
	)
}

func TestPS384_WithInvalidSignature(t *testing.T) {
	f := func(signer, verifier Signer, claims BinaryMarshaler) {
		t.Helper()

		tokenBuilder := NewTokenBuilder(signer)
		token, _ := tokenBuilder.Build(claims)

		err := verifier.Verify(token.Payload(), token.Signature())
		if err == nil {
			t.Errorf("want %v, got nil", ErrInvalidSignature)
		}
	}
	f(
		getSigner(NewPS256(rsaPublicKey1, rsaPrivateKey1)),
		getSigner(NewPS256(rsaPublicKey2, rsaPrivateKey2)),
		&StandardClaims{},
	)
	f(
		getSigner(NewPS384(rsaPublicKey1, rsaPrivateKey1)),
		getSigner(NewPS384(rsaPublicKey2, rsaPrivateKey2)),
		&StandardClaims{},
	)
	f(
		getSigner(NewPS512(rsaPublicKey1, rsaPrivateKey1)),
		getSigner(NewPS512(rsaPublicKey2, rsaPrivateKey2)),
		&StandardClaims{},
	)

	f(
		getSigner(NewPS256(rsaPublicKey1, rsaPrivateKey1)),
		getSigner(NewPS256(rsaPublicKey2, rsaPrivateKey2)),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		getSigner(NewPS384(rsaPublicKey1, rsaPrivateKey1)),
		getSigner(NewPS384(rsaPublicKey2, rsaPrivateKey2)),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		getSigner(NewPS512(rsaPublicKey1, rsaPrivateKey1)),
		getSigner(NewPS512(rsaPublicKey2, rsaPrivateKey2)),
		&customClaims{
			TestField: "baz",
		},
	)
}
