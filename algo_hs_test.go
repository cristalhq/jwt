package jwt

import (
	"testing"
)

func TestHS256_WithValidSignature(t *testing.T) {
	hs256Signer := NewHS256([]byte("key"))
	tokenBuilder := NewTokenBuilder(hs256Signer)
	claims := &StandardClaims{}

	token, _ := tokenBuilder.Build(claims)

	result := hs256Signer.Verify(token.Signature(), token.Payload())
	if result != nil {
		t.Errorf("want `%v`, got: `%v`", nil, result)
	}
}

func TestHS256_WithInvalidSignature(t *testing.T) {
	hs256Signer1 := NewHS256([]byte("key1"))
	hs256Signer2 := NewHS256([]byte("key2"))
	tokenBuilder := NewTokenBuilder(hs256Signer1)
	claims := &StandardClaims{}

	token, _ := tokenBuilder.Build(claims)

	result := hs256Signer2.Verify(token.Signature(), token.Payload())
	if result == nil {
		t.Errorf("want `%v`, got: `%v`", ErrInvalidSignature, result)
	}
}

func TestHS384_WithValidSignature(t *testing.T) {
	hs384Signer := NewHS384([]byte("key"))
	tokenBuilder := NewTokenBuilder(hs384Signer)
	claims := &StandardClaims{}

	token, _ := tokenBuilder.Build(claims)

	result := hs384Signer.Verify(token.Signature(), token.Payload())
	if result != nil {
		t.Errorf("want `%v`, got: `%v`", nil, result)
	}
}

func TestHS384_WithInvalidSignature(t *testing.T) {
	hs384Signer1 := NewHS384([]byte("key1"))
	hs384Signer2 := NewHS384([]byte("key2"))
	tokenBuilder := NewTokenBuilder(hs384Signer1)
	claims := &StandardClaims{}

	token, _ := tokenBuilder.Build(claims)

	result := hs384Signer2.Verify(token.Signature(), token.Payload())
	if result == nil {
		t.Errorf("want `%v`, got: `%v`", ErrInvalidSignature, result)
	}
}

func TestHS512_WithValidSignature(t *testing.T) {
	hs512Signer := NewHS512([]byte("key"))
	tokenBuilder := NewTokenBuilder(hs512Signer)
	claims := &StandardClaims{}

	token, _ := tokenBuilder.Build(claims)

	result := hs512Signer.Verify(token.Signature(), token.Payload())
	if result != nil {
		t.Errorf("want `%v`, got: `%v`", nil, result)
	}
}

func TestHS512_WithInvalidSignature(t *testing.T) {
	hs512Signer1 := NewHS512([]byte("key1"))
	hs512Signer2 := NewHS512([]byte("key2"))
	tokenBuilder := NewTokenBuilder(hs512Signer1)
	claims := &StandardClaims{}

	token, _ := tokenBuilder.Build(claims)

	result := hs512Signer2.Verify(token.Signature(), token.Payload())
	if result == nil {
		t.Errorf("want `%v`, got: `%v`", ErrInvalidSignature, result)
	}
}
