package jwt

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHS256_WithValidSignature(t *testing.T) {
	hs256Signer := NewHS256([]byte("key"))
	tokenBuilder := NewTokenBuilder(hs256Signer)
	claims := &StandardClaims{}

	token, err := tokenBuilder.Build(claims)
	assert.NoError(t, err)

	assert.Nil(t, hs256Signer.Verify(token.Signature(), token.Payload()))
}

func TestHS256_WithInvalidSignature(t *testing.T) {
	hs256Signer1 := NewHS256([]byte("key1"))
	hs256Signer2 := NewHS256([]byte("key2"))
	tokenBuilder := NewTokenBuilder(hs256Signer1)
	claims := &StandardClaims{}

	token, _ := tokenBuilder.Build(claims)

	assert.Error(t, hs256Signer2.Verify(token.Signature(), token.Payload()))
}

func TestHS384_WithValidSignature(t *testing.T) {
	hs384Signer := NewHS384([]byte("key"))
	tokenBuilder := NewTokenBuilder(hs384Signer)
	claims := &StandardClaims{}

	token, err := tokenBuilder.Build(claims)
	assert.NoError(t, err)

	assert.Nil(t, hs384Signer.Verify(token.Signature(), token.Payload()))
}

func TestHS384_WithInvalidSignature(t *testing.T) {
	hs384Signer1 := NewHS384([]byte("key1"))
	hs384Signer2 := NewHS384([]byte("key2"))
	tokenBuilder := NewTokenBuilder(hs384Signer1)
	claims := &StandardClaims{}

	token, _ := tokenBuilder.Build(claims)

	assert.Error(t, hs384Signer2.Verify(token.Signature(), token.Payload()))
}

func TestHS512_WithValidSignature(t *testing.T) {
	hs512Signer := NewHS512([]byte("key"))
	tokenBuilder := NewTokenBuilder(hs512Signer)
	claims := &StandardClaims{}

	token, err := tokenBuilder.Build(claims)
	assert.NoError(t, err)

	assert.Nil(t, hs512Signer.Verify(token.Signature(), token.Payload()))
}

func TestHS512_WithInvalidSignature(t *testing.T) {
	hs512Signer1 := NewHS512([]byte("key1"))
	hs512Signer2 := NewHS512([]byte("key2"))
	tokenBuilder := NewTokenBuilder(hs512Signer1)
	claims := &StandardClaims{}

	token, _ := tokenBuilder.Build(claims)

	assert.Error(t, hs512Signer2.Verify(token.Signature(), token.Payload()))
}