package jwt

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

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