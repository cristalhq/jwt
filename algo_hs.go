package jwt

import (
	"crypto"
	"crypto/hmac"
)

var _ Signer = (*hsAlg)(nil)

type hsAlg struct {
	alg  Algorithm
	hash crypto.Hash
	key  []byte
}

// NewHS256 returns new HMAC Signer using SHA256 hash.
func NewHS256(key []byte) Signer {
	return &hsAlg{
		alg:  HS256,
		hash: crypto.SHA256,
		key:  key,
	}
}

// NewHS384 returns new HMAC Signer using SHA384 hash.
func NewHS384(key []byte) Signer {
	return &hsAlg{
		alg:  HS384,
		hash: crypto.SHA384,
		key:  key,
	}
}

// NewHS512 returns new HMAC Signer using SHA512 hash.
func NewHS512(key []byte) Signer {
	return &hsAlg{
		alg:  HS512,
		hash: crypto.SHA512,
		key:  key,
	}
}

func (h hsAlg) Algorithm() Algorithm {
	return h.alg
}

func (h hsAlg) Sign(payload []byte) ([]byte, error) {
	hasher := hmac.New(h.hash.New, h.key)

	_, err := hasher.Write(payload)
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func (h hsAlg) Verify(expected, payload []byte) error {
	signed, err := h.Sign(payload)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, signed) {
		return ErrInvalidSignature
	}
	return nil
}
