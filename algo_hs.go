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
func NewHS256(key []byte) (Signer, error) {
	if len(key) == 0 {
		return nil, ErrInvalidKey
	}
	return &hsAlg{
		alg:  HS256,
		hash: crypto.SHA256,
		key:  key,
	}, nil
}

// NewHS384 returns new HMAC Signer using SHA384 hash.
func NewHS384(key []byte) (Signer, error) {
	if len(key) == 0 {
		return nil, ErrInvalidKey
	}
	return &hsAlg{
		alg:  HS384,
		hash: crypto.SHA384,
		key:  key,
	}, nil
}

// NewHS512 returns new HMAC Signer using SHA512 hash.
func NewHS512(key []byte) (Signer, error) {
	if len(key) == 0 {
		return nil, ErrInvalidKey
	}
	return &hsAlg{
		alg:  HS512,
		hash: crypto.SHA512,
		key:  key,
	}, nil
}

func (h hsAlg) Algorithm() Algorithm {
	return h.alg
}

func (h hsAlg) Sign(payload []byte) ([]byte, error) {
	return h.sign(payload)
}

func (h hsAlg) Verify(payload, signature []byte) error {
	signed, err := h.sign(payload)
	if err != nil {
		return err
	}
	if !hmac.Equal(signature, signed) {
		return ErrInvalidSignature
	}
	return nil
}

func (h hsAlg) sign(payload []byte) ([]byte, error) {
	hasher := hmac.New(h.hash.New, h.key)

	_, err := hasher.Write(payload)
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}
