package jwt

import (
	"crypto"
	"crypto/hmac"
)

var _ Signer = (*hsAlg)(nil)

type hsAlg struct {
	alg  Algorithm
	key  []byte
	hash crypto.Hash
}

// NewHS256 returns new HMAC Signer using SHA256 hash.
func NewHS256(key []byte) Signer {
	return &hsAlg{HS256, key, crypto.SHA256}
}

// NewHS384 returns new HMAC Signer using SHA384 hash.
func NewHS384(key []byte) Signer {
	return &hsAlg{HS384, key, crypto.SHA384}
}

// NewHS512 returns new HMAC Signer using SHA512 hash.
func NewHS512(key []byte) Signer {
	return &hsAlg{HS512, key, crypto.SHA512}
}

func (h *hsAlg) Algorithm() Algorithm {
	return h.alg
}

func (h *hsAlg) Sign(payload []byte) ([]byte, error) {
	if !h.hash.Available() {
		return nil, ErrHashUnavailable
	}

	hasher := hmac.New(h.hash.New, h.key)

	_, err := hasher.Write(payload)
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func (h *hsAlg) Verify(expected, payload []byte) error {
	signed, err := h.Sign(payload)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, signed) {
		return ErrSignatureInvalid
	}
	return nil
}
