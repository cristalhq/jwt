package jwt

import (
	"crypto"
	"crypto/hmac"
)

var _ Signer = (*hsAlg)(nil)

type hsAlg struct {
	alg  Algorithm
	hash crypto.Hash
}

// NewHS256 returns new HMAC Signer using SHA256 hash.
func NewHS256() Signer {
	return &hsAlg{HS256, crypto.SHA256}
}

// NewHS384 returns new HMAC Signer using SHA384 hash.
func NewHS384() Signer {
	return &hsAlg{HS384, crypto.SHA384}
}

// NewHS512 returns new HMAC Signer using SHA512 hash.
func NewHS512() Signer {
	return &hsAlg{HS512, crypto.SHA512}
}

func (h *hsAlg) Algorithm() Algorithm {
	return h.alg
}

func (h *hsAlg) Sign(payload []byte, key interface{}) ([]byte, error) {
	keyBytes, ok := key.([]byte)
	if !ok {
		return nil, ErrInvalidKeyType
	}
	if !h.hash.Available() {
		return nil, ErrHashUnavailable
	}

	hasher := hmac.New(h.hash.New, keyBytes)

	_, err := hasher.Write(payload)
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func (h *hsAlg) Verify(expected, payload []byte, key interface{}) error {
	keyBytes, ok := key.([]byte)
	if !ok {
		return ErrInvalidKeyType
	}
	if !h.hash.Available() {
		return ErrHashUnavailable
	}

	signed, err := h.Sign(payload, keyBytes)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, signed) {
		return ErrSignatureInvalid
	}
	return nil
}
