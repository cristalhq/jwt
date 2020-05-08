package jwt

import (
	"crypto"
	"crypto/hmac"
	"hash"
)

// NewSignerHS returns a new HMAC-based signer.
func NewSignerHS(alg Algorithm, key []byte) (Signer, error) {
	if len(key) == 0 {
		return nil, ErrInvalidKey
	}
	hash, err := getHashHMAC(alg)
	if err != nil {
		return nil, err
	}
	return &hsAlg{
		alg:      alg,
		hash:     hash,
		key:      key,
		hashPool: newHashPool(),
	}, nil
}

// NewVerifierHS returns a new HMAC-based verifier.
func NewVerifierHS(alg Algorithm, key []byte) (Verifier, error) {
	if len(key) == 0 {
		return nil, ErrInvalidKey
	}
	hash, err := getHashHMAC(alg)
	if err != nil {
		return nil, err
	}
	return &hsAlg{
		alg:      alg,
		hash:     hash,
		key:      key,
		hashPool: newHashPool(),
	}, nil
}

func getHashHMAC(alg Algorithm) (crypto.Hash, error) {
	switch alg {
	case HS256:
		return crypto.SHA256, nil
	case HS384:
		return crypto.SHA384, nil
	case HS512:
		return crypto.SHA512, nil
	default:
		return 0, ErrUnsupportedAlg
	}
}

type hsAlg struct {
	alg      Algorithm
	hash     crypto.Hash
	key      []byte
	hashPool *hashPool
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
	hasher := h.hashPool.getHash(func() hash.Hash {
		return hmac.New(h.hash.New, h.key)
	})
	defer h.hashPool.putHash(hasher)

	_, err := hasher.Write(payload)
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}
