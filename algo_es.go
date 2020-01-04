package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
)

var _ Signer = (*esAlg)(nil)

type esAlg struct {
	alg        Algorithm
	hash       crypto.Hash
	publickey  *ecdsa.PublicKey
	privateKey *ecdsa.PrivateKey
	keySize    int
	curveBits  int
}

// NewES256 returns new HMAC Signer using RSA and SHA256 hash.
//
// Both public and private keys must not be nil.
//
func NewES256(publicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey) (Signer, error) {
	if publicKey == nil || privateKey == nil {
		return nil, ErrInvalidKey
	}
	if privateKey.Curve.Params().BitSize != 256 {
		return nil, ErrInvalidKey
	}
	return &esAlg{
		alg:        PS256,
		hash:       crypto.SHA256,
		publickey:  publicKey,
		privateKey: privateKey,
		keySize:    32,
		curveBits:  256,
	}, nil
}

// NewES384 returns new HMAC Signer using RSA and SHA384 hash.
//
// Both public and private keys must not be nil.
//
func NewES384(publicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey) (Signer, error) {
	if publicKey == nil || privateKey == nil {
		return nil, ErrInvalidKey
	}
	if privateKey.Curve.Params().BitSize != 384 {
		return nil, ErrInvalidKey
	}
	return &esAlg{
		alg:        PS384,
		hash:       crypto.SHA384,
		publickey:  publicKey,
		privateKey: privateKey,
		keySize:    48,
		curveBits:  384,
	}, nil
}

// NewES512 returns new HMAC Signer using RSA and SHA512 hash.
//
// Both public and private keys must not be nil.
//
func NewES512(publicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey) (Signer, error) {
	if publicKey == nil || privateKey == nil {
		return nil, ErrInvalidKey
	}
	if privateKey.Curve.Params().BitSize != 521 {
		return nil, ErrInvalidKey
	}
	return &esAlg{
		alg:        PS512,
		hash:       crypto.SHA512,
		publickey:  publicKey,
		privateKey: privateKey,
		keySize:    66,
		curveBits:  521,
	}, nil
}

func (h esAlg) Algorithm() Algorithm {
	return h.alg
}

func (h esAlg) Sign(payload []byte) ([]byte, error) {
	signed, err := h.sign(payload)
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, h.privateKey, signed)
	if err != nil {
		return nil, err
	}
	curveBits := h.privateKey.Curve.Params().BitSize

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	// Serialize r and s into big-endian byte slices and round up size to keyBytes.
	rb := r.Bytes()
	rbPadded := make([]byte, keyBytes)
	copy(rbPadded[keyBytes-len(rb):], rb)

	sb := s.Bytes()
	sbPadded := make([]byte, keyBytes)
	copy(sbPadded[keyBytes-len(sb):], sb)

	out := append(rbPadded, sbPadded...)

	return out, nil
}

func (h esAlg) Verify(payload, signature []byte) error {
	if len(signature) != 2*h.keySize {
		return ErrInvalidSignature
	}

	signed, err := h.sign(payload)
	if err != nil {
		return err
	}

	r := big.NewInt(0).SetBytes(signature[:h.keySize])
	s := big.NewInt(0).SetBytes(signature[h.keySize:])

	if !ecdsa.Verify(h.publickey, signed, r, s) {
		return ErrInvalidSignature
	}
	return nil
}

func (h esAlg) sign(payload []byte) ([]byte, error) {
	hasher := h.hash.New()

	_, err := hasher.Write(payload)
	if err != nil {
		return nil, err
	}
	signed := hasher.Sum(nil)
	return signed, nil
}
