package jwt

import (
	"crypto/ed25519"
)

var _ Signer = (*edDSAAlg)(nil)

type edDSAAlg struct {
	alg        Algorithm
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

// NewEdDSA returns new signer using EdDSA algorithm.
//
// Both public and private keys must not be nil.
//
func NewEdDSA(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (Signer, error) {
	if len(publicKey) == 0 || len(privateKey) == 0 {
		return nil, ErrInvalidKey
	}
	return &edDSAAlg{
		alg:        EdDSA,
		publicKey:  publicKey,
		privateKey: privateKey,
	}, nil
}

func (h edDSAAlg) Algorithm() Algorithm {
	return h.alg
}

func (h edDSAAlg) Sign(payload []byte) ([]byte, error) {
	return ed25519.Sign(h.privateKey, payload), nil
}

func (h edDSAAlg) Verify(payload, signature []byte) error {
	if !ed25519.Verify(h.publicKey, payload, signature) {
		return ErrInvalidSignature
	}
	return nil
}
