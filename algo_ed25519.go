package jwt

import (
	"crypto/ed25519"
)

var _ Signer = (*ed25519Alg)(nil)

type ed25519Alg struct {
	alg        Algorithm
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

// NewEd25519 returns new signer using EdDSA algorithm.
//
// Both public and private keys must not be nil.
//
func NewEd25519(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) Signer {
	return &ed25519Alg{
		alg:        Ed25519,
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

func (h *ed25519Alg) Algorithm() Algorithm {
	return h.alg
}

func (h *ed25519Alg) Sign(payload []byte) ([]byte, error) {
	return ed25519.Sign(h.privateKey, payload), nil
}

func (h *ed25519Alg) Verify(expected, payload []byte) error {
	if !ed25519.Verify(h.publicKey, payload, expected) {
		return ErrInvalidSignature
	}
	return nil
}
