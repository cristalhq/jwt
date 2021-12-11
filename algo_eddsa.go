package jwt

import (
	"crypto/ed25519"
)

// NewSignerEdDSA returns a new ed25519-based signer.
func NewSignerEdDSA(key ed25519.PrivateKey) (*EdDSAAlg, error) {
	if len(key) == 0 {
		return nil, ErrNilKey
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrInvalidKey
	}
	return &EdDSAAlg{
		publicKey:  nil,
		privateKey: key,
	}, nil
}

// NewVerifierEdDSA returns a new ed25519-based verifier.
func NewVerifierEdDSA(key ed25519.PublicKey) (*EdDSAAlg, error) {
	if len(key) == 0 {
		return nil, ErrNilKey
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, ErrInvalidKey
	}
	return &EdDSAAlg{
		publicKey:  key,
		privateKey: nil,
	}, nil
}

type EdDSAAlg struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func (ed *EdDSAAlg) Algorithm() Algorithm {
	return EdDSA
}

func (ed *EdDSAAlg) SignSize() int {
	return ed25519.SignatureSize
}

func (ed *EdDSAAlg) Sign(payload []byte) ([]byte, error) {
	return ed25519.Sign(ed.privateKey, payload), nil
}

func (ed *EdDSAAlg) Verify(token *Token) error {
	switch {
	case !token.isValid():
		return ErrUninitializedToken
	case !constTimeAlgEqual(token.Header().Algorithm, EdDSA):
		return ErrAlgorithmMismatch
	default:
		return ed.verify(token.PayloadPart(), token.Signature())
	}
}

func (ed *EdDSAAlg) verify(payload, signature []byte) error {
	if !ed25519.Verify(ed.publicKey, payload, signature) {
		return ErrInvalidSignature
	}
	return nil
}
