package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

var _ Signer = (*rsAlg)(nil)

type rsAlg struct {
	alg        Algorithm
	hash       crypto.Hash
	publickey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

// NewRS256 returns new RSA Signer using RSA and SHA256 hash.
//
// Both public and private keys must not be nil.
//
func NewRS256(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (Signer, error) {
	if publicKey == nil || privateKey == nil {
		return nil, ErrInvalidKey
	}
	return &rsAlg{
		alg:        RS256,
		hash:       crypto.SHA256,
		publickey:  publicKey,
		privateKey: privateKey,
	}, nil
}

// NewRS384 returns new RSA Signer using RSA and SHA384 hash.
//
// Both public and private keys must not be nil.
//
func NewRS384(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (Signer, error) {
	if publicKey == nil || privateKey == nil {
		return nil, ErrInvalidKey
	}
	return &rsAlg{
		alg:        RS384,
		hash:       crypto.SHA384,
		publickey:  publicKey,
		privateKey: privateKey,
	}, nil
}

// NewRS512 returns new RSA Signer using RSA and SHA512 hash.
//
// Both public and private keys must not be nil.
//
func NewRS512(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (Signer, error) {
	if publicKey == nil || privateKey == nil {
		return nil, ErrInvalidKey
	}
	return &rsAlg{
		alg:        RS512,
		hash:       crypto.SHA512,
		publickey:  publicKey,
		privateKey: privateKey,
	}, nil
}

func (h rsAlg) Algorithm() Algorithm {
	return h.alg
}

func (h rsAlg) Sign(payload []byte) ([]byte, error) {
	signed, err := h.sign(payload)
	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, h.privateKey, h.hash, signed)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func (h rsAlg) Verify(payload, signature []byte) error {
	signed, err := h.sign(payload)
	if err != nil {
		return err
	}

	err = rsa.VerifyPKCS1v15(h.publickey, h.hash, signed, signature)
	if err != nil {
		return ErrInvalidSignature
	}
	return nil
}

func (h rsAlg) sign(payload []byte) ([]byte, error) {
	hasher := h.hash.New()

	_, err := hasher.Write(payload)
	if err != nil {
		return nil, err
	}
	signed := hasher.Sum(nil)
	return signed, nil
}
