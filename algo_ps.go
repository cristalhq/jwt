package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

var (
	optsPS256 = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	}

	optsPS384 = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA384,
	}

	optsPS512 = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA512,
	}
)

var _ Signer = (*psAlg)(nil)

type psAlg struct {
	alg        Algorithm
	hash       crypto.Hash
	publickey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	opts       *rsa.PSSOptions
}

// NewPS256 returns new PS256 Signer using RSA PSS and SHA256 hash.
//
// Both public and private keys must not be nil.
//
func NewPS256(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (Signer, error) {
	if publicKey == nil || privateKey == nil {
		return nil, ErrInvalidKey
	}
	return &psAlg{
		alg:        PS256,
		hash:       crypto.SHA256,
		publickey:  publicKey,
		privateKey: privateKey,
		opts:       optsPS256,
	}, nil
}

// NewPS384 returns new PS384 Signer using RSA PSS and SHA384 hash.
//
// Both public and private keys must not be nil.
//
func NewPS384(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (Signer, error) {
	if publicKey == nil || privateKey == nil {
		return nil, ErrInvalidKey
	}
	return &psAlg{
		alg:        PS384,
		hash:       crypto.SHA384,
		publickey:  publicKey,
		privateKey: privateKey,
		opts:       optsPS384,
	}, nil
}

// NewPS512 returns new PS512 Signer using RSA PSS and SHA512 hash.
//
// Both public and private keys must not be nil.
//
func NewPS512(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (Signer, error) {
	if publicKey == nil || privateKey == nil {
		return nil, ErrInvalidKey
	}
	return &psAlg{
		alg:        PS512,
		hash:       crypto.SHA512,
		publickey:  publicKey,
		privateKey: privateKey,
		opts:       optsPS512,
	}, nil
}

func (h psAlg) Algorithm() Algorithm {
	return h.alg
}

func (h psAlg) Sign(payload []byte) ([]byte, error) {
	signed, err := h.sign(payload)
	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPSS(rand.Reader, h.privateKey, h.hash, signed, h.opts)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func (h psAlg) Verify(payload, signature []byte) error {
	signed, err := h.sign(payload)
	if err != nil {
		return err
	}

	err = rsa.VerifyPSS(h.publickey, h.hash, signed, signature, h.opts)
	if err != nil {
		return ErrInvalidSignature
	}
	return nil
}

func (h psAlg) sign(payload []byte) ([]byte, error) {
	hasher := h.hash.New()

	_, err := hasher.Write(payload)
	if err != nil {
		return nil, err
	}
	signed := hasher.Sum(nil)
	return signed, nil
}
