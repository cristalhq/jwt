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
	privatekey *rsa.PrivateKey
}

// NewRS256 returns new HMAC Signer using RSA and SHA256 hash.
//
// Both public and private keys must not be nil.
//
func NewRS256(publicKey *rsa.PublicKey, privatekey *rsa.PrivateKey) Signer {
	return &rsAlg{
		alg:        RS256,
		hash:       crypto.SHA256,
		publickey:  publicKey,
		privatekey: privatekey,
	}
}

// NewRS384 returns new HMAC Signer using RSA and SHA384 hash.
//
// Both public and private keys must not be nil.
//
func NewRS384(publicKey *rsa.PublicKey, privatekey *rsa.PrivateKey) Signer {
	return &rsAlg{
		alg:        RS384,
		hash:       crypto.SHA384,
		publickey:  publicKey,
		privatekey: privatekey,
	}
}

// NewRS512 returns new HMAC Signer using RSA and SHA512 hash.
//
// Both public and private keys must not be nil.
//
func NewRS512(publicKey *rsa.PublicKey, privatekey *rsa.PrivateKey) Signer {
	return &rsAlg{
		alg:        RS512,
		hash:       crypto.SHA512,
		publickey:  publicKey,
		privatekey: privatekey,
	}
}

func (h *rsAlg) Algorithm() Algorithm {
	return h.alg
}

func (h *rsAlg) Sign(payload []byte) ([]byte, error) {
	hasher := h.hash.New()

	_, err := hasher.Write(payload)
	if err != nil {
		return nil, err
	}

	bytes, err := rsa.SignPKCS1v15(rand.Reader, h.privatekey, h.hash, hasher.Sum(nil))
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func (h *rsAlg) Verify(expected, payload []byte) error {
	hasher := h.hash.New()

	_, err := hasher.Write(expected)
	if err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(h.publickey, h.hash, hasher.Sum(nil), payload)
}
