package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

// NewSignerPS returns a new RSA-PSS-based signer.
func NewSignerPS(alg Algorithm, key *rsa.PrivateKey) (*PSAlg, error) {
	if key == nil {
		return nil, ErrNilKey
	}
	hash, opts, err := getParamsPS(alg)
	if err != nil {
		return nil, err
	}
	return &PSAlg{
		alg:        alg,
		hash:       hash,
		privateKey: key,
		opts:       opts,
	}, nil
}

// NewVerifierPS returns a new RSA-PSS-based signer.
func NewVerifierPS(alg Algorithm, key *rsa.PublicKey) (*PSAlg, error) {
	if key == nil {
		return nil, ErrNilKey
	}
	hash, opts, err := getParamsPS(alg)
	if err != nil {
		return nil, err
	}
	return &PSAlg{
		alg:       alg,
		hash:      hash,
		publicKey: key,
		opts:      opts,
	}, nil
}

func getParamsPS(alg Algorithm) (crypto.Hash, *rsa.PSSOptions, error) {
	switch alg {
	case PS256:
		return crypto.SHA256, optsPS256, nil
	case PS384:
		return crypto.SHA384, optsPS384, nil
	case PS512:
		return crypto.SHA512, optsPS512, nil
	default:
		return 0, nil, ErrUnsupportedAlg
	}
}

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

type PSAlg struct {
	alg        Algorithm
	hash       crypto.Hash
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	opts       *rsa.PSSOptions
}

func (ps *PSAlg) SignSize() int {
	return ps.privateKey.Size()
}

func (ps *PSAlg) Algorithm() Algorithm {
	return ps.alg
}

func (ps *PSAlg) Sign(payload []byte) ([]byte, error) {
	digest, err := hashPayload(ps.hash, payload)
	if err != nil {
		return nil, err
	}

	signature, errSign := rsa.SignPSS(rand.Reader, ps.privateKey, ps.hash, digest, ps.opts)
	if errSign != nil {
		return nil, errSign
	}
	return signature, nil
}

func (ps *PSAlg) Verify(token *Token) error {
	switch {
	case !token.isValid():
		return ErrUninitializedToken
	case !constTimeAlgEqual(token.Header().Algorithm, ps.alg):
		return ErrAlgorithmMismatch
	default:
		return ps.verify(token.PayloadPart(), token.Signature())
	}
}

func (ps *PSAlg) verify(payload, signature []byte) error {
	digest, err := hashPayload(ps.hash, payload)
	if err != nil {
		return err
	}

	errVerify := rsa.VerifyPSS(ps.publicKey, ps.hash, digest, signature, ps.opts)
	if errVerify != nil {
		return ErrInvalidSignature
	}
	return nil
}
