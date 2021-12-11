package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

// NewSignerRS returns a new RSA-based signer.
func NewSignerRS(alg Algorithm, key *rsa.PrivateKey) (*RSAlg, error) {
	if key == nil {
		return nil, ErrNilKey
	}
	hash, err := getHashRS(alg)
	if err != nil {
		return nil, err
	}
	return &RSAlg{
		alg:        alg,
		hash:       hash,
		privateKey: key,
		publicKey:  nil,
	}, nil
}

// NewVerifierRS returns a new RSA-based verifier.
func NewVerifierRS(alg Algorithm, key *rsa.PublicKey) (*RSAlg, error) {
	if key == nil {
		return nil, ErrNilKey
	}
	hash, err := getHashRS(alg)
	if err != nil {
		return nil, err
	}
	return &RSAlg{
		alg:        alg,
		hash:       hash,
		privateKey: nil,
		publicKey:  key,
	}, nil
}

func getHashRS(alg Algorithm) (crypto.Hash, error) {
	var hash crypto.Hash
	switch alg {
	case RS256:
		hash = crypto.SHA256
	case RS384:
		hash = crypto.SHA384
	case RS512:
		hash = crypto.SHA512
	default:
		return 0, ErrUnsupportedAlg
	}
	return hash, nil
}

type RSAlg struct {
	alg        Algorithm
	hash       crypto.Hash
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

func (rs *RSAlg) Algorithm() Algorithm {
	return rs.alg
}

func (rs *RSAlg) SignSize() int {
	return rs.privateKey.Size()
}

func (rs *RSAlg) Sign(payload []byte) ([]byte, error) {
	digest, err := hashPayload(rs.hash, payload)
	if err != nil {
		return nil, err
	}

	signature, errSign := rsa.SignPKCS1v15(rand.Reader, rs.privateKey, rs.hash, digest)
	if errSign != nil {
		return nil, errSign
	}
	return signature, nil
}

func (rs *RSAlg) Verify(token *Token) error {
	switch {
	case !token.isValid():
		return ErrUninitializedToken
	case !constTimeAlgEqual(token.Header().Algorithm, rs.alg):
		return ErrAlgorithmMismatch
	default:
		return rs.verify(token.PayloadPart(), token.Signature())
	}
}

func (rs *RSAlg) verify(payload, signature []byte) error {
	digest, err := hashPayload(rs.hash, payload)
	if err != nil {
		return err
	}

	errVerify := rsa.VerifyPKCS1v15(rs.publicKey, rs.hash, digest, signature)
	if errVerify != nil {
		return ErrInvalidSignature
	}
	return nil
}
