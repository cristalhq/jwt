package jwt

import (
	"crypto"
	"crypto/hmac"
	"hash"
	"sync"
)

// NewSignerHS returns a new HMAC-based signer.
func NewSignerHS(alg Algorithm, key []byte) (*HSAlg, error) {
	return newHS(alg, key)
}

// NewVerifierHS returns a new HMAC-based verifier.
func NewVerifierHS(alg Algorithm, key []byte) (*HSAlg, error) {
	return newHS(alg, key)
}

func newHS(alg Algorithm, key []byte) (*HSAlg, error) {
	if len(key) == 0 {
		return nil, ErrNilKey
	}
	hash, ok := getHashHMAC(alg)
	if !ok {
		return nil, ErrUnsupportedAlg
	}
	return &HSAlg{
		alg:  alg,
		hash: hash,
		key:  key,
		hashPool: &sync.Pool{
			New: func() interface{} {
				return hmac.New(hash.New, key)
			},
		},
	}, nil
}

func getHashHMAC(alg Algorithm) (crypto.Hash, bool) {
	switch alg {
	case HS256:
		return crypto.SHA256, true
	case HS384:
		return crypto.SHA384, true
	case HS512:
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

type HSAlg struct {
	alg      Algorithm
	hash     crypto.Hash
	key      []byte
	hashPool *sync.Pool
}

func (hs *HSAlg) Algorithm() Algorithm {
	return hs.alg
}

func (hs *HSAlg) SignSize() int {
	return hs.hash.Size()
}

func (hs *HSAlg) Sign(payload []byte) ([]byte, error) {
	return hs.sign(payload)
}

func (hs *HSAlg) Verify(token *Token) error {
	switch {
	case !token.isValid():
		return ErrUninitializedToken
	case !constTimeAlgEqual(token.Header().Algorithm, hs.alg):
		return ErrAlgorithmMismatch
	default:
		return hs.verify(token.PayloadPart(), token.Signature())
	}
}

func (hs *HSAlg) verify(payload, signature []byte) error {
	digest, err := hs.sign(payload)
	if err != nil {
		return err
	}
	if !hmac.Equal(signature, digest) {
		return ErrInvalidSignature
	}
	return nil
}

func (hs *HSAlg) sign(payload []byte) ([]byte, error) {
	hasher := hs.hashPool.Get().(hash.Hash)
	defer func() {
		hasher.Reset()
		hs.hashPool.Put(hasher)
	}()

	if _, err := hasher.Write(payload); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}
