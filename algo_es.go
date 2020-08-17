package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
)

// NewSignerES returns a new ECDSA-based signer.
func NewSignerES(alg Algorithm, key *ecdsa.PrivateKey) (Signer, error) {
	if key == nil {
		return nil, ErrInvalidKey
	}
	hash, keySize, curveBits, err := getParamsES(alg)
	if err != nil {
		return nil, err
	}
	return &esAlg{
		alg:        alg,
		hash:       hash,
		privateKey: key,
		keySize:    keySize,
		curveBits:  curveBits,
	}, nil
}

// NewVerifierES returns a new ECDSA-based verifier.
func NewVerifierES(alg Algorithm, key *ecdsa.PublicKey) (Verifier, error) {
	if key == nil {
		return nil, ErrInvalidKey
	}
	hash, keySize, curveBits, err := getParamsES(alg)
	if err != nil {
		return nil, err
	}
	return &esAlg{
		alg:       alg,
		hash:      hash,
		publickey: key,
		keySize:   keySize,
		curveBits: curveBits,
	}, nil
}

func getParamsES(alg Algorithm) (crypto.Hash, int, int, error) {
	switch alg {
	case ES256:
		return crypto.SHA256, 32, 256, nil
	case ES384:
		return crypto.SHA384, 48, 384, nil
	case ES512:
		return crypto.SHA512, 66, 521, nil
	default:
		return 0, 0, 0, ErrUnsupportedAlg
	}
}

type esAlg struct {
	alg        Algorithm
	hash       crypto.Hash
	publickey  *ecdsa.PublicKey
	privateKey *ecdsa.PrivateKey
	keySize    int
	curveBits  int
}

func (es esAlg) Algorithm() Algorithm {
	return es.alg
}

func (es esAlg) SignSize() int {
	return (es.privateKey.Curve.Params().BitSize + 7) / 4
}

func (es esAlg) Sign(payload []byte) ([]byte, error) {
	signed, err := es.sign(payload)
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, es.privateKey, signed)
	if err != nil {
		return nil, err
	}

	keyBytes := es.SignSize() / 2

	rBytes, sBytes := r.Bytes(), s.Bytes()
	signature := make([]byte, keyBytes*2)
	copy(signature[keyBytes-len(rBytes):], rBytes)
	copy(signature[keyBytes*2-len(sBytes):], sBytes)
	return signature, nil
}

func (es esAlg) Verify(payload, signature []byte) error {
	if len(signature) != 2*es.keySize {
		return ErrInvalidSignature
	}

	signed, err := es.sign(payload)
	if err != nil {
		return err
	}

	r := big.NewInt(0).SetBytes(signature[:es.keySize])
	s := big.NewInt(0).SetBytes(signature[es.keySize:])

	if !ecdsa.Verify(es.publickey, signed, r, s) {
		return ErrInvalidSignature
	}
	return nil
}

func (es esAlg) sign(payload []byte) ([]byte, error) {
	hasher := es.hash.New()

	_, err := hasher.Write(payload)
	if err != nil {
		return nil, err
	}
	signed := hasher.Sum(nil)
	return signed, nil
}
