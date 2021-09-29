package jwt

import "errors"

// JWT sign, verify, build and parse errors.
var (
	// ErrNilKey indicates that key is nil.
	ErrNilKey = errors.New("jwt: key is nil")

	// ErrInvalidKey indicates that key is not valid.
	ErrInvalidKey = errors.New("jwt: key is not valid")

	// ErrUnsupportedAlg indicates that given algorithm is not supported.
	ErrUnsupportedAlg = errors.New("jwt: algorithm is not supported")

	// ErrInvalidFormat indicates that token format is not valid.
	ErrInvalidFormat = errors.New("jwt: token format is not valid")

	// ErrAudienceInvalidFormat indicates that audience format is not valid.
	ErrAudienceInvalidFormat = errors.New("jwt: audience format is not valid")

	// ErrDateInvalidFormat indicates that date format is not valid.
	ErrDateInvalidFormat = errors.New("jwt: date is not valid")

	// ErrAlgorithmMismatch indicates that token is signed by another algorithm.
	ErrAlgorithmMismatch = errors.New("jwt: token is signed by another algorithm")

	// ErrInvalidSignature indicates that signature is not valid.
	ErrInvalidSignature = errors.New("jwt: signature is not valid")
)
