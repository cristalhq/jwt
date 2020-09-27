package jwt

import "errors"

// Build and parse errors.
var (
	// ErrInvalidKey indicates that key is not valid.
	ErrInvalidKey = errors.New("jwt: key is not valid")

	// ErrUnsupportedAlg indicates that given algorithm is not supported.
	ErrUnsupportedAlg = errors.New("jwt: algorithm is not supported")

	// ErrInvalidFormat indicates that token format is not valid.
	ErrInvalidFormat = errors.New("jwt: token format is not valid")

	// ErrInvalidHeaderFormat indicates that token header format is not valid.
	ErrInvalidHeaderFormat = errors.New("jwt: token header format is not valid")

	// ErrInvalidClaimsFormat indicates that token claims format is not valid.
	ErrInvalidClaimsFormat = errors.New("jwt: token claims format is not valid")

	// ErrInvalidSignatureFormat indicates that token signature format is not valid.
	ErrInvalidSignatureFormat = errors.New("jwt: token signature format is not valid")

	// ErrAudienceInvalidFormat indicates that audience format is not valid.
	ErrAudienceInvalidFormat = errors.New("jwt: audience format is not valid")

	// ErrDateInvalidFormat indicates that date format is not valid.
	ErrDateInvalidFormat = errors.New("jwt: date is not valid")

	// ErrAlgorithmMismatch indicates that token is signed by another algorithm.
	ErrAlgorithmMismatch = errors.New("jwt: token is signed by another algorithm")

	// ErrInvalidSignature indicates that signature is not valid.
	ErrInvalidSignature = errors.New("jwt: signature is not valid")
)
