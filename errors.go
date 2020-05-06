package jwt

// Error represents a JWT error.
type Error string

func (e Error) Error() string {
	return string(e)
}

var _ error = (Error)("")

// Build and parse errors.
const (
	// ErrInvalidKey indicates that key is invalid.
	ErrInvalidKey = Error("jwt: key is invalid")

	// ErrInvalidFormat indicates that token format is invalid.
	ErrInvalidFormat = Error("jwt: token format is invalid")

	// ErrAudienceInvalidFormat indicates that audience format is invalid.
	ErrAudienceInvalidFormat = Error("jwt: audience format is invalid")

	// ErrAlgorithmMismatch indicates that token is signed by another algorithm.
	ErrAlgorithmMismatch = Error("jwt: token is signed by another algorithm")

	// ErrInvalidSignature indicates that signature is incorrect.
	ErrInvalidSignature = Error("jwt: signature is invalid")
)
