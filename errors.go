package jwt

// Error represents a JWT error.
type Error string

func (e Error) Error() string {
	return string(e)
}

var _ error = (Error)("")

const (
	// ErrPartMissed indicates that token format is invalid.
	ErrPartMissed = Error("token format is invalid")

	// ErrInvalidKey when provided an incorrect key.
	ErrInvalidKey = Error("key is invalid")
	// ErrInvalidKeyType when provided an incorrect key type.
	ErrInvalidKeyType = Error("key is of invalid type")
	// ErrHashUnavailable hash wasn't registered.
	ErrHashUnavailable = Error("the requested hash function is unavailable")
	// ErrSignatureInvalid signature wasn't correct.
	ErrSignatureInvalid = Error("signature is invalid")
)
