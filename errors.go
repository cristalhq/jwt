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

	// ErrInvalidSignature signature wasn't correct.
	ErrInvalidSignature = Error("jwt: signature is invalid")
)

// Validation errors.
const (
	// ErrTokenExpired is the error when token is expited.
	ErrTokenExpired = Error("jwt: token has expited")

	// ErrAudValidation is the error for an invalid "aud" claim.
	ErrAudValidation = Error("jwt: aud claim is invalid")

	// ErrExpValidation is the error for an invalid "exp" claim.
	ErrExpValidation = Error("jwt: exp claim is invalid")

	// ErrIatValidation is the error for an invalid "iat" claim.
	ErrIatValidation = Error("jwt: iat claim is invalid")

	// ErrIssValidation is the error for an invalid "iss" claim.
	ErrIssValidation = Error("jwt: iss claim is invalid")

	// ErrJtiValidation is the error for an invalid "jti" claim.
	ErrJtiValidation = Error("jwt: jti claim is invalid")

	// ErrNbfValidation is the error for an invalid "nbf" claim.
	ErrNbfValidation = Error("jwt: nbf claim is invalid")

	// ErrSubValidation is the error for an invalid "sub" claim.
	ErrSubValidation = Error("jwt: sub claim is invalid")
)
