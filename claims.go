package jwt

import "encoding/json"

// StandardClaims https://tools.ietf.org/html/rfc7519#section-4.1
type StandardClaims struct {
	// Audience claim identifies the recipients that the JWT is intended for.
	Audience Audience `json:"aud,omitempty"`

	// ExpiresAt claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
	// Use of this claim is OPTIONAL.
	ExpiresAt Timestamp `json:"exp,omitempty"`

	// ID claim provides a unique identifier for the JWT.
	ID string `json:"jti,omitempty"`

	// IssuedAt claim identifies the time at which the JWT was issued.
	// This claim can be used to determine the age of the JWT.
	// Use of this claim is OPTIONAL.
	IssuedAt Timestamp `json:"iat,omitempty"`

	// Issuer claim identifies the principal that issued the JWT.
	// Use of this claim is OPTIONAL.
	Issuer string `json:"iss,omitempty"`

	// NotBefore claim identifies the time before which the JWT MUST NOT be accepted for processing.
	// Use of this claim is OPTIONAL.
	NotBefore Timestamp `json:"nbf,omitempty"`

	// Subject claim identifies the principal that is the subject of the JWT.
	// Use of this claim is OPTIONAL.
	Subject string `json:"sub,omitempty"`
}

// MarshalBinary is needed for Build and TokenBuilder.Build functions.
//
// Same interface (encoding.MarshalBinary) must be implemented by custom user claims.
//
func (sc *StandardClaims) MarshalBinary() (data []byte, err error) {
	return json.Marshal(sc)
}
