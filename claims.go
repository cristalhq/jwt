package jwt

import (
	"crypto/subtle"
	"time"
)

// RegisteredClaims represents claims for JWT.
// See: https://tools.ietf.org/html/rfc7519#section-4.1
//
type RegisteredClaims struct {
	// ID claim provides a unique identifier for the JWT.
	ID string `json:"jti,omitempty"`

	// Audience claim identifies the recipients that the JWT is intended for.
	Audience Audience `json:"aud,omitempty"`

	// Issuer claim identifies the principal that issued the JWT.
	// Use of this claim is OPTIONAL.
	Issuer string `json:"iss,omitempty"`

	// Subject claim identifies the principal that is the subject of the JWT.
	// Use of this claim is OPTIONAL.
	Subject string `json:"sub,omitempty"`

	// ExpiresAt claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
	// Use of this claim is OPTIONAL.
	ExpiresAt *NumericDate `json:"exp,omitempty"`

	// IssuedAt claim identifies the time at which the JWT was issued.
	// This claim can be used to determine the age of the JWT.
	// Use of this claim is OPTIONAL.
	IssuedAt *NumericDate `json:"iat,omitempty"`

	// NotBefore claim identifies the time before which the JWT MUST NOT be accepted for processing.
	// Use of this claim is OPTIONAL.
	NotBefore *NumericDate `json:"nbf,omitempty"`
}

// IsForAudience reports whether token has a given audience.
func (sc *RegisteredClaims) IsForAudience(audience string) bool {
	for _, aud := range sc.Audience {
		if constTimeEqual(aud, audience) {
			return true
		}
	}
	return false
}

// IsIssuer reports whether token has a given issuer.
func (sc *RegisteredClaims) IsIssuer(issuer string) bool {
	return constTimeEqual(sc.Issuer, issuer)
}

// IsSubject reports whether token has a given subject.
func (sc *RegisteredClaims) IsSubject(subject string) bool {
	return constTimeEqual(sc.Subject, subject)
}

// IsID reports whether token has a given id.
func (sc *RegisteredClaims) IsID(id string) bool {
	return constTimeEqual(sc.ID, id)
}

// IsValidExpiresAt reports whether a token isn't expired at a given time.
func (sc *RegisteredClaims) IsValidExpiresAt(now time.Time) bool {
	return sc.ExpiresAt == nil || sc.ExpiresAt.After(now)
}

// IsValidNotBefore reports whether a token isn't used before a given time.
func (sc *RegisteredClaims) IsValidNotBefore(now time.Time) bool {
	return sc.NotBefore == nil || sc.NotBefore.Before(now)
}

// IsValidIssuedAt reports whether a token was created before a given time.
func (sc *RegisteredClaims) IsValidIssuedAt(now time.Time) bool {
	return sc.IssuedAt == nil || sc.IssuedAt.Before(now)
}

// IsValidAt reports whether a token is valid at a given time.
func (sc *RegisteredClaims) IsValidAt(now time.Time) bool {
	return sc.IsValidExpiresAt(now) && sc.IsValidNotBefore(now) && sc.IsValidIssuedAt(now)
}

func constTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
