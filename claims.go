package jwt

import (
	"encoding/json"
	"time"
)

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

// MarshalBinary default marshaling to JSON.
func (sc StandardClaims) MarshalBinary() (data []byte, err error) {
	return json.Marshal(sc)
}

// IsPermittedFor returns true if claims is allowed to be used by the audience.
func (sc StandardClaims) IsPermittedFor(audience string) bool {
	for _, aud := range sc.Audience {
		if aud == audience {
			return true
		}
	}
	return false
}

// IsExpired returns true if the token is expired.
func (sc StandardClaims) IsExpired(now time.Time) bool {
	expireAt := sc.ExpiresAt.Time()

	if expireAt.IsZero() {
		return false
	}
	return expireAt.Before(now)
}

// IsID returns true if claims has the given id.
func (sc StandardClaims) IsID(id string) bool {
	return sc.ID == id
}

// IsIssuedBefore returns true if the token was issued before of given time.
func (sc StandardClaims) IsIssuedBefore(now time.Time) bool {
	issuedAt := sc.IssuedAt.Time()

	if issuedAt.IsZero() {
		return false
	}
	return issuedAt.Before(now)
}

// IsIssuedBy returns true if the token was issued by any of given issuers.
func (sc StandardClaims) IsIssuedBy(issuers ...string) bool {
	for _, issuer := range issuers {
		if sc.Issuer == issuer {
			return true
		}
	}
	return false
}

// HasPassedNotBefore returns true if the token activation is used after the given time.
func (sc StandardClaims) HasPassedNotBefore(now time.Time) bool {
	notBefore := sc.NotBefore.Time()

	if notBefore.IsZero() {
		return true
	}
	return notBefore.Before(now)
}

// IsSubject returns true if claims has the given subject.
func (sc StandardClaims) IsSubject(subject string) bool {
	return sc.Subject == subject
}
