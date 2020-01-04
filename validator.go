package jwt

import (
	"time"
)

// Check used to validate StandardClaims.
//
type Check func(claims *StandardClaims) error

// Validator used to validate StandardClaims.
//
type Validator struct {
	checks []Check
}

// NewValidator returns new instance of validator.
//
func NewValidator(checks ...Check) *Validator {
	return &Validator{
		checks: checks,
	}
}

// Validate given claims and return first error.
//
func (v Validator) Validate(claims *StandardClaims) error {
	for _, c := range v.checks {
		if err := c(claims); err != nil {
			return err
		}
	}
	return nil
}

// ValidateAll will run all the checks and return a slice of errors, if any.
//
func (v Validator) ValidateAll(claims *StandardClaims) []error {
	var errs []error
	for _, c := range v.checks {
		if err := c(claims); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// AudienceChecker validates the "aud" claim.
//
func AudienceChecker(aud Audience) Check {
	return func(claims *StandardClaims) error {
		for _, givenAud := range aud {
			for _, tokenAud := range claims.Audience {
				if tokenAud == givenAud {
					return nil
				}
			}
		}
		return ErrAudValidation
	}
}

// ExpirationTimeChecker validates the "exp" claim.
//
func ExpirationTimeChecker(now time.Time) Check {
	return func(claims *StandardClaims) error {
		if claims.IsExpired(now) {
			return ErrExpValidation
		}
		return nil
	}
}

// IDChecker validates the "jti" claim.
//
func IDChecker(jti string) Check {
	return func(claims *StandardClaims) error {
		if !claims.IsID(jti) {
			return ErrJtiValidation
		}
		return nil
	}
}

// IssuedAtChecker validates the "iat" claim.
//
func IssuedAtChecker(now time.Time) Check {
	return func(claims *StandardClaims) error {
		if !claims.IsIssuedBefore(now) {
			return ErrIatValidation
		}
		return nil
	}
}

// IssuerChecker validates the "iss" claim.
//
func IssuerChecker(iss string) Check {
	return func(claims *StandardClaims) error {
		if !claims.IsIssuedBy(iss) {
			return ErrIssValidation
		}
		return nil
	}
}

// NotBeforeChecker validates the "nbf" claim.
//
func NotBeforeChecker(now time.Time) Check {
	return func(claims *StandardClaims) error {
		if !claims.HasPassedNotBefore(now) {
			return ErrNbfValidation
		}
		return nil
	}
}

// SubjectChecker validates the "sub" claim.
//
func SubjectChecker(sub string) Check {
	return func(claims *StandardClaims) error {
		if !claims.IsSubject(sub) {
			return ErrSubValidation
		}
		return nil
	}
}

// ValidAtChecker validates whether the token is valid at the specified time, based on
// the values of the IssuedAt, NotBefore and ExpiresAt claims in the claims.
//
func ValidAtChecker(now time.Time) Check {
	return func(claims *StandardClaims) error {
		if claims.IsExpired(now) ||
			!claims.IsIssuedBefore(now) ||
			claims.HasPassedNotBefore(now) {
			return ErrTokenExpired
		}
		return nil
	}
}

// ValidAtNowChecker validates whether the token is valid at the current time, based on
// the values of the IssuedAt, NotBefore and ExpiresAt claims in the claims.
//
func ValidAtNowChecker() Check {
	return func(claims *StandardClaims) error {
		now := time.Now()
		if claims.IsExpired(now) ||
			!claims.IsIssuedBefore(now) ||
			claims.HasPassedNotBefore(now) {
			return ErrTokenExpired
		}
		return nil
	}
}
