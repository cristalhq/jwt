package jwt

import (
	"testing"
	"time"
)

func TestValidator(t *testing.T) {
	f := func(check Check, claims *StandardClaims, wantErr error) {
		t.Helper()

		validator := NewValidator(check)
		err := validator.Validate(claims)
		switch {
		case err != nil && wantErr == nil:
			t.Errorf("got %#v, want nil", err)
		case err != nil && wantErr != nil && err != wantErr:
			t.Errorf("got %#v, want %#v", err, wantErr)
		case err == nil && wantErr != nil:
			t.Errorf("got nil, want %#v", wantErr)
		}
	}

	// AudienceChecker
	f(
		AudienceChecker(Audience([]string{"winner"})),
		&StandardClaims{Audience: Audience([]string{"winner"})},
		nil,
	)
	f(
		AudienceChecker(Audience([]string{"user"})),
		&StandardClaims{Audience: Audience([]string{"winner"})},
		ErrAudValidation,
	)

	// IDChecker
	f(
		IDChecker("test-id"),
		&StandardClaims{ID: "test-id"},
		nil,
	)
	f(
		IDChecker("test-id"),
		&StandardClaims{ID: "id-test"},
		ErrJtiValidation,
	)

	// IssuerChecker
	f(
		IssuerChecker("best-issuer"),
		&StandardClaims{Issuer: "best-issuer"},
		nil,
	)
	f(
		IssuerChecker("best-issuer"),
		&StandardClaims{Issuer: "better-issuer"},
		ErrIssValidation,
	)

	// SubjectChecker
	f(
		SubjectChecker("great-subject"),
		&StandardClaims{Subject: "great-subject"},
		nil,
	)
	f(
		SubjectChecker("great-subject"),
		&StandardClaims{Subject: "can-be-better"},
		ErrSubValidation,
	)
}

func TestTimingValidator(t *testing.T) {
	now := time.Now()
	later := now.Add(time.Minute)

	f := func(check Check, claims *StandardClaims, wantErr error) {
		t.Helper()

		validator := NewValidator(check)
		err := validator.Validate(claims)
		switch {
		case err != nil && wantErr == nil:
			t.Errorf("got %#v, want nil", err)
		case err != nil && wantErr != nil && err != wantErr:
			t.Errorf("got %#v, want %#v", err, wantErr)
		case err == nil && wantErr != nil:
			t.Errorf("got nil, want %#v", wantErr)
		}
	}

	// ExpirationTimeChecker
	f(
		ExpirationTimeChecker(now),
		&StandardClaims{},
		nil,
	)
	f(
		ExpirationTimeChecker(now),
		&StandardClaims{ExpiresAt: Timestamp(later.Unix())},
		nil,
	)
	f(
		ExpirationTimeChecker(later),
		&StandardClaims{ExpiresAt: Timestamp(now.Unix())},
		ErrExpValidation,
	)

	// IsIssuedBeforeChecker
	f(
		IsIssuedBeforeChecker(now),
		&StandardClaims{},
		nil,
	)
	f(
		IsIssuedBeforeChecker(now),
		&StandardClaims{IssuedAt: Timestamp(now.Unix())},
		nil,
	)
	f(
		IsIssuedBeforeChecker(now),
		&StandardClaims{IssuedAt: Timestamp(later.Unix())},
		ErrIatValidation,
	)

	// NotBeforeChecker
	f(
		NotBeforeChecker(later),
		&StandardClaims{},
		nil,
	)
	f(
		NotBeforeChecker(later),
		&StandardClaims{NotBefore: Timestamp(now.Unix())},
		ErrNbfValidation,
	)
	f(
		NotBeforeChecker(now),
		&StandardClaims{NotBefore: Timestamp(later.Unix())},
		nil,
	)

	// ValidAtChecker
	// f(
	// 	ValidAtChecker(now),
	// 	&StandardClaims{},
	// 	nil,
	// )
	// f(
	// 	ValidAtChecker(now),
	// 	&StandardClaims{
	// 		NotBefore: Timestamp(later.Unix()),
	// 	},
	// 	ErrSubValidation,
	// )
}

func TestCustomValidator(t *testing.T) {
	customCheck := func() Check {
		var count int
		return func(claims *StandardClaims) error {
			aud := "first means a winner"
			if count != 0 {
				aud = "not a winner anymore"
			}

			count++

			if !claims.IsPermittedFor(aud) {
				return ErrIatValidation
			}
			return nil
		}
	}

	claims := &StandardClaims{
		Audience: Audience([]string{"first means a winner"}),
	}
	validator := NewValidator(customCheck())

	if err := validator.Validate(claims); err != nil {
		t.Errorf("1st validation should be fine, got %#v", err)
	}

	if err := validator.Validate(claims); err == nil {
		t.Errorf("2st validation should fail, got nil")
	}
}
