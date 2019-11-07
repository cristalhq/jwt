package jwt

import (
	"testing"
	"time"
)

func TestValidator(t *testing.T) {
	now := time.Now()

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

	f(
		AudienceChecker(Audience([]string{"winner"})),
		&StandardClaims{
			Audience: Audience([]string{"winner"}),
		},
		nil,
	)
	f(
		AudienceChecker(Audience([]string{"user"})),
		&StandardClaims{
			Audience: Audience([]string{"winner"}),
		},
		ErrAudValidation,
	)

	f(
		ExpirationTimeChecker(now),
		&StandardClaims{
			ExpiresAt: Timestamp(now.Add(time.Minute).Unix()),
		},
		nil,
	)
	f(
		ExpirationTimeChecker(now.Add(time.Minute)),
		&StandardClaims{
			ExpiresAt: Timestamp(now.Unix()),
		},
		ErrExpValidation,
	)

	f(
		IDChecker("test-id"),
		&StandardClaims{
			ID: "test-id",
		},
		nil,
	)
	f(
		IDChecker("test-id"),
		&StandardClaims{
			ID: "id-test",
		},
		ErrJtiValidation,
	)

	f(
		IssuedAtChecker(now),
		&StandardClaims{
			IssuedAt: Timestamp(now.Unix()),
		},
		nil,
	)
	f(
		IssuedAtChecker(now),
		&StandardClaims{
			IssuedAt: Timestamp(now.Add(time.Minute).Unix()),
		},
		ErrIatValidation,
	)

	f(
		IssuerChecker("best-issuer"),
		&StandardClaims{
			Issuer: "best-issuer",
		},
		nil,
	)
	f(
		IssuerChecker("best-issuer"),
		&StandardClaims{
			Issuer: "better-issuer",
		},
		ErrIssValidation,
	)

	f(
		NotBeforeChecker(now.Add(time.Minute)),
		&StandardClaims{
			NotBefore: Timestamp(now.Unix()),
		},
		nil,
	)
	f(
		NotBeforeChecker(now),
		&StandardClaims{
			NotBefore: Timestamp(now.Add(time.Minute).Unix()),
		},
		ErrNbfValidation,
	)

	f(
		SubjectChecker("great-subject"),
		&StandardClaims{
			Subject: "great-subject",
		},
		nil,
	)
	f(
		SubjectChecker("great-subject"),
		&StandardClaims{
			Subject: "can-be-better",
		},
		ErrSubValidation,
	)
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
