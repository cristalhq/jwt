package jwt

import (
	"testing"
	"time"
)

func TestClaims(t *testing.T) {
	f := func(claims *StandardClaims, f func(claims *StandardClaims) bool, want bool) {
		t.Helper()

		got := f(claims)
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	f(
		&StandardClaims{
			Audience: Audience([]string{"winner"}),
		},
		func(claims *StandardClaims) bool {
			return claims.HasAudience("winner")
		},
		true,
	)
	f(
		&StandardClaims{
			Audience: Audience([]string{"w0nner"}),
		},
		func(claims *StandardClaims) bool {
			return claims.HasAudience("winner")
		},
		false,
	)

	f(
		&StandardClaims{
			ID: "test-id",
		},
		func(claims *StandardClaims) bool {
			return claims.IsID("test-id")
		},
		true,
	)

	f(
		&StandardClaims{
			Issuer: "test-issuer",
		},
		func(claims *StandardClaims) bool {
			return claims.IsIssuer("test-issuer")
		},
		true,
	)
}

func TestTimingClaims(t *testing.T) {
	before := time.Now()
	after := before.Add(time.Minute)

	f := func(claims *StandardClaims, f func(claims *StandardClaims) bool, want bool) {
		t.Helper()

		got := f(claims)
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	// IsValidExpiresAt
	f(
		&StandardClaims{},
		func(claims *StandardClaims) bool {
			return claims.IsValidExpiresAt(after)
		},
		true,
	)
	f(
		&StandardClaims{ExpiresAt: NewNumericDate(before)},
		func(claims *StandardClaims) bool {
			return claims.IsValidExpiresAt(after)
		},
		false,
	)
	f(
		&StandardClaims{ExpiresAt: NewNumericDate(after)},
		func(claims *StandardClaims) bool {
			return claims.IsValidExpiresAt(before)
		},
		true,
	)

	// IsValidIssuedAt
	f(
		&StandardClaims{},
		func(claims *StandardClaims) bool {
			return claims.IsValidIssuedAt(after)
		},
		true,
	)
	f(
		&StandardClaims{IssuedAt: NewNumericDate(before)},
		func(claims *StandardClaims) bool {
			return claims.IsValidIssuedAt(after)
		},
		true,
	)
	f(
		&StandardClaims{IssuedAt: NewNumericDate(after)},
		func(claims *StandardClaims) bool {
			return claims.IsValidIssuedAt(before)
		},
		false,
	)

	// IsValidNotBefore
	f(
		&StandardClaims{},
		func(claims *StandardClaims) bool {
			return claims.IsValidNotBefore(after)
		},
		true,
	)
	f(
		&StandardClaims{NotBefore: NewNumericDate(before)},
		func(claims *StandardClaims) bool {
			return claims.IsValidNotBefore(after)
		},
		true,
	)
	f(
		&StandardClaims{NotBefore: NewNumericDate(after)},
		func(claims *StandardClaims) bool {
			return claims.IsValidNotBefore(before)
		},
		false,
	)
}
