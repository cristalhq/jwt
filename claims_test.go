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
			return claims.IsPermittedFor("winner")
		},
		true,
	)
	f(
		&StandardClaims{
			Audience: Audience([]string{"w0nner"}),
		},
		func(claims *StandardClaims) bool {
			return claims.IsPermittedFor("winner")
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
			return claims.IsIssuedBy("test-issuer")
		},
		true,
	)
}

func TestTimingClaims(t *testing.T) {
	now := time.Now()
	later := now.Add(time.Minute)

	f := func(claims *StandardClaims, f func(claims *StandardClaims) bool, want bool) {
		t.Helper()

		got := f(claims)
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	// IsExpired
	f(
		&StandardClaims{},
		func(claims *StandardClaims) bool {
			return claims.IsExpired(later)
		},
		false,
	)
	f(
		&StandardClaims{ExpiresAt: Timestamp(now.Unix())},
		func(claims *StandardClaims) bool {
			return claims.IsExpired(later)
		},
		true,
	)
	f(
		&StandardClaims{ExpiresAt: Timestamp(later.Unix())},
		func(claims *StandardClaims) bool {
			return claims.IsExpired(now)
		},
		false,
	)

	// IsIssuedBefore
	f(
		&StandardClaims{},
		func(claims *StandardClaims) bool {
			return claims.IsIssuedBefore(later)
		},
		true,
	)
	f(
		&StandardClaims{IssuedAt: Timestamp(now.Unix())},
		func(claims *StandardClaims) bool {
			return claims.IsIssuedBefore(later)
		},
		true,
	)
	f(
		&StandardClaims{IssuedAt: Timestamp(later.Unix())},
		func(claims *StandardClaims) bool {
			return claims.IsIssuedBefore(now)
		},
		false,
	)

	// HasPassedNotBefore
	f(
		&StandardClaims{},
		func(claims *StandardClaims) bool {
			return claims.HasPassedNotBefore(later)
		},
		true,
	)
	f(
		&StandardClaims{NotBefore: Timestamp(now.Unix())},
		func(claims *StandardClaims) bool {
			return claims.HasPassedNotBefore(later)
		},
		false,
	)
	f(
		&StandardClaims{NotBefore: Timestamp(later.Unix())},
		func(claims *StandardClaims) bool {
			return claims.HasPassedNotBefore(now)
		},
		true,
	)
}
