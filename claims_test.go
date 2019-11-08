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
	before := time.Now()
	after := before.Add(time.Minute)

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
			return claims.IsExpired(after)
		},
		false,
	)
	f(
		&StandardClaims{ExpiresAt: Timestamp(before.Unix())},
		func(claims *StandardClaims) bool {
			return claims.IsExpired(after)
		},
		true,
	)
	f(
		&StandardClaims{ExpiresAt: Timestamp(after.Unix())},
		func(claims *StandardClaims) bool {
			return claims.IsExpired(before)
		},
		false,
	)

	// IsIssuedBefore
	f(
		&StandardClaims{},
		func(claims *StandardClaims) bool {
			return claims.IsIssuedBefore(after)
		},
		false,
	)
	f(
		&StandardClaims{IssuedAt: Timestamp(before.Unix())},
		func(claims *StandardClaims) bool {
			return claims.IsIssuedBefore(after)
		},
		true,
	)
	f(
		&StandardClaims{IssuedAt: Timestamp(after.Unix())},
		func(claims *StandardClaims) bool {
			return claims.IsIssuedBefore(before)
		},
		false,
	)

	// HasPassedNotBefore
	f(
		&StandardClaims{},
		func(claims *StandardClaims) bool {
			return claims.HasPassedNotBefore(after)
		},
		true,
	)
	f(
		&StandardClaims{NotBefore: Timestamp(before.Unix())},
		func(claims *StandardClaims) bool {
			return claims.HasPassedNotBefore(after)
		},
		true,
	)
	f(
		&StandardClaims{NotBefore: Timestamp(after.Unix())},
		func(claims *StandardClaims) bool {
			return claims.HasPassedNotBefore(before)
		},
		false,
	)
}
