package jwt

import (
	"testing"
	"time"
)

func TestClaims(t *testing.T) {
	f := func(claims *RegisteredClaims, f func(claims *RegisteredClaims) bool, want bool) {
		t.Helper()

		got := f(claims)
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	f(
		&RegisteredClaims{Audience: Audience([]string{"winner"})},
		func(claims *RegisteredClaims) bool {
			return claims.IsForAudience("winner")
		},
		true,
	)
	f(
		&RegisteredClaims{Audience: Audience([]string{"oops", "winner"})},
		func(claims *RegisteredClaims) bool {
			return claims.IsForAudience("winner")
		},
		true,
	)
	f(
		&RegisteredClaims{Audience: Audience([]string{"w0nner"})},
		func(claims *RegisteredClaims) bool {
			return claims.IsForAudience("winner")
		},
		false,
	)
	f(
		&RegisteredClaims{ID: "test-id"},
		func(claims *RegisteredClaims) bool {
			return claims.IsID("test-id")
		},
		true,
	)
	f(
		&RegisteredClaims{Issuer: "test-issuer"},
		func(claims *RegisteredClaims) bool {
			return claims.IsIssuer("test-issuer")
		},
		true,
	)
	f(
		&RegisteredClaims{Subject: "test-subject"},
		func(claims *RegisteredClaims) bool {
			return claims.IsSubject("test-subject")
		},
		true,
	)
}

func TestTimingClaims(t *testing.T) {
	before := time.Now()
	after := before.Add(time.Minute)

	f := func(claims *RegisteredClaims, f func(claims *RegisteredClaims) bool, want bool) {
		t.Helper()

		got := f(claims)
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	// IsValidExpiresAt
	f(
		&RegisteredClaims{},
		func(claims *RegisteredClaims) bool {
			return claims.IsValidExpiresAt(after)
		},
		true,
	)
	f(
		&RegisteredClaims{ExpiresAt: NewNumericDate(before)},
		func(claims *RegisteredClaims) bool {
			return claims.IsValidExpiresAt(after)
		},
		false,
	)
	f(
		&RegisteredClaims{ExpiresAt: NewNumericDate(after)},
		func(claims *RegisteredClaims) bool {
			return claims.IsValidExpiresAt(before)
		},
		true,
	)

	// IsValidIssuedAt
	f(
		&RegisteredClaims{},
		func(claims *RegisteredClaims) bool {
			return claims.IsValidIssuedAt(after)
		},
		true,
	)
	f(
		&RegisteredClaims{IssuedAt: NewNumericDate(before)},
		func(claims *RegisteredClaims) bool {
			return claims.IsValidIssuedAt(after)
		},
		true,
	)
	f(
		&RegisteredClaims{IssuedAt: NewNumericDate(after)},
		func(claims *RegisteredClaims) bool {
			return claims.IsValidIssuedAt(before)
		},
		false,
	)

	// IsValidNotBefore
	f(
		&RegisteredClaims{},
		func(claims *RegisteredClaims) bool {
			return claims.IsValidNotBefore(after)
		},
		true,
	)
	f(
		&RegisteredClaims{NotBefore: NewNumericDate(before)},
		func(claims *RegisteredClaims) bool {
			return claims.IsValidNotBefore(after)
		},
		true,
	)
	f(
		&RegisteredClaims{NotBefore: NewNumericDate(after)},
		func(claims *RegisteredClaims) bool {
			return claims.IsValidNotBefore(before)
		},
		false,
	)
}

func TestIsValidAt(t *testing.T) {
	now := time.Now()
	before := now.Add(-time.Minute)
	beforeNow := now.Add(-10 * time.Second)
	afterNow := now.Add(10 * time.Second)
	after := now.Add(time.Minute)

	f := func(claims *RegisteredClaims, f func(claims *RegisteredClaims) bool, want bool) {
		t.Helper()

		got := f(claims)
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	f(
		&RegisteredClaims{},
		func(claims *RegisteredClaims) bool { return claims.IsValidAt(after) },
		true,
	)
	f(
		&RegisteredClaims{
			ExpiresAt: NewNumericDate(after),
			NotBefore: NewNumericDate(before),
			IssuedAt:  NewNumericDate(beforeNow),
		},
		func(claims *RegisteredClaims) bool { return claims.IsValidAt(now) },
		true,
	)
	f(
		&RegisteredClaims{
			ExpiresAt: NewNumericDate(after),
			NotBefore: NewNumericDate(before),
			IssuedAt:  NewNumericDate(afterNow),
		},
		func(claims *RegisteredClaims) bool { return claims.IsValidAt(now) },
		false,
	)
}
