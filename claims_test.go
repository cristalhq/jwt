package jwt

import (
	"testing"
	"time"
)

func TestClaims(t *testing.T) {
	testCases := []struct {
		claims *RegisteredClaims
		f      func(claims *RegisteredClaims) bool
		want   bool
	}{
		{
			&RegisteredClaims{Audience: Audience([]string{"winner"})},
			func(claims *RegisteredClaims) bool {
				return claims.IsForAudience("winner")
			},
			true,
		},
		{
			&RegisteredClaims{Audience: Audience([]string{"oops", "winner"})},
			func(claims *RegisteredClaims) bool {
				return claims.IsForAudience("winner")
			},
			true,
		},
		{
			&RegisteredClaims{Audience: Audience([]string{"w0nner"})},
			func(claims *RegisteredClaims) bool {
				return claims.IsForAudience("winner")
			},
			false,
		},
		{
			&RegisteredClaims{ID: "test-id"},
			func(claims *RegisteredClaims) bool {
				return claims.IsID("test-id")
			},
			true,
		},
		{
			&RegisteredClaims{Issuer: "test-issuer"},
			func(claims *RegisteredClaims) bool {
				return claims.IsIssuer("test-issuer")
			},
			true,
		},
		{
			&RegisteredClaims{Subject: "test-subject"},
			func(claims *RegisteredClaims) bool {
				return claims.IsSubject("test-subject")
			},
			true,
		},
	}

	for _, tc := range testCases {
		mustEqual(t, tc.f(tc.claims), tc.want)
	}
}

func TestTimingClaims(t *testing.T) {
	before := time.Now()
	after := before.Add(time.Minute)

	testCases := []struct {
		claims *RegisteredClaims
		f      func(claims *RegisteredClaims) bool
		want   bool
	}{
		// IsValidExpiresAt
		{
			&RegisteredClaims{},
			func(claims *RegisteredClaims) bool {
				return claims.IsValidExpiresAt(after)
			},
			true,
		},
		{
			&RegisteredClaims{ExpiresAt: NewNumericDate(before)},
			func(claims *RegisteredClaims) bool {
				return claims.IsValidExpiresAt(after)
			},
			false,
		},
		{
			&RegisteredClaims{ExpiresAt: NewNumericDate(after)},
			func(claims *RegisteredClaims) bool {
				return claims.IsValidExpiresAt(before)
			},
			true,
		},

		// IsValidIssuedAt
		{
			&RegisteredClaims{},
			func(claims *RegisteredClaims) bool {
				return claims.IsValidIssuedAt(after)
			},
			true,
		},
		{
			&RegisteredClaims{IssuedAt: NewNumericDate(before)},
			func(claims *RegisteredClaims) bool {
				return claims.IsValidIssuedAt(after)
			},
			true,
		},
		{
			&RegisteredClaims{IssuedAt: NewNumericDate(after)},
			func(claims *RegisteredClaims) bool {
				return claims.IsValidIssuedAt(before)
			},
			false,
		},

		// IsValidNotBefore
		{
			&RegisteredClaims{},
			func(claims *RegisteredClaims) bool {
				return claims.IsValidNotBefore(after)
			},
			true,
		},
		{
			&RegisteredClaims{NotBefore: NewNumericDate(before)},
			func(claims *RegisteredClaims) bool {
				return claims.IsValidNotBefore(after)
			},
			true,
		},
		{
			&RegisteredClaims{NotBefore: NewNumericDate(after)},
			func(claims *RegisteredClaims) bool {
				return claims.IsValidNotBefore(before)
			},
			false,
		},
	}

	for _, tc := range testCases {
		mustEqual(t, tc.f(tc.claims), tc.want)
	}
}

func TestIsValidAt(t *testing.T) {
	now := time.Now()
	before := now.Add(-time.Minute)
	beforeNow := now.Add(-10 * time.Second)
	afterNow := now.Add(10 * time.Second)
	after := now.Add(time.Minute)

	testCases := []struct {
		claims *RegisteredClaims
		f      func(claims *RegisteredClaims) bool
		want   bool
	}{
		{
			&RegisteredClaims{},
			func(claims *RegisteredClaims) bool { return claims.IsValidAt(after) },
			true,
		},
		{
			&RegisteredClaims{
				ExpiresAt: NewNumericDate(after),
				NotBefore: NewNumericDate(before),
				IssuedAt:  NewNumericDate(beforeNow),
			},
			func(claims *RegisteredClaims) bool { return claims.IsValidAt(now) },
			true,
		},
		{
			&RegisteredClaims{
				ExpiresAt: NewNumericDate(after),
				NotBefore: NewNumericDate(before),
				IssuedAt:  NewNumericDate(afterNow),
			},
			func(claims *RegisteredClaims) bool { return claims.IsValidAt(now) },
			false,
		},
	}

	for _, tc := range testCases {
		mustEqual(t, tc.f(tc.claims), tc.want)
	}
}
