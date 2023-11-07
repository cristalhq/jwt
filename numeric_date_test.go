package jwt

import (
	"strconv"
	"testing"
	"time"
)

func TestNumericDateMarshal(t *testing.T) {
	f := func(got *NumericDate, want string) {
		t.Helper()

		raw, err := got.MarshalJSON()
		mustOk(t, err)
		mustEqual(t, string(raw), want)
	}

	now := time.Now()
	nowTS := now.Unix()

	f(NewNumericDate(time.Time{}), `null`)
	f(NewNumericDate(now), strconv.Itoa(int(nowTS)))
}

func TestNumericDateUnmarshal(t *testing.T) {
	f := func(s string, want NumericDate) {
		t.Helper()

		var got NumericDate
		err := got.UnmarshalJSON([]byte(s))
		mustOk(t, err)
		mustEqual(t, got.Unix(), want.Unix())
	}

	f(`1588707274`, asNumericDate(1588707274))
	f(`1588707274.3769999`, asNumericDate(1588707274))
	f(`"12345"`, asNumericDate(12345))
}

func TestNumericDateUnmarshalMalformed(t *testing.T) {
	f := func(got string) {
		t.Helper()

		var nd NumericDate
		err := nd.UnmarshalJSON([]byte(got))
		mustFail(t, err)
	}

	f(``)
	f(`{}`)
	f(`[{}]`)
	f(`abc12`)
	f(`"abc"`)
	f(`["admin",{}]`)
	f(`["admin",123]`)
	f(`{}`)
	f(`[]`)
	f(`1e+309`)
}

func asNumericDate(n int64) NumericDate {
	return *NewNumericDate(time.Unix(n, 0))
}
