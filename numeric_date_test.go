package jwt

import (
	"strconv"
	"testing"
	"time"
)

func TestNumericDateMarshal(t *testing.T) {
	now := time.Now()
	nowTS := now.Unix()

	testCases := []struct {
		value *NumericDate
		want  string
	}{
		{NewNumericDate(time.Time{}), `null`},
		{NewNumericDate(now), strconv.Itoa(int(nowTS))},
	}

	for _, tc := range testCases {
		raw, err := tc.value.MarshalJSON()
		mustOk(t, err)
		mustEqual(t, string(raw), tc.want)
	}
}

func TestNumericDateUnmarshal(t *testing.T) {
	testCases := []struct {
		s    string
		want NumericDate
	}{
		{`1588707274`, asNumericDate(1588707274)},
		{`1588707274.3769999`, asNumericDate(1588707274)},
		{`"12345"`, asNumericDate(12345)},
	}

	for _, tc := range testCases {
		var have NumericDate
		err := have.UnmarshalJSON([]byte(tc.s))
		mustOk(t, err)
		mustEqual(t, have.Unix(), tc.want.Unix())
	}
}

func TestNumericDateUnmarshalMalformed(t *testing.T) {
	testCases := []struct {
		value string
	}{
		{``},
		{`{}`},
		{`[{}]`},
		{`abc12`},
		{`"abc"`},
		{`["admin",{}]`},
		{`["admin",123]`},
		{`{}`},
		{`[]`},
		{`1e+309`},
	}

	for _, tc := range testCases {
		var nd NumericDate
		err := nd.UnmarshalJSON([]byte(tc.value))
		mustFail(t, err)
	}
}

func asNumericDate(n int64) NumericDate {
	return *NewNumericDate(time.Unix(n, 0))
}
