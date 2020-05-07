package jwt

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

func TestNumericDateMarshal(t *testing.T) {
	f := func(got *NumericDate, want string) {
		t.Helper()

		raw, err := json.Marshal(got)
		if err != nil {
			t.Errorf("want no err, got: %#v", err)
		}

		if string(raw) != want {
			t.Errorf("want %#v, got: %#v", want, string(raw))
		}
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
		err := json.Unmarshal([]byte(s), &got)
		if err != nil {
			t.Errorf("want no err, got: %#v", err)
		}
		if got.Unix() != want.Unix() {
			t.Errorf("want %#v, got %#v", want.Unix(), got.Unix())
		}
	}

	f(`1588707274`, asNumericDate(1588707274))
	f(`1588707274.3769999`, asNumericDate(1588707274))
	f(`"12345"`, asNumericDate(12345))
}

func TestNumericDateUnmarshalMalformed(t *testing.T) {
	f := func(got string) {
		t.Helper()

		var nd NumericDate
		err := json.Unmarshal([]byte(got), &nd)
		if err == nil {
			t.Error("want err")
		}
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
}

func asNumericDate(n int64) NumericDate {
	return *NewNumericDate(time.Unix(n, 0))
}
