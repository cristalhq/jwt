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
	f := func(got string, want NumericDate) {
		t.Helper()

		var a NumericDate
		err := json.Unmarshal([]byte(got), &a)
		if err != nil {
			t.Errorf("want no err, got: %#v", err)
		}
	}

	f(`1588707274.3769999`, NumericDate{})
	// f(`[]`, NumericDate{})
	// f(`"admin"`, NumericDate{"admin"})
	// f(`["admin"]`, NumericDate{"admin"})
	// f(`["admin","co-admin"]`, NumericDate{"admin", "co-admin"})
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
	f(`abc12`)
	f(`{}`)
	f(`[{}]`)
	f(`["admin",{}]`)
	f(`["admin",123]`)
	f(`abc12`)
	f(`{}`)
	f(`[]`)
}
