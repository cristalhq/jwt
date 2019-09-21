package jwt

import (
	"encoding/json"
	"testing"
)

func TestTimestampMarshal(t *testing.T) {
	f := func(got Timestamp, want string) {
		t.Helper()

		raw, err := json.Marshal(got)
		if err != nil {
			t.Errorf("want no err, got: %v", err)
		}

		if string(raw) != want {
			t.Errorf("want `%v`, got: `%v`", want, string(raw))
		}
	}

	f(0, `0`)
	f(Timestamp(42), `42`)
}

func TestTimestampUnmarshal(t *testing.T) {
	f := func(got string, want Timestamp) {
		t.Helper()

		var ts Timestamp
		err := json.Unmarshal([]byte(got), &ts)
		if err != nil {
			t.Errorf("want no err, got: %v", err)
		}

		if want != ts {
			t.Errorf("want `%v`, got: `%v`", want, ts)
		}
	}

	f(`null`, 0)
	f(`0`, 0)
	f(`42`, 42)
}
