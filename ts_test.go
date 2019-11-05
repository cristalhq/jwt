package jwt

import (
	"encoding/json"
	"testing"
	"time"
)

func TestTimestampMarshal(t *testing.T) {
	f := func(got Timestamp, want time.Time) {
		t.Helper()

		if got.Time().Equal(want) {
			t.Errorf("want `%v`, got: `%v`", want, got.Time())
		}
	}

	f(0, time.Time{})
	f(Timestamp(0), time.Time{})

	now := time.Now()
	f(Timestamp(now.Unix()), now)
}

func TestTimestampUnmarshal(t *testing.T) {
	f := func(got string, want Timestamp, shouldErr bool) {
		t.Helper()

		var ts Timestamp
		err := json.Unmarshal([]byte(got), &ts)
		if err != nil && !shouldErr {
			t.Errorf("want no err, got: %v", err)
		}
		if err == nil && shouldErr {
			t.Errorf("want err, but got nil")
		}

		if want != ts {
			t.Errorf("want `%v`, got: `%v`", want, ts)
		}
	}

	f(`null`, 0, false)
	f(`0`, 0, false)
	f(`42`, 42, false)

	f(``, 0, true)
	f(`a4`, 0, true)
	f(`"42"`, 0, true)
}
