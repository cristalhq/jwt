package jwt

import (
	"encoding/json"
	"testing"
)

func TestAudienceMarshal(t *testing.T) {
	f := func(got Audience, want string) {
		t.Helper()

		raw, err := json.Marshal(got)
		if err != nil {
			t.Errorf("want no err, got: %v", err)
		}

		if string(raw) != want {
			t.Errorf("want `%v`, got: `%v`", want, string(raw))
		}
	}

	f(nil, `""`)
	f(Audience{}, `""`)
	f(Audience{"admin"}, `"admin"`)
	f(Audience{"admin", "co-admin"}, `["admin","co-admin"]`)
}

func TestAudienceUnmarshal(t *testing.T) {
	f := func(got string, want Audience, wantErr bool) {
		t.Helper()

		var a Audience
		err := json.Unmarshal([]byte(got), &a)
		if err != nil {
			if !wantErr {
				t.Errorf("want no err, got: %v", err)
			}
		} else {
			if wantErr {
				t.Errorf("want no err, got: %v", err)
			}
		}

		if len(want) != len(a) {
			t.Errorf("want `%v`, got: `%v`", len(want), len(a))
		}
		for i := range a {
			if a[i] != want[i] {
				t.Errorf("want `%v`, got: `%v`", want[i], a[i])
			}
		}
	}

	f(`abc12`, Audience{}, true)
	f(`{}`, Audience{}, true)
	f(`[]`, Audience{}, false)
	f(`"admin"`, Audience{"admin"}, false)
	f(`["admin"]`, Audience{"admin"}, false)
	f(`["admin","co-admin"]`, Audience{"admin", "co-admin"}, false)
}
