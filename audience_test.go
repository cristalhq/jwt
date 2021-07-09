package jwt

import (
	"testing"
)

func TestAudienceMarshal(t *testing.T) {
	f := func(got Audience, want string) {
		t.Helper()

		raw, err := got.MarshalJSON()
		if err != nil {
			t.Errorf("want no err, got: %#v", err)
		}

		if string(raw) != want {
			t.Errorf("want %#v, got: %#v", want, string(raw))
		}
	}

	f(nil, `""`)
	f(Audience{}, `""`)
	f(Audience{"admin"}, `"admin"`)
	f(Audience{"admin", "co-admin"}, `["admin","co-admin"]`)
}

func TestAudienceUnmarshal(t *testing.T) {
	f := func(got string, want Audience) {
		t.Helper()

		var a Audience
		err := a.UnmarshalJSON([]byte(got))
		if err != nil {
			t.Errorf("want no err, got: %#v", err)
		}

		if len(want) != len(a) {
			t.Errorf("want %#v, got: %#v", len(want), len(a))
		}
		for i := range a {
			if a[i] != want[i] {
				t.Errorf("want %#v, got: %#v", want[i], a[i])
			}
		}
	}

	f(`[]`, Audience{})
	f(`"admin"`, Audience{"admin"})
	f(`["admin"]`, Audience{"admin"})
	f(`["admin","co-admin"]`, Audience{"admin", "co-admin"})
}

func TestAudienceUnmarshalMalformed(t *testing.T) {
	f := func(got string) {
		t.Helper()

		var a Audience
		err := a.UnmarshalJSON([]byte(got))
		if err == nil {
			t.Error("want err")
		}
	}

	f(``)
	f(`abc12`)
	f(`123`)
	f(`{}`)
	f(`[{}]`)
	f(`["admin",{}]`)
	f(`["admin",123]`)
}
