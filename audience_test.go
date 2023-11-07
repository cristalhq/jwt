package jwt

import (
	"testing"
)

func TestAudienceMarshal(t *testing.T) {
	f := func(got Audience, want string) {
		t.Helper()

		raw, err := got.MarshalJSON()
		mustOk(t, err)
		mustEqual(t, string(raw), want)
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
		mustOk(t, err)
		mustEqual(t, len(a), len(want))

		for i := range a {
			mustEqual(t, a[i], want[i])
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
		mustFail(t, err)
	}

	f(``)
	f(`abc12`)
	f(`123`)
	f(`{}`)
	f(`[{}]`)
	f(`["admin",{}]`)
	f(`["admin",123]`)
}
