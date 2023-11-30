package jwt

import (
	"testing"
)

func TestAudienceMarshal(t *testing.T) {
	testCases := []struct {
		have Audience
		want string
	}{
		{nil, `""`},
		{Audience{}, `""`},
		{Audience{"admin"}, `"admin"`},
		{Audience{"admin", "co-admin"}, `["admin","co-admin"]`},
	}

	for _, tc := range testCases {
		raw, err := tc.have.MarshalJSON()
		mustOk(t, err)
		mustEqual(t, string(raw), tc.want)
	}
}

func TestAudienceUnmarshal(t *testing.T) {
	testCases := []struct {
		have string
		want Audience
	}{
		{`[]`, Audience{}},
		{`"admin"`, Audience{"admin"}},
		{`["admin"]`, Audience{"admin"}},
		{`["admin","co-admin"]`, Audience{"admin", "co-admin"}},
	}

	for _, tc := range testCases {
		var a Audience
		err := a.UnmarshalJSON([]byte(tc.have))
		mustOk(t, err)
		mustEqual(t, len(a), len(tc.want))

		for i := range a {
			mustEqual(t, a[i], tc.want[i])
		}
	}
}

func TestAudienceUnmarshalMalformed(t *testing.T) {
	testCases := []struct {
		have string
	}{
		{``},
		{`abc12`},
		{`123`},
		{`{}`},
		{`[{}]`},
		{`["admin",{}]`},
		{`["admin",123]`},
	}

	for _, tc := range testCases {
		var a Audience
		err := a.UnmarshalJSON([]byte(tc.have))
		mustFail(t, err)
	}
}
