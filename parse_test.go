package jwt

import (
	"testing"
)

func TestParseString(t *testing.T) {
	f := func(got string, header Header, payload, signature string) {
		t.Helper()

		_, err := ParseString(got)
		if err == nil {
			t.Error("got nil want nil")
		}
	}

	// TODO
	f(``, Header{}, "", "")
}

func TestParseMalformed(t *testing.T) {
	f := func(got string) {
		t.Helper()

		_, err := ParseString(got)
		if err == nil {
			t.Error("got nil want nil")
		}
	}

	f(`xyz.xyz`)
	f(`a.xyz.xyz`)
	f(`xyz.ab/c.xyz`)
	f(`xyz.abc.x/yz`)
	f(`x/z.ab_c.xyz`)
	f(`ab_c.xyz.xyz`)
}
