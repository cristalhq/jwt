package jwt

import (
	"encoding/json"
	"testing"
)

func TestNumericDateMarshal(t *testing.T) {
	f := func(got *NumericDate, want string) {
		t.Helper()

		raw, err := json.Marshal(got)
		if err != nil {
			t.Errorf("want no err, got: %v", err)
		}

		if string(raw) != want {
			t.Errorf("want %#v, got: %#v", want, string(raw))
		}
	}

	_ = f
	// now := time.Now()
	// f(NewNumericDate(now), `""`)
	// f(NewNumericDate(time.Time{}), `["admin","co-admin"]`)
	// f(NumericDate{now}, now.String())
}

// func TestNumericDateUnmarshal(t *testing.T) {
// 	f := func(got string, want NumericDate, wantErr bool) {
// 		t.Helper()

// 		var a NumericDate
// 		err := json.Unmarshal([]byte(got), &a)
// 		if err != nil {
// 			if !wantErr {
// 				t.Errorf("want no err, got: %v", err)
// 			}
// 		} else {
// 			if wantErr {
// 				t.Errorf("want no err, got: %v", err)
// 			}
// 		}

// 		if len(want) != len(a) {
// 			t.Errorf("want %#v, got: %#v", len(want), len(a))
// 		}
// 		for i := range a {
// 			if a[i] != want[i] {
// 				t.Errorf("want %#v, got: %#v", want[i], a[i])
// 			}
// 		}
// 	}

// 	f(`abc12`, NumericDate{}, true)
// 	f(`{}`, NumericDate{}, true)
// 	f(`[]`, NumericDate{}, false)
// 	f(`"admin"`, NumericDate{"admin"}, false)
// 	f(`["admin"]`, NumericDate{"admin"}, false)
// 	f(`["admin","co-admin"]`, NumericDate{"admin", "co-admin"}, false)
// }
