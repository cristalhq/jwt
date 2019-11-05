package jwt

import "encoding/json"

// Audience is a special claim that be a single string or an array of strings
// see RFC 7519.
type Audience []string

// MarshalJSON implements a marshaling function for "aud" claim.
func (a Audience) MarshalJSON() ([]byte, error) {
	switch len(a) {
	case 0:
		return json.Marshal("")
	case 1:
		return json.Marshal(a[0])
	default:
		return json.Marshal([]string(a))
	}
}

// UnmarshalJSON implements json.Unmarshaler interface.
func (a *Audience) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}

	switch v := v.(type) {
	case string:
		*a = Audience{v}
	case []interface{}:
		aud := make(Audience, len(v))
		for i := range v {
			aud[i] = v[i].(string)
		}
		*a = aud
	}
	return nil
}
