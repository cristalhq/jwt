package jwt

import (
	"encoding/json"
	"time"
)

const marshalTimePrecision = time.Second

// NumericDate represents date for StandardClaims
// See: https://tools.ietf.org/html/rfc7519#section-2
//
type NumericDate struct {
	time.Time
}

// NewNumericDate creates a new NumericDate value from time.Time.
func NewNumericDate(t time.Time) *NumericDate {
	if t.IsZero() {
		return nil
	}
	out := NumericDate{t}
	return &out
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (t *NumericDate) UnmarshalJSON(data []byte) error {
	var value json.Number
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	f, err := value.Float64()
	if err != nil {
		return err
	}
	secs := int64(f)
	nSecs := int64((f - float64(secs)) * 1e9)
	*t = NumericDate{time.Unix(secs, nSecs)}
	return nil
}

// MarshalJSON implements the json.Marshaler interface.
func (t *NumericDate) MarshalJSON() ([]byte, error) {
	ts := t.Truncate(marshalTimePrecision).UnixNano()
	f := float64(ts) / float64(time.Second)
	return json.Marshal(f)
}
