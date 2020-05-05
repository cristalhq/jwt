package jwt

import (
	"encoding/json"
	"math"
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
	return &NumericDate{t}
}

// MarshalJSON implements the json.Marshaler interface.
func (t *NumericDate) MarshalJSON() ([]byte, error) {
	ts := t.Truncate(marshalTimePrecision).UnixNano()
	f := float64(ts) / float64(time.Second)
	return json.Marshal(f)
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
	sec, dec := math.Modf(f)
	ts := time.Unix(int64(sec), int64(dec*1e9))
	*t = NumericDate{ts}
	return nil
}
