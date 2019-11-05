package jwt

import (
	"strconv"
	"time"
)

// Timestamp represents time as number of seconds from 1970-01-01T00:00:00Z UTC until the specified moment.
type Timestamp int64

// Time used to convert int64 to time.Time.
func (t Timestamp) Time() time.Time {
	if t == 0 {
		return time.Time{}
	}
	return time.Unix(int64(t), 0)
}

// UnmarshalJSON implements json.Unmarshaler interface.
func (t *Timestamp) UnmarshalJSON(data []byte) error {
	s := string(data)
	if s == "null" {
		return nil
	}

	q, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}

	*(*int64)(t) = q
	return nil
}
