package jwt

import (
	"encoding/json"
)

type customClaims struct {
	StandardClaims

	TestField string `json:"test_field"`
}

func (cs *customClaims) MarshalBinary() (data []byte, err error) {
	return json.Marshal(cs)
}
