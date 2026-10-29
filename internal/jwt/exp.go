package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// ExpiresAt returns the exp claim from an unparsed JWT, if present.
func ExpiresAt(token string) (int64, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return 0, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		padding := strings.Repeat("=", (-len(parts[1]) % 4))
		payload, err = base64.URLEncoding.DecodeString(parts[1] + padding)
		if err != nil {
			return 0, false
		}
	}
	var claims struct {
		Exp float64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return 0, false
	}
	return int64(claims.Exp), true
}
