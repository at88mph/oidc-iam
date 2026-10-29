package jwt

import (
	"encoding/base64"
	"testing"
)

func TestExpiresAt(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":1700000000}`))
	tok := "header." + payload + ".sig"
	got, ok := ExpiresAt(tok)
	if !ok || got != 1700000000 {
		t.Fatalf("ExpiresAt() = (%d, %v), want (1700000000, true)", got, ok)
	}
	_, ok = ExpiresAt("not-a-jwt")
	if ok {
		t.Fatal("expected false for non-JWT")
	}
}
