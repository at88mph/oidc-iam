package account

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/at88mph/oidc-iam/internal/config"
	"github.com/at88mph/oidc-iam/internal/jwt"
)

const (
	accessSlackSeconds   = 60
	refreshSlackSeconds  = 300
	defaultScope         = "openid profile offline_access"
)

// Account is stored as ~/.config/oidc-iam/<name>.json.
type Account struct {
	Issuer                      string `json:"issuer"`
	ClientID                    string `json:"client_id"`
	ClientSecret                string `json:"client_secret"`
	Scope                       string `json:"scope"`
	AccessToken                 string `json:"access_token"`
	RefreshToken                string `json:"refresh_token"`
	TokenType                   string `json:"token_type"`
	ExpiresAt                   int64  `json:"expires_at"`
	RefreshExpiresAt            int64  `json:"refresh_expires_at"`
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

// Path returns the on-disk path for a named account.
func Path(name string) (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".json"), nil
}

// Load reads an account by name.
func Load(name string) (*Account, string, error) {
	path, err := Path(name)
	if err != nil {
		return nil, "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, path, fmt.Errorf("account %q not found at %s", name, path)
		}
		return nil, path, err
	}
	var a Account
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, path, fmt.Errorf("parse %s: %w", path, err)
	}
	if a.Scope == "" {
		a.Scope = defaultScope
	}
	return &a, path, nil
}

// Save writes the account atomically with mode 0600.
func Save(path string, a *Account) error {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".oidc-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// ApplyTokenResponse updates tokens from an OAuth token response.
func (a *Account) ApplyTokenResponse(accessToken, refreshToken, tokenType string, expiresIn int) {
	now := time.Now().Unix()
	a.AccessToken = accessToken
	if refreshToken != "" {
		a.RefreshToken = refreshToken
		if exp, ok := jwt.ExpiresAt(refreshToken); ok {
			a.RefreshExpiresAt = exp
		}
	}
	if tokenType != "" {
		a.TokenType = tokenType
	} else {
		a.TokenType = "Bearer"
	}
	if expiresIn > 0 {
		a.ExpiresAt = now + int64(expiresIn)
	}
}

// NeedsRefresh reports whether a new access token should be fetched.
func (a *Account) NeedsRefresh(now time.Time) bool {
	if a.AccessToken == "" {
		return true
	}
	unix := now.Unix()
	if a.ExpiresAt > 0 && a.ExpiresAt-unix <= accessSlackSeconds {
		return true
	}
	if a.RefreshToken != "" && a.RefreshExpiresAt > 0 && a.RefreshExpiresAt-unix <= refreshSlackSeconds {
		return true
	}
	return false
}
