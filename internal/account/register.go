package account

import (
	"fmt"
	"os"
	"strings"
)

// Register creates a new account JSON file. It errors if the account already exists.
// scope is optional; empty means defaultScope.
func Register(name, issuer, clientID, clientSecret, scope string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("account name is required")
	}
	if strings.Contains(name, "/") || strings.Contains(name, string(os.PathSeparator)) || name == "." || name == ".." {
		return "", fmt.Errorf("invalid account name %q", name)
	}
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return "", fmt.Errorf("issuer URL is required")
	}
	if !strings.HasSuffix(issuer, "/") {
		issuer += "/"
	}
	if clientID == "" {
		return "", fmt.Errorf("client ID is required")
	}
	if clientSecret == "" {
		return "", fmt.Errorf("client secret is required")
	}
	scope = strings.TrimSpace(scope)
	if scope == "" {
		scope = defaultScope
	}

	path, err := Path(name)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); err == nil {
		return path, fmt.Errorf("account %q already exists at %s", name, path)
	} else if !os.IsNotExist(err) {
		return path, err
	}

	a := &Account{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scope:        scope,
	}
	if err := Save(path, a); err != nil {
		return path, err
	}
	return path, nil
}
