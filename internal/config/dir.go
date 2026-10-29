package config

import (
	"os"
	"path/filepath"
)

const defaultConfigDir = ".config/oidc-iam"

// Dir returns the directory holding account JSON files.
func Dir() (string, error) {
	if d := os.Getenv("OIDC_IAM_CONFIG_DIR"); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, defaultConfigDir), nil
}
