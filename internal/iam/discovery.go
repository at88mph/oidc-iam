package iam

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/at88mph/oidc-iam/internal/account"
)

type discoveryDocument struct {
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

// EnsureEndpoints loads OIDC discovery metadata when endpoints are missing.
func EnsureEndpoints(a *account.Account) error {
	if a.TokenEndpoint != "" && a.DeviceAuthorizationEndpoint != "" {
		return nil
	}
	if a.Issuer == "" {
		return fmt.Errorf("missing issuer")
	}
	issuer := a.Issuer
	if !strings.HasSuffix(issuer, "/") {
		issuer += "/"
	}
	url := issuer + ".well-known/openid-configuration"
	resp, err := http.Get(url) //nolint:noctx // CLI tool
	if err != nil {
		return fmt.Errorf("discovery GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery GET %s: HTTP %s", url, resp.Status)
	}
	var doc discoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("discovery decode: %w", err)
	}
	if doc.TokenEndpoint == "" {
		return fmt.Errorf("no token_endpoint in discovery for %s", a.Issuer)
	}
	if doc.DeviceAuthorizationEndpoint == "" {
		return fmt.Errorf("no device_authorization_endpoint (device flow not enabled?)")
	}
	a.TokenEndpoint = doc.TokenEndpoint
	a.DeviceAuthorizationEndpoint = doc.DeviceAuthorizationEndpoint
	return nil
}
