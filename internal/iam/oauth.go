package iam

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/at88mph/oidc-iam/internal/account"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

type deviceStartResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	Interval                int    `json:"interval"`
}

func postForm(tokenURL string, clientID, clientSecret string, form url.Values) (*tokenResponse, int, error) {
	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := http.DefaultClient.Do(req) //nolint:noctx
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("token response: %w (body: %s)", err, truncate(body))
	}
	return &tr, resp.StatusCode, nil
}

func truncate(b []byte) string {
	const max = 200
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "..."
}

// Refresh exchanges the refresh token for new tokens.
func Refresh(a *account.Account) error {
	if err := EnsureEndpoints(a); err != nil {
		return err
	}
	if a.RefreshToken == "" {
		return fmt.Errorf("no refresh_token; run device login first")
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {a.RefreshToken},
	}
	tr, status, err := postForm(a.TokenEndpoint, a.ClientID, a.ClientSecret, form)
	if err != nil {
		return fmt.Errorf("refresh: %w", err)
	}
	if tr.AccessToken == "" {
		msg := tr.Error
		if tr.ErrorDesc != "" {
			msg = tr.ErrorDesc
		}
		if msg == "" {
			msg = http.StatusText(status)
		}
		return fmt.Errorf("refresh failed: %s", msg)
	}
	a.ApplyTokenResponse(tr.AccessToken, tr.RefreshToken, tr.TokenType, tr.ExpiresIn)
	return nil
}

// StartDeviceAuthorization begins the OAuth device code flow.
func StartDeviceAuthorization(a *account.Account) (*deviceStartResponse, error) {
	if err := EnsureEndpoints(a); err != nil {
		return nil, err
	}
	form := url.Values{
		"client_id": {a.ClientID},
		"scope":     {a.Scope},
	}
	req, err := http.NewRequest(http.MethodPost, a.DeviceAuthorizationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(a.ClientID, a.ClientSecret)

	resp, err := http.DefaultClient.Do(req) //nolint:noctx
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("device authorization: HTTP %s: %s", resp.Status, truncate(body))
	}
	var start deviceStartResponse
	if err := json.NewDecoder(resp.Body).Decode(&start); err != nil {
		return nil, fmt.Errorf("device authorization decode: %w", err)
	}
	if start.DeviceCode == "" {
		return nil, fmt.Errorf("device authorization: missing device_code")
	}
	if start.Interval <= 0 {
		start.Interval = 5
	}
	return &start, nil
}

// PollDeviceAuthorization waits until the user completes browser login.
func PollDeviceAuthorization(a *account.Account, deviceCode string, interval int) error {
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
	}
	for {
		tr, _, err := postForm(a.TokenEndpoint, a.ClientID, a.ClientSecret, form)
		if err != nil {
			return fmt.Errorf("device poll: %w", err)
		}
		if tr.AccessToken != "" {
			a.ApplyTokenResponse(tr.AccessToken, tr.RefreshToken, tr.TokenType, tr.ExpiresIn)
			return nil
		}
		switch tr.Error {
		case "authorization_pending":
			time.Sleep(time.Duration(interval) * time.Second)
		case "slow_down":
			interval++
			time.Sleep(time.Duration(interval) * time.Second)
		case "":
			return fmt.Errorf("device login failed: empty response")
		default:
			msg := tr.Error
			if tr.ErrorDesc != "" {
				msg = tr.ErrorDesc
			}
			return fmt.Errorf("device login failed: %s", msg)
		}
	}
}

// AccessToken returns a valid access token, refreshing when needed.
func AccessToken(name string) (string, error) {
	a, path, err := account.Load(name)
	if err != nil {
		return "", err
	}
	hadEndpoints := a.TokenEndpoint != ""
	if err := EnsureEndpoints(a); err != nil {
		return "", err
	}
	dirty := !hadEndpoints && a.TokenEndpoint != ""
	if a.NeedsRefresh(time.Now()) {
		if err := Refresh(a); err != nil {
			return "", fmt.Errorf("%w (try: oidc login %s)", err, name)
		}
		dirty = true
	}
	if dirty {
		if err := account.Save(path, a); err != nil {
			return "", err
		}
	}
	return a.AccessToken, nil
}
