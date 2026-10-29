package iam

import (
	"bufio"
	"fmt"
	"os"

	"github.com/at88mph/oidc-iam/internal/account"
)

// Login runs the device code flow and persists tokens.
func Login(name string, in *bufio.Reader) error {
	a, path, err := account.Load(name)
	if err != nil {
		return err
	}
	if err := EnsureEndpoints(a); err != nil {
		return err
	}
	if err := account.Save(path, a); err != nil {
		return err
	}

	start, err := StartDeviceAuthorization(a)
	if err != nil {
		return err
	}
	verify := start.VerificationURIComplete
	if verify == "" {
		verify = start.VerificationURI
	}
	fmt.Fprintf(os.Stderr, "Open: %s\n", verify)
	fmt.Fprintf(os.Stderr, "Code: %s\n", start.UserCode)
	fmt.Fprint(os.Stderr, "Press Enter after signing in in the browser...")
	if _, err := in.ReadString('\n'); err != nil {
		return err
	}

	if err := PollDeviceAuthorization(a, start.DeviceCode, start.Interval); err != nil {
		return err
	}
	if err := account.Save(path, a); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "oidc: tokens saved to %s\n", path)
	return nil
}