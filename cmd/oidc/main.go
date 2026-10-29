package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/at88mph/oidc-iam/internal/account"
	"github.com/at88mph/oidc-iam/internal/iam"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "oidc: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("missing command")
	}
	switch args[0] {
	case "login":
		return cmdLogin(args[1:])
	case "token":
		return cmdToken(args[1:])
	case "register":
		return cmdRegister(args[1:])
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func cmdLogin(args []string) error {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: oidc login <account>")
		return fmt.Errorf("login requires exactly one account name")
	}
	return iam.Login(args[0], bufio.NewReader(os.Stdin))
}

func cmdToken(args []string) error {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: oidc token <account>")
		return fmt.Errorf("token requires exactly one account name")
	}
	tok, err := iam.AccessToken(args[0])
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}

func cmdRegister(args []string) error {
	if len(args) < 4 {
		fmt.Fprintln(os.Stderr, "Usage: oidc register <name> <issuer> <client_id> <client_secret> [scope ...]")
		return fmt.Errorf("register requires name, issuer, client ID, and client secret")
	}
	scope := strings.Join(args[4:], " ")
	path, err := account.Register(args[0], args[1], args[2], args[3], scope)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "oidc: account created at %s\n", path)
	return nil
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage:
  oidc register <name> <issuer> <client_id> <client_secret> [scope ...]
                         Create account JSON (default scope: openid profile offline_access)
  oidc login <account>   Device code login; store tokens in ~/.config/oidc-iam/<account>.json
  oidc token <account>   Print a valid access token (refresh when needed)

Environment:
  OIDC_IAM_CONFIG_DIR    Account directory (default: ~/.config/oidc-iam)`)
}
