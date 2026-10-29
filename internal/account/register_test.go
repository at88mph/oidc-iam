package account

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegister(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OIDC_IAM_CONFIG_DIR", dir)

	path, err := Register("wlcg", "https://iam.example.org", "cid", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "wlcg.json")
	if path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 0600", info.Mode().Perm())
	}

	a, _, err := Load("wlcg")
	if err != nil {
		t.Fatal(err)
	}
	if a.Issuer != "https://iam.example.org/" {
		t.Fatalf("issuer = %q, want trailing slash", a.Issuer)
	}
	if a.Scope != defaultScope {
		t.Fatalf("scope = %q, want %q", a.Scope, defaultScope)
	}

	_, err = Register("custom", "https://iam.example.org", "cid", "secret", "openid wlcg offline_access")
	if err != nil {
		t.Fatal(err)
	}
	a, _, err = Load("custom")
	if err != nil {
		t.Fatal(err)
	}
	if a.Scope != "openid wlcg offline_access" {
		t.Fatalf("scope = %q", a.Scope)
	}

	_, err = Register("wlcg", "https://iam.example.org", "other", "secret", "")
	if err == nil {
		t.Fatal("expected error when account exists")
	}
}
