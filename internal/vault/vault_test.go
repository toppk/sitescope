package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func save(t *testing.T, path string, pass string, base *Secrets, kv ...string) {
	t.Helper()
	e := NewEdit()
	defer e.Destroy()
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == "" {
			e.Remove(kv[i])
			continue
		}
		if err := e.Set(kv[i], []byte(kv[i+1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := Save(path, []byte(pass), base, e); err != nil {
		t.Fatal(err)
	}
}

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.age")
	save(t, path, "correct horse", nil, "linode_token", "tok-linode-123", "cloudflare_token", "cf-456")

	s, err := Load(path, []byte("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(s.Names(), ","); got != "cloudflare_token,linode_token" {
		t.Fatalf("names = %s", got)
	}
	if v, _ := s.Get("linode_token"); v != "tok-linode-123" {
		t.Fatalf("linode_token = %q", v)
	}

	// edit on top of the loaded vault: replace one, remove one, add one
	save(t, path, "correct horse", s, "linode_token", "tok-new", "cloudflare_token", "", "x", "y")
	s.Destroy()
	if s.Names() != nil && len(s.Names()) != 0 {
		t.Fatal("destroyed vault still lists names")
	}
	s2, err := Load(path, []byte("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Destroy()
	if got := strings.Join(s2.Names(), ","); got != "linode_token,x" {
		t.Fatalf("names after edit = %s", got)
	}
	if v, _ := s2.Get("linode_token"); v != "tok-new" {
		t.Fatalf("linode_token = %q", v)
	}
}

func TestWrongPassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.age")
	save(t, path, "right", nil, "a", "b")
	if _, err := Load(path, []byte("wrong")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("err = %v, want ErrWrongPassphrase", err)
	}
	if _, err := Load(path, nil); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("empty passphrase: err = %v", err)
	}
}

func TestNoPlaintextOnDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	secret := "SUPER-SECRET-TOKEN-VALUE-0123456789"
	save(t, path, "pw", nil, "token_name_marker", secret)
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("expected only the vault file, found %d entries", len(entries))
	}
	b, _ := os.ReadFile(path)
	for _, needle := range []string{secret, "token_name_marker", "SSV1"} {
		if bytes.Contains(b, []byte(needle)) {
			t.Fatalf("vault file contains %q in plaintext", needle)
		}
	}
	if !bytes.HasPrefix(b, []byte("age-encryption.org/v1")) {
		t.Fatal("vault is not an age file")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", fi.Mode().Perm())
	}
}

func TestInvalidName(t *testing.T) {
	e := NewEdit()
	if err := e.Set("bad name", []byte("v")); err == nil {
		t.Fatal("accepted a name with a space")
	}
}

func TestTooLarge(t *testing.T) {
	e := NewEdit()
	defer e.Destroy()
	e.Set("big", bytes.Repeat([]byte("x"), MaxSize))
	if err := Encrypt(&bytes.Buffer{}, []byte("pw"), nil, e); err == nil {
		t.Fatal("oversized vault accepted")
	}
}
