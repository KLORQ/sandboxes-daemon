package registrycredentials

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

type fakeVault struct {
	service string
	account string
	secret  string
	err     error
	reads   int
}

func (f *fakeVault) Get(_ context.Context, service, account string) (string, error) {
	f.reads++
	if f.service != service || f.account != account {
		return "", ErrNotFound
	}
	return f.secret, f.err
}

func (f *fakeVault) Set(_ context.Context, service, account, secret string) error {
	f.service, f.account, f.secret = service, account, secret
	return f.err
}

func (f *fakeVault) Delete(_ context.Context, service, account string) error {
	f.service, f.account = service, account
	return f.err
}

func TestSaveRegistryCredential(t *testing.T) {
	vault := &fakeVault{}
	store, err := NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := store.Save(context.Background(), Credential{
		Registry: "GHCR.IO", Username: "alice", Password: []byte("synthetic-token"), Scope: ScopeSandbox, SandboxName: "sample",
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Registry != "ghcr.io" || summary.Scope != ScopeSandbox || summary.SandboxName != "sample" {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	if vault.service != vaultService || vault.account != "ghcr.io/sandbox/sample" {
		t.Fatalf("unexpected vault key: %q / %q", vault.service, vault.account)
	}
	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal([]byte(vault.secret), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Username != "alice" || payload.Password != "synthetic-token" {
		t.Fatal("stored credential payload mismatch")
	}
}

func TestSaveRejectsInvalidCredentialWithoutWriting(t *testing.T) {
	tests := []Credential{
		{Registry: "ghcr.io", Username: "invalid:user", Password: []byte("token")},
		{Registry: "https://ghcr.io", Username: "alice", Password: []byte("token")},
		{Registry: "ghcr.io/path", Username: "alice", Password: []byte("token")},
		{Registry: "ghcr.io:0", Username: "alice", Password: []byte("token")},
		{Registry: "ghcr.io", Username: "alice", Password: []byte("token"), Scope: ScopeSandbox},
		{Registry: "ghcr.io", Username: "alice", Password: []byte("token"), SandboxName: "unexpected"},
		{Registry: "ghcr.io", Username: "alice", Password: []byte("token"), Scope: "all"},
	}
	for i, credential := range tests {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			vault := &fakeVault{}
			store, err := NewStore(vault)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Save(context.Background(), credential); err == nil {
				t.Fatal("invalid credential must be rejected")
			}
			if vault.secret != "" {
				t.Fatal("invalid credential must not reach keychain")
			}
		})
	}
}

func TestSaveFailsClosedWhenVaultUnavailable(t *testing.T) {
	vault := &fakeVault{err: errors.New("vault unavailable")}
	store, err := NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(context.Background(), Credential{Registry: "docker.io", Username: "alice", Password: []byte("synthetic-token")}); err == nil {
		t.Fatal("unavailable keychain must fail")
	}
}

func TestDeleteRegistryCredential(t *testing.T) {
	vault := &fakeVault{}
	store, err := NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	removed, err := store.Delete(context.Background(), "ghcr.io", ScopeAllSandboxes, "")
	if err != nil || !removed {
		t.Fatalf("delete returned removed=%t err=%v", removed, err)
	}
	if vault.account != "ghcr.io/all-sandboxes" {
		t.Fatalf("unexpected delete account %q", vault.account)
	}
}

func TestIPv6RegistrySaveAndDelete(t *testing.T) {
	vault := &fakeVault{}
	store, err := NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Save(context.Background(), Credential{Registry: "[::1]", Username: "alice", Password: []byte("synthetic-token")})
	if err != nil {
		t.Fatal(err)
	}
	savedAccount := vault.account
	if _, err := store.Delete(context.Background(), "::1", ScopeHostOnly, ""); err != nil {
		t.Fatal(err)
	}
	if savedAccount != "[::1]/host-only" || vault.account != savedAccount {
		t.Fatalf("save and delete use different accounts: %q, %q", savedAccount, vault.account)
	}
}

func TestDeleteMissingRegistryCredential(t *testing.T) {
	vault := &fakeVault{err: ErrNotFound}
	store, err := NewStore(vault)
	if err != nil {
		t.Fatal(err)
	}
	removed, err := store.Delete(context.Background(), "ghcr.io", ScopeHostOnly, "")
	if err != nil || removed {
		t.Fatalf("missing delete returned removed=%t err=%v", removed, err)
	}
}

func TestNativeVaultStoresCredentialInBackend(t *testing.T) {
	backend := &fakeKeyringBackend{items: make(map[string]string)}
	vault := NativeVault{backend: backend}
	if err := vault.Set(context.Background(), "service", "ghcr.io/host-only", "synthetic-token"); err != nil {
		t.Fatal(err)
	}
	if len(backend.items) != 1 || backend.items["service/ghcr.io/host-only"] != "synthetic-token" {
		t.Fatalf("vault did not store the exact entry: %#v", backend.items)
	}
}

type fakeKeyringBackend struct{ items map[string]string }

func (f *fakeKeyringBackend) Get(service, account string) (string, error) {
	value, ok := f.items[service+"/"+account]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return value, nil
}

func (f *fakeKeyringBackend) Set(service, account, secret string) error {
	f.items[service+"/"+account] = secret
	return nil
}

func (f *fakeKeyringBackend) Delete(service, account string) error {
	key := service + "/" + account
	if _, ok := f.items[key]; !ok {
		return keyring.ErrNotFound
	}
	delete(f.items, key)
	return nil
}
