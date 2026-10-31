package oauthsession

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type testVault struct {
	values map[string]string
	fail   bool
}

func (v *testVault) Set(_ context.Context, service, account, value string) error {
	if v.fail {
		return errors.New("synthetic-access")
	}
	v.values[service+":"+account] = value
	return nil
}
func (v *testVault) Get(_ context.Context, service, account string) (string, error) {
	value, ok := v.values[service+":"+account]
	if !ok || v.fail {
		return "", errors.New("synthetic-access")
	}
	return value, nil
}
func (v *testVault) Delete(_ context.Context, service, account string) error {
	if v.fail {
		return errors.New("synthetic-access")
	}
	delete(v.values, service+":"+account)
	return nil
}

func TestVaultSinkIsolationAndRedaction(t *testing.T) {
	vault := &testVault{values: make(map[string]string)}
	a, err := NewVaultSink(vault, "provider-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewVaultSink(vault, "provider-b")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tokens := Tokens{AccessToken: "synthetic-access", RefreshToken: "synthetic-refresh", TokenType: "Bearer", ExpiresIn: 60}
	if err := a.Save(ctx, tokens); err != nil {
		t.Fatal(err)
	}
	got, expiry, err := a.Load(ctx)
	if err != nil || got.AccessToken != tokens.AccessToken || expiry.Before(time.Now()) {
		t.Fatal("stored token unavailable or expired")
	}
	if _, _, err := b.Load(ctx); err == nil {
		t.Fatal("other provider could read token")
	}
	if err := b.Save(ctx, Tokens{AccessToken: "another", TokenType: "Bearer"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Load(ctx); err != nil {
		t.Fatal("other provider was deleted")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", tokens, tokens), "synthetic") {
		t.Fatal("tokens leaked through formatting")
	}
	vault.fail = true
	if err := a.Save(ctx, tokens); err == nil || strings.Contains(err.Error(), "synthetic") {
		t.Fatal("vault error was not redacted")
	}
}
