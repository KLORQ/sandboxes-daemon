package oauthsession

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

func TestTokenManagerConcurrentRefresh(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil || r.Form.Get("refresh_token") != "synthetic-refresh" {
			t.Error("unexpected refresh request")
		}
		_, _ = fmt.Fprint(w, `{"access_token":"new-token","refresh_token":"new-refresh","token_type":"Bearer","expires_in":300}`)
	}))
	defer server.Close()
	vault := &testVault{values: make(map[string]string)}
	sink, err := NewVaultSink(vault, "provider")
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Save(context.Background(), Tokens{AccessToken: "old-token", RefreshToken: "synthetic-refresh", TokenType: "Bearer", ExpiresIn: 1}); err != nil {
		t.Fatal(err)
	}
	coordinator := NewRefreshCoordinator()
	manager, err := NewTokenManager(sink, server.Client().Transport, server.URL+"/token", "client", coordinator)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewTokenManager(sink, server.Client().Transport, server.URL+"/token", "client", coordinator)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 20)
	for i := range 20 {
		selected := manager
		if i%2 != 0 {
			selected = second
		}
		wg.Go(func() {
			value, err := selected.AccessToken(context.Background())
			if err == nil && value != "new-token" {
				err = fmt.Errorf("unexpected access token")
			}
			results <- err
		})
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("refresh calls: %d", calls.Load())
	}
	stored, _, err := sink.Load(context.Background())
	if err != nil || stored.RefreshToken != "new-refresh" {
		t.Fatal("rotated refresh token not stored")
	}
}

func TestLogoutWaitsForRefresh(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = fmt.Fprint(w, `{"access_token":"new-token","refresh_token":"new-refresh","token_type":"Bearer","expires_in":300}`)
	}))
	defer server.Close()
	vault := &testVault{values: make(map[string]string)}
	sink, err := NewVaultSink(vault, "provider")
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Save(context.Background(), Tokens{AccessToken: "old-token", RefreshToken: "synthetic-refresh", TokenType: "Bearer", ExpiresIn: 1}); err != nil {
		t.Fatal(err)
	}
	manager, err := NewTokenManager(sink, server.Client().Transport, server.URL+"/token", "client", NewRefreshCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	refreshDone := make(chan error, 1)
	go func() { _, err := manager.AccessToken(context.Background()); refreshDone <- err }()
	<-started
	logoutDone := make(chan error, 1)
	go func() { logoutDone <- manager.Logout(context.Background()) }()
	close(release)
	if err := <-refreshDone; err != nil {
		t.Fatal(err)
	}
	if err := <-logoutDone; err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AccessToken(context.Background()); err == nil {
		t.Fatal("credential survived logout")
	}
}

func TestTokenManagerRejectsUnknownExpiry(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unexpected refresh") }))
	defer server.Close()
	vault := &testVault{values: make(map[string]string)}
	sink, err := NewVaultSink(vault, "provider")
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Save(context.Background(), Tokens{AccessToken: "synthetic-token", TokenType: "Bearer"}); err != nil {
		t.Fatal(err)
	}
	manager, err := NewTokenManager(sink, server.Client().Transport, server.URL+"/token", "client", NewRefreshCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AccessToken(context.Background()); err == nil {
		t.Fatal("unknown token expiry accepted")
	}
}
