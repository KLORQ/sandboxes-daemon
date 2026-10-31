package oauthsession

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestCallbackListener(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	c, err := Listen(s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	auth, err := s.AuthorizationURL("https://identity.example/authorize", "client", c.RedirectURI(), nil)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(auth)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, c.RedirectURI()+"?state=wrong&code=synthetic", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "attacker.example"
	wrongHost, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = wrongHost.Body.Close()
	if wrongHost.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid host status: %d", wrongHost.StatusCode)
	}
	bad, err := client.Get(c.RedirectURI() + "?state=wrong&code=synthetic")
	if err != nil {
		t.Fatal(err)
	}
	_ = bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid state status: %d", bad.StatusCode)
	}
	response, err := client.Get(c.RedirectURI() + "?" + url.Values{"state": {u.Query().Get("state")}, "code": {"synthetic-code"}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("valid callback status: %d", response.StatusCode)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	code, err := c.Wait(ctx)
	if err != nil || code != "synthetic-code" {
		t.Fatalf("callback: %q %v", code, err)
	}
}

func TestListenLoopbackFallback(t *testing.T) {
	var calls []string
	_, err := listenLoopback(func(network, address string) (net.Listener, error) {
		calls = append(calls, network+" "+address)
		return nil, errors.New("synthetic bind error")
	})
	if err == nil || len(calls) != 2 || calls[0] != "tcp4 127.0.0.1:0" || calls[1] != "tcp6 [::1]:0" {
		t.Fatalf("unexpected loopback fallback: %v, %v", calls, err)
	}
}

func TestCallbackDenialEndsFlow(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	c, err := Listen(s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	auth, err := s.AuthorizationURL("https://identity.example/authorize", "client", c.RedirectURI(), nil)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(auth)
	if err != nil {
		t.Fatal(err)
	}
	query := url.Values{"state": {u.Query().Get("state")}, "error": {"access_denied"}, "error_description": {"synthetic-secret"}}
	response, err := (&http.Client{Timeout: time.Second}).Get(c.RedirectURI() + "?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = c.Wait(ctx)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("expected denial: %v", err)
	}
}

func TestCallbackRequiresDeadlineAndCloses(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	c, err := Listen(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Wait(context.Background()); err == nil {
		t.Fatal("missing deadline accepted")
	}
	client := &http.Client{Timeout: time.Second}
	if resp, err := client.Get(c.RedirectURI()); err == nil {
		_ = resp.Body.Close()
		t.Fatal("listener still open")
	}
}
