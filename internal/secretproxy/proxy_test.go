package secretproxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProxyInjectsHostCredentialAndStripsGuestAuth(t *testing.T) {
	var gotAuth, gotAPIKey, gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAPIKey = r.Header.Get("X-Api-Key")
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	manager := New()
	defer func() { _ = manager.Close() }()
	_, err := manager.Start(context.Background(), "dev", "openai", Service{Upstream: upstream.URL, Header: "Authorization", Prefix: "Bearer "}, "host-secret")
	if err != nil {
		t.Fatal(err)
	}
	addr := strings.TrimPrefix(guestURL(manager, "dev", "openai"), "http://192.168.127.254")
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1"+addr+"/v1/models", nil)
	req.Header.Set("Authorization", "guest-value")
	req.Header.Set("X-Api-Key", "guest-value")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || gotAuth != "Bearer host-secret" || gotAPIKey != "" || gotPath != "/v1/models" {
		t.Fatalf("status=%d auth=%q apikey=%q path=%q", resp.StatusCode, gotAuth, gotAPIKey, gotPath)
	}
}

func guestURL(manager *Manager, sandbox, service string) string {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if p := manager.proxies[sandbox+"/"+service]; p != nil {
		return p.url
	}
	return ""
}

func TestUnixProxyChannelInjectsSecretAndRequiresToken(t *testing.T) {
	var gotAuth, gotGuestAuth, gotMethod, gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotGuestAuth = r.Header.Get("X-Guest-Auth")
		gotMethod = r.Method
		gotPath = r.URL.Path
		_, _ = w.Write([]byte("streamed-body"))
	}))
	defer upstream.Close()

	m := New()
	defer func() { _ = m.Close() }()
	dir, err := os.MkdirTemp("/tmp", "kqproxy")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "proxy.sock")
	token := "0123456789abcdef0123456789abcdef"
	if _, err := m.StartUnix(context.Background(), "dev", "openai", Service{Upstream: upstream.URL, Header: "Authorization", Prefix: "Bearer "}, "s3cret", socket, token); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}}
	req, _ := http.NewRequest(http.MethodPost, "http://upstream.test/v1/chat?q=1", strings.NewReader("payload"))
	req.Header.Set(TokenHeader, token)
	req.Header.Set("X-Guest-Auth", "guest-value")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "streamed-body" {
		t.Fatalf("body = %q", body)
	}
	if gotAuth != "Bearer s3cret" {
		t.Fatalf("upstream authorization = %q", gotAuth)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/chat" {
		t.Fatalf("upstream request = %s %s", gotMethod, gotPath)
	}

	unauthorized, _ := http.NewRequest(http.MethodGet, "http://upstream.test/v1/chat", nil)
	unauthorized.Header.Set(TokenHeader, "ffffffffffffffffffffffffffffffff")
	resp, err = client.Do(unauthorized)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong token status = %d", resp.StatusCode)
	}
	if gotAuth != "Bearer s3cret" {
		t.Fatal("unauthorized request reached upstream")
	}
	_ = gotGuestAuth
}
