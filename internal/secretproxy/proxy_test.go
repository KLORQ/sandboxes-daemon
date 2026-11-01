package secretproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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
