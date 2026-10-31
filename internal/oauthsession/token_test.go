package oauthsession

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestExchangeAndRefresh(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			if r.Form.Get("code") != "synthetic-code" || r.Form.Get("code_verifier") == "" {
				t.Error("invalid exchange")
			}
		case "refresh_token":
			if r.Form.Get("refresh_token") != "synthetic-refresh" {
				t.Error("invalid refresh")
			}
		default:
			t.Error("unexpected grant")
		}
		_, _ = fmt.Fprint(w, `{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","token_type":"Bearer","expires_in":60}`)
	}))
	defer server.Close()
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.bindTokenEndpoint(server.URL + "/token"); err != nil {
		t.Fatal(err)
	}
	redirect := "http://127.0.0.1:12345/callback"
	auth, err := s.AuthorizationURL(server.URL+"/authorize", "client", redirect, nil)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(auth)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ValidateCallback(url.Values{"state": {u.Query().Get("state")}, "code": {"synthetic-code"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Exchange(context.Background(), server.Client().Transport, server.URL+"/other", "client", redirect, "synthetic-code"); err == nil {
		t.Fatal("unbound token endpoint accepted")
	}
	tokens, err := s.Exchange(context.Background(), server.Client().Transport, server.URL+"/token", "client", redirect, "synthetic-code")
	if err != nil || tokens.AccessToken != "synthetic-access" {
		t.Fatalf("exchange failed: %v", err)
	}
	if _, err := s.Exchange(context.Background(), server.Client().Transport, server.URL+"/token", "client", redirect, "synthetic-code"); err == nil {
		t.Fatal("replayed exchange accepted")
	}
	tokens, err = Refresh(context.Background(), server.Client().Transport, server.URL+"/token", "client", tokens.RefreshToken)
	if err != nil || tokens.AccessToken != "synthetic-access" {
		t.Fatalf("refresh failed: %v", err)
	}
}

func TestRefreshRejectsRedirect(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/token", http.StatusTemporaryRedirect)
			return
		}
		t.Error("redirect followed")
	}))
	defer server.Close()
	if _, err := Refresh(context.Background(), server.Client().Transport, server.URL+"/redirect", "client", "synthetic-refresh"); err == nil {
		t.Fatal("redirect accepted")
	}
}
