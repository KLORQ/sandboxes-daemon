package oauthsession

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestAuthorizeSyntheticProvider(t *testing.T) {
	challenge := ""
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if r.Form.Get("code") != "synthetic-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			t.Error("token exchange did not match authorization")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprint(w, `{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","token_type":"Bearer","expires_in":60}`)
	}))
	defer provider.Close()
	vault := &testVault{values: make(map[string]string)}
	sink, err := NewVaultSink(vault, "synthetic-provider")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	open := func(_ context.Context, raw string) error {
		u, err := url.Parse(raw)
		if err != nil {
			return err
		}
		q := u.Query()
		challenge = q.Get("code_challenge")
		redirect := q.Get("redirect_uri") + "?" + url.Values{"state": {q.Get("state")}, "code": {"synthetic-code"}}.Encode()
		resp, err := (&http.Client{Timeout: time.Second}).Get(redirect)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("callback returned %d", resp.StatusCode)
		}
		return nil
	}
	err = Authorize(ctx, Provider{AuthorizationEndpoint: provider.URL + "/authorize", TokenEndpoint: provider.URL + "/token", ClientID: "synthetic-client", Transport: provider.Client().Transport}, open, sink)
	if err != nil {
		t.Fatal(err)
	}
	tokens, _, err := sink.Load(ctx)
	if err != nil || tokens.AccessToken != "synthetic-access" || tokens.RefreshToken != "synthetic-refresh" {
		t.Fatal("tokens were not passed to sink")
	}
}
