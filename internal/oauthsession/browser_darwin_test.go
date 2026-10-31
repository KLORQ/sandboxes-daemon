//go:build darwin

package oauthsession

import (
	"strings"
	"testing"
)

func TestBrowserScriptValidation(t *testing.T) {
	script, err := browserScript("https://identity.example/authorize?state=synthetic")
	if err != nil || !strings.HasPrefix(script, "open location ") {
		t.Fatal("valid authorization URL rejected")
	}
	for _, raw := range []string{"http://identity.example/auth", "https://user@identity.example/auth", "https://identity.example/\nend tell"} {
		if _, err := browserScript(raw); err == nil {
			t.Fatalf("unsafe URL accepted: %q", raw)
		}
	}
}
