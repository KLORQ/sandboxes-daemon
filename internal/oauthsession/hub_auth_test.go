package oauthsession

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type hubAuthRoundTripper func(*http.Request) (*http.Response, error)

func (f hubAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestValidateDockerHubCredentialsSendsBoundedHubRequest(t *testing.T) {
	called := false
	transport := hubAuthRoundTripper(func(req *http.Request) (*http.Response, error) {
		called = true
		if req.Method != http.MethodPost || req.URL.String() != DockerHubAuthEndpoint || req.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("unexpected request: %s %s headers=%v", req.Method, req.URL, req.Header)
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(body)
		if !strings.Contains(string(body), `"identifier":"alice"`) || !strings.Contains(string(body), `"secret":"synthetic-pat"`) {
			t.Fatalf("credentials missing from controlled request body")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"synthetic-short-token"}`))}, nil
	})
	password := []byte("synthetic-pat")
	if err := ValidateDockerHubCredentials(context.Background(), transport, "alice", password); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("Docker Hub auth transport was not called")
	}
}

func TestValidateDockerHubCredentialsRejectsAuthAndMalformedResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{name: "rejected", status: http.StatusUnauthorized, body: `{}`, want: ErrDockerHubCredentialRejected},
		{name: "empty token", status: http.StatusOK, body: `{"access_token":"   "}`},
		{name: "invalid token type", status: http.StatusOK, body: `{"access_token":42}`},
		{name: "unexpected status", status: http.StatusInternalServerError, body: `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := hubAuthRoundTripper(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			err := ValidateDockerHubCredentials(context.Background(), transport, "alice", []byte("synthetic-pat"))
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("error=%v, want %v", err, tc.want)
			}
			if tc.want == nil && err == nil {
				t.Fatal("expected invalid response to fail")
			}
		})
	}
}
