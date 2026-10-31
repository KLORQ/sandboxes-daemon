package oauthsession

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const DockerHubAuthEndpoint = "https://hub.docker.com/v2/auth/token"

var ErrDockerHubCredentialRejected = errors.New("docker Hub rejected the supplied credentials")

// NewDockerHubAuthTransport creates a direct TLS transport for the fixed Hub
// authentication endpoint. It ignores proxy environment variables so Docker
// credentials are not forwarded to an ambient proxy.
func NewDockerHubAuthTransport() *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 2,
	}
}

// ValidateDockerHubCredentials verifies a username/PAT pair through Docker's
// supported Hub auth endpoint. The returned short-lived bearer is discarded;
// callers store only the original PAT in the host vault.
func ValidateDockerHubCredentials(ctx context.Context, transport http.RoundTripper, username string, password []byte) error {
	if err := validateDockerHubCredentialsInput(transport, username, password); err != nil {
		return err
	}
	endpoint, err := dockerHubAuthURL()
	if err != nil {
		return err
	}
	requestBody, err := dockerHubAuthBody(username, password)
	if err != nil {
		return err
	}
	defer clear(requestBody)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return errors.New("build Docker Hub authentication request failed")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	return sendDockerHubAuthRequest(transport, req)
}

func validateDockerHubCredentialsInput(transport http.RoundTripper, username string, password []byte) error {
	if transport == nil || !validHubUsername(username) || len(password) == 0 || len(password) > 2048 || !utf8.Valid(password) {
		return errors.New("invalid Docker Hub credentials")
	}
	return nil
}

func dockerHubAuthURL() (string, error) {
	u, err := url.Parse(DockerHubAuthEndpoint)
	if err != nil || u.Scheme != httpsScheme || u.Host != "hub.docker.com" || u.Path != "/v2/auth/token" || u.RawQuery != "" {
		return "", errors.New("invalid Docker Hub authentication endpoint")
	}
	return u.String(), nil
}

func dockerHubAuthBody(username string, password []byte) ([]byte, error) {
	identifier, err := json.Marshal(username)
	if err != nil {
		return nil, errors.New("encode Docker Hub credentials failed")
	}
	body := make([]byte, 0, len(identifier)+len(password)+32)
	body = append(body, `{"identifier":`...)
	body = append(body, identifier...)
	body = append(body, `,"secret":`...)
	body = appendJSONStringBytes(body, password)
	return append(body, '}'), nil
}

func sendDockerHubAuthRequest(transport http.RoundTripper, req *http.Request) error {
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("docker Hub authentication request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return ErrDockerHubCredentialRejected
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("docker Hub authentication endpoint returned an unexpected status")
	}
	const maxAuthResponse = 32 << 10
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAuthResponse+1))
	if err != nil || len(body) > maxAuthResponse {
		clear(body)
		return errors.New("invalid Docker Hub authentication response")
	}
	defer clear(body)
	var result struct {
		AccessToken json.RawMessage `json:"access_token"`
	}
	if json.Unmarshal(body, &result) != nil || !validHubAccessToken(result.AccessToken) {
		return errors.New("invalid Docker Hub authentication response")
	}
	clear(result.AccessToken)
	return nil
}

func appendJSONStringBytes(dst, value []byte) []byte {
	const hex = "0123456789abcdef"
	dst = append(dst, '"')
	for _, b := range value {
		switch b {
		case '"', '\\':
			dst = append(dst, '\\', b)
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\f':
			dst = append(dst, '\\', 'f')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if b < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', hex[b>>4], hex[b&0x0f])
			} else {
				dst = append(dst, b)
			}
		}
	}
	return append(dst, '"')
}

func validHubAccessToken(token json.RawMessage) bool {
	token = bytes.TrimSpace(token)
	return len(token) > 2 && token[0] == '"' && token[len(token)-1] == '"' &&
		len(bytes.TrimSpace(token[1:len(token)-1])) > 0
}

func validHubUsername(username string) bool {
	return username != "" && len(username) <= 255 && strings.TrimSpace(username) == username && !strings.ContainsAny(username, "\x00\r\n")
}
