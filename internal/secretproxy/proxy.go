// Package secretproxy provides per-sandbox loopback HTTP proxies that inject a
// service credential on the host. Secret values never enter the guest.
package secretproxy

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Service describes one supported upstream and its auth header.
type Service struct {
	Upstream string
	Header   string
	Prefix   string
}

const (
	authHeader   = "Authorization"
	bearerPrefix = "Bearer "
)

var services = map[string]Service{
	"openai":     {Upstream: "https://api.openai.com", Header: authHeader, Prefix: bearerPrefix},
	"anthropic":  {Upstream: "https://api.anthropic.com", Header: "x-api-key"},
	"groq":       {Upstream: "https://api.groq.com", Header: authHeader, Prefix: bearerPrefix},
	"mistral":    {Upstream: "https://api.mistral.ai", Header: authHeader, Prefix: bearerPrefix},
	"openrouter": {Upstream: "https://openrouter.ai", Header: authHeader, Prefix: bearerPrefix},
	"xai":        {Upstream: "https://api.x.ai", Header: authHeader, Prefix: bearerPrefix},
}

// Lookup returns the fixed upstream configuration for a service.
func Lookup(service string) (Service, bool) {
	cfg, ok := services[strings.ToLower(service)]
	return cfg, ok
}

type proxy struct {
	server   *http.Server
	listener net.Listener
	url      string
}

// TokenHeader carries the per-VM bearer sent by the guest proxy helper. It is
// only meaningful on the unix-socket transport, where the socket path is
// already scoped to one sandbox.
const TokenHeader = "X-Klorq-Proxy-Token" //nolint:gosec // HTTP header name, not a credential.

// Manager owns proxies keyed by sandbox and service.
type Manager struct {
	mu      sync.Mutex
	proxies map[string]*proxy
}

// New creates a manager.
func New() *Manager { return &Manager{proxies: make(map[string]*proxy)} }

// Start starts (or reuses) a loopback proxy for sandbox/service.
func (m *Manager) Start(ctx context.Context, sandbox, service string, cfg Service, secret string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if sandbox == "" || service == "" || secret == "" {
		return "", errors.New("sandbox, service and secret are required")
	}
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil || upstream.Host == "" || (upstream.Scheme != "https" && (upstream.Scheme != "http" || !isLoopbackHost(upstream.Host))) {
		return "", errors.New("invalid upstream")
	}
	key := sandbox + "/" + service
	m.mu.Lock()
	if existing := m.proxies[key]; existing != nil {
		m.mu.Unlock()
		return existing.url, nil
	}
	m.mu.Unlock()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("listen for secret proxy: %w", err)
	}
	reverse := httputil.NewSingleHostReverseProxy(upstream)
	reverse.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "secret proxy upstream unavailable", http.StatusBadGateway)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never forward a guest-supplied credential. The host proxy is the only
		// authority for this upstream.
		r.Header.Del("Authorization")
		r.Header.Del("X-Api-Key")
		if cfg.Header != "" {
			r.Header.Set(cfg.Header, cfg.Prefix+secret)
		}
		r.Header.Set("X-Klorq-Secret-Proxy", service)
		reverse.ServeHTTP(w, r)
	})
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second}
	p := &proxy{server: srv, listener: listener, url: "http://192.168.127.254:" + portOf(listener)}
	m.mu.Lock()
	if existing := m.proxies[key]; existing != nil {
		m.mu.Unlock()
		_ = listener.Close()
		return existing.url, nil
	}
	m.proxies[key] = p
	m.mu.Unlock()
	go func() { _ = srv.Serve(listener) }()
	return p.url, nil
}

func isLoopbackHost(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func portOf(listener net.Listener) string {
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return "0"
	}
	return port
}

// StartUnix starts a per-sandbox proxy on a unix socket. Every request must
// carry the per-VM token; the socket is private (0600) and owned by the run
// directory, so the token is defense in depth rather than the only control.
func (m *Manager) StartUnix(ctx context.Context, sandbox, service string, cfg Service, secret, socketPath, token string) (string, error) {
	if err := validUnixStart(ctx, sandbox, service, secret, socketPath, token); err != nil {
		return "", err
	}
	upstream, err := parseUpstream(cfg.Upstream)
	if err != nil {
		return "", err
	}
	key := sandbox + "/" + service
	m.mu.Lock()
	if existing := m.proxies[key]; existing != nil {
		m.mu.Unlock()
		return existing.url, nil
	}
	m.mu.Unlock()
	listener, err := listenPrivateUnix(socketPath)
	if err != nil {
		return "", err
	}
	reverse := httputil.NewSingleHostReverseProxy(upstream)
	reverse.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "proxy upstream unavailable", http.StatusBadGateway)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get(TokenHeader)
		if len(got) != len(token) || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.Error(w, "proxy channel unauthorized", http.StatusForbidden)
			return
		}
		r.Header.Del(TokenHeader)
		r.Header.Del("Authorization")
		r.Header.Del("X-Api-Key")
		if cfg.Header != "" {
			r.Header.Set(cfg.Header, cfg.Prefix+secret)
		}
		r.Header.Set("X-Klorq-Secret-Proxy", service)
		reverse.ServeHTTP(w, r)
	})
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second}
	p := &proxy{server: srv, listener: listener, url: "unix:" + socketPath}
	m.mu.Lock()
	if existing := m.proxies[key]; existing != nil {
		m.mu.Unlock()
		_ = listener.Close()
		_ = os.Remove(socketPath)
		return existing.url, nil
	}
	m.proxies[key] = p
	m.mu.Unlock()
	go func() { _ = srv.Serve(listener) }()
	return p.url, nil
}

func validUnixStart(ctx context.Context, sandbox, service, secret, socketPath, token string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sandbox == "" || service == "" || secret == "" || socketPath == "" || len(token) < 32 {
		return errors.New("sandbox, service, secret, socket path and a 32+ byte token are required")
	}
	return nil
}

func parseUpstream(raw string) (*url.URL, error) {
	upstream, err := url.Parse(raw)
	if err != nil || upstream.Host == "" || (upstream.Scheme != "https" && (upstream.Scheme != "http" || !isLoopbackHost(upstream.Host))) {
		return nil, errors.New("invalid upstream")
	}
	return upstream, nil
}

func listenPrivateUnix(path string) (net.Listener, error) {
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen for proxy channel: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("protect proxy channel socket: %w", err)
	}
	return listener, nil
}

// StopSandbox closes every proxy owned by a sandbox.
func (m *Manager) StopSandbox(sandbox string) error {
	m.mu.Lock()
	var selected []*proxy
	for key, p := range m.proxies {
		if strings.HasPrefix(key, sandbox+"/") {
			selected = append(selected, p)
			delete(m.proxies, key)
		}
	}
	m.mu.Unlock()
	var failures []error
	for _, p := range selected {
		if err := p.server.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// Close closes every proxy.
func (m *Manager) Close() error {
	m.mu.Lock()
	all := make([]*proxy, 0, len(m.proxies))
	for key, p := range m.proxies {
		all = append(all, p)
		delete(m.proxies, key)
	}
	m.mu.Unlock()
	var failures []error
	for _, p := range all {
		if err := p.server.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
