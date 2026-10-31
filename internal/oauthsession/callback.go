package oauthsession

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Callback owns a single-use loopback listener for an OAuth transaction.
type Callback struct {
	listener net.Listener
	server   *http.Server
	result   chan string
	failed   chan error
}

// Listen binds a loopback-only ephemeral port before the authorization URL is
// constructed. Call Wait or Close to release the listener.
func Listen(s *Session) (*Callback, error) {
	if s == nil {
		return nil, errors.New("OAuth session is required")
	}
	listener, err := listenLoopback(net.Listen)
	if err != nil {
		return nil, fmt.Errorf("bind OAuth callback: %w", err)
	}
	c := &Callback{listener: listener, result: make(chan string, 1), failed: make(chan error, 1)}
	c.server = &http.Server{Handler: c.handler(s), ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10}
	go func() {
		if err := c.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			c.failed <- err
		}
	}()
	return c, nil
}

func listenLoopback(listen func(string, string) (net.Listener, error)) (net.Listener, error) {
	listener, err := listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return listen("tcp6", "[::1]:0")
	}
	return listener, nil
}

// RedirectURI is the exact redirect registered for this listener.
func (c *Callback) RedirectURI() string { return "http://" + c.listener.Addr().String() + "/callback" }

func (c *Callback) handler(s *Session) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Host != c.listener.Addr().String() || r.URL.Path != "/callback" || r.URL.RawPath != "" {
			http.Error(w, "invalid callback", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		bound := s.redirect == c.RedirectURI()
		s.mu.Unlock()
		if !bound {
			http.Error(w, "invalid callback", http.StatusBadRequest)
			return
		}
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			http.Error(w, "invalid callback", http.StatusBadRequest)
			return
		}
		code, err := s.ValidateCallback(query)
		if err != nil {
			if errors.Is(err, ErrDenied) {
				http.Error(w, "Authorization denied. You may close this window.", http.StatusBadRequest)
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
				c.failed <- ErrDenied
				return
			}
			http.Error(w, "invalid callback", http.StatusBadRequest)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		_, _ = fmt.Fprintln(w, "Authorization received. You may close this window.")
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		c.result <- code
	})
}

// Wait returns the single authorization code or the context/serve error and
// always closes the listener. The caller must apply a deadline.
func (c *Callback) Wait(ctx context.Context) (string, error) {
	defer func() { _ = c.Close() }()
	if _, ok := ctx.Deadline(); !ok {
		return "", errors.New("OAuth callback deadline is required")
	}
	select {
	case code := <-c.result:
		return code, nil
	case err := <-c.failed:
		return "", fmt.Errorf("OAuth callback server: %w", err)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Close stops the listener and any active callback connections.
func (c *Callback) Close() error { return c.server.Close() }
