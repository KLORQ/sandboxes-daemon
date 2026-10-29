// Package daemon contains the local control plane.
package daemon

import "context"

// Config is the daemon configuration.
type Config struct {
	SocketPath string
	StateDir   string
}

// Run starts the daemon and blocks until ctx is canceled.
func Run(ctx context.Context, _ Config) error {
	<-ctx.Done()
	return ctx.Err()
}
