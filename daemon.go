// Package daemon contains the local control plane.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	localv1 "github.com/KLORQ/sandboxes-api/gen/go/sandboxes/local/v1"
	runtime "github.com/KLORQ/sandboxes-runtime"
	"google.golang.org/grpc"

	"github.com/KLORQ/sandboxes-daemon/internal/server"
	"github.com/KLORQ/sandboxes-daemon/internal/service"
	"github.com/KLORQ/sandboxes-daemon/internal/store"
)

// Config is the daemon configuration.
type Config struct {
	SocketPath   string
	StateDir     string
	Backend      runtime.Backend
	DefaultImage string
}

// Run starts the daemon and blocks until ctx is canceled.
func Run(ctx context.Context, cfg Config) error {
	if cfg.SocketPath == "" || cfg.StateDir == "" {
		return fmt.Errorf("socket path and state dir are required")
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	st, err := store.Open(ctx, filepath.Join(cfg.StateDir, "sandboxes.db"))
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	svc := service.New(st, cfg.Backend)
	if cfg.DefaultImage != "" {
		svc.DefaultImage = cfg.DefaultImage
	}
	changed, err := svc.Reconcile(ctx)
	if err != nil {
		return fmt.Errorf("reconcile: %w", err)
	}
	if changed > 0 {
		slog.Info("reconciled interrupted state", "records", changed)
	}
	if err := removeStaleSocket(ctx, cfg.SocketPath); err != nil {
		return err
	}
	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "unix", cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("listen unix socket: %w", err)
	}
	defer func() { _ = os.Remove(cfg.SocketPath) }()
	if err := os.Chmod(cfg.SocketPath, 0o600); err != nil {
		_ = lis.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	grpcServer := grpc.NewServer()
	localv1.RegisterSandboxServiceServer(grpcServer, server.NewSandbox(svc))
	localv1.RegisterOperationServiceServer(grpcServer, server.NewOperation(svc))

	go func() {
		<-ctx.Done()
		grpcServer.GracefulStop()
	}()

	slog.Info("daemon listening", "socket", cfg.SocketPath, "state", cfg.StateDir)
	if err := grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

func removeStaleSocket(ctx context.Context, path string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	dialer := net.Dialer{Timeout: 200 * time.Millisecond}
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("daemon is already listening on %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	return nil
}
