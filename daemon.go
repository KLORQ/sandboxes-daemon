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
	"syscall"
	"time"

	localv1 "github.com/KLORQ/sandboxes-api/gen/go/sandboxes/local/v1"
	runtime "github.com/KLORQ/sandboxes-runtime"
	"google.golang.org/grpc"

	"github.com/KLORQ/sandboxes-daemon/internal/oauthsession"
	"github.com/KLORQ/sandboxes-daemon/internal/registrycredentials"
	"github.com/KLORQ/sandboxes-daemon/internal/server"
	"github.com/KLORQ/sandboxes-daemon/internal/service"
	"github.com/KLORQ/sandboxes-daemon/internal/store"
)

// Config is the daemon configuration.
type Config struct {
	SocketPath     string
	StateDir       string
	Backend        runtime.Backend
	DefaultImage   string
	Cleanup        func() error
	OAuthProviders map[string]service.OAuthProvider
	OAuthVault     oauthsession.Vault
}

// Run starts the daemon and blocks until ctx is canceled.
func Run(ctx context.Context, cfg Config) (runErr error) {
	if cfg.SocketPath == "" || cfg.StateDir == "" {
		return fmt.Errorf("socket path and state dir are required")
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	lock, err := lockStateDirectory(cfg.StateDir)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	defer func() { runErr = errors.Join(runErr, runCleanup(cfg.Cleanup)) }()
	st, err := store.Open(ctx, filepath.Join(cfg.StateDir, "sandboxes.db"))
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	svc := service.New(st, cfg.Backend)
	configureOAuth(svc, cfg)
	registryCredentialStore, err := registrycredentials.NewStore(registrycredentials.NativeVault{})
	if err != nil {
		return fmt.Errorf("create registry credential store: %w", err)
	}
	svc.SetRegistryCredentialStore(registryCredentialStore)
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
	if err := ensureSocketAvailable(cfg.SocketPath); err != nil {
		return err
	}
	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "unix", cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("listen unix socket: %w", err)
	}
	if err := os.Chmod(cfg.SocketPath, 0o600); err != nil {
		_ = lis.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	grpcServer := grpc.NewServer()
	defer grpcServer.Stop()
	registerLocalServices(grpcServer, svc)

	runDone := make(chan struct{})
	defer close(runDone)
	go stopGRPCOnCancel(ctx, runDone, grpcServer)

	slog.Info("daemon listening", "socket", cfg.SocketPath, "state", cfg.StateDir)
	if err := grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

func registerLocalServices(grpcServer *grpc.Server, svc *service.Service) {
	localv1.RegisterSandboxServiceServer(grpcServer, server.NewSandbox(svc))
	localv1.RegisterOperationServiceServer(grpcServer, server.NewOperation(svc))
	localv1.RegisterRegistryCredentialServiceServer(grpcServer, server.NewRegistryCredential(svc))
	localv1.RegisterAccountServiceServer(grpcServer, server.NewAccount(svc))
}

func configureOAuth(svc *service.Service, cfg Config) {
	svc.SetOAuthProviders(cfg.OAuthProviders)
	if cfg.OAuthVault != nil {
		svc.SetOAuthVault(cfg.OAuthVault)
	}
}

func runCleanup(cleanup func() error) error {
	if cleanup == nil {
		return nil
	}
	return cleanup()
}

func stopGRPCOnCancel(ctx context.Context, runDone <-chan struct{}, grpcServer *grpc.Server) {
	select {
	case <-runDone:
		return
	case <-ctx.Done():
	}
	graceDone := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(graceDone)
	}()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-graceDone:
	case <-timer.C:
		grpcServer.Stop()
	}
}

// lockStateDirectory prevents cooperative daemon instances from sharing one
// SQLite store and runtime resources. The lock file is retained after shutdown.
func lockStateDirectory(dir string) (*os.File, error) {
	path := filepath.Join(dir, "daemon.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- state directory is configured by the operator; symlinks are rejected
	if err != nil {
		return nil, fmt.Errorf("open daemon state lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("daemon state lock must be a regular file")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("daemon state directory is already in use: %w", err)
	}
	return file, nil
}

func ensureSocketAvailable(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect daemon socket: %w", err)
	}
	return fmt.Errorf("daemon socket path already exists")
}
