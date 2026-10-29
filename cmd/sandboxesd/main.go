package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	daemon "github.com/KLORQ/sandboxes-daemon"
	"github.com/KLORQ/sandboxes-daemon/internal/version"
)

func main() {
	var (
		socketPath string
		stateDir   string
		showVer    bool
	)
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve home directory:", err)
		os.Exit(1)
	}
	defaultState := filepath.Join(home, ".sandboxes")
	flag.StringVar(&stateDir, "state", defaultState, "state directory")
	flag.StringVar(&socketPath, "socket", filepath.Join(defaultState, "sandboxesd.sock"), "unix socket path")
	flag.BoolVar(&showVer, "version", false, "print version")
	flag.Parse()

	if showVer {
		_, _ = fmt.Fprintln(os.Stdout, version.Version)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := daemon.Run(ctx, daemon.Config{SocketPath: socketPath, StateDir: stateDir}); err != nil {
		slog.Error("daemon stopped", "error", err)
		os.Exit(1)
	}
}
