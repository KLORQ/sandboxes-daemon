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

	runtime "github.com/KLORQ/sandboxes-runtime"
	runtimectr "github.com/KLORQ/sandboxes-runtime/ctr"

	daemon "github.com/KLORQ/sandboxes-daemon"
	"github.com/KLORQ/sandboxes-daemon/internal/version"
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		socketPath     string
		stateDir       string
		containerdPath string
		ctrPath        string
		runtimeName    string
		snapshotter    string
		image          string
		fifoDir        string
		showVer        bool
	)
	home, err := os.UserHomeDir()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "resolve home directory:", err)
		return 1
	}
	defaultState := filepath.Join(home, ".sandboxes")
	flag.StringVar(&stateDir, "state", defaultState, "state directory")
	flag.StringVar(&socketPath, "socket", filepath.Join(defaultState, "sandboxesd.sock"), "unix socket path")
	flag.StringVar(&containerdPath, "containerd", "", "containerd socket; empty keeps state-only mode")
	flag.StringVar(&ctrPath, "ctr", "ctr", "ctr binary path")
	flag.StringVar(&runtimeName, "runtime", "io.containerd.nerdbox.v1", "containerd runtime name")
	flag.StringVar(&snapshotter, "snapshotter", "erofs", "containerd snapshotter")
	flag.StringVar(&image, "image", "alpine:3.22", "default image")
	flag.StringVar(&fifoDir, "fifo-dir", "", "runtime FIFO directory")
	flag.BoolVar(&showVer, "version", false, "print version")
	flag.Parse()

	if showVer {
		_, _ = fmt.Fprintln(os.Stdout, version.Version)
		return 0
	}

	var backend runtime.Backend
	if containerdPath != "" {
		if fifoDir == "" {
			fifoDir = filepath.Join(stateDir, "fifo")
		}
		if err := os.MkdirAll(fifoDir, 0o700); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "create fifo dir:", err)
			return 1
		}
		created, err := runtimectr.NewBackend(runtimectr.Config{
			Socket:      containerdPath,
			CTR:         ctrPath,
			Runtime:     runtimeName,
			Snapshotter: snapshotter,
		}, runtimectr.BackendOptions{Image: image, FIFODir: fifoDir})
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "create runtime backend:", err)
			return 1
		}
		backend = created
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := daemon.Run(ctx, daemon.Config{
		SocketPath:   socketPath,
		StateDir:     stateDir,
		Backend:      backend,
		DefaultImage: image,
	}); err != nil {
		slog.Error("daemon stopped", "error", err)
		return 1
	}
	return 0
}
