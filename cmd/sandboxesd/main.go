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

	gateway "github.com/KLORQ/sandboxes-gateway"
	runtime "github.com/KLORQ/sandboxes-runtime"
	runtimectr "github.com/KLORQ/sandboxes-runtime/ctr"

	daemon "github.com/KLORQ/sandboxes-daemon"
	daemonnetwork "github.com/KLORQ/sandboxes-daemon/internal/network"
	"github.com/KLORQ/sandboxes-daemon/internal/version"
)

type options struct {
	socketPath     string
	stateDir       string
	containerdPath string
	ctrPath        string
	runtimeName    string
	snapshotter    string
	image          string
	fifoDir        string
	gvproxyPath    string
	runDir         string
	dnsUpstream    string
	showVersion    bool
}

func main() {
	os.Exit(run())
}

func run() int {
	opts := parseOptions()
	if opts.showVersion {
		_, _ = fmt.Fprintln(os.Stdout, version.Version)
		return 0
	}
	backend, cleanup, err := buildBackend(opts)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if cleanup != nil {
		defer cleanup()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := daemon.Run(ctx, daemon.Config{
		SocketPath:   opts.socketPath,
		StateDir:     opts.stateDir,
		Backend:      backend,
		DefaultImage: opts.image,
	}); err != nil {
		slog.Error("daemon stopped", "error", err)
		return 1
	}
	return 0
}

func parseOptions() options {
	var opts options
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	defaultState := filepath.Join(home, ".sandboxes")
	flag.StringVar(&opts.stateDir, "state", defaultState, "state directory")
	flag.StringVar(&opts.socketPath, "socket", filepath.Join(defaultState, "sandboxesd.sock"), "unix socket path")
	flag.StringVar(&opts.containerdPath, "containerd", "", "containerd socket; empty keeps state-only mode")
	flag.StringVar(&opts.ctrPath, "ctr", "ctr", "ctr binary path")
	flag.StringVar(&opts.runtimeName, "runtime", "io.containerd.nerdbox.v1", "containerd runtime name")
	flag.StringVar(&opts.snapshotter, "snapshotter", "erofs", "containerd snapshotter")
	flag.StringVar(&opts.image, "image", "alpine:3.22", "default image")
	flag.StringVar(&opts.fifoDir, "fifo-dir", "", "runtime FIFO directory")
	flag.StringVar(&opts.gvproxyPath, "gvproxy", "", "patched gvproxy binary; empty disables networking")
	flag.StringVar(&opts.runDir, "run-dir", "", "gateway runtime directory")
	flag.StringVar(&opts.dnsUpstream, "dns-upstream", "", "optional DNS upstream")
	flag.BoolVar(&opts.showVersion, "version", false, "print version")
	flag.Parse()
	return opts
}

func buildBackend(opts options) (runtime.Backend, func(), error) {
	if opts.containerdPath == "" {
		return nil, nil, nil
	}
	fifoDir := opts.fifoDir
	if fifoDir == "" {
		fifoDir = filepath.Join(opts.stateDir, "fifo")
	}
	if err := os.MkdirAll(fifoDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create fifo dir: %w", err)
	}
	network, manager, err := buildNetwork(opts)
	if err != nil {
		return nil, nil, err
	}
	backend, err := runtimectr.NewBackend(runtimectr.Config{
		Socket:      opts.containerdPath,
		CTR:         opts.ctrPath,
		Runtime:     opts.runtimeName,
		Snapshotter: opts.snapshotter,
	}, runtimectr.BackendOptions{Image: opts.image, FIFODir: fifoDir, Network: network})
	if err != nil {
		return nil, nil, fmt.Errorf("create runtime backend: %w", err)
	}
	cleanup := func() {
		if manager != nil {
			_ = manager.Close(context.Background())
		}
	}
	return backend, cleanup, nil
}

func buildNetwork(opts options) (runtime.Network, *gateway.Manager, error) {
	if opts.gvproxyPath == "" {
		return nil, nil, nil
	}
	runDir := opts.runDir
	if runDir == "" {
		runDir = filepath.Join(opts.stateDir, "run")
	}
	manager, err := gateway.New(gateway.Config{
		GVProxy:     opts.gvproxyPath,
		RunDir:      runDir,
		DNSUpstream: opts.dnsUpstream,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create gateway manager: %w", err)
	}
	return daemonnetwork.New(manager, runDir), manager, nil
}
