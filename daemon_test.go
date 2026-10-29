package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunRequiresConfig(t *testing.T) {
	if err := Run(context.Background(), Config{}); err == nil {
		t.Fatal("expected config error")
	}
}

func TestRunStartsAndStops(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "sandboxesd.sock")
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{SocketPath: socket, StateDir: dir})
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("socket was not created")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon did not stop")
	}
}
