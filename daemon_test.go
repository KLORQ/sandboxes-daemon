package daemon

import (
	"context"
	"errors"
	"testing"
)

func TestRunStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, Config{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected error: %v", err)
	}
}
