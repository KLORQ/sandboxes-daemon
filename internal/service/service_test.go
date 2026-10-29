package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	core "github.com/KLORQ/sandboxes-core"
	"github.com/KLORQ/sandboxes-core/operation"
	"github.com/KLORQ/sandboxes-core/sandbox"
	"github.com/KLORQ/sandboxes-daemon/internal/store"
)

func TestLifecycle(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st)

	op, err := svc.Create(ctx, CreateRequest{Name: "dev", Image: "scratch"})
	if err != nil {
		t.Fatal(err)
	}
	if op.State != operation.Done {
		t.Fatalf("create state = %s", op.State)
	}
	sb, err := svc.Get(ctx, op.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if sb.State != sandbox.Stopped {
		t.Fatalf("state = %s", sb.State)
	}

	if _, err := svc.Start(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	sb, err = svc.Get(ctx, sb.ID)
	if err != nil || sb.State != sandbox.Running {
		t.Fatalf("start: %+v, %v", sb, err)
	}

	if _, err := svc.Stop(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	sb, err = svc.Get(ctx, sb.ID)
	if err != nil || sb.State != sandbox.Stopped {
		t.Fatalf("stop: %+v, %v", sb, err)
	}

	if _, err := svc.Delete(ctx, sb.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(ctx, sb.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestDuplicateName(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st)

	if _, err := svc.Create(ctx, CreateRequest{Name: "dev"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(ctx, CreateRequest{Name: "dev"}); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestDeleteRunningRequiresForce(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := New(st)

	op, err := svc.Create(ctx, CreateRequest{Name: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(ctx, op.SandboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Delete(ctx, op.SandboxID, false); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	if _, err := svc.Delete(ctx, op.SandboxID, true); err != nil {
		t.Fatal(err)
	}
}
