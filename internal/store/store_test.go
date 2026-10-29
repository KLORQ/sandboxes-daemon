package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	core "github.com/KLORQ/sandboxes-core"
	"github.com/KLORQ/sandboxes-core/operation"
	"github.com/KLORQ/sandboxes-core/sandbox"
)

func TestSandboxAndOperationLifecycle(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	now := time.Unix(100, 0).UTC()
	sb := sandbox.Sandbox{
		ID: "sb-1", Name: "dev", State: sandbox.Stopped, Generation: 1,
		Image: "scratch", CreatedAt: now, UpdatedAt: now,
	}
	op := operation.Operation{
		ID: "op-1", SandboxID: "sb-1", Kind: operation.KindCreate,
		State: operation.Done, Generation: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.CreateSandboxWithOperation(ctx, sb, op); err != nil {
		t.Fatal(err)
	}

	got, err := st.Get(ctx, "sb-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "dev" {
		t.Fatalf("name = %s", got.Name)
	}
	byName, err := st.GetByName(ctx, "dev")
	if err != nil || byName.ID != "sb-1" {
		t.Fatalf("by name: %+v, %v", byName, err)
	}

	opGot, err := st.Operations().Get(ctx, "op-1")
	if err != nil || opGot.State != operation.Done {
		t.Fatalf("operation: %+v, %v", opGot, err)
	}

	items, next, err := st.List(ctx, sandbox.ListOptions{PageSize: 10})
	if err != nil || len(items) != 1 || next != "" {
		t.Fatalf("list: %+v %q %v", items, next, err)
	}

	sb.State = sandbox.Running
	sb.Generation = 2
	sb.UpdatedAt = now.Add(time.Second)
	op2 := operation.Operation{
		ID: "op-2", SandboxID: "sb-1", Kind: operation.KindStart,
		State: operation.Done, Generation: 2, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.ApplySandboxOperation(ctx, sb, op2); err != nil {
		t.Fatal(err)
	}
	got, err = st.Get(ctx, "sb-1")
	if err != nil || got.State != sandbox.Running || got.Generation != 2 {
		t.Fatalf("updated: %+v, %v", got, err)
	}

	op3 := operation.Operation{
		ID: "op-3", SandboxID: "sb-1", Kind: operation.KindDelete,
		State: operation.Done, Generation: 3, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.DeleteSandboxWithOperation(ctx, "sb-1", op3); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(ctx, "sb-1"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestPagination(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	now := time.Unix(100, 0).UTC()
	for i, id := range []string{"sb-1", "sb-2", "sb-3"} {
		sb := sandbox.Sandbox{
			ID: id, Name: id, State: sandbox.Stopped, Generation: 1,
			CreatedAt: now.Add(time.Duration(i) * time.Second), UpdatedAt: now,
		}
		if err := st.Create(ctx, sb); err != nil {
			t.Fatal(err)
		}
	}
	first, next, err := st.List(ctx, sandbox.ListOptions{PageSize: 2})
	if err != nil || len(first) != 2 || next == "" {
		t.Fatalf("first page: %+v %q %v", first, next, err)
	}
	second, next2, err := st.List(ctx, sandbox.ListOptions{PageSize: 2, PageToken: next})
	if err != nil || len(second) != 1 || next2 != "" {
		t.Fatalf("second page: %+v %q %v", second, next2, err)
	}
}
