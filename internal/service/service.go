// Package service implements sandbox control-plane use cases.
package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	core "github.com/KLORQ/sandboxes-core"
	"github.com/KLORQ/sandboxes-core/operation"
	"github.com/KLORQ/sandboxes-core/sandbox"

	"github.com/KLORQ/sandboxes-daemon/internal/store"
)

// Service coordinates durable sandbox state and operations.
type Service struct {
	store   *store.Store
	journal *operation.Journal
	now     func() time.Time
}

// New creates a control-plane service.
func New(st *store.Store) *Service {
	return &Service{
		store:   st,
		journal: operation.NewJournal(st.Operations()),
		now:     time.Now,
	}
}

// CreateRequest describes a new sandbox.
type CreateRequest struct {
	Name           string
	Image          string
	Workspace      string
	IdempotencyKey string
}

// Create creates a stopped sandbox and a completed create operation.
func (s *Service) Create(ctx context.Context, req CreateRequest) (operation.Operation, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return operation.Operation{}, fmt.Errorf("%w: name is required", core.ErrConflict)
	}
	if len(name) > 63 {
		return operation.Operation{}, fmt.Errorf("%w: name is too long", core.ErrConflict)
	}
	now := s.now().UTC()
	sbID, err := newID("sb")
	if err != nil {
		return operation.Operation{}, err
	}
	opID, err := newID("op")
	if err != nil {
		return operation.Operation{}, err
	}
	image := req.Image
	if image == "" {
		image = "scratch"
	}
	sb := sandbox.Sandbox{
		ID:         sbID,
		Name:       name,
		State:      sandbox.Stopped,
		Generation: 1,
		Image:      image,
		Workspace:  req.Workspace,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	op := operation.Operation{
		ID:             opID,
		SandboxID:      sbID,
		Kind:           operation.KindCreate,
		State:          operation.Done,
		Generation:     1,
		IdempotencyKey: req.IdempotencyKey,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.store.CreateSandboxWithOperation(ctx, sb, op); err != nil {
		return operation.Operation{}, err
	}
	return op, nil
}

// Reconcile repairs state left behind by an interrupted daemon.
func (s *Service) Reconcile(ctx context.Context) (int, error) {
	now := s.now().UTC()
	changed := 0
	all, err := s.listAll(ctx)
	if err != nil {
		return 0, err
	}
	for i := range all {
		sb := all[i]
		switch sb.State {
		case sandbox.Running, sandbox.Creating, sandbox.Deleting:
			sb.State = sandbox.Unknown
			sb.Error = "daemon restarted; runtime state is unknown"
			sb.UpdatedAt = now
			if err := s.store.Update(ctx, sb); err != nil {
				return changed, err
			}
			changed++
		}
	}
	unfinished, err := s.store.Operations().ListUnfinished(ctx)
	if err != nil {
		return changed, err
	}
	for i := range unfinished {
		op := unfinished[i]
		if err := s.journal.Fail(ctx, op.ID, "daemon restarted"); err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}

// Get returns a sandbox by ID.
func (s *Service) Get(ctx context.Context, id string) (sandbox.Sandbox, error) {
	return s.store.Get(ctx, id)
}

// GetByName returns a sandbox by name.
func (s *Service) GetByName(ctx context.Context, name string) (sandbox.Sandbox, error) {
	return s.store.GetByName(ctx, name)
}

// List returns one page of sandboxes.
func (s *Service) List(ctx context.Context, opts sandbox.ListOptions) ([]sandbox.Sandbox, string, error) {
	return s.store.List(ctx, opts)
}

// Start transitions a sandbox to running.
func (s *Service) Start(ctx context.Context, id string) (operation.Operation, error) {
	sb, err := s.store.Get(ctx, id)
	if err != nil {
		return operation.Operation{}, err
	}
	if sb.State == sandbox.Running {
		return operation.Operation{}, fmt.Errorf("%w: sandbox is already running", core.ErrConflict)
	}
	if sb.State == sandbox.Deleting || sb.State == sandbox.Deleted {
		return operation.Operation{}, fmt.Errorf("%w: sandbox is being deleted", core.ErrConflict)
	}
	return s.apply(ctx, sb, operation.KindStart, sandbox.Running)
}

// Stop transitions a sandbox to stopped.
func (s *Service) Stop(ctx context.Context, id string) (operation.Operation, error) {
	sb, err := s.store.Get(ctx, id)
	if err != nil {
		return operation.Operation{}, err
	}
	if sb.State == sandbox.Deleting || sb.State == sandbox.Deleted {
		return operation.Operation{}, fmt.Errorf("%w: sandbox is being deleted", core.ErrConflict)
	}
	return s.apply(ctx, sb, operation.KindStop, sandbox.Stopped)
}

// Delete removes a sandbox.
func (s *Service) Delete(ctx context.Context, id string, force bool) (operation.Operation, error) {
	sb, err := s.store.Get(ctx, id)
	if err != nil {
		return operation.Operation{}, err
	}
	if sb.State == sandbox.Running && !force {
		return operation.Operation{}, fmt.Errorf("%w: running sandbox requires force", core.ErrConflict)
	}
	now := s.now().UTC()
	opID, err := newID("op")
	if err != nil {
		return operation.Operation{}, err
	}
	op := operation.Operation{
		ID:         opID,
		SandboxID:  id,
		Kind:       operation.KindDelete,
		State:      operation.Done,
		Generation: sb.Generation + 1,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := s.store.DeleteSandboxWithOperation(ctx, id, op); err != nil {
		return operation.Operation{}, err
	}
	return op, nil
}

// GetOperation returns an operation by ID.
func (s *Service) GetOperation(ctx context.Context, id string) (operation.Operation, error) {
	return s.store.Operations().Get(ctx, id)
}

// WaitOperation waits until an operation reaches a terminal state.
func (s *Service) WaitOperation(ctx context.Context, id string) (operation.Operation, error) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		op, err := s.GetOperation(ctx, id)
		if err != nil {
			return operation.Operation{}, err
		}
		if op.State == operation.Done || op.State == operation.Failed {
			return op, nil
		}
		select {
		case <-ctx.Done():
			return operation.Operation{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Service) apply(ctx context.Context, sb sandbox.Sandbox, kind operation.Kind, state sandbox.State) (operation.Operation, error) {
	now := s.now().UTC()
	opID, err := newID("op")
	if err != nil {
		return operation.Operation{}, err
	}
	sb.State = state
	sb.Generation++
	sb.UpdatedAt = now
	op := operation.Operation{
		ID:         opID,
		SandboxID:  sb.ID,
		Kind:       kind,
		State:      operation.Done,
		Generation: sb.Generation,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := s.store.ApplySandboxOperation(ctx, sb, op); err != nil {
		return operation.Operation{}, err
	}
	return op, nil
}

func (s *Service) listAll(ctx context.Context) ([]sandbox.Sandbox, error) {
	var out []sandbox.Sandbox
	token := ""
	for {
		items, next, err := s.store.List(ctx, sandbox.ListOptions{PageSize: 200, PageToken: token})
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		if next == "" {
			return out, nil
		}
		token = next
	}
}

func newID(prefix string) (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(raw[:]), nil
}
