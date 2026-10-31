package service

import (
	"context"
	"fmt"
	"io"
	"time"

	core "github.com/KLORQ/sandboxes-core"
	"github.com/KLORQ/sandboxes-core/operation"
	"github.com/KLORQ/sandboxes-core/sandbox"
	runtime "github.com/KLORQ/sandboxes-runtime"
)

type execSession struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// Exec runs a non-interactive guest command while tracking its lifecycle.
func (s *Service) Exec(ctx context.Context, id string, req runtime.ExecRequest) (int, error) {
	return s.exec(ctx, id, req, nil)
}

// ExecInteractive runs a tracked interactive guest process.
func (s *Service) ExecInteractive(ctx context.Context, id string, req runtime.InteractiveExecRequest) (int, error) {
	return s.exec(ctx, id, req.ExecRequest, &req)
}

func (s *Service) exec(ctx context.Context, id string, req runtime.ExecRequest, interactive *runtime.InteractiveExecRequest) (int, error) {
	release, err := s.acquireLifecycle(ctx, id)
	if err != nil {
		return 0, err
	}
	sb, err := s.store.Get(ctx, id)
	if err != nil {
		release()
		return 0, err
	}
	executor, ok := s.backend.(runtime.Executor)
	if !ok {
		release()
		return 0, fmt.Errorf("%w: runtime does not support exec", core.ErrConflict)
	}
	sb, err = s.readyForExec(ctx, sb)
	if err != nil {
		release()
		return 0, err
	}
	if req.Workdir == "" {
		req.Workdir = sb.Workspace
	}
	execCtx, cancel := context.WithCancel(ctx)
	for _, output := range []*io.Writer{&req.Stdout, &req.Stderr} {
		if contextual, ok := (*output).(interface {
			WithContext(context.Context) io.Writer
		}); ok {
			*output = contextual.WithContext(execCtx)
		}
	}
	session := &execSession{cancel: cancel, done: make(chan struct{})}
	s.execMu.Lock()
	if s.execSessions == nil {
		s.execSessions = make(map[string]map[*execSession]struct{})
	}
	if len(s.execSessions[id]) >= 32 {
		s.execMu.Unlock()
		release()
		cancel()
		return 0, fmt.Errorf("%w: too many active exec sessions", core.ErrConflict)
	}
	if s.execSessions[id] == nil {
		s.execSessions[id] = make(map[*execSession]struct{})
	}
	s.execSessions[id][session] = struct{}{}
	s.execMu.Unlock()
	release()
	defer func() {
		cancel()
		s.execMu.Lock()
		delete(s.execSessions[id], session)
		if len(s.execSessions[id]) == 0 {
			delete(s.execSessions, id)
		}
		close(session.done)
		s.execMu.Unlock()
	}()
	return s.runSession(execCtx, executor, s.backend.Handle(sb.Name), req, interactive)
}

func (s *Service) runSession(ctx context.Context, executor runtime.Executor, handle runtime.Handle, req runtime.ExecRequest, interactive *runtime.InteractiveExecRequest) (int, error) {
	if interactive == nil {
		return s.runExec(ctx, executor, handle, req)
	}
	native, ok := s.backend.(runtime.InteractiveExecutor)
	if !ok {
		return 0, fmt.Errorf("%w: runtime does not support interactive exec", core.ErrConflict)
	}
	interactive.ExecRequest = req
	return native.ExecInteractive(ctx, handle, *interactive)
}

func (s *Service) readyForExec(ctx context.Context, sb sandbox.Sandbox) (sandbox.Sandbox, error) {
	if sb.State == sandbox.Stopped {
		if err := s.startForExec(ctx, sb); err != nil {
			return sandbox.Sandbox{}, err
		}
		updated, err := s.store.Get(ctx, sb.ID)
		if err != nil {
			return sandbox.Sandbox{}, err
		}
		sb = updated
	} else if sb.State != sandbox.Running {
		return sandbox.Sandbox{}, fmt.Errorf("%w: sandbox is not ready for exec", core.ErrConflict)
	}
	if sb.Meta == nil {
		sb.Meta = &sandbox.Meta{}
	}
	sb.Meta.LastUsedAt = s.now().UTC()
	if err := s.store.Update(ctx, sb); err != nil {
		return sandbox.Sandbox{}, fmt.Errorf("record sandbox use: %w", err)
	}
	return sb, nil
}

func (s *Service) startForExec(ctx context.Context, sb sandbox.Sandbox) error {
	handle := s.backend.Handle(sb.Name)
	handle.Ports = runtimePorts(sb.Ports)
	handle.Allow = runtimeRules(policyAllow(sb.Policy))
	handle.Deny = runtimeRules(policyDeny(sb.Policy))
	if err := s.backend.Start(ctx, handle); err != nil {
		return s.markRuntimeUnknown(ctx, sb, err)
	}
	if _, err := s.apply(ctx, sb, operation.KindStart, sandbox.Running); err != nil {
		return s.markRuntimeUnknown(ctx, sb, err)
	}
	return nil
}

func (s *Service) runExec(ctx context.Context, fallback runtime.Executor, handle runtime.Handle, req runtime.ExecRequest) (int, error) {
	if native, ok := s.backend.(runtime.CancelableExecutor); ok && cancelableOutputs(req) {
		return native.ExecCancelable(ctx, handle, req)
	}
	return fallback.Exec(ctx, handle, req)
}

func cancelableOutputs(req runtime.ExecRequest) bool {
	for _, output := range []io.Writer{req.Stdout, req.Stderr} {
		if output != nil {
			if _, ok := output.(runtime.ContextWriter); !ok {
				return false
			}
		}
	}
	return true
}

// cancelExecSessions is called with the sandbox lifecycle gate held.
func (s *Service) cancelExecSessions(ctx context.Context, id string) error {
	s.execMu.Lock()
	sessions := make([]*execSession, 0, len(s.execSessions[id]))
	for session := range s.execSessions[id] {
		sessions = append(sessions, session)
		session.cancel()
	}
	s.execMu.Unlock()
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for _, session := range sessions {
		select {
		case <-session.done:
		case <-waitCtx.Done():
			return fmt.Errorf("wait for exec sessions: %w", waitCtx.Err())
		}
	}
	return nil
}
