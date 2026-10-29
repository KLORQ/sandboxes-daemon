// Package server exposes the local daemon over gRPC.
package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	localv1 "github.com/KLORQ/sandboxes-api/gen/go/sandboxes/local/v1"
	core "github.com/KLORQ/sandboxes-core"
	"github.com/KLORQ/sandboxes-core/operation"
	"github.com/KLORQ/sandboxes-core/sandbox"
	"github.com/KLORQ/sandboxes-daemon/internal/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SandboxServer implements the sandbox gRPC service.
type SandboxServer struct {
	localv1.UnimplementedSandboxServiceServer
	svc *service.Service
}

// OperationServer implements the operation gRPC service.
type OperationServer struct {
	localv1.UnimplementedOperationServiceServer
	svc *service.Service
}

// NewSandbox creates a sandbox gRPC service.
func NewSandbox(svc *service.Service) *SandboxServer { return &SandboxServer{svc: svc} }

// NewOperation creates an operation gRPC service.
func NewOperation(svc *service.Service) *OperationServer { return &OperationServer{svc: svc} }

// Create creates a sandbox.
func (s *SandboxServer) Create(ctx context.Context, req *localv1.CreateRequest) (*localv1.CreateResponse, error) {
	op, err := s.svc.Create(ctx, service.CreateRequest{
		Name:           req.GetName(),
		Image:          req.GetImage(),
		Workspace:      req.GetWorkspace(),
		IdempotencyKey: req.GetIdempotencyKey(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.CreateResponse{Operation: toProtoOperation(op)}, nil
}

// Get returns a sandbox.
func (s *SandboxServer) Get(ctx context.Context, req *localv1.GetRequest) (*localv1.GetResponse, error) {
	sb, err := s.svc.Get(ctx, req.GetId())
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.GetResponse{Sandbox: toProtoSandbox(sb)}, nil
}

// List returns a page of sandboxes.
func (s *SandboxServer) List(ctx context.Context, req *localv1.ListRequest) (*localv1.ListResponse, error) {
	items, next, err := s.svc.List(ctx, sandbox.ListOptions{
		PageSize:  int(req.GetPageSize()),
		PageToken: req.GetPageToken(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	resp := &localv1.ListResponse{NextPageToken: next, Items: make([]*localv1.Sandbox, 0, len(items))}
	for _, item := range items {
		resp.Items = append(resp.Items, toProtoSandbox(item))
	}
	return resp, nil
}

// Start starts a sandbox.
func (s *SandboxServer) Start(ctx context.Context, req *localv1.StartRequest) (*localv1.StartResponse, error) {
	op, err := s.svc.Start(ctx, req.GetId())
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.StartResponse{Operation: toProtoOperation(op)}, nil
}

// Stop stops a sandbox.
func (s *SandboxServer) Stop(ctx context.Context, req *localv1.StopRequest) (*localv1.StopResponse, error) {
	op, err := s.svc.Stop(ctx, req.GetId())
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.StopResponse{Operation: toProtoOperation(op)}, nil
}

// Delete deletes a sandbox.
func (s *SandboxServer) Delete(ctx context.Context, req *localv1.DeleteRequest) (*localv1.DeleteResponse, error) {
	op, err := s.svc.Delete(ctx, req.GetId(), req.GetForce())
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.DeleteResponse{Operation: toProtoOperation(op)}, nil
}

// Watch streams current sandbox state changes.
func (s *SandboxServer) Watch(req *localv1.WatchRequest, stream grpc.ServerStreamingServer[localv1.WatchResponse]) error {
	ctx := stream.Context()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	seen := make(map[string]string)
	for {
		if err := s.sendChanges(ctx, req, stream, seen); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (s *SandboxServer) sendChanges(ctx context.Context, req *localv1.WatchRequest, stream grpc.ServerStreamingServer[localv1.WatchResponse], seen map[string]string) error {
	if id := req.GetSandboxId(); id != "" {
		sb, err := s.svc.Get(ctx, id)
		if err != nil {
			return mapError(err)
		}
		return sendSandbox(stream, seen, sb, req.GetAfterRevision())
	}
	token := ""
	for {
		items, next, err := s.svc.List(ctx, sandbox.ListOptions{PageSize: 200, PageToken: token})
		if err != nil {
			return mapError(err)
		}
		for _, sb := range items {
			if err := sendSandbox(stream, seen, sb, req.GetAfterRevision()); err != nil {
				return err
			}
		}
		if next == "" {
			return nil
		}
		token = next
	}
}

func sendSandbox(stream grpc.ServerStreamingServer[localv1.WatchResponse], seen map[string]string, sb sandbox.Sandbox, after int64) error {
	key := fmt.Sprintf("%d/%s/%s", sb.Generation, sb.State, sb.Error)
	if seen[sb.ID] == key || sb.Generation <= after {
		return nil
	}
	seen[sb.ID] = key
	return stream.Send(&localv1.WatchResponse{
		Type:     "sandbox",
		Sandbox:  toProtoSandbox(sb),
		Revision: sb.Generation,
	})
}

// Get returns an operation.
func (s *OperationServer) Get(ctx context.Context, req *localv1.OperationServiceGetRequest) (*localv1.OperationServiceGetResponse, error) {
	op, err := s.svc.GetOperation(ctx, req.GetId())
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.OperationServiceGetResponse{Operation: toProtoOperation(op)}, nil
}

// Wait waits for an operation.
func (s *OperationServer) Wait(ctx context.Context, req *localv1.OperationServiceWaitRequest) (*localv1.OperationServiceWaitResponse, error) {
	op, err := s.svc.WaitOperation(ctx, req.GetId())
	if err != nil {
		return nil, mapError(err)
	}
	return &localv1.OperationServiceWaitResponse{Operation: toProtoOperation(op)}, nil
}

func mapError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, core.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, core.ErrConflict):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

func toProtoSandbox(sb sandbox.Sandbox) *localv1.Sandbox {
	return &localv1.Sandbox{
		Id:            sb.ID,
		Name:          sb.Name,
		State:         sandboxState(sb.State),
		Generation:    sb.Generation,
		Image:         sb.Image,
		Workspace:     sb.Workspace,
		Error:         sb.Error,
		CreatedAtUnix: unix(sb.CreatedAt),
		UpdatedAtUnix: unix(sb.UpdatedAt),
	}
}

func toProtoOperation(op operation.Operation) *localv1.Operation {
	return &localv1.Operation{
		Id:            op.ID,
		SandboxId:     op.SandboxID,
		Kind:          operationKind(op.Kind),
		State:         operationState(op.State),
		Generation:    op.Generation,
		Error:         op.Error,
		CreatedAtUnix: unix(op.CreatedAt),
		UpdatedAtUnix: unix(op.UpdatedAt),
	}
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func sandboxState(v sandbox.State) localv1.SandboxState {
	switch v {
	case sandbox.Pending:
		return localv1.SandboxState_SANDBOX_STATE_PENDING
	case sandbox.Creating:
		return localv1.SandboxState_SANDBOX_STATE_CREATING
	case sandbox.Running:
		return localv1.SandboxState_SANDBOX_STATE_RUNNING
	case sandbox.Stopping:
		return localv1.SandboxState_SANDBOX_STATE_STOPPING
	case sandbox.Stopped:
		return localv1.SandboxState_SANDBOX_STATE_STOPPED
	case sandbox.Deleting:
		return localv1.SandboxState_SANDBOX_STATE_DELETING
	case sandbox.Deleted:
		return localv1.SandboxState_SANDBOX_STATE_DELETED
	case sandbox.Failed:
		return localv1.SandboxState_SANDBOX_STATE_FAILED
	default:
		return localv1.SandboxState_SANDBOX_STATE_UNKNOWN
	}
}

func operationKind(v operation.Kind) localv1.OperationKind {
	switch v {
	case operation.KindCreate:
		return localv1.OperationKind_OPERATION_KIND_CREATE
	case operation.KindStart:
		return localv1.OperationKind_OPERATION_KIND_START
	case operation.KindStop:
		return localv1.OperationKind_OPERATION_KIND_STOP
	case operation.KindDelete:
		return localv1.OperationKind_OPERATION_KIND_DELETE
	default:
		return localv1.OperationKind_OPERATION_KIND_UNSPECIFIED
	}
}

func operationState(v operation.State) localv1.OperationState {
	switch v {
	case operation.Pending:
		return localv1.OperationState_OPERATION_STATE_PENDING
	case operation.Running:
		return localv1.OperationState_OPERATION_STATE_RUNNING
	case operation.Done:
		return localv1.OperationState_OPERATION_STATE_DONE
	case operation.Failed:
		return localv1.OperationState_OPERATION_STATE_FAILED
	default:
		return localv1.OperationState_OPERATION_STATE_UNSPECIFIED
	}
}
