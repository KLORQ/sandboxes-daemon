package server

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	localv1 "github.com/KLORQ/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/KLORQ/sandboxes-daemon/internal/service"
	"github.com/KLORQ/sandboxes-daemon/internal/store"
)

func TestGRPCLifecycle(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	svc := service.New(st)
	localv1.RegisterSandboxServiceServer(grpcServer, NewSandbox(svc))
	localv1.RegisterOperationServiceServer(grpcServer, NewOperation(svc))
	go func() { _ = grpcServer.Serve(lis) }()
	defer grpcServer.Stop()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	sandboxes := localv1.NewSandboxServiceClient(conn)
	operations := localv1.NewOperationServiceClient(conn)

	created, err := sandboxes.Create(ctx, &localv1.CreateRequest{Name: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if created.GetOperation().GetState() != localv1.OperationState_OPERATION_STATE_DONE {
		t.Fatalf("create state = %s", created.GetOperation().GetState())
	}
	id := created.GetOperation().GetSandboxId()

	got, err := sandboxes.Get(ctx, &localv1.GetRequest{Id: id})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetSandbox().GetState() != localv1.SandboxState_SANDBOX_STATE_STOPPED {
		t.Fatalf("state = %s", got.GetSandbox().GetState())
	}

	list, err := sandboxes.List(ctx, &localv1.ListRequest{PageSize: 10})
	if err != nil || len(list.GetItems()) != 1 {
		t.Fatalf("list: %+v, %v", list, err)
	}

	if _, err := sandboxes.Start(ctx, &localv1.StartRequest{Id: id}); err != nil {
		t.Fatal(err)
	}
	got, err = sandboxes.Get(ctx, &localv1.GetRequest{Id: id})
	if err != nil || got.GetSandbox().GetState() != localv1.SandboxState_SANDBOX_STATE_RUNNING {
		t.Fatalf("start: %+v, %v", got, err)
	}

	if _, err := sandboxes.Stop(ctx, &localv1.StopRequest{Id: id}); err != nil {
		t.Fatal(err)
	}
	if _, err := sandboxes.Delete(ctx, &localv1.DeleteRequest{Id: id}); err != nil {
		t.Fatal(err)
	}
	if _, err := sandboxes.Get(ctx, &localv1.GetRequest{Id: id}); status.Code(err) != codes.NotFound {
		t.Fatalf("expected not found, got %v", err)
	}

	if _, err := operations.Get(ctx, &localv1.OperationServiceGetRequest{Id: created.GetOperation().GetId()}); err != nil {
		t.Fatal(err)
	}
}

func TestGRPCWatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	svc := service.New(st)
	localv1.RegisterSandboxServiceServer(grpcServer, NewSandbox(svc))
	localv1.RegisterOperationServiceServer(grpcServer, NewOperation(svc))
	go func() { _ = grpcServer.Serve(lis) }()
	defer grpcServer.Stop()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	sandboxes := localv1.NewSandboxServiceClient(conn)

	created, err := sandboxes.Create(ctx, &localv1.CreateRequest{Name: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := sandboxes.Watch(ctx, &localv1.WatchRequest{})
	if err != nil {
		t.Fatal(err)
	}
	event, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if event.GetType() != "sandbox" || event.GetSandbox().GetId() != created.GetOperation().GetSandboxId() {
		t.Fatalf("unexpected event: %+v", event)
	}
	if _, err := sandboxes.Start(ctx, &localv1.StartRequest{Id: event.GetSandbox().GetId()}); err != nil {
		t.Fatal(err)
	}
	event, err = stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if event.GetSandbox().GetState() != localv1.SandboxState_SANDBOX_STATE_RUNNING {
		t.Fatalf("unexpected state: %s", event.GetSandbox().GetState())
	}
}
