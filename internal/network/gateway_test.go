package network

import (
	"context"
	"path/filepath"
	"testing"

	gateway "github.com/KLORQ/sandboxes-gateway"
	"github.com/KLORQ/sandboxes-gateway/policy"
)

type fakeManager struct {
	policy  policy.Policy
	net     gateway.Network
	stopped string
}

func (f *fakeManager) Start(_ context.Context, p policy.Policy) (gateway.Network, error) {
	f.policy = p
	return f.net, nil
}

func (f *fakeManager) Stop(_ context.Context, name string) error {
	f.stopped = name
	return nil
}

func TestAdapterStart(t *testing.T) {
	manager := &fakeManager{net: gateway.Network{
		SocketPath:  "/run/dev.sock",
		MAC:         "fa:43:25:01:02:03",
		DeviceIP:    "192.168.127.2",
		GatewayIP:   "192.168.127.1",
		Annotations: []string{"net=1"},
	}}
	adapter := New(manager, "/tmp/audit")
	attachment, err := adapter.Start(context.Background(), "dev")
	if err != nil {
		t.Fatal(err)
	}
	if manager.policy.SandboxID != "dev" || manager.policy.Revision != 1 {
		t.Fatalf("policy = %+v", manager.policy)
	}
	if manager.policy.AuditPath != filepath.Join("/tmp/audit", "dev.audit.jsonl") {
		t.Fatalf("audit path = %s", manager.policy.AuditPath)
	}
	if attachment.SocketPath != "/run/dev.sock" || len(attachment.Annotations) != 1 {
		t.Fatalf("attachment = %+v", attachment)
	}
}

func TestAdapterStop(t *testing.T) {
	manager := &fakeManager{}
	adapter := New(manager, "/tmp/audit")
	if err := adapter.Stop(context.Background(), "dev"); err != nil {
		t.Fatal(err)
	}
	if manager.stopped != "dev" {
		t.Fatalf("stopped = %s", manager.stopped)
	}
}
