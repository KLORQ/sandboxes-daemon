// Package network adapts the gateway manager to the runtime network contract.
package network

import (
	"context"
	"path/filepath"

	gateway "github.com/KLORQ/sandboxes-gateway"
	"github.com/KLORQ/sandboxes-gateway/policy"
	runtime "github.com/KLORQ/sandboxes-runtime"
)

// Manager is the subset of the gateway manager used by the adapter.
type Manager interface {
	Start(ctx context.Context, p policy.Policy) (gateway.Network, error)
	Stop(ctx context.Context, name string) error
}

// Adapter supplies default-deny gateway attachments to the runtime.
type Adapter struct {
	manager  Manager
	auditDir string
}

// New creates a gateway network adapter.
func New(manager Manager, auditDir string) *Adapter {
	return &Adapter{manager: manager, auditDir: auditDir}
}

// Start starts a gateway with a default-deny policy.
func (a *Adapter) Start(ctx context.Context, sandbox string) (runtime.NetworkAttachment, error) {
	net, err := a.manager.Start(ctx, policy.Policy{
		Revision:  1,
		SandboxID: sandbox,
		AuditPath: filepath.Join(a.auditDir, sandbox+".audit.jsonl"),
	})
	if err != nil {
		return runtime.NetworkAttachment{}, err
	}
	return runtime.NetworkAttachment{
		SocketPath:  net.SocketPath,
		MAC:         net.MAC,
		DeviceIP:    net.DeviceIP,
		GatewayIP:   net.GatewayIP,
		Annotations: net.Annotations,
	}, nil
}

// Stop stops the sandbox gateway.
func (a *Adapter) Stop(ctx context.Context, sandbox string) error {
	return a.manager.Stop(ctx, sandbox)
}

var _ runtime.Network = (*Adapter)(nil)
