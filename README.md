# sandboxes-daemon

Policy updates use atomic single-rule mutations. The legacy whole-policy
replacement RPC is rejected to prevent stale clients from restoring revoked
rules; clients must upgrade with the coordinated API and SDK release.

Status: pre-alpha.

Local control plane. Owns the operation journal, reconciliation, SQLite store,
local API, and supervision of runtime and gateway processes.

## Boundaries

- secrets are not stored in plaintext;
- SQL transactions are not held across VM or network I/O;
- partial failures never report success.
- registry secrets use the host OS credential vault and are never written to SQLite.

## Run

```sh
go run ./cmd/sandboxesd \
  --state "$HOME/.sandboxes" \
  --socket "$HOME/.sandboxes/sandboxesd.sock"
```

The daemon owns `sandboxes.db` and exposes a local gRPC socket with `0600`
permissions. It refuses to start when the socket path already exists; stale
paths are not removed automatically because their ownership is unverified.
The daemon also holds a state-directory lock while running; a second cooperating
daemon using that state directory fails to start. The lock file is retained.

Runtime mode is explicit:

```sh
# state-only default
sandboxesd --state "$HOME/.sandboxes"

# containerd/nerdbox backend
sandboxesd --state "$HOME/.sandboxes" \
  --containerd "$HOME/.sandboxes/containerd/containerd.sock" \
  --gvproxy "$HOME/.sandboxes/bin/gvproxy-policy-v2" \
  --image alpine:3.22
```

Empty `--containerd` keeps the state-only control plane. With a runtime backend,
create/start/stop/delete call the runtime adapter. With `--gvproxy`, the daemon
also starts a default-deny gateway and attaches nerdbox network annotations;
exec/PTY still remain unsupported.

`RegistryCredentialService` stores registry login entries in macOS Keychain,
Windows Credential Manager, or Linux Secret Service. It fails closed when the
native vault is unavailable and has no plaintext fallback. Credential scopes
are persisted separately. Authentication verification and use by guest image
pulls are not wired yet.

The account RPC runs trusted daemon-configured OAuth only. On Docker Hub device
login it exchanges the returned access token for a Hub PAT, stores access and
refresh tokens in the native vault, stores the PAT under separate host-only and
all-sandboxes registry scopes, and records a non-authenticating fingerprint so
logout removes only credentials created by that account flow. Existing registry
entries are not overwritten. Docker account login uses the Docker public
device-flow client ID embedded in Docker CLI and the installed Docker
Sandboxes `sbx` binary. No Klorq OAuth registration is needed. Browser launch
is supported on macOS; other platforms return unsupported.
