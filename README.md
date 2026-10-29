# sandboxes-daemon

Status: pre-alpha.

Local control plane. Owns the operation journal, reconciliation, SQLite store,
local API, and supervision of runtime and gateway processes.

## Boundaries

- secrets are not stored in plaintext;
- SQL transactions are not held across VM or network I/O;
- partial failures never report success.

## Run

```sh
go run ./cmd/sandboxesd \
  --state "$HOME/.sandboxes" \
  --socket "$HOME/.sandboxes/sandboxesd.sock"
```

The daemon owns `sandboxes.db`, exposes a local gRPC socket with `0600`
permissions, and removes a stale socket only after a failed liveness probe.
