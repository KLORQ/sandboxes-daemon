# sandboxes-daemon

Status: pre-alpha.

Local control plane. Owns the operation journal, reconciliation, SQLite store,
local API, and supervision of runtime and gateway processes.

## Boundaries

- secrets are not stored in plaintext;
- SQL transactions are not held across VM or network I/O;
- partial failures never report success.
