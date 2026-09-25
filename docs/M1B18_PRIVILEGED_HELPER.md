# M1B18 privileged-helper process boundary

M1B18 adds a process boundary for the future production privileged helper without enabling storage mutation.

The feature-gated `lsm-privileged-helper-protocol` binary:

- reads one bounded JSON request from standard input;
- rejects inputs larger than 64 KiB before protocol execution;
- decodes the versioned typed request and rejects unknown top-level/nested effective fields by requiring the decoded value to round-trip to the same JSON value;
- revalidates the request digest, durable execution identity, native-manifest binding and operation safety rules;
- returns only a validation receipt;
- always reports `mutation_enabled=false` and `execution_started=false`;
- does not spawn storage tools, open block devices, advance the durable journal or perform privileged writes.

The wire request remains semantic. It carries one validated `NativeOperationSpec`, not a shell command or arbitrary argv. Exact command compilation and privileged execution remain separate later gates.

## Safety invariants

The protocol boundary must fail closed when:

- schema version is unknown;
- request size exceeds the fixed limit;
- JSON is malformed or contains fields not represented by the typed request;
- request digest does not match its effective fields;
- the operation payload is not in the approved growth-only set;
- XFS lacks a mounted target;
- a device path is not a safe absolute `/dev/...` path;
- production mutation is enabled unexpectedly.

M1B18 intentionally does **not** make `storagemgr apply` available. `MUTATION_ENABLED=false` remains the production invariant.
