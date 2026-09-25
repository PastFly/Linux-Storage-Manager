# M1B19 privileged-helper live revalidation

M1B19 makes the future privileged-helper boundary independently verify the exact target identity before any command compilation or storage mutation can be considered.

Protocol schema v2 binds each request to:

- the durable execution ID;
- source/native manifest digests;
- the exact fresh target-identity digest;
- the original absolute target selector;
- the exact resolved `/dev/...` device;
- one authorized typed native mutation step.

The feature-gated helper process performs its own read-only host discovery, captures a fresh target manifest for the bound target, and requires the live manifest digest, target selector and resolved device to match the request exactly.

A successful response is still validation-only:

- `status=identity_revalidated`;
- `mutation_enabled=false`;
- `execution_started=false`.

The helper does not compile mutation argv, spawn storage tools, open devices for writing, or advance the durable journal. Any identity drift fails closed before those later gates.
