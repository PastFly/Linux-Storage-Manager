# Offline candidate evidence consistency

This standalone, dependency-free library compares **untrusted claims** to an independently supplied policy and to a second snapshot. `EvidenceConsistent` is not CI, approval, a merge gate, or authorization. There is no network, file, process, parsing, publishing, or merge functionality. No provider API mapping is implied.

The caller must independently authenticate policy and source data; establish complete, fresh enumeration (including all pages, reruns and conflicting statuses), expected issuer and immutable definition, actual candidate tree and ordered parents, and isolation of execution. `complete` and `success` are only caller assertions. Any unknown or missing data must be rejected by the caller, never mapped to a successful value. Identical snapshots cannot detect ABA, stale API responses, or later changes. Enforcement needs a separate atomic platform mechanism.

Policy pins repository, PR, base, head, candidate and tree. This version accepts only a two-parent merge with ordered `[base, head]`, exactly one successful evidence record per distinct check, unique nonzero run IDs and attempts, and exact issuer and definition labels. Labels are opaque bounded ASCII identifiers defined by the caller, not GitHub field names. Evidence ordering must match between snapshots. Multiple checks sharing a run ID, extra evidence, and unsupported forms block conservatively. `run_id` is an opaque caller-supplied record identifier: the model does not distinguish workflow runs from jobs or check-runs. It does not select a latest attempt; multiple records for a check block, while a lone nonzero attempt is merely a claim and does not prove that other attempts are absent. `success=false` represents every non-success state, including pending and failure. No statement is made about whether a given provider can supply or authenticate these claims.

Run the isolated tests without fetching dependencies:

```sh
cargo test --offline --manifest-path tools/trusted-ci-policy/Cargo.toml
```

This package is deliberately separate from the root workspace; its tests are not run by the existing root workspace CI. Integration and trusted provenance remain future work.
