# Offline candidate evidence consistency

This standalone, dependency-free library compares **untrusted claims** to an independently supplied policy and to a second snapshot. `EvidenceConsistent` is not CI, approval, a merge gate, or authorization. There is no network, file, process, parsing, publishing, or merge functionality. No provider API mapping is implied.

The caller must independently authenticate policy and source data; establish complete, fresh enumeration (including all pages, reruns and conflicting statuses), expected issuer and immutable definition, actual candidate tree and ordered parents, and isolation of execution. `complete` and `success` are only caller assertions. Any unknown or missing data must be rejected by the caller, never mapped to a successful value. Identical snapshots cannot detect ABA, stale API responses, or later changes. Enforcement needs a separate atomic platform mechanism.

Policy pins repository, PR, base, head, candidate and tree. Only a two-parent merge with ordered `[base, head]` and exactly one successful evidence record per required check is supported. Each record claims a nonzero workflow `run_id`, `job_id`, `check_run_id` and `attempt`; job and check-run IDs must each be unique. Multiple jobs may share a run ID only with the same attempt, issuer and definition. Duplicate checks, inconsistent attempts, conflicting claims, extra evidence and unsupported forms block. Separate `run_success`, `success` (job), and `check_success` claims must all be true; the caller must map only confirmed completed-success states to true. Labels are opaque bounded ASCII policy identifiers, not assumed GitHub fields. Evidence ordering must match between snapshots.

The record's grouping is a caller claim, not proof that a job belongs to a run or points to a check-run. No numerical equality between job ID and check-run ID is assumed. The model neither selects the latest attempt nor proves other attempts absent; a lone attempt is only a claim. GitHub documents [jobs for a specific run attempt](https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run-attempt), including job ID, run ID and check-run URL, and documents [check-run filtering and pagination](https://docs.github.com/en/rest/checks/runs#list-check-runs-for-a-git-reference). An adapter must independently verify relationships, statuses, provenance and full enumeration; none is implemented here.

Run the isolated tests without fetching dependencies:

```sh
cargo test --offline --manifest-path tools/trusted-ci-policy/Cargo.toml
```

This package is deliberately separate from the root workspace; its tests are not run by the existing root workspace CI. Integration and trusted provenance remain future work.
