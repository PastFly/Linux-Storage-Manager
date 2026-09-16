# Safety model

Storage management is destructive by nature. Safety is an architectural requirement, not a UI warning.

## Invariants

- **M0 is read-only.** No command that changes persistent or runtime storage state is allowed.
- **Fail closed.** Unknown device types, incomplete dependency chains, contradictory metadata, and unsupported layouts must block future write plans.
- **No implicit shell.** Commands are invoked directly with explicit argument vectors.
- **Re-discover before execution.** A future plan must be rejected if the topology changed after the plan was produced.
- **Backup before mutation.** Partition-table and LVM metadata backups are mandatory where applicable.
- **Verify after mutation.** Success means the resulting topology and filesystem size match the plan, not merely that a subprocess returned exit code 0.

## Future operation classes

Every planned step will carry a reversibility classification:

- `Reversible`
- `PartiallyReversible`
- `Irreversible`

A workflow containing an irreversible step must state that explicitly before execution.

## Root privileges

Inspection should run unprivileged where possible. Future privileged operations should be isolated, minimal, auditable, and invoked only after a validated plan.

## Unsupported examples in early releases

- moving a partition start sector;
- shrinking XFS;
- automatic RAID recovery;
- filesystem conversion;
- arbitrary shell hooks.
