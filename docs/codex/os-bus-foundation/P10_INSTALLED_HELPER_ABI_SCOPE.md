# P10 installed helper ABI prerequisite

This bounded implementation continues the authorized full P00–P12 assignment.
It preserves all mandatory reference failures and does not pass M1, M2, M3 or
ACT-01–ACT-07. Production Runtime activation refusal remains in place.

Implement Stage A from the source-bound audit at
`test/reports/foundation/continuation-20261011-full-goal/environment/p10-installed-helper-audit/QUALIFICATION_PROPOSAL.md`:
the real installed helper, an ordinary package-time bound production bridge,
and packaged HelperWorker against the canonical reference bus in a disposable
pinned NixOS VM. No host bus, custom privileged helper, environment-selected
helper/config/address or root BEAM is permitted.

## Ownership and edits

- The worker owns new `nix/tests/activation.nix` and
  `scripts/foundation/p10_activation/` files: immutable exact-name fixture C
  actor/service/policy, bounded guest runner, pure fixture checks and workload.
- The parent owns this scope, STATUS/COMPATIBILITY, separate bridge build and
  new immutable capture, independent review and VM scheduling.
- Existing production source, captured packages/candidates, installed profile
  inputs, workload thresholds, earlier failed reports and reference assertions
  are unchanged. Required fixture additions must be individually inventoried.
- New evidence is under
  `test/reports/foundation/continuation-20261011-full-goal/environment/p10-installed-helper-stage-a/`.

## Verification

Use the audit's exact A0–A7 rows and strict selected/executed/pass/fail/block
accounting. Verify canonical socket/daemon ownership, profile hashes and helper
wrapper UID/GID/mode/suid semantics before launch. Actual pre-GLib environment,
real/effective/saved IDs, groups and inherited FD witnesses are required;
controller observations must agree. Helper status requires the exact GHB record
and worker observation, never inference from successful Port close.

The successful service must be nonroot, receive independent allowed calls and
real FD readback, and deny the other named fixture user. Failure rows retain
exact numeric helper errors and no-owner assertions. The live no-name child
must remain charged/contained until observed termination. All owned transient
units and children must be stopped/reaped, exported evidence retained and VM
shutdown confirmed on success or failure.

Run pure fixture regressions, strict C compilation and Nix evaluation before
one serialized VM. Every required missing facility remains BLOCKED. Preserve
each failed attempt. After two failed Sol repair rounds, stop edits and report
the evidenced impasse for bounded recovery. No readiness promotion or candidate
canonical cutover follows Stage A. Production pairing/Runtime consumers and
paired ACT qualification are separate dependent work.
