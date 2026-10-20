# RES-03 baseline-aware observation repair

Status: fixture-only regression and repair verified locally and in a fresh
same-candidate disposable VM; independent saved-evidence/doc reviews PASS, final
preservation and completion recorded in the evidence directory.
Worktree `.trees/os-bus-foundation`, branch `codex/os-bus-foundation`,
base `7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4`; readiness remains L0.
All candidate11 and earlier source/artifact/evidence bytes remain frozen.

## Evidence and contract

Candidate11's first security refresh is retained FAIL21executed/20passed/1failed
at RES-03 usage equality. Actor local socket close acknowledges no server cleanup.
The current guest metrics predicate permits current connections==current Router
peer count even if both exceed the frozen baseline. Saved snapshots53/54 show
this precise observation gap:5 to6 connections, one extra registered burst Peer,
zero other counters/reservations and external FD30 to30. It does not prove a
persistent production leak or eventual recovery in that failed execution.

Repair only the fixture's post-burst observation. Add
`await_resource_baseline(before, measure, timeout_ms)` in vm_security/run.py.
It keeps one monotonic deadline, uses the unchanged workload quiescence_ms2000,
and measures until the full original usage and Router peer records equal the
frozen before state (Router rows may be ordered by peer identity for comparison).
Never accept a callback result that returns after the deadline. Cap measurements
at128 to bound polling and evidence; exhausting the cap fails. Do not sleep,
reset the deadline, force server cleanup, remove actors or accept partial credit.
Measurement callback failures propagate as failures. Keep the existing generic
metrics checks, healthy concurrent workload probes and all original post-burst
assertions. Retain samples/elapsed time/attempt count with the successful outcome;
on failure retain the original report snapshots and terminal observation.

The2000ms budget bounds accepting/retrying observations, not interrupting a stalled
callback. Existing channel I/O deadlines remain separate. No hard native timeout,
whole-program security acceptance or indefinite-leak claim is introduced.

## Ownership and validation

Write scope is exactly two fixture files:

- `scripts/foundation/vm_security/test_fixture.py`: deterministic regressions first.
- `scripts/foundation/vm_security/run.py`: minimal baseline-aware wait/integration.

No production or other fixture/workload/selection/Nix entrypoint edits are allowed.
Existing State.await/4 retained-ingress semantics are unchanged. Parent owns all
tests, runtime, VM execution and documentation; test worker owns only added Python
regressions and cannot alter existing tests. Independent static and saved-evidence
review follows. Parent documents are this scope, STATUS and COMPATIBILITY.

Required regressions: extra Peer in both authorities then exact recovery needs
another measurement; persistent extra Peer times out; same counts with wrong
Peer/UID credit refuses; Router-only/Limits-only/name/egress retention refuses;
late exact callback cannot pass; one deadline cannot reset; bounded sample cap;
measurement failure cannot become success. Use a controlled monotonic clock and
pure snapshots to make these tests deterministic. Preserve missing-implementation
RED then GREEN on identical test bytes; these unit cases are fixture evidence.

Parent verifies original workload bounds/assertions and every other file/source/
artifact/evidence hash remain unchanged, runs scoped fixture checks, then qualifies
the same immutable candidate11 in a NEW disposable-VM report directory. Preserve
the failed original invocation and its17 exported files. Actual success requires
all21 selected rows, all13 owned normal exits and VMoff plus exact source/fixture/
candidate binding. A production failure must remain FAIL and stop this fixture
scope; do not work around it locally. Full P08/P09/P10/P11/P12 remain open.

Evidence: `test/reports/foundation/continuation-20261010-res03-quiescence/`.
No commits/merges/pushes/remote writes/releases/deployments/live-host-bus traffic,
memory updates or redispatch of the rejected registered-Peer FD04 audit.

## Execution checkpoint

RED28/13 expected missing-helper errors→GREEN28/0 on identical test bytes;
15 original Python tests byte-preserved. Independent spec/quality static reviews
PASS. Fresh same-candidate11 VM21/21,0failed/skipped/blocked,all13 normal EOF exits,
no shutdown errors and VMoff. RES-03 full baseline matched in one94.075ms
observation; this successful VM did not exercise a retry and does not establish
eventual cleanup in the original failed run. Both runs and17guest files each
remain separate. Production59 sources/artifacts69/source-to-BEAM47 mappings,
original-main209files/prior3654evidence/all ten earlier candidates remain unchanged.
Two checker-only inventory/newline corrections are retained, not production fixes.
Saved-evidence/doc reviews PASS; final preservation and res03-completion.json
record the verified outcome in this scope's evidence directory. Full goal stays active at L0; later scopes/gates remain open.
