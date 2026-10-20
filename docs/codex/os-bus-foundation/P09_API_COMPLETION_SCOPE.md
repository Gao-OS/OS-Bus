# P09 API dispatch and introspection completion scope

Status: bounded source repair and candidate09 evidence complete; candidate API234/0,
reference234/1 and paired gate FAIL. Full Foundation remains active at L0.
Worktree: `.trees/os-bus-foundation`, branch `codex/os-bus-foundation`,
base `7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4`.

## Preserved inputs and ownership

Candidate08 is immutable: `/tmp/os-bus-security-candidate-20261010-08`, manifest
SHA256 `735f8127e3caec8d52523a234145810cc30bc6bfac08cc9bb329b4a136433b3c`.
The five existing reload/alias/Set/GetAll tests and eight actor reports stay
selected, with their workloads, deadlines and previous evidence preserved.
One additional paired API test adds two required actor reports; selection
is six tests/ten reports for unchanged08 RED and repaired09. The repaired
candidate passes its API rows; the retained reference failure keeps the paired gate FAIL.
The parent owns tests, dispatch/admission edits, runner accounting, builds,
captures, sockets/VMs, source preservation and final ledger. Disjoint source
workers may own only Policy.XML or ExDBus.Introspection, without running builds
or tests. A fixture worker owns only
`apps/gao_bus/test/fixtures/reload_actor.py`, adding the API sequence and CLI
modes while preserving original modes. An architecture worker separately owns
only `docs/adr/ADR-006-activation-and-release-bootstrap.md`.

## Required behavior and evidence

- Apply the pinned dbus-daemon1.14.10 interface/path dispatch truth table: legacy
  methods, Peer and Introspect support every valid path; explicit Properties and
  Monitoring interfaces apply only at the canonical path. Unknown applicable
  member gives UnknownMethod; unknown/unavailable explicit interface gives
  UnknownInterface. An omitted INTERFACE is an actual omitted wire header.
- UpdateActivationEnvironment authorization precedes canonical-path refusal and
  signature validation. Unauthorized controls cannot create effects. Monitoring
  and activation remain truthfully unsupported on the candidate until P10.
- Independently parse full introspection XML: required method input/output
  signatures/directions, bus signals, Features/Interfaces read access and const
  annotations, implemented ReloadConfig; applicable off-path interfaces and
  root/org/freedesktop discovery children. Candidate must not advertise disabled
  Monitoring. Backend-only optional methods/features do not require equality.
- Verify Peer.Ping and trusted GetMachineId on canonical/root/unrelated paths;
  stable GetId across repeated calls and clients, valid format and independent
  machine identity. Existing unit epoch/unavailable-machine regressions stay
  selected. Authentication GUID and bus ID are not required to be equal.
- Exercise complete Properties negative contracts: wrong signatures/arity,
  unknown interface/property precedence, propertyless implemented interfaces,
  both read-only properties and supported variant types, off-path calls, stable
  backend-local values after rejections. Empty target-interface behavior has a
  separate spec-permitted candidate contract; the reference rejects it.
- Record complete raw request/reply frames, correlations, envelopes, zero rights,
  actual UID/GID/PID/group proofs, coherent policy and unchanged config snapshots,
  physical NO_REPLY_EXPECTED barrier, healthy traffic and normal cleanup.
  Accumulate contract failures so both backend reports survive assertions.
  An authorized root ReloadConfig advances generation1 to2 with identical rules;
  record both generations explicitly. Frozen api_contract_selection.json requires
  exactly212 ordinary and22 root operations per backend,234 total, including
  every ordered request/expected-outcome column, rather than actor self-accounting.

## Repair and acceptance boundary

Retain actual candidate08/reference RED results before production repair. The
same six-test/ten-actor selection remains mandatory after a new candidate09
capture. Its reference NO_REPLY_EXPECTED UnknownMethod failure is retained as a
failed comparison, never waived to obtain an all-green gate.
Production write scope: BusMethod, BusInterface, ExDBus.Introspection and
Policy.XML, plus Peer.valid_hello?/1. The captured eight off-path fresh Hello
failures trace to Peer's canonical-path admission pattern; removing that
restriction retains the valid object path and all other Hello checks. The Hello
success reply must address the newly assigned unique name. Router's admission
already allows these paths and requires no scope expansion.
Method-specific XML control bindings intersect loaded send permission
with the reference privileged-caller predicate for environment/monitor controls;
explicit StartServiceByName uses loaded send permission. These are no-effect
control-boundary repairs; activation launch/delivery remains P10. No generic
root privilege is added. GetId drops the mutable environment override and uses
the current bus epoch ID, preserving its format and stability contract.
Old invalid UnknownMethod/UnknownObject expectations are corrected only after
saved reference/source proof; preserve their original source/results explicitly.
Security refresh is required for affected dispatch/authorization changes.
The queued-repeat and optional-INTERFACE reference failures remain selected and
unchanged. Registered-Peer FD04 remains unverified; no rejected-task redispatch.
This scope does not finish full P08/P09, activation, release, installed policy or
VM rollback. No commits, remote writes, releases, live-bus traffic or memory edits.


## Executed checkpoint

Candidate09 changes exactly five production files/seven beams from08, with
native source/artifact unchanged;58 sources/68 artifacts bind to manifest
`009c91af48455e712322fc7574fbd8e55b3c720f1f35e580cdd3eba3910dc40f` and source
`c964b510eb169e658bc59d760529bbf71ab99fd72c145e5638fd55966f8b40ac`.
Scoped warnings-as-errors compilation passes; GaoBus80/0,
ExDBus19tests+1doctest/0 and affected XML/lifecycle54/0 include all11 lifetime,
actual EPIPE and natural-expiry cases. No full FD04/P08 acceptance is inferred.

The unchanged six-test/ten-actor VM selection yields candidate234/0 and
reference234/1; paired5passed/1failed tests and9passed/1failed actors,
zero skipped/blocked/missing. Both VMs power off normally. Independent parent
saved-wire verification and independent review reproduce RED122/1 and repaired0/1
from4002 complete physical frames. Candidate09 native security refresh passes
fixture15/0 and VM21/0, all13 owned processes exit0, without claiming M1 acceptance.

The source-backed reference no-reply-AbsentMember divergence remains selected:
request204 flags1, barrier request205, UnknownMethod reply206(reply_serial204),
then barrier reply(reply_serial205). All failed runs and checker attempts remain
preserved. This bounded repair/evidence checkpoint is complete; the paired gate,
full P09/installed-policy qualification and the full Foundation objective are open.
Evidence directory: test/reports/foundation/continuation-20261010-p09-api-completion/.
