# P09: bounded asynchronous reload and ordered publication

Continue the full CODEX_GOAL assignment at baseline `7aba5a4` in
`codex/os-bus-foundation`. This is a separate implementation scope; previous
scopes, evidence, frozen candidates and main-checkout changes remain intact.

## Contract

Preparation runs in one monitored worker under a Policy-owned linked named
Task.Supervisor, with one child maximum. Policy retains sole ownership of its
protected ETS generation. Application explicitly selects Router publication;
the existing Policy-only fixture contract defaults to standalone publication.
Missing Router never changes the selected publication mode.

Policy traps exits so ordinary supervised shutdown drains its exact linked
reload supervisor. Brutal owner death may leave that supervisor retiring after
Policy DOWN. Fresh startup monitors the exact PID returned by a name collision
and waits within one fixed absolute 5000ms deadline before retrying. It never
adopts, stops or kills the existing supervisor; a live incumbent causes bounded
startup failure. No fresh worker starts before the previous supervisor retires.

Production admission reserves one separate fixed reload slot in Limits before
enqueueing a candidate. It is independent of XML ingress/egress thresholds.
The reservation belongs to the exact Policy PID, survives requesting-peer exit
and stays charged until the worker actually terminates. Pending orphan admission
expires; late admission, result, commit, timer and release references cannot
publish or retire a later job. There is no reload queue or coalescing.

The worker loads and compiles authorization, accounts and discovery together.
Production direct replacement reserves admission before enqueueing only the raw
candidate and compiles in the worker. Explicit standalone trusted fixtures keep
their legacy compile-before-admission error ordering; this exception cannot be
selected by a missing Router.
Policy notifies the captured Router PID; Router performs a short, memory-only
CAS commit validating Policy incarnation, request reference, base generation,
captured Router identity and absolute deadline. All production replacement APIs
use this boundary. File-backed production replacement preserves runtime
compatibility; standalone trusted fixture replacement keeps its existing API.
Normal synchronous results and wire completion wait for publication/discard and
actual worker DOWN, with admission retired before notifying the caller. This
preserves immediate sequential reload APIs. Timeout may report its error while
the worker drains, but cannot release the busy slot early. The wire path is deferred.

Router retains one bounded reply record containing correlation, caller identity,
the request's captured snapshot and optional frame acknowledgement. It retains
no original body or FD bundle. Original FDs and ingress retire immediately.
Only the requesting Peer's existing route_complete acknowledgement is deferred
until terminal commit/error, preserving NO_REPLY ReloadConfig-to-Ping order.
Other clients continue routing under the old complete generation during loading.
An admitted reload continues after caller exit; no reply reaches a replacement
connection. Completion uses current serial state and the old request snapshot
for receive authorization. Preserve configured send authorization and existing
error mappings; overlapping requests return LimitsExceeded/reload_busy.

Timeout refuses publication, terminates the worker and retains admission until
DOWN. This does not claim immediate cancellation of dirty NIF or filesystem work.
Internal start options may provide a narrow preparation barrier for deterministic
tests; there is no client-controlled preparation hook.

## Allowed changes

Five production files only: `policy.ex`, `router.ex`, `bus_interface.ex`,
`limits.ex`, `application.ex` in `apps/gao_bus/lib/gao_bus/`.
New tests `policy/async_reload_test.exs`, `policy/async_router_reload_test.exs`,
`reload_limits_test.exs` and optional new `fixtures/async_reload_*` actors.
This scope, STATUS.md and new evidence under
`test/reports/foundation/continuation-20261011-async-reload/`.

No changes to native transport, decoder, Config/Capture/Services, existing tests,
reference oracle, mandatory comparison failures, activation or packaging.
Parent alone runs build/tests/VMs; workers have disjoint source/test ownership.
Host root-only system-profile reload socket tests remain prohibited.

## Verification checklist

- [x] Preserve fresh original-main/workspace/evidence/candidate hash basis.
- [x] Reverify inherited native lifecycle/writer regressions.
- [x] Deterministic RED before each production slice.
- [x] Worker overlap keeps Router healthy and generations coherent.
- [x] Admission is bounded; busy, orphan, death, timeout and duplicate cleanup.
- [x] Router commit ordering, exact PID/epoch/base and stale publication refusal
      (Policy regressions plus Router integration/static review; limit below).
- [x] Caller exit, NO_REPLY effect/ack order and captured receive authorization.
- [x] Invalid/restart-required preparation preserves the complete prior row.
- [x] Synchronous and standalone API compatibility.
- [x] Scoped compile, format, regressions and independent source reviews executed
      (the existing affected gate remains FAIL284/1; no acceptance waiver).
- [x] Final preservation and exact evidence ledger; readiness remains L0 unless
      the full mandatory program gates actually pass.

Known queued-repeat, optional-INTERFACE and no-reply comparisons remain FAIL.
This scope cannot establish P08/P09 completion, activation, M1 or replacement
acceptance merely from focused green results.

## Executed evidence and limits

Evidence: `test/reports/foundation/continuation-20261011-async-reload/`.
Final new tests PASS31/0 (Policy18, Router8, Limits5); strict compile and scoped
format PASS. Unchanged discovery PASS66/0, Unix/Peer PASS61/0, and Router/Limits
PASS48/0 bind the final source/build. The earlier inherited lifecycle/writer
PASS11/0 binds the unchanged native/Peer inputs, not the full final build.
Selections overlap and must not be summed into a qualification total.

The final existing Config/Policy/API selection is FAIL284/1 at the retained
`xml_quotas_test.exs:258` optional-INTERFACE comparison. Intermediate FAIL284/2
is preserved; its additional supervisor-startup failure received deterministic
`policy-kill-startup-red3` and final GREEN31/0. Startup red1/red2 are preserved
fixture failures, not the intended lifecycle RED. Admission-before-compilation,
worker compilation, Policy/Router preparation and Limits RED attempts also stay.

Exact commit caller/PID/epoch/job/base/deadline and stale-incarnation refusal
have dynamic Policy tests. Router publication, responsiveness, caller exit,
same-Peer NO_REPLY acknowledgement order and captured receive policy have real
peer/integration tests. No injected Router stale-finish dynamic regression or
FD-bearing ReloadConfig dynamic regression was added; those paths received
static review. Released ingress credits and an empty reply FD list do not prove
received-FD cleanup for reload. Both independent source reviews are
PASS_STATIC_WITH_LIMITS, with no final source findings.

No new candidate or VM ran in this scope. Frozen candidate13 and its selected
native VM PASS21/0/fixture28/0 remain historical and do not bind these five new
production changes. Full P08/P09, activation, headless release/inherited startup,
packaged soak and rollback remain unfinished. Post-ledger preservation PASS
includes original-main209, prior-evidence3941,395 outside-scope workspace files
and thirteen frozen candidates. `final-preservation.json` and
`final-verification.json` record the final metadata/build/log confirmation;
`FINAL_REPORT.md` is the concise index. Checked execution items do not turn the
retained affected gate or mandatory comparison failures into PASS.
