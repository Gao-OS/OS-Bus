# P05 / RES-01 natural retirement evidence

This fixture correction is authorized by CODEX_GOAL.md P05 and TEST_PLAN.md
RES-01/FAIL-01. It addresses the separately evidenced teardown acceptance gap
in the original eight-case resource fixture. It does not address or reclassify
the retained VM4 reused-authentication timeout.

## Evidence and allowed changes

`scripts/foundation/vm_security_res01/run.py` currently observes process-group
absence after the inherited `Channel.stop()` can kill residual descendants.
Its `validate_teardown()` accepts EOF/exit0/final group absence without a
pre-containment witness and permits deliberate-death exit statuses for every
actor. The existing `TeardownAcceptance` controls do not reject that missing
evidence. These source facts are independent of the unmeasured 400ms timeout.

Own only the relevant teardown predicate, stop callsites, imports and focused
controls in `scripts/foundation/vm_security_res01/{run.py,test_fixture.py}`;
one new `cleanup.py` copied from the accepted listener/UID guest helper; the
fixture README; and new evidence under
`test/reports/foundation/continuation-20261011-full-goal/environment/m1-res01-teardown1/`.
Preserve unrelated sources, historical fixtures, reports and failed VM evidence.
Root owns ledger updates, reviews, controls and the exclusive VM schedule.

Use the byte-exact accepted `stop_channel` body from
`scripts/foundation/m1_listener_transfer/cleanup.py`. Adapt only the calling
identity shape and explicit deliberate-death handling where required. Natural
retirement must record stdin closure, waited/reaped wrapper with exit0, and
actual actor PID, wrapper PID and owned group absence before any fallback.
Retain raw log drains and failure records. Fallback remains containment evidence
and cannot qualify natural retirement. Do not treat a numeric PID alone as
proof of an actor incarnation or permit an unrelated process to be signalled.

Permit a deliberate actor death only for the exact victim already recorded by
the boundary trial. Join the victim PID/incarnation to the recorded death
operation and retirement evidence. Other actors and the daemon require natural
EOF/exit0 retirement. A blanket -9/137 allowance is prohibited.

## Meaningful regression and verification

First preserve the active source and author controls that fail against its
actual predicate: otherwise valid EOF/exit0/final-group-gone must be rejected
when the pre-containment witness is absent, false, timed out or has probe
errors. A deliberate-death record must not authorize that status for a
different actor. Require positive natural-retirement and exact-victim cases.

Then implement only the evidenced fixture correction and run the same controls
plus the affected pure fixture selection. Record actual counts, raw outputs,
finite command retirement and before/after input hashes. Use inert process
witnesses only for checker regressions; they are not Linux runtime evidence.
Obtain fresh specification review followed by independent quality review.

Do not run a blind repeat of the eight-case VM. Its held phases retain one
400ms absolute deadline, authentication absolute1500ms/idle500ms, probe/settle/
reallocation1000ms, authority60s/guest120s/host900s/cleanup5s. The existing
`m1-res01-implementation1/diagnosis5/MEASUREMENT_SPEC.md` is still required before
choosing a scheduling repair. Preserve operation order, every original
observation and all denials. No new timeout, skip, admission or policy exception.

The later `#Ref<` versus actual `#Reference<` match-checker defect is separate
work and is excluded from this correction. Production source and candidate18
remain unchanged. Original VM4 remains selected8/executed3/passed2/failed1/
blocked5/skipped0. Full RES-01, M1, the evidence index and higher milestones
remain unqualified; readinessL0 and product_qualified=false.
