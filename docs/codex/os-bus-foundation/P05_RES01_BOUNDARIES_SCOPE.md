# P05 / RES-01 independent native resource boundaries

This local work is authorized by CODEX_GOAL.md P05 and TEST_PLAN.md RES-01.
It follows the bounded static design at
test/reports/foundation/continuation-20261011-full-goal/environment/m1-res01-design1/STATIC_DESIGN.md.
It complements the unchanged 21-row vm_security selection and the separate
10-case method matrix. It cannot qualify M1 or alter accepted FD evidence.

Own only NEW scripts/foundation/vm_security_res01/{actor.py,launcher.exs,run.py,
workload.json,test_fixture.py,README.md,test.nix}. Reuse unchanged vm_security
Client/packet, Channel/Actor, daemon/policy/state/capture. No competing backend,
production API, dependency or production edits. You are not alone: preserve all
other edits, sources and evidence, especially all unchanged vm_security files.

Execute eight explicit dimensions: UID/global connections (4/6), UID/global
authenticating (2/3), peer/global well-known-name associations (2/4), peer/global
match entries (2/3). The production system has no per-UID names/matches controls;
do not invent or certify them. Use actual UID1100/1101 actors and explicit guest
socket /run/osbus-security/res01/bus. Only a disposable VM may execute the daemon.

Implement the guarded fixture-only launcher described in STATIC_DESIGN.md:
two exact in-memory defaults substitutions and one exact read-only snapshot
extension before the existing command loop. Fail on source pin/anchor/count
drift. Record the transformed execution honestly. Include only the narrow
UID1100 org.foundation.Res01A own allowance in a root-owned overlay of the
original restrictive native policy. Do not broaden other access or mutate
authority state from the observation channel.

Per boundary require N successful live allocations and unique targeted N+1
exhaustion, exact closed/reset admission or serial-correlated LimitsExceeded,
no durable partial state, complete before/after/reused/retired state, all UID/
global/peer credits, queue/reverse associations and match references, original
healthy observer and authority identities, <=1000ms probe and reallocation.
Authentication holds stop after actual AUTH OK before BEGIN; prestart actors
and complete each held phase within400ms, preserving absolute1500/idle500ms.
Missing or timed-out execution stays failed/blocked, never passed or skipped.

Keep the original snapshot fields, complete Limits state and held peer identity
joins. Cross-process snapshots need bounded settled readbacks. Show retirement
for successful release/removal, real socket close and bounded actor-process
death, without synthetic credit injection. Require no retained ingress tombstones.
Preserve every outcome, raw response, provenance and typed per-case accounting.

Use explicit quit+flush before unchanged Channel.stop for owned daemon, without
waiting for a nonexistent JSON response. Save all owned exits, exact native
socket removal and guest shutdown. Authority60/guest120/host900 remain unchanged.

Root owns meaningful fixture RED/GREEN, ordered specification then independent
quality review, exact current candidate binding, source approval and exclusive
runtime schedule. Author sources only until root authorizes execution; no import,
syntax, tests, hashes, Mix, Nix, builds, VM, git/remote/host/account/memory changes.
Production repair requires a meaningful runtime regression and narrow root scope.

All reference, FD/resource/helper/packaged600s/P12 blockers remain. Readiness L0,
product qualification false, full P00-P12/M0-M4 incomplete. No commit, merge,
push, release, host live-bus traffic, account changes or old evidence edits.
