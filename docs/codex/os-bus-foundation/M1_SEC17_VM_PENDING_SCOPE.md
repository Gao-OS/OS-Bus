# SEC17 independent pending-call and capability cleanup evidence

Existing P05/SEC17/FAIL01 requires monitored cleanup after actual Peer death.
The two local pending-call regressions pass; accepted UID VM2 separately covers
names, queues and matches. Its snapshot does not establish pending-call or orphan
capability cleanup. Prepare the smallest finite extension of the existing
scripts/foundation/m1_uid_abrupt_peer fixture for two cases: killed callee with
NoReply to the surviving caller, and killed caller with no reply misdirected to
the surviving callee. Use the existing independent actor send/poll commands.

Worker owns only fresh m1-sec17-pending-cleanup1/source1 preparation. Preserve
all original scripts, accepted evidence, production and other workers' files.
Copy only finite required source inputs; retain inherited actors/policy bytes.
Extend the existing snapshot, run/contract and scoped controls for exact pending
caller/callee/serial/trusted UID, capability table and survivor grant, retained
fixture-owned ingress, and final healthy native baseline. Preserve prior checks
and selectors. The kill/readback path must not unregister, disconnect or release
authority explicitly. Release synthetic fixture-owned ingress only after the
automatic cleanup assertions. Keep every existing deadline and workload bound.

Preparation only: saved-file/hash/JSON/AST reads are allowed; no task imports,
tests, builds, VMs, probes, API calls or production changes. Root owns later
review, scoped execution and any existing-schema approval/build/realization.
Do not add a harness, launcher mechanism or approval layer. No new runtime is
authorized by this preparation scope. Keep FD04 off limits, SEC03/06/08 and
paused SEC09–12 restrictions intact. No optional audit, broad fuzzing, unrelated
hardening, host live-bus/system changes, Git publication or memory mutation.

This is Gao native pending/capability/non-FD evidence only. Reference/network and
full FD/resource qualification remain blocked; no complete SEC17 row, M1 gate or
higher readiness may be claimed from this extension. Full goal remains incomplete.
