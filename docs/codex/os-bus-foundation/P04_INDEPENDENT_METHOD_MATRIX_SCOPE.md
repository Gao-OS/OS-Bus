# P04 independent method-matrix extension

This is authorized local work under CODEX_GOAL.md P04/SEC-14. It adds executable
regressions to the existing VM security harness. It does not qualify M1 or
replace any selected assertion. Existing vm_security files are immutable inputs
to pending FD evidence and must remain byte-for-byte unchanged.

Own only NEW scripts/foundation/vm_security_method_matrix/{actor.py,run.py,
workload.json,test_fixture.py,README.md,test.nix}. Reuse vm_security's independent
packet/Client, Channel/Actor, daemon.exs, policy.exs, capture and snapshot channel.
No second backend, production test API, dependency or general harness framework.
Production sources are read-only until a meaningful failing regression identifies
a concrete defect and root authorizes the narrow repair. Preserve other workers'
edits and every earlier report, source approval and failed namespace.

Select exactly ten ordered SEC-14 subcases, preserving the existing21 security
row selection and prior fixture thresholds separately:

1. RequestName/s -> InvalidArgs.
2. ReleaseName/empty -> InvalidArgs.
3. GetNameOwner/u -> InvalidArgs.
4. NameHasOwner/empty -> InvalidArgs.
5. AddMatch/u -> InvalidArgs.
6. RemoveMatch/empty -> InvalidArgs.
7. Properties.Get/empty at canonical path -> InvalidArgs.
8. ListNames/u -> InvalidArgs.
9. ListNames at org.foundation.Wrong -> UnknownInterface.
10. Properties.Get/empty at /wrong -> UnknownInterface.

Use explicit /run/osbus-security/method-matrix/bus in one disposable Linux VM,
actual UID1100 observer and UID1101 test actors, and the original restrictive
native policy. Verify PID/UID/GID externally from /proc and against trusted live
Router records. Retain raw request/reply frames, serial correlation, exact ordered
subcase IDs/errors, current source/artifact/runtime/config/workload hashes and
selected/executed/passed/failed/blocked/skipped counts. Missing, duplicate,
reordered, unexecuted or incorrectly correlated subcases cannot qualify.

Before and after each invalid operation, establish the same Router and peer
identities, observer unique/owned name, names/queues/match/capability/whole credit
state and policy generation after bounded quiescence. Each rejection must have
the exact controlled error and no mutation. Probe the observer within1000ms.
Run valid follow-ups for the affected methods, including ordinary off-path
ListNames and canonical Properties.Get, so blanket rejection cannot pass.
Follow-up ownership/match effects must be explicitly verified and fully retired.
Do not alter interface/path precedence or expectations.

Actor extension may subclass the existing independent Client solely to record
complete frames and decode the actual variant returned by Properties.Get.
Keep explicit guards, finite bytes/time and actual process-group teardown.
Use existing Channel/Actor cleanup; save all owned exits, verify socket removal
and VM poweroff. No host system/session bus or host/account/git/remote changes.

Root owns TDD/regression execution, ordered specification then independent
quality review, exact source/prerequisite approval and runtime schedule.
Author source-only until root execution authorization. Provide meaningful
fixture regressions for missing/duplicate/wrong/uncorrelated subcase evidence,
raw vectors and variant parsing. Root must observe a failed assertion on the
old aggregate-only acceptance before accepting the stricter implementation.
Do not fabricate a production RED if the existing implementation is correct.

Use pinned current production candidate only after complete current source/
artifact verification; capture a fresh candidate if production changes.
Pin nixpkgs from devenv.lock. Authority60/guest120/host900 seconds unchanged.
No competing heavy run, larger deadline, selected skip, false readiness or
product promotion. New ten-subcase results are scoped P04 evidence. Required
reference, FD/resource/helper/package/600s/P12 blockers remain. Highest verified
readiness L0; full P00-P12 goal incomplete.
