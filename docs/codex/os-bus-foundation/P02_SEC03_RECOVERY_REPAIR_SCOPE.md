# P02 SEC03: bounded recovery after malformed DATA

Source1 was rejected for its receipt catalogue, source2 for live registration
serial evidence, and source3's actual once-only VM failed during nonhex-data
recovery. Preserve all three sources, prior Sol repairs, rejections and VM
failure. No retry of an occupied workload. A bounded Astra recovery may prepare
only fresh `environment/m1-sec03-complete1/source4/**` plus a fresh diagnosis
subdirectory of that source. Other workers remain active; do not revert them.

The failed reference exchange was AUTH EXTERNAL -> DATA, DATA z0 -> ERROR, then
direct canonical AUTH -> ERROR (another AUTH in progress). The actor's canonical
retry incorrectly asserted immediate OK. The original sealed investigation
already required CANCEL for outstanding DATA exchanges. The pinned1.14.10
specification says ERROR leaves the sender's state unchanged (2640–2659), a
client receiving ERROR sends CANCEL (2933–2935,3004–3005), CANCEL aborts the
exchange and requires REJECTED (2541–2545), and WaitingForReject accepts only
REJECTED (3020–3035). Pinned dbus-auth.c process_data1700–1740 and server
WaitingForData1874–1905 corroborate that behavior. Re-read exact archive bytes.

Diagnose the actual raw trace and exact actor canonical AST. Prepare an
offline old-source regression with a finite fake peer implementing the pinned
ERROR/CANCEL/REJECTED state sequence, then the corrected source regression.
Test same-connection continuity, no initial NUL replay, no BEGIN/Hello before OK,
required REJECTED after CANCEL, direct retry after REJECTED, fresh canonical and
terminal-close recovery. A missing/bad CANCEL response or unexpected OK must
remain rejected, never converted to a fresh passing connection. Preserve the
original malformed-identity security/effects/credential assertions and trace.

Correct only recovery sequencing and its explicit transcript/validator/replay
bindings where necessary: cancel the failed authentication exchange before
canonical same-stream AUTH when protocol state requires it. Any new evidence
fields must be independently revalidated. Do not normalize reference numeric
or login-name conformance failures, remove any51case, change exact original
payloads/categories, drop serial/resource oracles, or change an expected mandatory
failure to pass. Full102pairs and original60contract/20witness, catalogue/serial
controls, backend command/exits and all fixed bounds remain required.

Source adaptation may update only necessary fresh paths/pins/guards and add
source-derived controls. Include original strict assertions and whole-file or
whole-method reverse equality identifying the exact recovery correction.
Inspect the entire fixed corpus statically for the same state assumption;
report any further substantive defect before expanding this recovery. No
production/candidate18/old evidence/map/consumer/catalogue/ledger mutation.

Preparation is stdlib/file-data/AST only. Do not run/import targets, controls,
parsers, clients, builds, VMs or brokers. Root SPEC, distinct QUALITY and pin
recheck precede separately recorded old RED, corrected GREEN, original affected
controls, import/parsers/build/realization and one paired VM/host observer. Keep
complete gate failure distinct from collector completion. Distinct raw review
precedes adoption. Readiness stays L0/product_qualified=false. No host bus/account
or Git mutation, remote write, release/publication or memory write.
