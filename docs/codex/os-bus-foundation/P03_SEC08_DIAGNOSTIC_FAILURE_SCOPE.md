# P03 SEC08: keep diagnostic failures secondary

Source4 distinct QUALITY withholds execution: storage.failure() guards journal
persistence but its fallback stderr print can throw before the collector's bare
raise. Source4 stays immutable/NOT RUN; source2 ENOSPC remains actual failure.

Own only fresh environment/m1-sec08-complete1/source5/**. Other agents are
active; preserve their edits. Reuse source4. Make the actual secondary-error
reporting helper preserve the primary exception when journal and stderr writes
both fail. Keep a secondary-failure record with the primary exception (for
example a Python exception note) if neither external channel works. Do not
claim unavailable persisted diagnostics as present. Preserve the original
exception object and traceback and bounded child retirement. Failure remains
failed/incomplete and cannot yield a receipt or success.

Extend meaningful controls to execute the actual handler AND actual reporting
helper with deterministic failed journal and failed diagnostic stream, without
processes/sockets/VMs/signals or real disk failure. The exact stopped source4
helper must supply a new RED; corrected helper must preserve primary identity,
traceback and the separate secondary/journal/stderr failure details. Retain
source4's existing116GREEN/10RED controls unchanged, including actual-handler
controls. Existing denied scenarios, policies, outcomes, bounds, storage size,
RAM, negative preimages and candidate19 bindings are unchanged. New controls
remain fixture checks, never backend security qualification.

The driver final SEC08_STORAGE_EXPORT status print is also before rethrow of a
saved target primary. Guard that reporting boundary so a failed output write or
flush cannot replace an already saved target exception. Retain the reporting
error with the primary; when no target primary exists the reporting failure
must still fail the driver. Add deterministic actual driver-tail AST RED/GREEN
checks with a failing output sink and preserved exception object/traceback,
without running a driver, VM or process. Preserve export/diagnostic/shutdown
attempts and all lifecycle predicates. Source4 exact tail is the RED preimage.
This is the same static primary-error repair2, not a new runtime attempt.

All other changes are fresh output/review/provenance/reversal paths. Keep
historical source4 and source3, including explicit Peer preimage/current drift
reconciliation; never skip old live-source mismatches silently. No production,
index/ledger/old output mutation. Preparation is own stdlib file-data/AST only;
no targets/imports/controls/parsers/compiler/build/VM/actors/consumers. Root
SPEC, distinct QUALITY and full pin check precede serialized actual execution;
raw review precedes receipts. Stop first unexpected failure. This is primary
static repair2; fixture runtime repair1, production auth runtime repair1,
Astra0. Any further evidenced repair impasse returns to root for bounded
escalation rather than an unreviewed third attempt. No host live bus/account/
mount/device, Git/remote/release or memory mutation. All targets NOT RUN;
L0/product_qualified=false.
