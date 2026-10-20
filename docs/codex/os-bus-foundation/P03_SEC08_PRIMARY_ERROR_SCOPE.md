# P03 SEC08: preserve the primary timeout and bind current candidate19

Source3 remains immutable and NOT_ACCEPTED_FOR_EXECUTION by QUALITY d0c7fb80.
Its collector's TimeoutExpired handler calls write_json before rethrowing;
failure in that reporting path would replace the primary timeout. No source3
target executed. Source2's ENOSPC and UNKNOWN_WITHOUT_EXPORTED_RAW remain.

Own only fresh environment/m1-sec08-complete1/source4/**. Other agents are
active; preserve their edits. Reuse source3's named8192MiB disposable disk,
measured storage provenance, direct raw/journal export and final shutdown.
Guard timeout-report persistence exactly as the existing backend/collector
failure persistence guards: independently report a secondary error, then
rethrow the original exception with its original traceback. A missing report
remains failed/incomplete, never a successful collection or receipt.

Prepare a meaningful isolated regression that executes the actual timeout
handler with a deterministic timeout plus reporting failure, without starting
processes/sockets/VMs or sending signals. The stopped source3 handler must fail
the primary-error assertion; the corrected handler must retain the exact
original exception object/traceback and separately record the secondary error.
Keep this a fixture control, not a production security qualification. Retain
all114existing GREEN/9RED controls and all32cases/backend with two independently
bracketed denials. Do not change policies, outcomes, expectations, bounds,
storage size, RAM, negative preimages or corpus to obtain a pass.

Root has executed the narrow Peer auth batching change: strict compile,
54focused tests and4FD regressions pass. Candidate19 is frozen at
environment/m1-res01-measurement1/sec07-auth-read-work1/candidate19:
manifest0d4ab06f469256785d4cb952563a2e5a471c4babf89e198cc5d6578f360e340b,
source4e334b95bc0ddd0afed797f9640c6971ba2a339c2a369f6500a0d7230d9e8350.
Only Peer source/module differ from18; helper/runtime remain unchanged. Bind
this current artifact explicitly; keep old18 receipts historical. Preserve
source3/donor files as historical file data separately from refreshed current
source pins. Never silently ignore a drifted historical live-source pin.

Other edits are fresh output/review paths, candidate/provenance/reversal
bindings and the regression/control dispatcher. No production/index/ledger or
old output mutation. Preparation is own stdlib file-data/AST only; no actual
target import/control/test/public parser/compiler/build/VM/broker/actor or
consumer execution. Root SPEC, distinct QUALITY, full pin recheck precede
serialized execution, and raw review precedes receipts. Stop at the first
unexpected target failure. Fixture runtime repair1 remains; primary-error
static repair1 is separate; production auth runtime repair1 and Astra0.
No host live bus/account/mount/device, Git/remote/release or memory mutation.
All targets start NOT RUN; L0/product_qualified=false.
