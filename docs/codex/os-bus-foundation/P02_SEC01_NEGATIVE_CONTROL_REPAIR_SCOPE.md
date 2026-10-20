# P02 SEC01: make the raw-byte negative control change a byte

Source2 is stopped after its actually recorded GREEN:16executed/15passed/
1failed. Preserve source1/source2 and every source, review, receipt and log.
The failed test_reject_raw_byte_mismatch selects split-1; expected_writes starts
with NUL (hex00), and the test assigns00 again. This is a no-op fixture mutation,
not evidence that the validator accepts a changed byte. Diagnose exact source
and preserve the failure before correcting anything.

Prepare only fresh environment/m1-sec01-complete1/source3/**. Correct that one
negative control to supply a genuinely different byte and explicitly establish
the precondition that it differs from the expected byte. Retain all16identity/
raw controls and the full original40controls. Do not change the validator,
expected wire,24internal boundaries,28cases/backend,56pairs, native GLib/sd-bus
clients, credential joins, resource/observer oracles, deadlines or policy.
Whole-file reverse must show the only semantic difference is the test mutation
and its explicit distinctness precondition. Preserve every source2 file with
mode/hash, including failed GREEN. Necessary fresh paths/markers/pins and
preparation accounting may change; do not copy old execution outputs as new.

Prepare source-derived old-test failure and corrected-test controls proving the
seed is valid, old mutation is identical, actual changed bytes are rejected,
and malformed mutation cannot be accepted by a weakened validator. Keep old
failed GREEN distinct from intended RED. Root SPEC and distinct QUALITY precede
separate actual recorded controls, import/parsers/build/realization and a fresh
once-only paired VM/observer. Preparation uses stdlib/file-data/AST only; no
target import/control/test/parser/compiler/client/build/VM/consumer execution.
Inspect for another substantive defect and stop/report it without further fix.

Other workers are active; do not revert their changes. No production/candidate18,
old evidence/map/consumer/catalogue/ledger edits, host bus/account action, Git
mutation, remote write, release/publication or memory write. L0/productfalse.
