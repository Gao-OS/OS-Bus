# Current SEC16 native-only first execution

Selection `complete_core_gao_v1` executes exactly the Gao/core SEC16 row using
the current immutable candidate. The historical source2 paired corpus, existing
`registration_current` adapter, and failed reference runtime remain unchanged.
A native success does not qualify reference or complete the paired gate.

`test.nix` accepts the same `candidatePath`, `artifactPath`, and
`runtimeManifestPath` arguments as the paired adapter. Candidate manifest:
`fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82`;
artifact: `b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1`;
runtime: `6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5`.
The adapter verifies all71sources/80runnable files and modes before copying the
fixture. It rebinds the same2candidate digest assignments, then applies the exact
reversible native selection changes in `selection.py` to the copied contract,
runner, and synthetic controls. The17other fixture files remain byte-identical.

All15per-backend contract functions remain byte-identical. The runtime backend
body differs only by the reporting checkpoint described below. Five cases, two positive flows, eight actors/eight retirements,
pre-Hello real closure, raw reply/signal order, sender/credential authority,
observer continuity, native resource recovery, policies, admission, cleanup,
and all numeric deadlines are retained. Only the explicitly selected Gao row
is counted: selected1/executed1/passed1 on success, with no reference skip or
fabricated reference result. The result string identifies native execution.

`workload.json` remains the original paired corpus metadata, explicitly labeled
`workload_role=original-paired-corpus`. The report separately records exact
versioned `execution_selection`/`execution_scope`; the validator checks these.
Bindings distinguish original corpus10case/backend pairs from selected5pairs.

Adapter revision4 removes only the synchronous `persist()` immediately after
`current['receipts'].append(receipt)` in the copied runner's `request()`.
Receipts remain appended in full before both unchanged assertions. Reporting is
deferred to the existing phase, settle `finally`, case, retirement, failure and
cleanup checkpoints; those checkpoints and the full snapshot/state reads are
byte-identical. This prevents repeated whole-report writes from consuming the
shared1000ms settle deadline while retaining ordinary1s/registration-case2s and
enclosing deadlines. No time is subtracted and no bound is increased.

The first native VM remains failed: all5cases,2positive flows and8actors
completed before final recovery settle failed at the request deadline assertion.
Its last successful GetNameOwner receipt measured5.036674ms; final settle
measured1978.164264ms. This identifies report persistence inside the deadline
path, without establishing its precise duration or a production defect.
Normal success and handled failure retain complete receipts at the remaining
checkpoints. An abnormal controller exit before the next checkpoint can lose
receipts appended since the last persisted report; such an exit cannot claim
complete saved evidence.

Repair evidence: `test/reports/foundation/resume-20261019/sec16-native-persistence-repair1/`.
Pure controlled-clock tests extract the actual request/snapshot/settle bodies;
they cover timely/late replies, shared and enclosing deadlines, response errors,
and receipt retention at unchanged settle checkpoints. No real timing or target
execution is part of this repair.

Offline preparation evidence: `test/reports/foundation/resume-20261019/sec16-native-preparation1/`.
Original synthetic controls21/21 and native controls23/23 pass. The two added
controls reject incorrect selection/scope/counts; the original negative count
control now mutates executed away from1. No original control was removed.

No build or VM execution was performed during preparation or this repair.
Root owns independent review, any fresh build and explicitly corrected serialized
VM, raw evidence review and any single-row adoption.
Readiness staysL0; product_qualified, requirement_qualification and
accepted_index_mutation stayfalse. The failed reference/spec disagreement is
recorded separately in `sec16-current-vm1-diagnosis1`.
