# P05 / RES01 bounded timing experiment

This experiment implements the missing observations in
`test/reports/foundation/continuation-20261011-full-goal/environment/m1-res01-implementation1/diagnosis5/MEASUREMENT_SPEC.md`
(SHA256 `c6557dabfc150fb10bfb37e57eb6fecfde475f499482805c142adf4884eeb56e`).
It is authorized by the full foundation goal. It measures the retained VM4
held-authentication failure; it does not qualify RES01 or choose a scheduling
repair in advance.

## Scope and preserved inputs

Own only new files in `scripts/foundation/vm_security_res01_measurement1/` and
new evidence in the continuation's `environment/m1-res01-measurement1/`.
Reuse the corrected `vm_security_res01` runner, actor, workload and byte-exact
cleanup helper, and the original `vm_security` transports. Pin those source
bytes before preparing guarded in-memory instrumentation. Do not edit them,
candidate18, production sources, historical reports, failed receipts or tests.
Root owns ledger updates, ordered reviews and the serialized VM schedule.

Keep the eight selected dimensions, every trial and operation, original
snapshots, wire receipts, state comparisons, policy and denial assertions.
Preserve held400ms, auth absolute1500ms/idle500ms, health/settle/reallocation1s,
authority60s, guest120s, host900s and cleanup5s. A measurement cannot extend,
reset, subtract from or reinterpret a deadline. Root privileges and signals
remain inside a marked disposable guest using the private fixture socket.

## Required observations

Retain monotonic before/after boundaries for request begin/read/receipt append,
settle write/flush/read/validation/state comparison, and Channel select/read/
line-log append/JSON parse. Include dimension, trial, phase, attempt and snapshot
ordinal where applicable, operation/member, actor PID and absolute deadline.
Use `finally` to retain failed attempts as well as successful ones. Preserve all
transport bytes and the original synchronous work during measurement.

Measure original snapshot construction, Limits snapshot, authority state
reads, each peer read and JSON-safe mapping in the launcher. Also distinguish
completed snapshots, JSON encoding, stdout write/flush and Channel receipt.
Keep these records separate from the compared snapshot dictionaries. Record
daemon-local elapsed intervals; never subtract Erlang's monotonic origin from
Python's guest clock without a measured calibration and uncertainty.

Keep bounded timing metadata in memory during held phases. Drain it at existing
action/failure/teardown boundaries; do not add physical qualification-file
writes or stdout chatter in the held interval. Record the instrumentation
source/transformation hashes and disclose its added overhead. Missing timing,
logs, snapshots, cleanup or failed original assertions stays failed/blocked.

## Verification and interpretation

Review the guarded instrumentation and assert unchanged original operations and
acceptance predicates. Add focused inert controls for failure-path timing,
unchanged raw logging and returned snapshots, and enforcement of the original
deadline. These controls are harness evidence, not Linux runtime qualification.
Obtain SPEC then independent QUALITY before actual experiment execution.
Freeze source/candidate/runtime bindings, build only the driver, verify realized
inputs, then execute one recorded disposable VM with independent host process
witnesses and bounded natural-retirement checks. Do not repeat it blindly.

Preserve the first unexpected failure. Analyze the saved breakdown before
proposing any measured scheduling correction. If the run reaches genuine
nonempty native match tables, retain the full raw observations for the separate
reference-checker task. Do not fix `#Ref<`/`#Reference<`, transplant accounting
references, fabricate snapshots or waive that assertion in this experiment.

Original VM4 remains selected8/executed3/passed2/failed1/blocked5/skipped0.
The experiment's results are diagnostic and cannot promote a requirement row,
M1, the accepted evidence index or readiness. Full foundation work remains
incomplete, readinessL0 and `product_qualified=false` until its gates pass.
