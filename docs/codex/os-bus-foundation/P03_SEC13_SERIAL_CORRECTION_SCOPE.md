# P03 SEC-13: correct prepared serial accounting

This is a bounded continuation of `P03_SEC13_COMPLETE_SCOPE.md`, authorized by
the full foundation goal. Its required observations, numeric bounds, candidate,
isolation, execution ordering and acceptance conditions remain in force.
Only fresh files under the continuation's
`environment/m1-sec13-complete1/source2/` are owned by source preparation.
Root owns this addendum, ledger, SPEC, execution and eventual adoption. A
distinct reviewer owns QUALITY. Preserve source1, its seals, two preparation
failures, root SPEC acceptance and QUALITY rejection unchanged.

QUALITY found that successful `BusInterface.make_reply` calls advance
`Router.next_serial` through the returned state, just as errors do. Source1
omits these replies, including Hello, health/barrier calls and NotSupported
control responses. Correct every affected workload, runtime, replay and
synthetic-control expectation from the actual production path. Retain complete
Router state comparisons and plus/minus-one rejection controls. Add controls
that reject each omitted class of reply. Record a component-by-component
derivation; do not infer runtime measurements from source arithmetic.

Expected source-derived deltas for independent rechecking are: positive batch
9; manual-positive window including two health probes 13; valid baseline to
manual recovery 19; fresh admission/health/retirement 12; reset reconnect,
enforcement, health and retirement 34. Priming 1, outage 4 and held-wire 1
remain separately verified. Do not alter production or candidate18 to fit the
fixture. No numeric limit, policy restriction or required observation may be
weakened. Source2 requires new seals, root SPEC and distinct QUALITY before
target execution. Preparation may use file-data and stdlib AST checks only.

This is source repair1 for the QUALITY finding. The two earlier preparation
reader/syntax repairs remain separately recorded. No SEC13 target stage ran
on rejected source1, and the earlier SPEC acceptance does not authorize it.
