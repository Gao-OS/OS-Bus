# P06 / PRO-06 normal nested interchange

This continuation implements the normal interchange portion of TEST_PLAN.md
PRO-06 and requirements R-06/R-15. It adds a finite GLib actor corpus in both
byte orders and exercises the current daemon against the unchanged reference
on the accepted SEC01 private core-system fixture. Typed expected values are
defined independently of ExDBus. A previously registered, separate-UID
observer must retain its identity and bus-instance ID across the exchanges.

Only these new implementation files are in scope:

- `apps/gao_bus_test/test/fixture/pro06_interchange.c`
- `apps/gao_bus_test/test/harness/pro06_interchange_test.exs`
- `scripts/foundation/pro06_interchange/{test.nix,package.py,run_suite.exs}`

Scoped execution records belong in
`test/reports/foundation/resume-20261019/pro06-normal-interchange1/`.
STATUS.md, COMPATIBILITY.md and that continuation's EVIDENCE.md may receive
precise execution entries. All existing production, helpers, tests, selected
gate expectations, policies, deadlines, candidate bytes, accepted index and
historical sealed reports remain unchanged.

Execution order:

1. Verify current source/candidate and preserve the accepted H04 index.
2. Compile the new actor and test helpers using the cached pinned environment.
   Preflight the dependency closure; use offline builds, with no substitutes.
3. Review the fixture and assertions, then run the two scoped backend tests
   serially in one disposable Linux VM. Preserve every failed attempt.
4. Read back actor identities, typed semantics, byte orders, command exits,
   selected/executed IDs, observer continuity and owned-process/VM teardown.
5. Record partial coverage and remaining blocked checks without promoting a
   required row whose full contract has not been executed.

This slice sends no `h` value, ancillary descriptor or descriptor fixture. The
existing independent codec corpus's FD-index assertions remain codec evidence
only. Neither nested-value equality nor this actor slice qualifies FD transfer
or completes PRO-06. No network-profile or installed-policy qualification is
claimed. No full baseline/precommit success is inferred from direct execution
of the scoped precompiled candidate.

The host live buses/system/accounts are out of bounds. All actor addresses are
explicit private Unix endpoints in the marked disposable VM. No optional
audit, penetration test, exploit development, broad fuzzing or external API
probe is authorized. SEC06/FD04 denials, SEC03 no-retry, SEC08 no-fourth and
authorization/P10 terminal recovery boundaries remain closed. No commit,
merge, push, publication, release, deployment or memory update is included.

M0 remains historically accepted; M1/P02 remains the earliest unfinished
package. The full foundation remains incomplete at L0/product_qualified=false.
