# P09: stale Router reload completion regressions

Continue CODEX_GOAL in the existing isolated foundation worktree. This is an
independent test-only follow-up to P09_ASYNC_RELOAD_SCOPE.md. Its historical
results and the known Config/Policy comparison failure remain unchanged.

## Scope and contract

Add cases and narrowly necessary private helpers only to
`apps/gao_bus/test/policy/async_router_reload_test.exs`, reusing its real private
Unix socket, kernel-derived identity, restrictive XML, and preparation barrier.
Preserve all eight existing cases and existing fixture behavior. No production,
reference expectation, native transport, activation, or packaging changes.

A completion with the wrong Policy PID, epoch, or job must not consume the
current waiter's correlation or route acknowledgement, publish policy, release
admission, or reply to the caller. A retired handle must not complete a later
reload. Other peers must remain responsive under the old whole generation.
Releasing the real worker must still publish the new generation, retire the
slot, complete the correct caller, and preserve same-connection ordering.

Parent alone runs builds/tests. Begin with a fresh eight-case baseline, then
run the added cases and the existing three-file async reload selection, strict
scoped compilation, and scoped formatting. Use the pinned profile, test
environment, explicit disposable socket addresses, fixed seed, and bounded
process group retirement. Required qualification gates remain separate.

## Evidence and ledger ownership

New evidence lives only under
`test/reports/foundation/continuation-20261011-full-goal/environment/m1-res01-measurement1/p09-router-stale-completion1/`.
This scope and the four current ledgers may be updated by the parent. Snapshot
before-images and input/artifact hashes. Preserve old evidence and candidates.
Do not rerun SEC06, SEC08, a failed reference prerequisite, or dependent VMs.

These regressions cannot certify P09 or M1. M0 is accepted; M1 remains earliest
unpassed; readiness remains L0 and product_qualified=false unless mandatory
gates independently pass. No host live-bus/system/account changes or publication.
