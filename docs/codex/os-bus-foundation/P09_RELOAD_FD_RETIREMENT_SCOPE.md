# P09: FD-bearing reload input retirement

Continue CODEX_GOAL independently of blocked milestone qualification. This
test-only scope follows the private-socket stale completion regressions.
Their final three-file baseline is freshly saved as 33 tests, 0 failures in
`environment/m1-res01-measurement1/p09-router-stale-completion1/async-final1.json`.

## Allowed changes

Add one real-descriptor case and narrowly necessary private helpers to
`apps/gao_bus/test/policy/async_router_reload_test.exs`. Preserve its ten existing
cases, setup, and helper bodies. Add
`apps/gao_bus/test/fixtures/async_reload_fd_actor.py`, reusing the existing
`transport_actor.Client` and frame encoding without modifying that module.
No production, native adapter, oracle, reference expectation, activation, or
packaging edits. Parent owns this scope, four current ledgers, and fresh evidence
under `environment/m1-res01-measurement1/p09-reload-fd-retirement1/` within the
full-goal report tree. Other sources/evidence/candidates remain untouched.

## Required outcomes

The independent Python actor uses only the supplied private Unix socket,
kernel UID EXTERNAL authentication and real FD negotiation. It sends a valid
empty-body ReloadConfig with UNIX_FDS=1 and a real pipe reader. Send only the
fixed-header prefix first; parent waits under one fixed bounded deadline for
that exact prefix, one received resource handle and one FD credit. Retain that
handle so a later closed result cannot be explained by garbage collection.

Complete the frame, close the actor's original reader and queue a same-peer
Ping. Hold actual policy preparation at the existing barrier. Before release,
verify explicit closure of the captured handle, no retained input FD/credit,
one live reload worker/slot, old coherent policy, exact deferred route ack,
no early caller bytes and healthy observer operation. The actor's still-open
pipe writer must raise BrokenPipeError, proving no reader copies remain.
Check the pipe is usable before transfer, and close all actor resources in a
finally block. Actor protocol and waits are bounded; no default-bus fallback.

Release the genuine worker. Require correlated reload then Ping replies with
no received FDs, new generation/discovery, and complete worker/slot/ack
retirement. No arbitrary sleeps or reset polling deadlines. Parent alone runs
syntax, scoped format/compile and the three-file reload regression selection.

## Claim boundary

Current source permits unused transferred descriptors: the count must match
actual resources but each descriptor need not have a body index. This case
does not alter that behavior or claim a reference comparison. It establishes
only cleanup on this valid async reload path, not full FD/fragmentation/fault
qualification. Existing denied/malformed and NO_REPLY tests remain separate.

M0 accepted; M1 earliest unpassed; readiness L0/product_qualified=false.
SEC03 failed prerequisite is not retried; freezer/dependent VM stay unrun.
SEC06 never redispatch; SEC08 attempt3 failed/no fourth. No host live-bus,
system/account changes, commits, publication, or memory writes.
