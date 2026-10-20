# P01 H-04: core system-fixture timeout and runner-failure cleanup

H-04 requires actual artifact capture, fixture timeout and teardown after runner
failure. Existing session tests and shell timeout units remain useful but cannot
qualify the independent-system core/network rows by themselves. This slice adds
the missing system-fixture lifecycle coverage without changing production.

Worker ownership is restricted to new `system_lifecycle_test.exs` under the
harness, new `h04_system_*` files under E2E fixtures, and preparation artifacts
under `resume-20261019/h04-current-lifecycle1/`. Root owns this scope, a new
standalone Nix VM entrypoint/build/runner, actual checks, and ledgers. Preserve
existing session fixtures/tests, ChildProcess/process_guard implementation,
policies, profiles, production source and consumer code byte-for-byte.

Use the exact conservative core system fixture already accepted for SEC01:
real accounts 1100/1101, pristine pinned reference daemon, explicit private
endpoints and the current immutable candidate/runtime. This is P01 lifecycle
qualification, not installed XML parity or M3 acceptance. No fixture policy
is broadened or silently substituted. Record every executed config/source/
runtime/guard byte and any startup-prefix extraction from its pinned donor.

Inside one disposable Linux VM, run the two backends sequentially. An independent
ordinary client must complete valid authentication and registration against the
explicit endpoint before the fixture timeout. Preserve its timeout, output and
external PID/incarnation retirement proof. Use a fresh ordinary client for the
runner-failure phase, kill only the fixture's owning runner, and externally
observe backend/actor/guard descendants being reaped. Retain selected/executed
IDs, seed, commands, config hashes, logs and failure artifacts. The interrupted
inner qualification stays blocked/running; outer cleanup proof is separate.

Record stale private endpoints before any wrapper-owned cleanup. Reaping and
wrapper cleanup must not be misreported as the daemon's graceful self-cleanup.
Copy artifacts before VM shutdown and retain explicit shutdown/host-child
reaping evidence. Missing actors, build/runtime inputs, timeout receipts,
identity or cleanup proof block H-04. New preparation or static checks are not
runtime success. Only actual complete core rows may be mapped; network remains
blocked until its declared profile runs.

Use existing finite guard/actor/lifecycle deadlines. Preserve all failures and
never extend a deadline merely to obtain a pass. Root runs scoped syntax/format
and lifecycle checks after source review. Offline Nix build failure is an
environment blocker; do not fetch/install dependencies or run on the host as a
substitute. No live system/session-bus operations, host account/system changes,
external API probes, optional security tests, publication or memory writes.
SEC06/FD04 denials and all existing SEC03/SEC08/native authorization/P10 retry
and terminal boundaries remain intact. Readiness stays L0 until all original
milestone gates pass; the full foundation goal remains incomplete.
