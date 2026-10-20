# Dependency-ordered implementation plan

## Execution policy

This plan orders implementation work, not calendar estimates. M0–M4 are acceptance boundaries. Work may be parallelized only where ownership and tests do not conflict; gate a milestone only after all its dependencies have evidence. Do not mark a package complete because its document exists.

Use a reviewable local change set per work package, or a small coherent grouping. Remote pushes, PR creation, publishing, and live deployment require separate authorization. Preserve user changes and avoid unrelated renames/framework upgrades.

## M0 — Baseline, strict harness, and runtime feasibility

### P00 — Reconcile the baseline and scope

**Inspect:** root/application `mix.exs`; config; applicable `AGENTS.md`; existing ADRs; `docs/e2e.md`; `docs/e2e-matrix.md`; test helpers/backends/actors; workflows; `Peer`, `Router`, `BusInterface`, `NameRegistry`, `MatchRules`, and wire code.

**Actions:** record actual SHA, dirty files, OS, toolchain, current tests and failures; confirm each finding in `SOURCES.md`; build a reproducible development invocation; distinguish default session fixtures from the new system-policy fixture. Inventory all source-level privileged and I/O entry points. Update `STATUS.md` before changing behavior.

**Deliverable:** baseline report and finding disposition (`reproduced`, `already fixed + tested`, `not applicable + evidence`, or `blocked`). Do not downgrade a finding without a test or a documented source/specification argument.

### P01 — Extend the harness and prove Unix prerequisites

**Depends on:** P00.

Preserve existing E2E IDs and actors. Add raw Unix/protocol clients able to construct invalid exchanges independently of ExDBus; add separate-UID execution in an isolated Linux environment; add dedicated daemon-process backends so whole-BEAM resource counts and crashes can be observed.

Implement strict required-gate accounting: selection manifest, expected backend/actor requirements, actual executed IDs, and failure on zero execution, selected known gaps, unexpected skips, missing tools, or backend startup/probe failure. Keep optional developer skips separate from qualifying gates. Retain diagnostic artifacts on successful qualifying runs as well as failures.

Perform a small runtime spike for kernel credentials, arbitrary FD ownership/closure, partial `sendmsg`, and inherited-listener adoption through the intended release startup chain. If no release exists yet, use a minimal launcher prototype and repeat the proof on the final packaged release in P11. Verify the OTP version's public API rather than copying assumptions from newer documentation. A missing required primitive triggers an explicit adapter ADR, not simulated support.

**Exit:** existing baseline is recorded, strict mode detects intentional missing actors, and runtime spikes provide executable proof or named blockers. M0 itself does not certify security. Tests: H-01–H-04, FD-01 preliminary, SYS-01 preliminary.

## M1 — Harden the isolated bus

### P02 — Real credentials and authentication state machine

**Depends on:** P01. **Primary code:** `peer.ex`, Unix transport/credential adapter, relevant ExDBus interop tests.

Replace asserted-UID identity with trusted peer credentials. Implement the legal authentication transitions and explicit pre-Hello state. Enforce system-mode rejection of anonymous and bypass paths; keep standards-compliant mechanism discovery and fragmented/pipelined EXTERNAL exchanges. Reject credential acquisition failure. Add authentication quotas/deadlines and resource-safe early closure. Until P08 provides complete FD semantics, M1 may decline FD negotiation, but it must still safely reject and reclaim unexpected incoming rights using the proven resource primitive. Do not negotiate support backed by a header-only stub; full FD interoperability remains mandatory for M2.

**Required evidence:** independent clients still authenticate; a non-root process cannot claim root; premature BEGIN, unsupported exchanges, invalid identity text, and early FD negotiation have correct failure behavior without affecting a registered observer. Tests: SEC-01–SEC-07, PRO-01 preliminary.

### P03 — Complete authorization and protect state mutation

**Depends on:** P02. **Primary code:** policy behaviour/provider, `router.ex`, `bus_interface.ex`, `name_registry.ex`, PubSub/monitor hooks.

Connect admission, ownership, send, receive, privileged bus methods, and monitoring checks. Remove hard-coded permissive credentials and absent-policy fallback. Add a conservative explicit system test policy rather than preserving a permissive development default. Make denied actions effect-free and instrument decisions with bounded metadata. Tie destination/ownership evaluation to coherent registry state.

The full XML loader arrives in P09. M1 still requires a real policy engine and enforceable decisions, not an XML placeholder or a temporary allow-all provider. Activation authorization is represented in the contract now and exercised end-to-end in P10.

**Required evidence:** adversarial tests for all configured checks, with unchanged state/no delivery/no disclosure after denial; policy absence/unavailability never allows operations. Tests: SEC-08–SEC-13.

### P04 — Input containment and strict core-method boundary

**Depends on:** P02; integrates with P03. **Primary code:** `message.ex`, wire decoder/types, `bus_interface.ex`, Router.

Implement enough framing/structural validation to prevent corrupt messages reaching core handlers. Define method schemas with path/interface/signature/argument validation. Replace unchecked body destructuring and ambiguous dispatch with controlled errors. Distinguish malformed protocol, incomplete input, unsupported extensions, and legal calls with bad arguments. Never decode a body failure into success or retain a terminally invalid prefix indefinitely.

**Required evidence:** malformed RequestName/ReleaseName/Get/Match calls cannot crash Router; an existing unrelated client's unique name and owned names survive the incident. Reject invalid version/fields/body lengths and attacker-selected crash paths. Tests: SEC-14–SEC-16, PRO-02–PRO-05. P06 later completes exhaustive wire semantics.

### P05 — Socket ownership, cleanup, and initial limits

**Depends on:** P02–P04. **Primary code:** `listener.ex`, `peer.ex`, peer supervisor/cleanup, resource accounting, diagnostics.

Remove unconditional socket unlink. Check the containing directory, ownership, actual socket type, and instance ownership before lifecycle operations; refuse ambiguous existing endpoints. Make transfer failure close the socket and stop the incomplete peer. Centralize monitor-based cleanup for abnormal peer death.

Set finite system-profile limits for connection/authentication buffers, in-flight ingress work, match/name counts, and diagnostic queues. Establish the reservation/accounting interface that P08 extends. Disable payload broadcasts/UI/cluster dependencies in the hardened headless path.

**Required evidence:** a second daemon cannot remove the first daemon's socket; bad peers and slow authentication cannot exhaust unlimited resources; abnormal peer death removes authority state. Tests: SEC-17, SYS-02, RES-01–RES-03, FAIL-01–FAIL-02.

**M1 exit:** P02–P05 complete; required security and affected existing E2E gates pass on Linux. Report at most **L1**. No host replacement and no claim of completed FD/system compatibility.

## M2 — Protocol semantics, FD correctness, and backpressure

### P06 — Complete codec and registration conformance

**Depends on:** P04.

Finish fixed/header/body validation, type/string/container constraints, extension handling, endian interoperability, fragmented/coalesced streams, exact consumption, and bounded parser work. Add property/generative testing plus independent wire fixtures; do not rely only on self-round-trips. Complete Hello ordering, duplicate/pre-Hello behavior, bus-instance identity, and sender handling.

**Evidence:** valid reference-client corpus and malformed corpus; deterministic seeds and minimized regressions; no invalid input reaching authority. Tests: PRO-01–PRO-07.

### P07 — Names, matches, and requested replies

**Depends on:** P03, P06.

Complete the name queue state machine, owner/requester updates, reserved-name handling, ListQueuedOwners, direct name resolution, and ordered ownership signals. Replace ad hoc match parsing with a bounded grammar; implement profile-required namespace/argument/sender semantics and duplicate-rule accounting. Remove unsolicited broadcast fallback. Keep authorized unicast and monitoring behavior distinct.

Introduce bounded pending-request state tied to the actual caller/callee incarnations and serial, with correct cleanup and configured requested-reply policy. Exercise aliases, service replacement during calls, unsolicited/duplicate replies, no-reply/no-auto-start flags, and send-failure retirement.

**Evidence:** same scenarios against a pinned reference configuration and OS-Bus; adversarial cases prove policy cannot be bypassed through names or replies. Tests: SEM-01–SEM-12.

### P08 — FD resource owner and complete bounded I/O

**Depends on:** P01 runtime proof, P05–P07. Transport/FD design may be developed alongside P06, but this gate waits for routing correctness.

Implement persistent FD-to-frame association, descriptor bundle ownership, recipient negotiation, control-truncation detection, count/index validation, partial-write continuation, fan-out ownership, and deterministic closure on all terminal paths. A source or recipient crash must not leak or double-close a daemon descriptor.

Complete ingress/egress/per-UID/global credit reservations, bounded activation placeholders, fairness, finite send behavior, and overload responses. Make scheduling/queue limits effective before enqueueing. Check that blocked writers do not obstruct control messages and cleanup.

**Evidence:** actual FD operations with independent clients; negative paths and process kills; pinned workload with memory/FD/queue artifacts and a healthy concurrent probe. Tests: FD-01–FD-10, RES-01–RES-06, FAIL-01–FAIL-04.

**M2 exit:** all required protocol/semantics/FD/resource tests and prior gates pass. Report at most **L2**. A working FD demo or codec suite alone is insufficient.

## M3 — Linux system compatibility and packaging

### P09 — XML configuration, policy generations, and bus APIs

**Depends on:** P03, P07; qualification requires M2.

Inventory the exact effective system configuration and `.service`/policy files for the pinned VM profile. Implement required XML/config semantics with provenance and ordered evaluation, secure include handling, validation, transactional reload, and no silent security downgrade. Record supported/rejected fields explicitly.

Implement real credential queries, profile-required bus control methods, Peer methods, accurate Introspection/Properties/Features/Interfaces, and authorization for privileged controls. Use registry identity snapshots rather than asserted names/PIDs. Support monitor semantics only if implemented and tested; otherwise omit the feature and return a truthful error. Do not advertise nonexistent interfaces.

**Evidence:** equivalent allow/deny/ownership decisions using the same policy files and identities; reload concurrency/failure tests; credential results checked from independent OS actors. Tests: POL-01–POL-07, API-01–API-04.

### P10 — Service activation and bootstrap

**Depends on:** P07, P09.

Implement the activation coordinator, service-file discovery and precedence, ListActivatableNames/StartServiceByName, automatic start where appropriate, bounded coalesced requests, authorized launch, validated launch identity, failure/error mapping, and post-activation delivery. Include both systemd-backed and traditional entries required by the profile. UpdateActivationEnvironment and other controls must follow the selected system/session profile's documented policy, not be blindly open.

Prove how the bus requests activation without circular startup dependencies. Test name acquisition races, queued caller exit, launch failure, timeout, no-auto-start, reload during activation, and identity-denied launch. Ensure completion/error processing stays off blocking Router callbacks.

**Evidence:** independent client triggers a previously stopped real fixture, the expected UID owns the name, the reply arrives, denied calls do not launch it, and failures drain all resources. Tests: ACT-01–ACT-07.

### P11 — Minimal release and systemd/NixOS integration

**Depends on:** P05, P08–P10.

Create a headless release excluding web/config/cluster applications. Add explicit configuration validation and supported invocation/lifecycle documentation. Handle inherited listening FDs through the real release launcher, readiness notification, shutdown, resource accounting, and no inherited-descriptor leakage into activated children.

Add a reproducible NixOS VM-test entrypoint using a pinned nixpkgs revision. Reuse devenv and the existing Nix layout; add only the build/test surface needed, such as a flake check where appropriate. Do not blindly override a live machine's `services.dbus` configuration. Model mutually exclusive reference/OS-Bus VM variants while keeping clients/service policies identical.

**Evidence:** minimal release boots independently of Phoenix/config/cluster; wrong inherited FDs fail safely; readiness reflects an operational bus; startup and activation are deadlock-free. Tests: SYS-01–SYS-05, integration subset of VM-01–VM-03.

**M3 exit:** policy/API/activation/lifecycle tests run and pass for the declared profile. Record unresolved configurations as unsupported. Report at most **L3**; do not bypass the separate M4 real-VM qualification.

## M4 — End-to-end qualification and rollback

### P12 — Real workloads, failure injection, and rollback evidence

**Depends on:** all previous packages.

Execute the rollout runbook in disposable VMs using the final packaged candidate. Exercise systemd's actual bus API, logind session/credential behavior, polkit allow/deny decisions, automatic activation, and a real FD use case such as a logind inhibitor FD. Verify clients really use OS-Bus rather than an alternate/private reference socket.

Run the NetworkManager virtual-device profile before claiming network-management coverage. Exercise policy reload, faulty clients, activation failure, bounded overload, and a core crash/restart. Verify the documented reconnect/recovery behavior, not uninterrupted continuity across a core epoch reset.

Perform candidate-to-reference rollback with a known-good boot generation/snapshot and out-of-band console. Rerun the workload suite after rollback and verify the reference daemon owns the intended endpoint. Preserve logs, policy hashes, counts, resource measurements, and reproducible commands.

**Evidence:** VM-01–VM-06, all prior required gates, final compatibility/readiness report. Maximum claim: **L4 — controlled-VM replacement candidate**. Live deployment is a separate operator action.

## Commands and build surfaces

The following are existing repository command patterns, not execution results of this handoff [R10, R11]. Run from the appropriate repository root/application directory and use the pinned environment. Confirm aliases and supported options from the actual checkout.

| Purpose | Existing command pattern |
| --- | --- |
| Dependencies | `mix deps.get` |
| Formatting | `mix format --check-formatted` |
| Compilation | `mix compile --warnings-as-errors` |
| Non-E2E tests | `mix test --exclude e2e` |
| GLib fixture | `make -C apps/gao_bus_test/test/fixture` |
| Reference full E2E | `E2E_KEEP_ARTIFACTS=1 E2E_BACKEND=reference E2E_GATE=all mix test --only e2e` |
| OS-Bus full E2E | `E2E_KEEP_ARTIFACTS=1 E2E_BACKEND=gao_bus E2E_GATE=all mix test --only e2e` |

The existing CI runs its E2E command from `apps/gao_bus_test`. Record the actual working directory for every result. Run the project's existing Credo/Dialyzer/precommit checks where present; do not claim that an alias exists just because a generated guideline mentions it.

**To implement:** strict gate invocation, raw-protocol and multi-UID fixture builds, resource qualification, and the VM-test command. Document real commands once they exist. `security`, `fd`, `system`, and `vm` in this handoff are logical gate categories, not currently guaranteed `E2E_GATE` values. Extend selectors/backends/CI together and preserve existing categories.

## Reporting and completion discipline

Each package needs changed-file references, test IDs, commands, actual results, and artifact locations. Preserve baseline failures separately from introduced regressions. No fake green checks: missing tools, dependency download failure, absent VM acceleration, and unsupported OS facilities are `blocked`, not `passed`.

Complete an intermediate package while another environment-dependent gate is blocked only when the dependency relationship permits it. Do not hide a partial outcome: state the highest **verified** readiness level and the next uncompleted work package.
