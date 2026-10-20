# P10: bounded activation, ordered delivery and real launch backends

Continue the full P00–P12/M0–M4 goal on `codex/os-bus-foundation`, base7aba5a4.
ADR-006 supplies the accepted implementation direction. This scope does not
change the profile, waive mandatory failures or redefine Foundation completion.
The earlier async-reload scope is closed and its evidence remains historical.

Fresh basis: `continuation-20261011-activation-admission/resume-before.json`:
original-main209, workspace405, production62, prior-evidence4039, thirteen frozen
candidates and63 existing artifacts. Parent owns scope/ledger, every execution
and preservation record. Workers have disjoint ownership and write tests before
production changes; parent verifies each meaningful RED before releasing work.

## Contract and dependency order

1. Add pure `GaoBus.Activation.State` attempt/waiter transitions and monitored
   activation admission/message leases in existing Limits. These are independent
   implementation pieces. They do not enable runtime activation by themselves.
2. Add one supervised coordinator and Router/bus-method integration. Router
   retains authorization, caller/serial claims, current-generation selection and
   delivery order. Reserve before enqueue; keep bodies/resources out of pure state.
3. Implement the exact systemd directed ActivationRequest/ActivationFailure
   protocol and existing configured helper Port ABI. Do not replace either with
   StartUnit, root BEAM, another privileged helper or shell interpolation.
4. Add the dedicated activation/FD fixture to the disposable profile without
   removing installed policies/services. Real canonical-address helper and paired
   reference/candidate ACT evidence follow actual backend implementation.

Pure state uses request `{epoch, request_ref}`, serial
`{epoch, caller_incarnation, serial}`, attempt `{epoch, attempt_ref}` and unit
`{epoch, SystemdService}` identities. Caller metadata contains the actual PID and
Router incarnation. Selected-definition identity covers source/content hash,
argv, bound account and SystemdService; it excludes policy-only generation changes.
Pure state retains bounded metadata and lease tokens, never bodies/native handles.

Use `new(epoch, options)` and `transition(state, event, now_ms)` returning
`{:ok, next_state, result, effects}` or `{:error, reason, unchanged_state}`.
Events cover admit, commit_issue, name_available, finish_waiter, caller_down,
expire, backend_result and reload. Effects request ordered launch/delivery,
terminal waiter retirement, lease release and absolute timer arm/cancel.
Name availability is a hint, never a trusted recipient. Keep waiters charged until
Router's exact ordered completion; one resolution per waiter may be outstanding.

Count every waiting entry, including joins, explicit starts, directed signals and
no-reply calls. Preserve XML max_pending_service_starts512 and zero semantics;
separate native peer/UID/global counts, bytes and FDs remain finite. The first
admission fixes the attempt deadline (reference service_start_timeout25000ms);
joins cannot extend it and each waiter has its earlier deadline. NO_AUTO_START
prevents automatic admission/joining, including signals, but not explicit starts.
NO_REPLY_EXPECTED suppresses replies while preserving bounded admission/cleanup.
Duplicate serial refusal preserves the earlier waiter and its lease. Reserve
requested-reply state only at actual forwarding to the resolved callee.

Limits must atomically validate source/peer identity and capacity, duplicate and
exclusively bind native handles, pin causal ingress and publish the lease token.
APIs: reserve_activation(ingress_token, identity, bytes, originals, coordinator,
server), claim_activation(lease_token, request_key, server), and
release_activation(lease_token, request_key, server). Claims belong to the exact
coordinator; stale/mismatched references cannot retire a newer reservation.
Failure rolls back copies and credits. Outgoing delivery owns separate egress
copies before activation retirement and preserves causal XML source accounting.

Caller DOWN closes activation handles and marks cancellation, but queued body
credits stay charged until the coordinator drains/discards them. Otherwise a
disconnect/reconnect producer can build an uncharged mailbox. Coordinator/epoch
death closes leases before retiring reservations, even if resource terms remain
referenced elsewhere. Cleanup failure never reports successful credit retirement.

Last waiter removal cancels unissued work. Issued work retains bounded attempt/
child tombstones; helper exit0 is not name readiness. Live unresolved children
cannot justify unlimited retries. Shared systemd units launch once while each
name resolves independently. A wire ActivationFailure has no attempt token;
authenticate current systemd1 owner/epoch/permissions and document unit-only
correlation. Local completions/timers still require exact attempt identities.

Reload never retargets issued work. Reauthorize unissued work/current delivery;
changed definitions cannot launch behind an unresolved old per-name attempt.
Use existing Failed with documented retryable text for that conservative refusal,
not an invented standard error. Bound drains and all attempt/unit/child records.

Runtime keeps its activation refusal until real consumers/backends exist. Unit
adapters cannot enable the full core profile or count as ACT-05. No false readiness
or service-start claim follows pure-state/lease tests. Launch helper qualification
requires canonical address inside a disposable VM; no host helper invocation.

## Allowed files and ownership

Transition worker: new `apps/gao_bus/lib/gao_bus/activation/state.ex` and
`apps/gao_bus/test/activation_state_test.exs`.
Accounting worker: `apps/gao_bus/lib/gao_bus/limits.ex` and new
`activation_limits_test.exs`/`activation_lease_test.exs` under the same test root.
Parent integration: new activation coordinator/backends under
`apps/gao_bus/lib/gao_bus/activation*`, Router, BusInterface, Application,
PendingCalls, Config.Runtime, Policy and Policy.XML when required by the contract;
new `activation_*` tests/fixtures. Existing native/Peer/codec sources and all
existing tests stay unchanged. Profile-fixture additions must be explicit and
preserve its installed inventory. This scope, STATUS, compatibility boundary and
new evidence under `continuation-20261011-activation-admission/` are allowed.

No commits/merges/pushes/remote writes/releases/deployment, host live-bus traffic,
memory updates or rejected registered-Peer FD04 audit redispatch. Old mandatory
queued-repeat, optional-INTERFACE and no-reply comparisons remain FAIL. A new
outside-scope failure stops dependent work; do not repair it or weaken old tests.

## Verification checklist

- [x] Fresh preservation/source/build basis and existing goal-turn classification.
- [x] Meaningful transition RED/GREEN: entry/attempt/unit bounds, deadlines, flags,
      duplicate serial, cancellation, reload/owner races and stale events.
- [x] Meaningful lease RED/GREEN: native budgets, real descriptors, causal ingress,
      owner/caller death, queued-body credit retention and exactly-once retirement.
- [ ] Supervised coordinator/Router integration and real wire StartServiceByName /
      automatic directed-call/signal admission, with healthy concurrent traffic.
- [x] Current-policy/current-owner delivery and pending-call handoff without replay
      (internal Router regressions; no ACT/runtime acceptance claim).
- [ ] Actual systemd/helper backend identity/error/timeout/tombstone behavior.
- [ ] Dedicated fixture/inventory and paired canonical-address disposable ACT gates.
- [ ] Scoped compile/format/affected regressions and independent source reviews.
- [x] Final preservation/evidence/ledger with honest acceptance/readiness limits.

P10 stays pending/in_progress until its implementation and mandatory evidence
exist. Full acceptance also depends on P07/P09; focused green pieces are progress,
not completion. P11 packaging and full M4 rollback remain separate required work.

Checkpoint2026-10-11: final activation121/0, P08 lifecycle11/0, strict compile/
format and independent static reviews PASS. Final affected119/1 at unchanged
router_fairness_test.exs:150 is a new outside-scope failure; dependent work stops
without diagnosis/repair/retry/test changes. The real helper consumer separately
remains BLOCKED_DESIGN by the pinned OTP Port output/exit contract; a dependency
fix/backport would require an explicit scope change. Production activation, real
helper/paired ACT, P11 containment and full acceptance remain unqualified.
