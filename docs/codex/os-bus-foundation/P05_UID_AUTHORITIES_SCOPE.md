# P05 / R-09 aggregate UID name and match budgets

The full CODEX_GOAL authorizes this required feature slice. ARCHITECTURE.md
section 8 and TEST_PLAN.md RES-01 require separate aggregate UID budgets;
connection times peer bounds do not implement those boundaries. This follows
environment/m1-uid-authorities1/STATIC_DESIGN.md and does not expand or relabel
the separate eight-case vm_security_res01 selection.

First implement the read-only internal Limits accepted UID/admission lookup
and MatchRules UID accounting, then NameRegistry ownership/queue association
accounting. Bind UID to active immutable Limits admission, never Router cache,
authentication text, a default UID, tombstones or an absent-policy grant.
Authority-to-Limits calls remain finite leaf lookups with no callback cycle.
Missing identity/accounting denies allocation; no new UID exemption.

Required native defaults: max_matches_per_uid and max_names_per_uid each 2048,
one quarter of existing global8192 and above single-peer native/XML defaults.
These are finite safety ceilings, not protocol constants. Preserve existing
native peer/global limits, XML units/zero/precedence, API/table shapes, errors,
canonical duplicates, queue order, flags and ownership effects. No dependency,
framework, policy, activation, helper, transport or release changes.

Match entries each charge one slot, including duplicates. A successful
canonical removal frees exactly one; missing removals free none. Names charge
owner/queued well-known associations, excluding unique Hello names from the
native UID unit. Apply net same/cross-UID transition deltas before effects;
promotion transfers no new association charge. Store immutable UID/admission
with local monitors; reclaim exactly once on cast/DOWN, prune zero state and
ignore stale DOWN without rebinding old entries to a new admission.

Production ownership is limited to apps/gao_bus/lib/gao_bus/{limits.ex,
match_rules.ex,name_registry.ex} plus the identity-error mapping clause in
bus_interface.ex. Begin TESTS ONLY in NEW uid_authority_limits_test.exs, with
identity/match/name slices tagged for focused RED. Root must observe meaningful
RED before authorizing each source implementation. Existing test fixture
admission adaptations may later touch limits_test, authority_limits_test,
match_rules_test, match_conformance_test, name_registry_test,
name_queue_conformance_test, bus_interface_test and name_reference_test only;
preserve every existing assertion and reference sequence. Additional direct
mutation fixtures require evidenced root scope before edits.

Verify shared-UID N/N+1 and second-UID independence; duplicate/removal,
malformed/denied/missing-remove nonmutation; identity absence/retirement/
incarnation drift, Router-cache spoof; race for last slot; killed peer and
duplicate cleanup; names queue/replacement/release/promotion deltas and absence
of ownership effects on denial; unchanged native/XML quota regressions.
Unit admissions are explicit fixtures, not real OS-identity evidence. Independent
actual-UID private-socket VM execution is separately mandatory for qualification.

Root owns exclusive runtime schedule, snapshots, RED/GREEN, affected scoped
checks, exact candidate binding and ledger updates. Source agents may author
only assigned files; no import/hash/syntax/test/build/VM/Git/remote/account/
memory execution without root assignment. Do not change candidate16 production
inputs until its pending eight-case RES01 VM has finished or is explicitly
retained blocked; new feature tests may be authored meanwhile.

Missing execution remains blocked. No required row is qualified by this scope.
Fixed authority60/guest120/host900 and private sockets/disposable VMs remain.
All reference/helper/FD/resource/packaged600s/P12 failures and old evidence remain.
Full P00-P12/M0-M4 incomplete, productfalse/readinessL0. No commit, merge, push,
release or host live system/session-bus action.
