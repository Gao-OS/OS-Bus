# Implementation-first source checkpoint

Base: `cd1b82c9c22344fd7548356d1e1a75fb64b7603d`.
Worktree: `.trees/os-bus-build-compat`, branch `codex/os-bus-build-compat`.
This matrix follows the user's instruction to finish implementation before
acceptance. Source presence does not pass a work package, milestone or gate.
`STATUS.md` remains the execution/evidence ledger, including historical failures.

| Package | Implemented source surfaces | Current implementation work | Acceptance |
| --- | --- | --- | --- |
| P00 | Checkout/evidence reconciliation and compatibility inventory | Preserve original changes and current exact checkout evidence | Historical baseline only; current source not qualified |
| P01 | Independent actors/backends, strict selection/result accounting, Unix adapter and inherited-listener fixtures | Existing harness retained | Missing/denied runtime prerequisites remain blocked |
| P02 | Kernel credential record, bounded EXTERNAL authentication, pre-Hello phases | Existing implementation retained | Security suites prohibited; no new execution |
| P03 | Admission, ownership, send/receive, control/monitor authorization and coherent policy snapshots | Existing implementation retained | Deferred/blocked; historical results not promoted |
| P04 | Core method schemas, frame/input containment and explicit invalid/incomplete results | Existing implementation retained | Deferred/blocked |
| P05 | Socket instance ownership, monitored peer cleanup, finite resource reservations and headless boundaries | Existing implementation retained | Deferred/blocked |
| P06 | Wire validation, exact consumption, extension handling, fragmentation and registration semantics | Existing implementation retained | Prior comparison failures remain failures; current source unaccepted |
| P07 | Name queues, subscription grammar/quotas, alias matching and caller/callee-bound replies | Existing implementation retained | Required comparison discrepancies remain open |
| P08 | Native FD resources, duplication/cleanup, partial writes and peer/UID/global quotas | Bounded match scan/FIFO fan-out, monitored queued ownership and activation terminal reservations written; specification/quality source reviews complete | 21 added declarations UNRUN; FD/resource/fault/fairness gates deferred/blocked |
| P09 | XML/account/service capture, ordered policies, transactional reload and real credential APIs | Activation backend restrictions now also checked before publication | Full installed-profile/API equivalence unaccepted |
| P10 | Activation coordinator, wait/systemd/helper backends, coalesced bounded requests and error mapping | Production systemd plan, installed-helper binding consumer/producer and enclosing guarded offline package assembly written; mixed-mode systemd failure completion repaired | 18 configuration/binding/failure declarations UNRUN; package build/installed behavior/activation unaccepted |
| P11 | Headless release, inherited socket validation, readiness and epoch fail-stop | Canonical reference/candidate NixOS VM module, fresh-source/release binding and NAR-imported inventory checks written and source-reviewed | Nix evaluation, release build and lifecycle execution UNRUN |
| P12 | Canonical real-service workload, daemon/listener identity, activation/FD/inhibitor checks, core restart and reference boot restore driver added | Same-profile reload/client-exit/service-failure/overload, real PAM/logind session identity and four-operation OS resource brackets written; source specification/quality reviews complete | All 11 canonical rows, VM/restart/rollback execution and resource thresholds UNRUN; NetworkManager unsupported in core profile |

The new canonical core profile is `foundation-core-canonical-v1`. It adds the
declared GLib service, accounts and action-specific polkit fixture to the complete
NixOS inventory; it does not prune the installed service set. Both VM variants use
identical application policies and services. This is a new source profile, not a
claim that the older `PROFILE_INVENTORY.md` artifacts already bind these additions.
Acceptance must capture its complete generated inventory and exact versions.

The offline P10 assembly image is a distinct build input route. It masks its bus
units before boot to assemble the installed-helper package without starting a
bus; it does not qualify the canonical profile. Its actual source/dependencies,
generated helper header/wrapper, toolchains and complete configuration/account
tree must be supplied and built during later acceptance. Existing temporary
helper worker fixtures remain **UNRUN / BLOCKED_TEST_FIXTURE** pending a trusted
installed package; no permissive worker bypass was added.

There are 39 new ExUnit source declarations in this checkpoint (21 core and 18
configuration/binding/failure), all **UNRUN**. Compiler/formatter/type checks are also
UNRUN. Scoped source review and Git/Python-AST/inline-XML checks cannot establish
Elixir/Nix validity, milestone completion or system-bus replacement readiness.

The canonical workload now declares seven normal real-service rows and four
same-profile VM-05 rows. The real logind session must exist; an empty session list
does not satisfy the identity row. External OS resource samples do not prove
internal BEAM queue/credit recovery. A successful future suite cannot replace
mandatory authorization, malformed-input, internal-resource, sustained or other
existing gates. Those gates remain separately required and blocked where
prohibited/unavailable. No broad audit or fuzzing campaign is introduced.

Current highest verified readiness: **L0**, `product_qualified=false`.
