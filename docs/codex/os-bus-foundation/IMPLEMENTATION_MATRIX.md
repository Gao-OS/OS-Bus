# Implementation-first source checkpoint

Base: `cd1b82c9c22344fd7548356d1e1a75fb64b7603d`.
Implementation worktree before publication: `.trees/os-bus-build-compat`, branch
`codex/os-bus-build-compat`. The authorized merge removes this worktree after
preserving its ignored evidence; the GitHub v0.3.0-alpha.1 source checkpoint
retains L0 and does not pass any additional acceptance gate.
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
| P07 | Name queues, subscription grammar/quotas, alias matching and caller/callee-bound replies | Existing implementation retained; [three reference dispositions recorded](P07_REFERENCE_DISPOSITIONS.md); supplementary independent Hello/ownership recorder and pure schema2 transcript oracle implemented with 19 ordinary offline Python tests PASS | All three original comparisons remain BLOCKED_DESIGN; historical FAILs retained; actual collector/interoperability execution UNRUN; no SEM or gate promoted |
| P08 | Native FD resources, duplication/cleanup, partial writes and peer/UID/global quotas | Bounded match scan/FIFO fan-out, monitored queued ownership and activation terminal reservations written; specification/quality source reviews complete | 19/21 added declarations PASS; 2 authorization declarations UNRUN; FD/resource/fault/fairness gates deferred/blocked |
| P09 | XML/account/service capture, ordered policies, transactional reload and real credential APIs | Activation backend restrictions now also checked before publication | Full installed-profile/API equivalence unaccepted |
| P10 | Activation coordinator, wait/systemd/helper backends, coalesced bounded requests and error mapping | Production systemd plan, installed-helper binding consumer/producer and enclosing guarded offline package assembly written; mixed-mode systemd failure completion repaired; exact zero activation-quota enforcement verified | 13/19 added declarations PASS (runtime 6, reload 3, mixed-mode failure 1, helper pairing/ELF 2, zero quota 1); 6 helper trust/safeguard declarations UNRUN; package build/installed behavior/activation unaccepted |
| P11 | Headless release, inherited socket validation, readiness and epoch fail-stop | Canonical reference/candidate NixOS VM module, fresh-source/release binding and NAR-imported inventory checks written and source-reviewed | Nix evaluation, release build and lifecycle execution UNRUN |
| P12 | Canonical real-service workload, daemon/listener identity, activation/FD/inhibitor checks, core restart and reference boot restore driver added | Same-profile reload/client-exit/service-failure/overload, real PAM/logind session identity and four-operation OS resource brackets written; source specification/quality reviews complete | All 11 canonical rows, VM/restart/rollback execution and resource thresholds UNRUN; NetworkManager unsupported in core profile |

The supplementary P07 source is documented in
`scripts/foundation/p07_ownership_signals/README.md`. It retains every decoded
receive before reply filtering, replays the original fourteen actions, records
physical/reply serials and per-connection GetId barriers, and implements an
independent spawned observer. Schema2 now subscribes W before A-D register,
captures four unique-name broadcast/GetId checkpoints, and checks each
connection's Hello reply before its correctly addressed unique NameAcquired.
The observer and actual collector remain UNRUN. The pure comparison retains
setup reply/acquisition interleaving and W's registration stream, plus
ownership-signal-to-signal interleaving separately for each connection. During
the fourteen ownership actions, reply placement remains raw-only. It requires
matching source/profile/kind and reference/candidate labels and rejects failed
runtime collection/cleanup. All results carry `qualifies_original_gate=false`.
Nineteen ordinary offline Python tests PASS, including a complete schema2
memory replay and interrupted journal preservation; synthetic/runtime-labelled
memory fixtures do not prove runtime behavior. Current RED/GREEN and independent
source-review evidence is under `test/reports/foundation/p07-hello-order-20261021/`.
The prior schema1 thirteen-test checkpoint remains unchanged under
`test/reports/foundation/p07-ownership-signals-20261021/`. These Python counts do
not change the ExUnit totals below. No production, original comparison,
profile, selection, expectation or gate-consumer source changed in this slice.

The new canonical core profile is `foundation-core-canonical-v1`. It adds the
declared GLib service, accounts and action-specific polkit fixture to the complete
NixOS inventory; it does not prune the installed service set. Both VM variants use
identical application policies and services. This is a new source profile, not a
claim that the older `PROFILE_INVENTORY.md` artifacts already bind these additions.
Acceptance must capture its complete generated inventory and exact versions.

The immutable P10 sourcePath/sourceNarHash pair for clean published commit
`3650933788ecce3b44e9067b05741d95d6295de5` is prepared under
`test/reports/foundation/p10-published-source-input-20261021/`: all 1,040 source
files (11,329,165 bytes), read-only, with per-file byte/executable-bit checks and
actual NAR hash `sha256-H3Mb9vT6ObB63aykFtrCxz6YOy52DfxAzXPRj3OTOss=`.
It includes the v0.3.0-alpha.1 build version and release documentation. Later
changes affect only AGENTS.md, README.md, this matrix and STATUS.md; the input
remains bound to the published commit, not later main commits. The older
1,039-file input and its relocation record remain immutable historical evidence.

Current main has 44 immediate ordinary deps directories, matching all 44 mix.lock
names. Metadata-only inventory found no missing/extra names; contents, revisions
and SCM completeness were not inspected or qualified. The two-present/42-absent
inventory applied only to the removed worktree. Complete validated deps/SCM and
actual Hex input pairs remain unprepared/unvalidated and null in INPUTS.json.
No dependency acquisition or Nix evaluation/build ran. A protected-safe broader
preparation scope is not established without the historical 98-input identities
or a reviewed plan binding them; none of those protected targets was probed or
reconstructed. Ordinary metadata inventory is permitted and does not qualify a
dependency input, package, installed helper or gate.

The offline P10 assembly image is a distinct build input route. It masks its bus
units before boot to assemble the installed-helper package without starting a
bus; it does not qualify the canonical profile. Beyond the prepared source
input, complete dependencies, a verified Hex archive, generated helper
header/wrapper, toolchains and complete configuration/account tree must still
be supplied and built during later acceptance. Existing temporary
helper worker fixtures remain **UNRUN / BLOCKED_TEST_FIXTURE** pending a trusted
installed package; no permissive worker bypass was added.

Of the 40 new ExUnit declarations in the current checkpoint, **32 PASS** and **8 remain
UNRUN**. The 21 core declarations comprise 10 accounting, 7 broadcast and 4
coordinator cases: 19 pass, while the 2 broadcast authorization cases remain
unrun under the security-test prohibition. The 19 configuration/binding/failure
declarations comprise 6 runtime, 3 reload, 8 helper-binding, 1 mixed-mode
failure and 1 zero-quota case: runtime, reload, mixed-mode failure, zero quota
and 2 positive helper pairing/ELF cases pass. The 6 helper trust/safeguard rejection cases remain
unrun under the security-test prohibition and closed scope. Their hold is
separate from the missing trusted installed-package acceptance fixture.

Ordinary scoped execution cumulatively passed **53 distinct test declarations**
(32 new and 21 inherited), with **63 test executions and 0 test failures**
including the 10-case accounting rerun after its regression assertion was
strengthened. The inherited coverage includes 10 ordinary coordinator, 2
systemd-ordering and 9 pure activation-state cases. The original 50-declaration,
60-execution checkpoint remains recorded unchanged in
`test/reports/foundation/ordinary-functional-20261020/FINAL.json` and
`test/reports/foundation/ordinary-functional-20261020/RESULTS.md`.
The incremental 3 declarations and cumulative totals are recorded in
`test/reports/foundation/ordinary-activation-zero-20261020/FINAL.json` and
`test/reports/foundation/ordinary-activation-zero-20261020/RESULTS.md`.
The new `activation_zero_limits_test.exs` case verifies that valid ingress and
identity with XML `max_pending_service_starts=0` receive the exact typed refusal,
leave the complete Limits snapshot unchanged, and permit ingress release.
Two inherited pure State cases also verify zero pending capacity and literal
zero-timeout behavior. No production defect was found, and production source
was unchanged.
The 2 positive helper cases, recorded in
`test/reports/foundation/ordinary-functional-20261020/10-helper-pairing-positive.json`,
compare synthetic manifest/configuration maps and parse synthetic ELF binaries
entirely in memory. They do not read an installed helper or establish its trust.
These fixtures use local supervised processes and disposable configuration
files. They do not run actual services, helpers, PID1, socket listeners or VMs.
Empty-FD NIF bookkeeping is exercised; it does not establish FD acceptance.

Ordinary scoped compilation is **PASS**:
`mix compile --warnings-as-errors` compiled 16 ExDBus and 42 GaoBus
source files in both `MIX_ENV=test` and `MIX_ENV=prod`. The final explicit
32-file formatter check is also
**PASS**; location-normalized ASTs matched before/after for all 18 formatted
files at that earlier checkpoint. One accounting test assertion was intentionally
strengthened afterward and its 10-case suite rerun. Exact commands, results and hashes are recorded in
`test/reports/foundation/ordinary-compile-format-20261020/FINAL.json`,
`test/reports/foundation/ordinary-prod-compile-20261020/compile-prod.json` and the current
`STATUS.md` entry. The selected ordinary test files were subsequently compiled
and executed as recorded above, including the helper-binding file's 2 positive
selections; its 6 rejection cases remain unexecuted. For the release runtime
snippet and the helper-manifest producer script, formatting proves
parsing/formatting only; those sources were not executed.
The new zero-quota test's initial formatter check failed solely on its multiline
`start_supervised!` layout; formatting and recheck passed. The initial formatting
failure is preserved in the incremental zero-activation evidence. It was not a
runtime implementation failure or failed production repair.

Type checks, full umbrella/release qualification, installed-helper/native
behavior and VM acceptance remain **UNRUN/BLOCKED**. Ordinary compilation also
built the native artifacts; that does not qualify their behavior or the trusted
installed-helper package. Scoped compilation/formatting, functional tests and
source checks do not establish source completeness, Nix validity, milestone completion or
system-bus replacement readiness. No acceptance gate is promoted.

The canonical workload now declares seven normal real-service rows and four
same-profile VM-05 rows. The real logind session must exist; an empty session list
does not satisfy the identity row. External OS resource samples do not prove
internal BEAM queue/credit recovery. A successful future suite cannot replace
mandatory authorization, malformed-input, internal-resource, sustained or other
existing gates. Those gates remain separately required and blocked where
prohibited/unavailable. No broad audit or fuzzing campaign is introduced.

Current highest verified readiness: **L0**, `product_qualified=false`.
