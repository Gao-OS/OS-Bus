# P09 provenance and service-account prerequisites

Status: completed prerequisite implementation and scoped evidence checkpoint.
Full Foundation remains active at L0.
Worktree: `.trees/os-bus-foundation`, branch `codex/os-bus-foundation`,
base `7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4`.
Candidate09 and all prior API/security/failure evidence remain immutable.

## Bounded implementation

ADR006 slice1 requires attributable configuration and trusted launch identity.
Complete these independent prerequisites before service discovery/publication:

1. Preserve every scalar/list/flag/limit declaration in XML expansion order,
   including shadowed values and original user spelling. Effective values keep
   their existing semantics. Every declaration, policy/rule and loaded source
   retains file, line, element, file occurrence and its actual include chain.
   Repeated includes have distinct occurrences. Nested/repeated/include-directory
   cases must retain their parents after recursion returns.
2. Runtime refusal carries the original reason and effective directive origins;
   missing metadata is not fabricated for manually supplied configurations.
   XML-derived identity/profile, settings, activation settings/limits and finite
   protocol-limit refusals retain the declaration that caused them. Restart-required
   file reload reports the changed declarations and keeps the previous whole
   policy generation; existing wire error names remain unchanged.
3. Local account snapshots retain per-user primary GID separately from sorted
   memberships, named UID/GID/groups and entry/file provenance with source hashes.
   Service-specific binding requires a real snapshot record; numeric ACL resolution
   is unchanged and cannot invent a launch identity. Legacy injected policy-only
   snapshots stay usable for policy but cannot supply missing primary GIDs.
   Retain finite read/parser bounds and reject observed read-time identity changes;
   do not claim an atomic read across independently mutable passwd/group files.

Production write scope: `config.ex`, `config/runtime.ex`, `policy.ex` for provenance;
`config/accounts.ex` for account records/binding. Disjoint workers own those sets.
New tests only: `config/provenance_test.exs`, `policy/file_reload_provenance_test.exs`
and `config/account_binding_test.exs`. Parent additionally owns the strict
restart-refusal assertion in existing `policy/file_reload_test.exs`: preserve its
original source, retain the exact reason/generation checks and add effective
file/line/occurrence/chain assertions for the richer required diagnostic.
Parent owns runtime commands, scoped builds,
RED/GREEN evidence, preservation, review integration and ledger updates.

No directory reader, service parser, launch effects, activation coordinator,
listener/release packaging or authorization expansion in this scope. Existing
activation runtime settings remain explicitly rejected. Successful provenance
does not satisfy all R-10/service-generation or full P09/P10 acceptance.

## Verification and preservation

Capture meaningful failing regressions on unchanged sources before edits, then
run scoped warnings-as-errors compile/format and the three new tests plus affected
Config/Runtime/Accounts/file-reload/policy tests. Keep failures and full logs.
Review specification compliance and code quality independently. Do not weaken
existing reference comparisons, remove policies, infer live service acceptance,
or redispatch the rejected registered-Peer FD04 audit. Preserve original main,
inherited work and frozen candidates. No commits, remote writes, releases,
host live-bus traffic or memory updates.

Evidence: `test/reports/foundation/continuation-20261010-p10-discovery/`.

## Current implementation checkpoint

Exactly four production files differ from frozen candidate09: Config, Runtime,
Policy and Accounts as scoped above. Candidate09 is preserved; its source/build
binding describes the preceding API checkpoint, not these current sources.
No discovery, activation, native, parser or Policy.XML changes were made.

Unchanged-source RED: 22 tests,17 failures,5 passes, exit2. Scoped production
format and warnings-as-errors compilation pass. The first GREEN had22/0
assertions but strict exit1 from one unused default argument in a test helper;
that run remains preserved. Parent removed only the unused default and formatted
the new tests with unchanged normalized ASTs. Production repair rounds0;
fixture lint correction1. Final affected strict selection:190 tests,0 failures,
exit0, no skipped/excluded rows; final eight-file format check passes. A subsequent
strict affected API/P08 refresh is recorded separately and preserves the11
lifetime/EPIPE/natural-expiry cases. These selections overlap and are not summed.

Local account file evidence records captured bytes and observed path/open-file
identity before/after bounded reads. It does not establish atomicity across
passwd/group or detect mutations invisible to that metadata. Compiled successful
Policy.XML origins and a joint policy/services/accounts generation remain future
work. Independent specification and code quality reviews both pass. New frozen
candidate10 binds these four sources/four beams (native unchanged): manifest
`481ac418dd6fa49bf6fcafd8a6a08358e12a0503110765da4f9f85322d3d87dd`, source
`63e9c6ce9b951b5ba85f2a5a3b708d315a816632041a7ceaacbd885d0c5ea32b`.
Frozen security21/0 plus fixture15/0 pass. Candidate API234/0; reference234/1,
retaining no-reply-AbsentMember. The six-test/ten-actor paired gate remains
FAIL5pass/1fail and9pass/1fail,0skips/blocks/missing. Independent saved-wire replay
verifies2017 physical frames; both VMs power off normally. Full P08/P09 and
readiness remain open/L0. The next separate scope is bounded discovery.
