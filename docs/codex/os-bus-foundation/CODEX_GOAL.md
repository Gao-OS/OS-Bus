# Codex goal: implement the OS-Bus Security & Compatibility Foundation

## Assignment

Work in `Gao-OS/OS-Bus`. Implement the program defined in this directory, from baseline verification through a tested system-bus replacement in disposable Linux VMs.

The user's primary objective is to implement the Linux system bus and, as the first product milestone, make it convenient and safe to replace the existing D-Bus daemon. Existing applications must not need an OS-Bus-specific client library, new authentication protocol, rewritten service identities, or permissive policy workarounds.

**This is an implementation task. Modify the code, add regression tests, run the available verification, and produce evidence. Do not stop after reviewing the repository or writing another plan.**

## Read first

Read applicable `AGENTS.md` files and the existing architecture/E2E documentation. Then read `REQUIREMENTS.md`, `ARCHITECTURE.md`, `IMPLEMENTATION_PLAN.md`, `TEST_PLAN.md`, and `ROLLOUT_RUNBOOK.md` in this directory. Use `SOURCES.md` to distinguish baseline findings from normative references.

The reviewed baseline is `7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4`. Record the actual checkout SHA and working-tree state. Do not reset the checkout to that old commit or overwrite unrelated user changes. Revalidate each finding on the current code.

## Required outcome

Execute the following milestones in dependency order:

1. **M0 — Evidence and harness.** Establish a reproducible Linux environment, preserve existing E2E cases, add strict gate accounting, and prove the runtime can acquire real peer credentials, handle arbitrary received FDs, and adopt an inherited listener safely.
2. **M1 — Security foundation.** Bind authentication to kernel credentials; reject authentication bypasses; enforce admission and authorization on every relevant path; validate untrusted messages before core state changes; isolate bad peers; make socket ownership and resource limits safe.
3. **M2 — Protocol and transport correctness.** Finish wire validation, registration/name/match/reply semantics, independent-client interoperability, FD ownership across fragmentation and partial writes, and bounded/fair I/O.
4. **M3 — Linux compatibility.** Support the declared profile's existing XML configuration/policies, real credential queries, service activation, service-manager integration, and a minimal headless release with no required web/config/cluster runtime.
5. **M4 — VM qualification.** Boot the declared NixOS/systemd test profile using OS-Bus, exercise real allowed and denied service operations, inject faults, and verify controlled rollback to the reference daemon.

A milestone may be marked complete only when its mandatory gate is actually executed and passes. A missing Linux runner, VM capability, service, dependency, or credential/FD facility is a blocker, not a successful skip. Continue other independent work when useful, but retain that blocker and do not certify a dependent milestone.

## Non-negotiable constraints

- Never stop, disable, replace, unlink, reconfigure, or connect test traffic to the host's live system or session bus. Use isolated sockets and disposable VMs. Live deployment is not authorized by this goal.
- Preserve Elixir/OTP and the useful umbrella boundaries. Prefer pure, total state-transition and validation functions with effects at explicit process/I/O boundaries. Do not perform a framework rewrite or expand distributed-bus scope.
- Treat socket clients as untrusted. Authentication text is not identity. A client cannot obtain more privilege by choosing a UID, sender header, destination alias, or connection name.
- Policy failure cannot allow an operation. Invalid initial configuration must prevent readiness; invalid reload must leave the last valid policy active. Do not invent blanket root or system-UID exemptions in the engine.
- Compatibility mode uses existing system policy semantics. Do not bypass `check_own`, omit receive authorization, turn off host security enforcement, or grant every peer broad permissions to make tests green.
- Never silently swallow malformed messages, unsupported security-relevant configuration, truncated ancillary data, send failures, or FD cleanup failures. Preserve documented forward-compatible protocol behavior rather than rejecting every unknown extension indiscriminately.
- Do not claim FD support from header round-trips. Test real descriptors with independent clients, bounded ownership, failure cleanup, partial sends, and recipient negotiation.
- Do not change reference expectations, weaken a negative test, add a selected-gate skip/known-gap, or disable CI merely to obtain green status. Explain legitimate specification corrections with evidence.
- Keep the wire library pure. A minimal Unix resource adapter/helper is permitted only when public supported OTP APIs cannot meet a required operation; document the evidence, security boundary, packaging, and tests in an ADR. No invented or undocumented FD APIs.
- No automatic host cutover, pushing, merging, publishing releases, or changing remote repository protection/settings. Local work and evidence are sufficient unless separately authorized.

## Working procedure

Start by creating an execution entry in `STATUS.md`. Inventory current source and tests, identify the smallest reproducible cases for the P0 findings, and run the existing baseline before fixing them where practical.

For each work package: write or identify a meaningful failing regression; implement the smallest coherent correction; run focused tests; run affected regression gates; update compatibility documentation and the execution ledger. Keep changes reviewable and separate unrelated refactors. Reuse the current backend/actor/oracle harness rather than creating a second competing test system.

Run security tests in separate daemon processes or disposable containers/VMs where identity and process-wide resource behavior matter. Use independent GLib/libdbus/sd-bus actors as appropriate; testing only ExDBus against GaoBus is insufficient.

Use the repository's pinned development environment. Check the actual Mix aliases before invoking them. Existing commands are documented in `IMPLEMENTATION_PLAN.md`; new gate names in this package are requirements to implement, not claims that they already exist.

When an implementation choice is not specified, choose a conservative design, document the trade-off, and continue. When a safety-critical requirement cannot be satisfied, leave an explicit blocker rather than fabricating a stub, reporting success, or expanding the supported-profile claim.

At an execution boundary, save a precise checkpoint in `STATUS.md`: actual changed files, verified tests, remaining failures, blocked dependencies, and the next smallest action. Do not promise background completion.

## Required final report

Report: (a) actual base and resulting commit/working-tree state; (b) implemented work packages; (c) exact commands and runtime versions; (d) executed/passed/failed/skipped/blocked counts per backend and gate; (e) evidence for each original security finding; (f) compatibility profile and exclusions; (g) FD/resource and VM/rollback results; (h) remaining risks and the next unfinished package.

State one readiness level from `REQUIREMENTS.md`, with reasons. Never equate “unit tests pass” or “M1 complete” with “safe to replace the Linux system bus.”
