# OS-Bus — Codex implementation handoff

**Program:** Security & Compatibility Foundation  
**Prepared:** 2026-10-09  
**Repository:** `Gao-OS/OS-Bus`  
**Reviewed baseline:** `7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4`  
**Status:** Implementation instructions, not an implementation or a readiness certificate.

## Objective

Make OS-Bus a safely testable replacement for the Linux **system D-Bus daemon**, preserving existing clients, service identities, policy files, and service activation within an explicitly tested Linux profile. Keep the broader GaoOS bus vision, but do not prioritize new protocols, distributed routing, configuration features, or a monitoring UI over this foundation.

The endpoint of this program is a **controlled-VM replacement candidate for a declared profile**. It is not a claim of universal distribution compatibility, an independently audited security certification, or authorization to replace the operator's live system bus.

## Use this package

Extract the archive at the repository root. It adds only `docs/codex/os-bus-foundation/`; it does not replace repository source files. Give Codex the contents of [CODEX_GOAL.md](CODEX_GOAL.md), or the short invocation below. The goal is ordinary instruction text; it does not require a particular Codex command or CLI version.

> Implement the OS-Bus Security & Compatibility Foundation according to docs/codex/os-bus-foundation/CODEX_GOAL.md. Read the package and applicable repository instructions first. Execute M0 through M4 in dependency order, beginning with failing security regressions and real kernel-credential authentication. Implement and verify changes; do not stop at another plan. Keep STATUS.md accurate, distinguish blocked tests from passes, and never modify the host's live system bus. Finish with evidence for each completed gate and explicit remaining blockers.

For a deliberately smaller first execution, add: **“This invocation is scoped to M0 and M1. Preserve M2–M4 as pending; do not report the whole program complete.”** Do not silently adopt that smaller scope for the full goal.

## Documents

| File | Purpose |
| --- | --- |
| [CODEX_GOAL.md](CODEX_GOAL.md) | The executable assignment, non-negotiable constraints, and final reporting contract. |
| [REQUIREMENTS.md](REQUIREMENTS.md) | Product boundary, security requirements, supported-profile policy, and completion levels. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Trust boundaries, functional state transitions, policy integration, transport and FD ownership. |
| [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) | Dependency-ordered work packages P00–P12, milestone exits, and evidence requirements. |
| [TEST_PLAN.md](TEST_PLAN.md) | Stable regression IDs, differential tests, fault injection, resource tests, and strict CI gates. |
| [ROLLOUT_RUNBOOK.md](ROLLOUT_RUNBOOK.md) | Isolated testing, NixOS VM integration, controlled cutover, and rollback verification. |
| [STATUS.md](STATUS.md) | Execution ledger to update during implementation; initially all work is pending. |
| [SOURCES.md](SOURCES.md) | Pinned repository evidence and primary technical references. |

## Reading and execution order

Read the goal, requirements, architecture, implementation plan, and test plan before editing. Consult the rollout document before adding service units or VM integration. Resolve source locations against the actual checkout, not just the reviewed commit.

| Milestone | Deliverable | May replace a live host bus? |
| --- | --- | --- |
| M0 | Reproduced baseline, strict test harness, runtime feasibility checks. | No. |
| M1 | Hardened isolated bus: identity, authorization, validation, containment. | No. |
| M2 | Protocol/routing correctness, durable FD ownership, bounded I/O. | No. |
| M3 | Declared system-compatibility profile, activation, minimal release. | No. |
| M4 | End-to-end VM replacement and rollback evidence for that profile. | No; separate operator approval remains required. |

## How to interpret this handoff

The previous review identified concrete source-level risks. Reproduce or disprove them in the current checkout before changing code. Source-level analysis, test existence, an old green workflow, and actual execution evidence are different things. A fix already present in newer code should be retained and verified, not rewritten merely to match this package.

Requirements in this package are engineering acceptance criteria. Protocol edge cases must be resolved against the official specification and a pinned reference daemon configuration; do not turn an incidental behavior of either implementation into the specification. See [SOURCES.md](SOURCES.md).
