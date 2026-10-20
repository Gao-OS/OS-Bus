# Baseline evidence and primary references

## Provenance

The preceding code review examined `Gao-OS/OS-Bus` at commit `7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4`. On 2026-10-09, the GitHub `main` branch was read again and still resolved to that commit. Its commit date is 2026-08-11. This handoff also reread the root agent guidance and E2E documentation and consulted the primary technical references below.

The risk register summarizes **source-level findings**, not newly executed exploits or tests. Neither the existence of a test nor a previously successful CI run demonstrates that the expanded acceptance requirements are satisfied. Codex must record fresh execution evidence from its actual checkout and environment.

## Repository sources

Paths below are pinned to the reviewed commit unless explicitly stated otherwise. The listed files were consulted in the preceding review or in handoff preparation. Reopen them on the actual checkout before editing.

| Ref | Evidence | Location |
| --- | --- | --- |
| R01 | Peer authentication, asserted UID handling, state transitions, buffers, send/receive and FD lifecycle. | [peer.ex](https://github.com/Gao-OS/OS-Bus/blob/7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4/apps/gao_bus/lib/gao_bus/peer.ex) |
| R02 | Default capability grants, policy callbacks, and ETS storage. | [policy/capability.ex](https://github.com/Gao-OS/OS-Bus/blob/7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4/apps/gao_bus/lib/gao_bus/policy/capability.ex) |
| R03 | Policy routing, broadcast fallback, response routing and peer bookkeeping. | [router.ex](https://github.com/Gao-OS/OS-Bus/blob/7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4/apps/gao_bus/lib/gao_bus/router.ex) |
| R04 | Bus-method dispatch, unchecked bodies, current API and activation coverage. | [bus_interface.ex](https://github.com/Gao-OS/OS-Bus/blob/7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4/apps/gao_bus/lib/gao_bus/bus_interface.ex) |
| R05 | Name ownership, replacement, queues and cleanup. | [name_registry.ex](https://github.com/Gao-OS/OS-Bus/blob/7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4/apps/gao_bus/lib/gao_bus/name_registry.ex) |
| R06 | Match-rule parser and sender/argument matching. | [match_rules.ex](https://github.com/Gao-OS/OS-Bus/blob/7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4/apps/gao_bus/lib/gao_bus/match_rules.ex) |
| R07 | Frame/header/body encoding and decoding, version and malformed-body handling. | [message.ex](https://github.com/Gao-OS/OS-Bus/blob/7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4/apps/ex_d_bus/lib/ex_dbus/message.ex) |
| R08 | Listener startup, handoff and unconditional path deletion. | [listener.ex](https://github.com/Gao-OS/OS-Bus/blob/7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4/apps/gao_bus/lib/gao_bus/listener.ex) |
| R09 | Core supervision ordering and optional cluster child. | [application.ex](https://github.com/Gao-OS/OS-Bus/blob/7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4/apps/gao_bus/lib/gao_bus/application.ex) |
| R10 | Current backend/actor/oracle harness, commands and known-gap behavior. | [docs/e2e.md](https://github.com/Gao-OS/OS-Bus/blob/7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4/docs/e2e.md) |
| R11 | Existing E2E toolchain, selectors, working directory and artifact upload. | [.github/workflows/e2e.yml](https://github.com/Gao-OS/OS-Bus/blob/7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4/.github/workflows/e2e.yml) |
| R12 | Current root guidance begins with Phoenix-specific application assumptions. | [AGENTS.md](https://github.com/Gao-OS/OS-Bus/blob/7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4/AGENTS.md) |
| R13 | Capability-first decision with optional XML compatibility layer. | [ADR-003](https://github.com/Gao-OS/OS-Bus/blob/7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4/docs/adr/ADR-003-capability-security.md) |
| R14 | Project boundary and existing runtime/library claims. | [README.md](https://github.com/Gao-OS/OS-Bus/blob/7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4/README.md) |
| R15 | Existing stable E2E-001–E2E-020 scenarios. | [docs/e2e-matrix.md](https://github.com/Gao-OS/OS-Bus/blob/7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4/docs/e2e-matrix.md) |

## Finding-to-work traceability

Each entry is a starting point for verification, not permission to assume the latest checkout still has the defect.

| ID | Baseline source-level finding | Sources | Work / regression evidence required |
| --- | --- | --- | --- |
| F01 | Nonempty EXTERNAL assertion becomes credentials without kernel-identity comparison; UID 0 receives broad capabilities. | R01, R02 | P02; SEC-01–SEC-03, SEC-06. |
| F02 | BEGIN is not guarded by authenticated success; anonymous authentication is accepted. | R01 | P02; SEC-04–SEC-07. |
| F03 | RequestName grants through the registry without invoking the defined ownership check. | R02, R04, R05 | P03; SEC-08. |
| F04 | Permissive defaults, missing receive authorization, and policy-absent allow path undermine the policy boundary. | R02, R03 | P03/P09; SEC-09–SEC-13, POL suite. |
| F05 | Unchecked method-body destructuring executes within Router; its failure domain includes later supervised peers/listener. | R04, R09 | P04; SEC-14–SEC-16, FAIL-03. |
| F06 | Decoder ignores version, tolerates body errors, and has problematic missing-signature/body consumption; peer retains invalid buffers. | R01, R07 | P04/P06; PRO suite. |
| F07 | Incomplete messages preserve bytes but not the accompanying FD state; complete resource ownership/cleanup is absent in the inspected path. | R01 | P08; FD-01–FD-10. |
| F08 | Send results are ignored and resource/queue backpressure is not established in the inspected routing/peer path. | R01, R03 | P05/P08; RES suite, FD-06. |
| F09 | No-rule peers receive broadcasts; sender matching is literal and rule parsing is ad hoc. | R03, R06 | P07; SEM-06–SEM-09. |
| F10 | Name queue/replacement behavior and unconditionally permitted response routing need complete reference semantics. | R02, R03, R05 | P07; SEM-01–SEM-04, SEM-10–SEM-12. |
| F11 | Credential APIs/activation and advertised Peer behavior are incomplete; XML compatibility is not the operational primary policy. | R04, R13 | P09–P11; API/POL/ACT/SYS suites. |
| F12 | Listener unconditionally deletes its configured path at startup/termination without proving endpoint ownership. | R08 | P05/P11; SYS-02, FAIL-02. |

## Primary technical references

These are external verification sources, not third-party review summaries. Recheck the exact versions used during implementation. A live manual can document a newer runtime than the project's pinned release.

| Ref | Source | Use |
| --- | --- | --- |
| S1 | [Official D-Bus specification](https://dbus.freedesktop.org/doc/dbus-specification.html) | Authentication, wire validity/extensions, bus names/routing, method semantics, and feature advertisement. The page consulted identifies specification 0.43; record the actual revision used in implementation. |
| S2 | [Official dbus-daemon manual](https://dbus.freedesktop.org/doc/dbus-daemon.1.html) | Existing daemon configuration, policy, limits and service integration. Verify detailed behavior with the same pinned reference configuration, not an unrelated permissive session fixture. |
| S3 | [OTP 28 socket documentation](https://www.erlang.org/docs/28/apps/kernel/socket.html) | Public receive/send/continuation, descriptor and option contracts. Confirm the exact installed patch release and Linux behavior with a runtime spike. |
| S4 | [systemd sd_listen_fds manual source](https://github.com/systemd/systemd/blob/main/man/sd_listen_fds.xml) | Service-manager listener handoff and lifetime rules. The consulted source blob is `19b0b0a98d3ee53e14342dc289215153dd59f933`; pin the matching source/version in the eventual platform report. |

The current unversioned OTP manual was also checked and identifies OTP 29, so it must not be copied unquestioningly into an OTP 28 implementation. The rendered systemd manual was unavailable to the research tool; its official repository XML source was used instead.

For unresolved edge cases, consult the pinned upstream implementation and add a differential test. Reference behavior is evidence, not a license to contradict an explicit normative requirement. Document any legitimate disagreement and its compatibility impact.

## What this package does not claim

No source changes, native helper, VM configuration, or regression implementation is delivered here. No new tests or VM cutovers were executed during document preparation. All package-specific gates and IDs are proposed work. The executable goal instructs Codex to implement them and produce the missing evidence.
