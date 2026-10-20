# Requirements and acceptance boundary

## Product definition

**OS-Bus replaces the userspace system-bus daemon, not the D-Bus protocol, client libraries, Linux device buses, or service-specific authorization systems.** The first replacement must work with unmodified existing clients and a declared inventory of service/configuration files.

Keep `ex_d_bus` reusable; use `gao_bus` for bus authority and Unix integration; keep `gao_config`, `gao_bus_web`, and cluster features out of the minimal production runtime. Their future evolution is outside this program except where necessary to prevent a security bypass or preserve compilation.

### Initial qualification profile

Use a reproducible NixOS VM with systemd and Unix-domain system-bus transport. Pin its nixpkgs revision, kernel, OTP/Elixir versions, reference `dbus-daemon`, configuration files, and service versions. Prefer the existing development environment; add VM-test support without replacing the project's established environment unnecessarily.

The core real-service set is systemd's system-bus API, systemd-logind, and polkit, plus a small activation/FD fixture. Add a NetworkManager profile with a virtual network device before claiming compatibility with network-management workloads. Device/desktop stacks such as BlueZ and UDisks are later profiles unless the deployment inventory makes them required.

This profile is a qualification target, not permission to ignore installed service policies. Capture the **entire effective policy/configuration inventory** loaded by the chosen profile. A file containing unsupported security or activation semantics makes that configuration unsupported. Do not delete the file, loosen its rules, or disable a security subsystem to make the profile qualify.

If SELinux/AppArmor or another mandatory access-control integration is enabled and required in a deployment, OS-Bus cannot claim replacement support there until its integration is implemented and tested. A credential/security-label query is not a substitute for MAC mediation. A deliberately minimal test profile may document those integrations as outside its claim; this must not become an automatic production downgrade.

## Requirement register

| ID | Requirement | First gate |
| --- | --- | --- |
| R-01 | Trusted credentials originate at the accepted Unix socket. Client assertions never replace UID/GID/PID or independently validated security metadata. Failure to obtain required identity is fatal to admission. | M1 |
| R-02 | Authentication and registration are distinct, explicit state machines. Unauthenticated or pre-Hello traffic cannot invoke normal bus operations. System mode rejects anonymous clients. | M1 |
| R-03 | Connection admission, ownership, sending, receiving, privileged bus methods, activation, and monitoring have explicit authorization points. No policy-unavailable allow fallback exists. | M1; activation completion M3 |
| R-04 | A denied operation has no unauthorized externally visible effect: no ownership mutation, delivery, monitor disclosure, or service start. Resolve alias-related policy behavior against the configured reference semantics. | M1–M3 |
| R-05 | Valid messages with invalid method arguments produce controlled method errors; malformed frames never reach core handlers. One bad client cannot trigger a restart of healthy established connections. | M1 |
| R-06 | Wire processing separates incomplete from invalid input, accounts for exact frames, imposes configured and protocol limits before expensive work, and implements supported extension behavior. | M1–M2 |
| R-07 | Name ownership, queueing, signals, match subscriptions, and requested replies follow the reference profile's externally observable semantics. No unsolicited broadcast fallback for peers with no rules. | M2 |
| R-08 | Real FD transfer works across fragmentation, coalescing, partial writes, fan-out, denial, and disconnect, with explicit exactly-once release of the daemon's resource ownership. | M2 |
| R-09 | Every ingress/egress/activation path has enforceable resource budgets. A slow recipient cannot block the bus authority; healthy traffic remains serviceable during bounded overload. | M1 baseline; M2 full |
| R-10 | Existing XML policies and relevant daemon configuration compile into an ordered, validated policy model. Unsupported security-relevant semantics are rejected with provenance, not ignored. | M3 |
| R-11 | Policy reload is transactional. Readers see a coherent generation; failed reload keeps the last valid generation. Initial invalid policy prevents service readiness. | M3 |
| R-12 | Credential queries report the actual live connection identity and correct ownership resolution; missing platform data is not fabricated. Expose only actually supported interfaces/features. | M3 |
| R-13 | Activation supports the declared profile's `.service` inventory, identity transitions, timeouts, errors, systemd integration, and bounded queued calls without circular dependencies. | M3 |
| R-14 | Minimal release startup, readiness, shutdown, inherited listening sockets, and filesystem socket ownership have explicit lifecycle rules. A second instance cannot remove another daemon's socket. | M1 ownership; M3 release |
| R-15 | Tests use independent actors and a pinned reference backend. Mandatory gate failures, unavailable backends, unexpected skips, and zero executed cases fail qualification. | M0 onward |
| R-16 | Observability cannot bypass authorization or create unbounded queues. Full payload logging and remote BEAM access are absent from the default headless profile. | M1–M3 |
| R-17 | Disposable VM boot, actual service operations, adverse scenarios, and rollback are executed before profile replacement is qualified. | M4 |

## Security posture

Protect three principal assets: truthful connection identity and name ownership; confidentiality/integrity of authorized message exchange; continued availability of the bus and healthy clients. The attacker model includes unprivileged local clients, malicious or compromised service accounts, malformed frames, crafted match rules, resource floods, and disconnected or stalled recipients.

Running as root in the VM is not evidence that non-root admission and policy work. Tests must include separate operating-system identities. The implementation must not embed a special “test auth” path in the production system profile.

Arbitrary hostile Elixir code inside the same BEAM VM is not isolated by a GenServer or ETS access mode. Therefore the production trust boundary excludes untrusted in-VM plugins and an unrestricted distributed-node connection. Changing public ETS to protected ETS is worthwhile internal discipline, not a complete security sandbox.

Service authorization remains with the service and, where applicable, polkit. OS-Bus must transport and expose trustworthy identity; it must not replace policy decisions with “service account means trusted” heuristics.

## Compatibility claims

Maintain a capability matrix with separate columns for **implemented**, **tested**, **profile-required**, and **unsupported**. Include the actual configuration and platform versions that were tested. Avoid a single misleading “D-Bus compatible: yes” flag.

Compatibility dimensions are: wire/authentication; names/routing/matches/replies; bus interfaces; policy/configuration; activation; Unix credentials/FDs; service-manager lifecycle; and declared real-service workloads.

The primary target is a standard system bus. Session-bus behavior can remain available and tested, but must be explicitly configured; do not carry a permissive session configuration into system-mode defaults. Remote transports and distributed routing remain outside the initial replacement claim.

## Readiness levels

| Level | Meaning | Required evidence |
| --- | --- | --- |
| L0 — Baseline only | Source reviewed or baseline established; unresolved safety gaps may remain. | M0 report. |
| L1 — Hardened isolated development bus | M1 regressions and containment verified. Not a replacement candidate. | M1 gate. |
| L2 — Protocol/transport candidate | M2 completed, independent interoperability and resource tests verified. System integration still unqualified. | M1 + M2 gates. |
| L3 — Profile integration candidate | M3 implemented and integration gate executed for a pinned configuration. | M1–M3 gates. |
| L4 — Controlled-VM replacement candidate | Real VM boot/workloads/faults/rollback pass for the declared profile. | All M0–M4 gates. |

L4 is the program's maximum claim. Production adoption additionally requires operator review, deployment-specific compatibility review, and independent security review proportional to the intended exposure. This package does not assert those reviews have occurred.

## Definition of done

Every required row has source, regression, actual execution result, and artifact provenance. The minimal release works without the web/config/cluster applications. The selected policy inventory is supported without permissive substitutions. Independent clients and real services pass both allowed and denied operations. Resource and FD evidence is repeatable. VM rollback is proven. Documentation is consistent with the code, and any unfinished scope is explicit rather than hidden in TODOs, skips, or compatibility flags.
