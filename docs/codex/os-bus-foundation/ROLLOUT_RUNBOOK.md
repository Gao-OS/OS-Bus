# Isolated qualification and rollback runbook

## Authorization boundary

This runbook authorizes development and tests in isolated processes/containers and **disposable Linux VMs only**. It does not authorize altering the operator's host bus, host boot configuration, production services, or remote machines.

Do not run daemon replacement commands on the development host. Do not stop or disable its D-Bus services. Do not unlink its system or user-session sockets. Do not mount a live host `/run/dbus`, `/run/user`, or host process namespace into fixtures. Never redirect a generated test client to an implicit default bus address.

All destructive steps below refer to a disposable VM whose identity the test harness has independently established. Root privileges for real identity/activation testing belong inside that VM. Repository source/store inputs may be shared read-only; credentials, host sockets, and unrelated writable host paths may not.

## Stage A — Freeze the qualification inputs

Record the source revision and artifact hash; nixpkgs/kernel/OTP/Elixir/systemd/reference-daemon versions; minimal release command; exact XML policy/configuration bytes; `.service` files and identities; service inventory; enabled security mechanisms; and resource/workload parameters.

Codex must implement and document a real build/test entrypoint for these inputs. No deployment command is supplied here as though it already exists. Use the established devenv/Nix layout and add reproducible VM checks as needed. Do not upgrade the toolchain or regenerate unrelated lock files solely to simplify this task.

Create two mutually exclusive **system-bus** variants: a known-good reference configuration and the OS-Bus candidate. Keep application clients and service policy files identical. A separate user-session bus may exist if the profile needs it; it must not be mistaken for the target system bus.

Account and group resolution during policy/activation setup must have a defined bootstrap path and finite failure behavior. Avoid depending on network/NSS services that themselves need the not-yet-ready bus. Resolve names outside routing callbacks and document any platform-dependent limitations.

**Exit evidence:** all inputs identified; candidate builds as a headless release; unsupported configuration and required platform capabilities reported before attempting replacement.

## Stage B — Isolated daemon qualification

Run the original E2E suite and all M1/M2 gates on private Unix sockets. Start OS-Bus and reference daemons in separate OS processes with independently verified addresses, PIDs, and configurations. Use raw/GLib/sd-bus or libdbus actors in addition to ExDBus.

Verify both success and denial paths for multiple UIDs. Complete FD and resource tests with external process inspection. Save fail-first/passing regressions when available, as well as crashes and resource samples. All fixtures must have finite deadlines and teardown that survives a failed test.

Do not promote beyond this stage merely because a normal Hello/Echo succeeds. Missing Linux credential support or an unsafe FD ownership mechanism is a blocker.

**Exit evidence:** M1/M2 gates pass with strict selection and no unexpected skips; highest allowed readiness remains L2.

## Stage C — Reference VM baseline

Boot the pinned reference VM and exercise the selected real workloads before substituting the daemon. Include systemd system-bus calls, logind identity/session operations, polkit allowed/denied requests, automatic activation, and actual FD use. Include NetworkManager with a virtual device when qualifying the network profile.

Verify the chosen actor really reaches the system-bus API. A successful privileged `systemctl` command can use another transport or bypass the path being tested; use an explicit system-bus actor and evidence of the selected socket. Likewise, use actual service authorization operations rather than treating a polkit process being alive as an authorization test.

Preserve this image/boot generation and its success artifacts. It is the rollback destination. Establish a VM serial or equivalent out-of-band console that does not depend on the candidate bus, network manager, or graphical session.

**Exit evidence:** the reference workload is known-good, a rollback image/generation exists, and console access is tested.

## Stage D — Candidate VM boot

Build and boot a VM variant whose service configuration starts only OS-Bus at the intended system-bus endpoint. Use a controlled boot transition; do not attempt an in-place hot swap of accepted client connections.

For a manager-owned listening socket, test inherited-FD adoption through the real release launcher. Validate process/environment/type; do not rebind or unlink the manager-owned endpoint. For any standalone socket mode, prove exclusive ownership and refuse ambiguous pre-existing paths. Readiness must follow usable policy, authority, and listener state, not merely the start of a BEAM process.

Verify the active daemon executable/process, owning unit, actual socket, and bus-instance identity. Detect accidental fallback to the reference daemon, autolaunch, or an isolated test bus. Record independent probes in the artifact bundle.

Boot without web/config/cluster dependencies and without unintended HTTP or distributed Erlang listeners. Confirm installed service policies were loaded unchanged. Unknown required policy or activation features stop qualification rather than being silently excluded.

**Exit evidence:** the intended candidate owns the system endpoint, initial services connect, and readiness/bootstrap are correct.

## Stage E — Workload and failure qualification

Run the same reference workload with the same identities and policy files. Check actual method results, ownership, authorized/denied effects, activation identity, and FD lifetime. A logind inhibitor is a useful real FD workload when enabled in the declared profile; verify both acquisition and release rather than only reading its returned handle index.

Exercise reload under traffic, invalid reload, malformed clients, policy denial, abrupt peer death, slow receivers, service activation failure, and bounded overload. Existing healthy connections must survive client-induced faults. Separately crash a core authority process and verify the documented coherent restart/reconnect behavior; that scenario need not preserve old connection identities.

Measure FD/resource accounting, numeric queue limits, healthy-request latency, and post-quiescence state. Capture workload seeds and exact commands. Do not classify unexpected skips, missing services, or a stopped fault-injection workload as success.

**Exit evidence:** VM-01 through VM-05 as applicable to the declared profile, plus all prior required gates, are actually executed and pass.

## Stage F — Rollback rehearsal

Inside the disposable VM, return to the saved known-good reference boot generation or image using the out-of-band recovery path. Prefer a controlled reboot/snapshot restore rather than pretending existing bus connections can migrate between daemon processes.

Verify that the reference daemon now owns the intended endpoint, the candidate is not a competing system-bus owner, and the original policy/configuration is restored. Rerun the real-service allowed/denied/activation/FD workload after rollback. Retain logs for the candidate failure/cutover, boot selection, restored daemon identity, and workload results.

Perform at least one rehearsal where recovery does not rely on a functioning candidate bus. A written “rollback command” without execution is not VM-06 evidence.

**Exit evidence:** VM-06 passes; artifact paths and the restore procedure are documented. Highest possible program readiness becomes L4 for the stated profile only.

## Stop conditions

Stop qualification on identity mismatch, unauthorized ownership/delivery/activation, missing enforcement, foreign socket removal, unsafe FD handling, unexplained persistent resource growth, inability to distinguish the actual bus backend, or inability to recover the reference VM.

Do not delete a failing workload or lower its required service inventory to pass an already declared profile. A genuinely revised narrower profile must be explicitly versioned and reported as such, with prior claims withdrawn and tests rerun.

## Production handoff, not automatic deployment

The final output should provide a candidate artifact hash, declared profile, gate evidence, unsupported configurations, known risks, and the tested recovery procedure. Actual adoption on the user's machine requires a separate operator decision and deployment-specific review.

Do not promise zero-downtime switching, continuity of existing bus identities across a core reset, or universal Linux compatibility. A passed VM program demonstrates the recorded workloads and security regressions for the recorded environment, not an absence of every possible vulnerability.
