# ADR-006: Activation and headless release bootstrap

Status: accepted implementation direction under the Foundation goal's conservative
design authority. Original architecture qualification was **NOT RUN**; the
2026-10-11 bridge and inherited-lifecycle amendments below have scoped
implementation evidence in STATUS.md. The actual headless production launcher
passes17 private process cases; installed-helper and complete system/runtime
qualification remain **BLOCKED/unqualified**.
Highest verified readiness remains L0. This does not complete P10/P11 or change
any existing mandatory gate.

## Scope and evidence

This decision completes the boundaries in Foundation ARCHITECTURE sections 5,
8–9 for R-03, R-09–R-14, ACT-01–ACT-07 and SYS-03/SYS-04. Keep the pure
`ex_d_bus` library, OTP umbrella, single Router ordering domain, ADR-004 resource
ownership and ADR-005 coherent authority epochs. No database, distributed
authority, web dependency, new privileged daemon, or generic command executor.

Inspected checkout: `codex/os-bus-foundation` at
`7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4`, with extensive inherited uncommitted
work. `Config.Runtime` currently refuses activation settings/limits, validates an
already-correct daemon UID, and supports only pathname listeners. `Listener`
owns/removes its created socket inode; `Router` returns ServiceUnknown for an
unowned call; `Policy.reload_file` rejects changes to its runtime signature.
These were the initial inspection's gaps; subsequent implementation and its
remaining qualification boundary are recorded in STATUS.md.

The retained `test/reports/foundation/p09-profile/{inventory,units-inventory}.json`
records three service directories, 16 service-file occurrences, 15 names and 17
XML occurrences. SYSTEM_PATH wins the duplicate PolicyKit1 entry. Nine systemd
targets exist; home1/network1/oom1/resolve1/sysupdate1 aliases are absent;
systemd1 is PID1, with no SystemdService and Exec=false. Retain absent aliases in
discovery and test their real failure. All service files say User=root; the
polkit unit runs as polkituser UID28. These are different launch paths, not a
reason to force the systemd process to UID0. Bind accounts from the VM's actual
local account database; the loader test's synthetic systemd-oom UID995 is not
deployment identity.

Reference source inspected without execution:

* dbus-daemon 1.14.10 archive
  `/nix/store/3b2k3qfri9kiq7lvjyvg9n2vbdl7ickc-dbus-1.14.10.tar.xz`, SHA256
  `ba1f21d2bd9d339da2d4aa8780c09df32fea87998b73da24f49ab9df1e36a50f`.
  `bus/activation.c`: directory collisions 472–480; pending-entry limits
  1841–1849, 1961–1962, 2054–2055; prelaunch policy 1867–1882; PID1 bootstrap
  1853–1858/2081–2085; systemd signal 2105–2119; helper selection 2216 onwards;
  helper exit mapping 1409–1458; zero exit 1472–1478; timeout 1580–1605;
  failure signal 2412 onwards. `bus/dispatch.c:431–457` applies automatic
  activation before full recipient policy can be evaluated.
* The retained same-version `p09-api04-groups/reference-source/bus/driver.c`:
  StartServiceByName 958–994; ActivationFailure authentication 2991–3037.
* Same archive `bus/activation-helper-bin.c:75–101` and
  `bus/activation-helper.c:146–206,245–366,422 onwards`: fixed helper ABI,
  environment, identity, service lookup and exec semantics.
* systemd 258.3 source
  `/nix/store/0zbx9sz4gnanvf3x78zk5ikryqg29dc4-source/src/core/dbus.c`, SHA256
  `6d71194311217f5bf4ac7315e7ddb3c520b33b7e9b694e6a236ef14ed67546fb`:
  `signal_activation_request` 100–160; signal subscription and asynchronous
  systemd1 name request 792–811. Source evidence is not a VM boot result.

## 1. Privilege and release startup

The system service manager performs the root-to-messagebus transition using
`User=messagebus` and `Group=messagebus` before starting the release. BEAM never
changes process-wide UID/GID. The release checks its real/effective identity
against the resolved XML user (UID4 in the recorded profile); mismatch fails
before acceptance/readiness. Resolve local accounts with bounded failure before
starting routing; do not depend on bus-activated or network NSS providers.

Package a foreground, exec-only launch chain. Every shell wrapper uses `exec`;
the final BEAM PID must equal the original manager-provided LISTEN_PID. Use the
headless release's actual foreground entrypoint, not `daemon`, a detached child,
`mix`, or an environment-variable rewrite to conceal a PID change. The existing
P01 `scripts/foundation/inherited_listener.exs` and launcher probe establish the
shape of the supported OTP27 API, not proof of the final release chain. If a
generated release wrapper forks or closes fd3, replace that packaging wrapper
with an exec-only entrypoint and prove it; do not silently rebind the endpoint.

Declare the candidate as the VM's `dbus.service`, or provide the equivalent
effective alias, with `dbus.socket`, `Type=notify`, `NotifyAccess=main`, foreground
operation and bounded startup timeout. The canonical unit identities matter:
systemd's activator checks whether dbus.service/dbus.socket are stopping. Do not
use Type=dbus/BusName=org.freedesktop.DBus to establish bus readiness. Select
explicit nofork/nopidfile/stderr invocation overrides; journald captures stderr.
These overrides explain the recorded XML fork/pidfile/syslog directives without
silently discarding them. Do not enable NoNewPrivileges if it disables the
already-configured traditional setuid helper; preserve and qualify the existing
profile's privilege boundary rather than silently excluding that launch path.

## 2. Listener handoff, readiness and termination

Represent the startup listener as an exclusive choice:
`{:inherited, 3, expected_path}` or `{:owned_path, path, mode}`. Inherited mode
requires LISTEN_PID equal to the actual BEAM PID, LISTEN_FDS=1 and the packaged
LISTEN_FDNAMES contract (`dbus`); reject extra/missing/wrong descriptors. Adopt
once using public `:socket.open(3, %{dup: true})`, then verify the actual owned
duplicate, AF_UNIX, stream, SO_ACCEPTCONN and the expected getsockname path.
Pinned OTP27 runtime probes found that `dup: false` borrows fd3: public close
and owner death retain the same OS socket inode, and neither duplication mode
sets FD_CLOEXEC. The original borrowed-fd proposal therefore cannot satisfy
descriptor lifetime or close-on-exec. Preserve that failed execution evidence.

After public validation, the existing Unix adapter's bounded ordinary-scheduler
`inherited_listener_handoff/1` verifies that original fd3 and the retained public
duplicate are sockets with exactly the same dev/inode, rechecks both as local
stream listeners, sets and reads FD_CLOEXEC on the duplicate, then closes raw
fd3 exactly once. It preserves other flags and never changes O_NONBLOCK, creates
another descriptor/resource, shuts down the socket or mutates its pathname.
Linux close EINTR is not retried against a possibly reused integer. The adopting
caller owns and retains the public duplicate through the call and cannot finish
exiting while this ordinary NIF runs; trusted startup must not concurrently close
or transfer either descriptor. OTP then owns normal and abnormal cleanup.

Exact environment validation precedes duplication; successful duplication consumes
the activation environment once, before acceptance/readiness/launch. A failed
validation/handoff closes the public duplicate and refuses startup without a
pathname fallback. Any unreleased raw fd3 is reclaimed when permanent release
startup exits; this mode cannot run under an embedded/recoverable listener
restart. Verify exact descriptor identities, owner death and actual flags through
the final packaged launcher. The accepted Peer path remains ADR-004.

Manager-owned listener shutdown **closes only the daemon's copy**: no shutdown,
chmod, bind, inode removal or stale-path cleanup. Owned-path mode retains the
existing inode-checked removal contract. Never treat LISTEN_PID mismatch as
permission to adopt an arbitrary fd or fall back to pathname mode.

After config, account/policy/service snapshots, Limits, authority and listener
are operational, send READY=1 from the main BEAM OS process to NOTIFY_SOCKET
using a bounded Unix datagram operation. NOTIFY_SOCKET can be pathname or Linux
abstract address; this is neither D-Bus nor a shell subprocess. Do not wait for
PID1 to own systemd1, any activated service, or a self-connection to the bus.
Validate required bootstrap facilities before notification; a transient absent
PID1 connection is expected and is handled by bounded activation waiting.

In release mode, an authority epoch failure terminates the release and lets the
manager restart it with a fresh listener handoff. Preserve coherent one_for_all
teardown; an outer release lifecycle observer must not restart only Listener
and attempt to consume the closed fd3 again. Normal stop ends admission, retires
activation/egress resources, closes peers/listener and exits within the unit's
stop timeout. Manager socket lifetime and accepted-connection lifetimes differ;
no connection/name continuity across the restart is promised.

## 3. Discovery, provenance and publication

Compile bounded service discovery alongside policy off the routing path. Keep
all directory/file occurrences and a selected map keyed by validated well-known
name. Retain Name, parsed Exec, User, optional SystemdService, source/hash,
directory index, account resolution and diagnostic provenance. Earlier effective
service directories win; preserve shadowed metadata. Reference same-directory
name collisions depend on directory enumeration (activation.c:472–475); report
ambiguous conflicting definitions as unsupported configuration instead of
claiming a portable winner. The recorded profile has no such conflict.

Bound directory entries, file bytes, string lengths, parser work and total
inventory before publication. Validate system service filenames/Name and required
fields against the supported reference contract. Keep missing systemd targets as
discoverable services whose activation can fail. Do not execute Exec=false as a
fallback for an absent SystemdService target.

Fix R-10 by attaching `{file, line, element, occurrence, include_chain}` to every
effective setting/limit/service decision and retaining shadowed occurrences.
Runtime refusal must carry the directive's provenance, including failed account
binding. A successful parse with an unsupported runtime consumer is not startup
success.

Publish one immutable configuration generation containing policy, service index
and account snapshot, committed through Router's ordering boundary. Reuse the
existing policy authority; do not build a competing registry or publish several
independent ETS updates. Reads use one generation for a decision. Invalid reload
keeps all old components. Runtime identity/listener/helper mode and other
non-reloadable settings remain restart-required, with provenance. Within that
boundary ReloadConfig refreshes service discovery and policy together; list
results change only after commit. The traditional helper's fixed configuration
must resolve the same service directories and user as the bus. A differing helper
configuration is unsupported, not an environment override opportunity.

For the recorded profile, service bodies and directory targets are immutable Nix
store objects. New generations can select newly built objects. A name-only helper
does not accept a content hash and independently rereads trusted configuration;
do not claim hash-bound cross-process launch atomicity for arbitrary mutable
service trees. Qualify the installed helper/configuration pairing at startup and
reload; changes that cannot preserve that pairing require restart. Root-owned
configuration publication is an operator trust boundary, never client input.

## 4. Launch backends

### systemd

When systemd activation is selected and an entry has SystemdService, produce
exactly a directed signal with sender `org.freedesktop.DBus`, destination
`org.freedesktop.systemd1`, path `/org/freedesktop/DBus`, interface
`org.freedesktop.systemd1.Activator`, member `ActivationRequest`, signature `s`
and body `[selected_unit_name]`. It is an authority effect, not an external
client with a forged sender. Deliver through the normal bounded routing/policy
boundary, including relevant recipient policy. No match rule is necessary for
a directed signal. Do not substitute Manager.StartUnit: its caller and policy
semantics differ.

If PID1 has not connected, retain one bounded dependency on systemd1 and wait
for its authorized name acquisition. Never exec its service file's false command
or attempt to start another PID1. Pending unit requests are flushed through the
current owner after acquisition. The bus reports readiness first, allowing PID1
to connect without a circular readiness dependency.

systemd queues a JOB_START/JOB_REPLACE and sends no success reply. Name acquisition
is bus activation success. Failure is a directed signal to org.freedesktop.DBus,
path `/org/freedesktop/systemd1`, same Activator interface, member
`ActivationFailure`, signature `sss` containing unit/error-name/error-text.
Accept it only from the current authenticated owner of systemd1, with required
privileged-caller and XML permissions, and only in systemd mode. Validate bounded
arguments. Fail matching pending unit requests; ignore unrelated/forged signals
without manufacturing replies to signals. The wire has no request token:
correlation is by unit/current owner/epoch, not an invented per-attempt ID.

### Traditional Exec/User

Reuse the configured, already-installed `dbus-daemon-launch-helper` and its
existing profile trust boundary. Invoke a regular unprivileged packaged bridge
through OTP's `spawn_executable` Port interface with exactly one argument: the
validated well-known service name. The bridge's build-time absolute helper
binding invokes that existing entrypoint with the same single name argument.
The ABI accepts no caller-chosen executable, UID, argv,
configuration path or environment override. The helper independently reads its
fixed system configuration, checks the invoking real UID against the configured
bus account and effective UID0, resolves Name/Exec/User, resets supplementary
groups/GID/UID and uses parsed argv with execv. It does not invoke a shell.
Do not implement a new setuid OS-Bus helper or grant BEAM root privileges.

The retained pinned OTP27 Port probe could not combine reliable external exit
notification with a bound on service output before worker mailbox enqueue.
The 2026-10-11 amendment therefore adds one unprivileged bridge per reserved
launch, without a new privilege transition. Its child receives empty environment
and `/dev/null` standard I/O; supported Linux close_range closes every inherited
descriptor except a private CLOEXEC setup-error pipe. Unsupported closure fails
closed. The bridge waits for its exact direct child and emits one16-byte GHBv1
record: magic/version, kind, stage, reserved zeros and a big-endian uint32 value.
It distinguishes proved no-start, exec failure after reaping, numeric exit,
actual signal and observation failure. It disables core dumps and dumpability;
services receive no status-channel writer. The build defaults to an unbound
helper and returns proved NOT_STARTED without forking. Actual installed-helper
binding, trust/identity checks and canonical-address behavior remain VM gates.

Run launch Ports in monitored bounded workers, never in Router callbacks. Supply
no message FDs/listener/NOTIFY_SOCKET or activation environment to children; prove
actual FD closure across Port/helper/exec. Preserve structured spawn/exit errors;
map documented helper exit codes using activation.c:1409–1458. Exit0 before name
acquisition continues waiting, because a daemonizing service can exit its initial
process. Neither successful exec nor a zero exit is name readiness. Preserve the
pure `Helper.command/2` installed-helper ABI planner; the worker separately plans
the bridge. Worker accumulation is capped at16 bytes, while the native writer
contract and FD closure establish the bound before mailbox enqueue. Require the
complete valid record and normal bridge/Port/worker lifecycle before reclaiming
an observed launch slot; exit137 never means an observed SIGKILL.

The production helper clears environment and hardcodes the system address. Real
helper tests therefore run at the canonical address **inside a disposable VM**.
A host-private address override does not test this ABI. Unit adapters may model
outcomes but cannot satisfy ACT-05. The polkit systemd path follows unit identity;
the traditional path follows service User and any subsequent service-owned drop.
Verify actual connection credentials independently in both cases.

Do not pretend closing a Port cancels a privileged daemon. Retain a bounded
live-child/launch record until reliable child termination and completed observer
lifecycle. Verified ownership can retire the per-name barrier but cannot release
the global charge of a live or uncertain child. A timed-out unresolved child
cannot justify unlimited replacement spawns: retain its per-name tombstone and
finite global child ceiling. Observer loss drains local waiter leases, marks
the separate child record uncertain and retains its charge until the manager
proves the old release cgroup empty. Deadline, reload, ownership and stale
completions cannot establish termination. Do not send signals to a recycled PID or stop systemd services
when one caller disappears. The VM unit's bounded cgroup shutdown is the final
process-containment boundary; exact termination behavior remains a required test.
The current in-process core restart loses external-child accounting. Production
Runtime activation remains refused until P11 implements and verifies release
fail-stop and cgroup cleanup before fresh admission.

## 5. Authority, admission and pending work

Router owns caller incarnations, ordering, authorization and the commit of an
activation request. A supervised activation coordinator owns launch attempts,
timers and waiting message resources. Workers own external Port operations.
Coordinator failure participates in the coherent authority epoch; workers do
not synchronously call Router while Router waits for them.

The internal reservation interface takes epoch, request ID, caller incarnation,
serial/type/flags, destination, generation, absolute monotonic deadline and an
owned message-resource lease. It returns either bounded admission or a terminal
error. Use Limits reservation **before** sending any enqueue message; a cast into
an unbounded mailbox is not admission. Completion events carry epoch/attempt
tokens and contain no authority decision. Duplicate/old completions retire only
their own resources.

* Explicit StartServiceByName follows the reference bus-method permission and
  argument contract; do not add a universal root requirement or invent a target
  method for its authorization. Return ALREADY_RUNNING=2 or eventual SUCCESS=1
  at the corresponding ownership decision.
* Automatic activation evaluates the original message's send/activation policy
  against the selected unowned destination before launch; full receive policy
  waits for a real recipient. Cover all reference-eligible directed traffic,
  including signals, not just calls. Unique names and broadcasts are not launch
  targets. NO_AUTO_START prevents automatic launch/queue participation; it does
  not disable an explicit StartServiceByName method. NO_REPLY_EXPECTED suppresses
  error/result generation while retaining necessary delivery/resource handling.
* Coalesce launches per destination; also avoid duplicate simultaneous systemd
  requests for the same unit. Each admitted waiting entry is charged: reference
  max_pending_service_starts counts entries, not distinct service names. Reserve
  finite per-peer/UID/global message counts, bytes, FDs and live-child work as
  additional safety limits. PID1 bootstrap work is bounded and accounted too.
* The first attempt sets an absolute service_start_timeout; joining callers
  cannot extend it. Each waiter retains its own earlier deadline/cancellation
  bound. Preserve reference timeout and error names (activation timeout is
  TimedOut); keep zero-limit semantics evidence-led. Do not replace an XML limit
  with an undocumented convenient constant.
* On name acquisition, ask Router to resolve the current owner and take the
  current config generation in the same ordered delivery decision. Recheck
  source incarnation, send/receive/FD permissions, owner incarnation and egress
  budget. Ownership is established by normal authorized RequestName; a name
  winner need not have the launch worker's PID. Do not compare systemd owner UID
  blindly with the traditional service-file User field.
* Reserve requested-reply state against the actual callee only when forwarding;
  activation waiters have their own reservations and duplicate-serial protection.
  Transfer accounting without a gap or double reservation leak. Do not replay
  already-committed bytes after an owner change.
* Reload does not retarget a started attempt to a new executable/unit. Requests
  already waiting retain their attempt identity; current policy governs every
  later launch commit/delivery. Recheck queued, not-yet-issued launches after a
  generation change and cancel denied callers. An issued external launch cannot
  be undone by revoking message permission. New requests use the current service
  definition; a changed definition cannot launch in parallel behind an unresolved
  old per-name attempt. Terminate that new request with a documented retryable
  failure until the old attempt resolves; test this conservative race outcome.
* Caller death retires its waiter/FDs/credits once; other callers continue. Last
  waiter removal cancels unissued work. For issued work retain only the bounded
  attempt/child tombstone until deadline/exit/ownership, not caller message data.
  Timeout, denial, failed exec, failed delivery and epoch teardown release every
  local FD lease and credit. Transfer ownership before acknowledging ingress
  completion; never retain the original bundle after Router has closed it.

Bound drains per turn so name acquisition or a failed unit with many waiters
cannot starve healthy traffic. Error queues and diagnostics consume budgets too.

## 6. Alternatives and implementation order

Root BEAM with in-process setuid would make privilege transitions global across
VM threads and enlarge the trusted runtime. A new privileged generic launcher
would duplicate the configured helper. Using StartUnit or replacing all Exec
entries with generated units would change the recorded compatibility contract.
All three are rejected. Retaining the existing helper costs a packaging/config
alignment requirement and real-VM qualification. An exec-only release limits
launcher flexibility but makes inherited FD/PID ownership verifiable.

Implementation returns to the Sol coordinator in these dependency slices:

1. Add directive provenance, complete trusted account binding, and bounded service
   discovery with retained precedence tests. Implement immutable candidate
   publication/reload; retain all installed policies and missing-target metadata.
2. Add pure activation transitions and Limits/message leases; test coalescing,
   entry limits, deadlines, flags, caller exit, owner/reload races and cleanup.
   Connect Router and bus methods with failing regressions first.
3. Add systemd signal backend and bounded helper Port workers with exact source
   error contracts. Add the required dedicated activation/FD fixture to the
   actual VM profile and regenerate its inventory; do not remove any service.
4. Package the foreground headless release, systemd user/units, inherited listener
   mode, readiness and epoch termination. Repeat the P01 handoff proof through
   the final release, including PID/FD identity, wrong descriptors, manager socket
   preservation and absence of inherited FDs in activated children.
5. Capture a new immutable candidate and run paired reference/candidate activation
   and boot qualification in disposable VMs. Complete full installed policy/API
   and existing security/FD gates, real systemd/logind/polkit/fixture workloads,
   resource recovery and rollback. Preserve candidate08 and earlier evidence.

Acceptance requires ACT-01–ACT-07 and SYS-03/SYS-04 without skips, exact selected
actors, actual identities and wire/effect evidence. Include PID1 connecting after
READY, forged ActivationFailure, absent aliases, helper denied identity, helper
exit0 without a name, helper timeout with a live child, service changes during
reload, FD-bearing activation failure and concurrent healthy traffic. Full P11
and M4 still require their other SYS/VM gates. P07 queued-repeat and P09
optional-INTERFACE mandatory failures are unchanged. Registered-Peer FD04 is
not audited by this ADR. All implementation/runtime acceptance checks above are
**NOT RUN** in this documentation assignment; no readiness promotion is implied.
