# Verification strategy and regression matrix

## 1. Rules for qualifying evidence

A test counts only when its intended actor actually runs against the intended backend/configuration and checks the observable requirement. Existing E2E-001–E2E-020 remain in the matrix; the new IDs below extend rather than renumber them. IDs are stable requirements for implementation, not claims that test files already exist.

Use three complementary layers: pure-function/property tests; isolated black-box protocol tests with independent clients; and disposable Linux VM system tests. Test OS identities and process-wide FD behavior outside the test runner's own bus process. Keep ordinary developer convenience separate from release qualification.

For each selected required `(scenario, backend, actor, profile)` combination, record `passed`, `failed`, or `blocked`. A legitimate out-of-scope combination is excluded by a versioned selection manifest **before** execution; it is not an ad hoc known-gap skip. Mandatory missing actors/backends, unexpected skipped cases, zero selected execution, and backend startup failures make the gate fail. Gao-specific fault injection need not be falsely applied to the reference daemon; declare that applicability explicitly and retain its mandatory Gao result.

Pin and record the reference daemon version, config bytes/hash, users/groups, service inventory, runtime versions, and feature selection. Use the same input and policy wherever comparison is meaningful. Normalize inherently varying identifiers into participant roles, but do not normalize away ordering, sender identity, denial, delivered contents, ownership, or activation side effects. Where the specification permits variation, assert an allowed invariant and document it rather than requiring identical diagnostic prose.

A bus that starts, a green CI status, or matching encoder/decoder round-trips do not establish these properties. Source findings from the review must become executable regressions or have a documented evidence-based disposition.

## 2. Harness and strict selection

| ID | Required scenario | Passing evidence |
| --- | --- | --- |
| H-01 | Baseline includes existing unit/interop/E2E suites and records actual selection. | Exact commands, counts, versions, and pre-existing failures saved; no claim that excluded E2E ran. |
| H-02 | Deliberately omit a required actor, fail a backend probe, and select an empty gate. | Each condition fails strict qualification rather than returning green or an unnoticed skip. |
| H-03 | Run independent raw-protocol and multiple real-UID actors on isolated sockets. | Actor identity verified externally; no mocked production UID, no implicit host bus address. |
| H-04 | Exercise artifact capture, fixture timeout, and teardown after test-runner failure. | Child daemons/fixtures/resources are reaped; selected and executed IDs, logs, config hashes, and seeds are retained. |

## 3. Authentication, authorization, and containment

Run identity-sensitive rows as a non-root client against the isolated system-mode daemon, with a concurrent already-registered healthy observer. Run the independent reference comparison where supported by the selected configuration.

| ID | Required scenario | Passing evidence |
| --- | --- | --- |
| SEC-01 | Valid EXTERNAL authentication through independent GLib and sd-bus/libdbus clients; fragmented and pipelined exchanges. | Clients complete Hello; returned identity agrees with independently known kernel identity. |
| SEC-02 | Non-root client asserts UID 0 or another user's identity. | No admission as that identity, no privileged ownership/call, and no fabricated root credential record. |
| SEC-03 | Empty, malformed, out-of-range, and noncanonical asserted identities; bare AUTH and DATA variants. | Valid standard flows remain valid; bad assertions never grant identity or crash the daemon. |
| SEC-04 | BEGIN before successful authentication, after rejection/cancellation, or after an unsupported mechanism. | No entry into normal bus operations; observer remains connected with unchanged names. |
| SEC-05 | ANONYMOUS and early/invalid FD negotiation in system mode. | No anonymous system-bus admission; negotiation only succeeds in an allowed authenticated state. |
| SEC-06 | Real/simulated adapter failure retrieving required kernel credentials; unavailable metadata. | Connection rejected or required operation denied; no asserted-UID or zero-value fallback. |
| SEC-07 | Oversized/incomplete authentication lines, repeated failures, slow trickle, and handshake expiry. | Bounded bytes/work/time/connections; offending peer closes and healthy observer remains serviceable. |
| SEC-08 | Own a forbidden system name as an ordinary UID and as a service UID. | Access denied before mutation; no unauthorized owner/queue entry or ownership signal. |
| SEC-09 | Denied send through a well-known destination, its unique name, and alternate owned aliases. | Outcome agrees with the configured reference policy; no identity/alias bypass. |
| SEC-10 | Sender allowed but receiver policy denies; include a signal and a reply where applicable. | No delivery; sender/receiver semantics match the same reference policy. |
| SEC-11 | Denied connection admission, privileged bus method, or config/activation control. | No unauthorized side effect or privilege acquired merely by addressing the bus object. |
| SEC-12 | Attempt unauthorized eavesdropping, monitoring, or access to internal payload diagnostics. | No private payload disclosure; unsupported monitoring is rejected and not advertised. |
| SEC-13 | No policy at startup, unavailable evaluator without a valid snapshot, and policy-process restart. | No fail-open path. A deliberately retained valid immutable snapshot is distinguished from absent policy; core reset is coherent if required. |
| SEC-14 | Structurally valid Bus calls with wrong body count/type/signature/path/interface. | Controlled error according to contract; same Router/healthy connection remains operational; no state mutation. |
| SEC-15 | Malformed frame designed to reach a former body-pattern-match crash. | Frame rejected before authority dispatch; no global peer restart or lost healthy ownership. |
| SEC-16 | Pre-Hello operations, repeated Hello, forged sender, and reordered registration input. | No premature privileges; stable registration identity; reply/signal sequencing and errors are correct. |
| SEC-17 | Crash/kill a peer while it owns names, queued requests, match rules, capabilities, and resources. | Idempotent monitored cleanup; no stale authority or leaked rights; unrelated peers survive. |

## 4. Wire and registration conformance

| ID | Required scenario | Passing evidence |
| --- | --- | --- |
| PRO-01 | Every split point in representative authentication/Hello/frame streams; several complete frames per read. | Same semantic sequence independent of fragmentation/coalescing; no buffered bytes or FDs are lost. |
| PRO-02 | Invalid version/type/serial/required header fields and valid unknown extension cases. | Invalid input rejected; required forward-compatible ignoring/filtering preserved; no blanket extension rejection. |
| PRO-03 | Duplicate/wrong-typed headers, mismatched signatures, invalid strings/paths, and invalid padding/containers. | Explicit terminal errors; no empty-body success or core crash. |
| PRO-04 | Truncated and oversized advertised lengths, missing body signature, and trailing body bytes. | Correct incomplete-versus-invalid distinction, exact frame consumption, pre-allocation bounds, eventual deadline closure. |
| PRO-05 | Deep signatures/containers, large collections, repeated invalid prefixes, and adversarial match argument values. | Work/memory/atom counts bounded; no arithmetic, pattern-match, or string-function crash in authority. |
| PRO-06 | Independent little-/big-endian corpus, variants, structs, arrays/dictionaries, and FD-index values. | Cross-implementation semantic equivalence; not only an ExDBus self-round-trip. |
| PRO-07 | Generated valid/invalid messages and stateful sequences with deterministic seeds. | Reproducible minimized counterexamples added as regressions; total validators return explicit results. |

## 5. Names, signals, subscriptions, and replies

| ID | Required scenario | Passing evidence |
| --- | --- | --- |
| SEM-01 | Current owner repeats RequestName with changed flags; queued requester repeats it. | Correct flag updates and response codes, no duplicate queue entry. |
| SEM-02 | Replacement with several waiters, including a replaced owner with DO_NOT_QUEUE. | Exact queue transition and ownership signals agree with the reference behavior. |
| SEM-03 | Release a queued request; disconnect owner/waiter; race release with disconnect. | Correct promotion and cleanup; no stale or duplicate ownership. |
| SEM-04 | Reserved, malformed, unique, and bus-self names; GetNameOwner/NameHasOwner/ListQueuedOwners. | Correct validation and lookup results; reserved bus authority cannot be acquired by a client. |
| SEM-05 | Hello and ownership transitions while observers subscribe. | Required unicast/broadcast signals go to correct recipients in valid causal order; Hello reply is not overtaken improperly. |
| SEM-06 | No match rules, nonmatching rules, and matching broadcast rules. | No-rule/nonmatch peers receive no broadcast; matching peers receive the expected signal. |
| SEM-07 | Well-known sender match across name acquisition, release, and replacement. | Match follows correct live ownership rather than literal comparison with a unique sender string. |
| SEM-08 | Quoting/escaping, namespaces, typed arguments, invalid keys, duplicate AddMatch/RemoveMatch, and quota exhaustion. | Correct grammar/duplicate accounting and errors; no partial subscription mutation or parser crash. |
| SEM-09 | Directed signal without a match rule; optional privileged monitoring. | Legitimate unicast delivery is not broken by broadcast filtering; monitor authorization/capability claims remain accurate. |
| SEM-10 | Replies from wrong callee, after owner replacement, duplicate/stale replies, and repeated serials on different connections. | Requested-reply authorization is bound to correct connection incarnations and cannot be hijacked. |
| SEM-11 | NO_REPLY_EXPECTED, NO_AUTO_START, call errors, send failure, timeout, and caller/callee disconnect. | Appropriate output only; no spurious reply/activation; pending-call budget reclaimed. |
| SEM-12 | A reference policy explicitly permits or denies unsolicited responses. | Compatibility follows the configured semantics rather than a new unconditional allow or unconditional deny. |

## 6. Real FD ownership and transport

Use independent native fixtures which can both inspect and use the received resource. Validate daemon-process descriptors externally, not solely via counters implemented by the code under test.

| ID | Required scenario | Passing evidence |
| --- | --- | --- |
| FD-01 | Transfer a pipe, regular file/memfd, and Unix socket using the selected OTP/helper implementation. | Receiver actually reads/writes/uses the intended resource; adapter owns and closes arbitrary descriptors correctly. |
| FD-02 | Rights arrive with a partial header/body, followed by later bytes; test each relevant boundary. | Frame receives its intended descriptor bundle after reassembly; no loss when the first decode returns incomplete. |
| FD-03 | Consecutive frames with different rights, mixed FD/no-FD messages, and coalesced input. | No descriptor is attached to another message; counts/index mapping remain correct. |
| FD-04 | Control truncation, wrong advertised count, invalid index, excess descriptors, and resource-bearing auth input. | Safe terminal rejection; all received daemon-owned resources reclaimed, including unassociated rights. |
| FD-05 | Send a resource-bearing message to a recipient without FD negotiation. | Explicit correct failure/disposition; never a header claiming resources that were silently stripped. |
| FD-06 | Force short writes and repeated writable notifications with a slow reader. | Exact byte stream and exactly the intended ancillary transfer; no duplicate rights on continuation. |
| FD-07 | Denied message, missing destination, failed activation, closed recipient, and send error. | All descriptor/queue references and budgets retired; independent leak check passes. |
| FD-08 | Source exits after enqueue; recipient exits during partial send; peer/resource-owner failure. | Defined completion/cancellation without use-after-close, double-close, or leak; healthy destination cannot receive a recycled unrelated FD. |
| FD-09 | Authorized resource-bearing fan-out to multiple recipients; one recipient stalls/exits. | Each authorized recipient gets correct resources; one path's cleanup does not invalidate another. |
| FD-10 | Repeated transfer/failure batches and service launch while rights are held. | No unexplained persistent FD growth; CLOEXEC/launch isolation prevents unintended inheritance. |

## 7. Resources and failure domains

| ID | Required scenario | Passing evidence |
| --- | --- | --- |
| RES-01 | Per-peer, per-UID, and global connection/authentication/name/match limits at N and N+1. | Boundary enforced before allocation/admission; counters remain consistent on denial and cleanup. |
| RES-02 | Fast producer and slow recipient; bounded ingress, egress, frame bytes, and pending requests. | Limits constrain actual queues/mailboxes/resources, not just a secondary bookkeeping structure. |
| RES-03 | Burst of malformed traffic and diagnostic events with a concurrent healthy probe. | Bounded logs/cardinality/observer queues; health probe remains within the declared test deadline. |
| RES-04 | Large broadcasts, many matches, and repeated queued calls under concurrent healthy requests. | Work per scheduling turn is bounded; control/cleanup/other peers are not starved. |
| RES-05 | Repeated churn, denials, timeout/cancel, and disconnect batches after warm-up. | Reservations return exactly once; no unexplained monotonic FD/name/match/reply/atom/resource growth. |
| RES-06 | Freeze qualification workload and run a sustained soak against the packaged release. | Saved numeric ceilings, samples, healthy latency, and completion counts demonstrate bounded behavior for that workload. |
| FAIL-01 | Abrupt peer failure, including termination paths that do not run normal cleanup callbacks. | Monitors/resource ownership reclaim all authoritative state; surviving peers stay registered. |
| FAIL-02 | Socket transfer/startup failure and second listener instance on an occupied path. | Incomplete peer/socket closed; incumbent listener/path and its clients are unchanged. |
| FAIL-03 | Deliberately crash a core authoritative process. | Documented epoch/reset/reconnect behavior; no live connections using stale authority or policy; no false claim of seamless continuity. |
| FAIL-04 | Crash optional observer/UI/config service and attempt cluster-enabled startup in the minimal profile. | Bus runtime does not depend on those services; production configuration refuses an unsupported insecure combination. |

### Numeric resource qualification

Before final qualification, check in a workload/limits manifest with actual numeric values: connection counts, active senders/receivers, message sizes, rights per message, max rules/names/requests, queue byte/count ceilings, memory ceiling, healthy-probe deadline, duration, and random seed. Values are engineering parameters for the declared profile, not protocol constants or universal performance promises.

Use at least three post-warm-up batches of 1,000 transfer/churn/failure operations for leak testing, alongside independent healthy clients. For a full sustained run, use at least a ten-minute bounded workload; keep a shorter deterministic PR variant as well. These are prescribed test workloads, not estimates of how long implementation will take.

Account for runtime warm-up and GC before interpreting memory; persistent FD/state leaks cannot be dismissed as GC noise. Save external FD counts and explain any legitimate baseline change. Unexplained post-quiescence resource growth fails the gate. Freeze thresholds before the qualifying run; changing them requires a recorded compatibility/capacity rationale and rerunning the affected tests, not simply raising them until green.

## 8. Policy, APIs, and activation

| ID | Required scenario | Passing evidence |
| --- | --- | --- |
| POL-01 | Load the pinned profile's complete effective XML/configuration inventory. | Inventory/hash and supported directives recorded; no removed policy files or broadened substitutes. |
| POL-02 | Ordered overlapping allow/deny rules for default, users/groups, ownership, send/receive, and replies. | Same effective decisions as reference for independently verified identities. |
| POL-03 | Included files/directories, precedence, missing files, cycles, invalid XML, and unknown security/activation directives. | Correct supported behavior; otherwise clear validation failure with provenance, not silent acceptance. |
| POL-04 | Known DOCTYPE, attempted network/external-entity expansion, deep includes, and oversized config. | Normal installed files load without DTD network access; malicious expansion is rejected/bounded. |
| POL-05 | Valid policy reload under concurrent calls and ownership changes. | Readers observe coherent generations; caches cannot preserve an obsolete unauthorized grant. |
| POL-06 | Invalid reload and unavailable initial config. | Reload retains valid policy; invalid initial state does not report ready or accept privileged work. |
| POL-07 | Required MAC directives/security metadata on supported and unsupported deployment profiles. | No fabricated label, disabled enforcement, or unsupported-profile success claim. |
| API-01 | UID/PID/credential queries for unique/well-known/bus names and vanished connections. | Correct live identity and errors; no PID-reuse substitution or asserted credential leakage. |
| API-02 | Peer.Ping/GetMachineId, GetId, introspection, Properties, and unsupported methods/features. | Real implementations and accurate advertised feature set; machine ID and bus-instance ID are not conflated. |
| API-03 | Privileged reload/monitor/environment-control requests from ordinary and authorized actors. | Policy-appropriate effect/error; disabled capabilities not falsely advertised. |
| API-04 | Account groups differ from process groups; peer exits while metadata is queried. | Documented trusted group/snapshot semantics and race-safe failure; no privilege granted from stale process metadata. |
| ACT-01 | Unowned activatable destination receives an allowed call or StartServiceByName. | Exactly the intended service starts; caller receives correct eventual response and owned-name identity. |
| ACT-02 | Several callers request the same service; requests include NO_AUTO_START. | Coalesced authorized launch, correct no-start behavior, bounded independent deadlines. |
| ACT-03 | Denied call/activation or launch identity violation. | Service never starts under an unauthorized/default root identity; no queued unauthorized delivery. |
| ACT-04 | Service missing, Exec failure, timeout, service exits before name acquisition. | Correct error/disposition and full queue/pending-call/FD cleanup. |
| ACT-05 | SystemdService activation and traditional Exec/User entries required by the profile. | Correct bootstrap path, identity and name readiness; no shell interpolation or circular bus startup wait. |
| ACT-06 | Name acquisition race, policy reload while activating, and caller exit. | Actual destination/current policy used at delivery; obsolete callers/resources retired. |
| ACT-07 | Service-file precedence/listing/config reload and activation request flood. | Correct selected service and ListActivatableNames, bounded launch work and diagnostics. |

## 9. Lifecycle and real VM qualification

| ID | Required scenario | Passing evidence |
| --- | --- | --- |
| SYS-01 | Inherit a real listening Unix FD through the final release startup chain. | PID/environment validation, correct socket type, usable listener, descriptor ownership and no child leakage. |
| SYS-02 | Existing foreign socket, symlink/non-socket path, stale ambiguous path, and shutdown. | No deletion of another instance's endpoint or unrelated file; only owned endpoints are removed. |
| SYS-03 | Minimal release startup/shutdown without Phoenix/config/cluster. | Ready only after policy and authority are usable; no unexpected HTTP/distribution listener or bootstrap dependency. |
| SYS-04 | Wrong/missing inherited FDs, invalid config, activation-bootstrap fault, and restart. | Safe failure or documented standalone mode; no misleading readiness or daemon-owned unlink of manager socket. |
| SYS-05 | Reload, graceful stop, restart with manager-owned listener, and finite shutdown timeout. | Correct cleanup and observed reconnect behavior; listener ownership and bus epochs remain coherent. |
| VM-01 | Boot identical pinned reference and OS-Bus variants and run independent probes. | Actual daemon identity/socket verified; no test silently talking to the reference bus or a private substitute. |
| VM-02 | Real systemd API, logind session/identity operations, and polkit allowed/denied requests. | Unmodified services work and deny appropriately for multiple real UIDs; not just ListNames success. |
| VM-03 | Real automatic activation and FD workload, including a logind inhibitor descriptor where supported by the chosen profile. | Correct service identity/authorization and usable/closed FD; limits/resources recover. |
| VM-04 | NetworkManager virtual-device workload in the declared network profile. | Authorized operations work, denied operations remain denied, and reference/OS-Bus behavior is compatible. |
| VM-05 | Policy reload, faulty clients, overload, service failure, and bus-core restart in the full VM. | Correct containment or documented reconnect/recovery, no policy bypass or resource leak. |
| VM-06 | Candidate → known-good reference rollback using a boot generation or snapshot. | Reference endpoint/daemon confirmed; same workload and denial checks pass after rollback; artifacts retained. |

VM-04 is mandatory before claiming the network profile. In a core-only profile it is explicitly out of scope, never counted as a passing network test. All core-profile VM rows must execute; lack of virtualization is a release blocker, not an accepted skip.

## 10. CI gate contract

| Gate category | Required contents | Trigger policy to implement |
| --- | --- | --- |
| Existing regression | Formatting/compile/static checks and original unit/E2E matrix. | Every relevant PR/local change set. |
| Security | H, SEC, affected PRO, basic RES/FAIL/SYS; both positive and negative identity cases. | Required Linux PR job. |
| Conformance | Full PRO/SEM/API and existing E2E against both backends where applicable. | Required before M2/M3 acceptance. |
| FD/resource | Real FD fixtures, fault paths, deterministic bounds; sustained run separately identified. | Required before M2 acceptance; sustained run scheduled/manual. |
| System integration | POL/ACT/SYS with the pinned system profile and actual release. | Required before M3 acceptance. |
| VM qualification | VM matrix, real-service artifacts, and rollback. | Required before M4/readiness claim. |

New gates must be wired through selector parsing, manifest generation, workflow jobs, required-result aggregation, and documentation together. Do not add a workflow job that selects no cases. If repository branch protection cannot be changed from this task, document the exact checks the operator must require; do not mutate repository settings automatically.

## 11. Artifact and final-report schema

For each run save: UTC timestamp; actual source SHA/dirty state; OS/kernel/runtime/reference versions; profile and config/service hashes; command and working directory; selected/executed/passed/failed/skipped/blocked counts; scenario/backend/actor IDs; error and readiness events; generated fixture logs; deterministic seeds; FD/resource/time-series samples; and VM boot/rollback logs where applicable.

Use bounded artifacts and generated test payloads; do not collect private host traffic or secrets. Preserve red-to-green evidence for newly fixed regressions when available. A test already fixed in the current checkout needs verified passing evidence and source disposition, not an artificial reintroduction of the vulnerability.
