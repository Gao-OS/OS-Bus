# Architecture and implementation constraints

This is a target architecture, not a claim that these facilities already exist. Preserve working repository boundaries. Suggested module names describe responsibilities; adapt them when an existing module already provides a suitable abstraction.

## 1. Runtime and trust boundary

The minimal release contains the protocol library, bus authority, Unix transport support, configuration/policy loading, and activation/lifecycle integration. It must not require Phoenix, LiveView, `gao_config`, cluster routing, a database, or a network service for startup or authorization.

| Boundary | Owner | Contract |
| --- | --- | --- |
| Accepted Unix socket → peer | Transport/credential adapter | Obtain real credentials before admission; establish sole I/O/resource ownership. |
| Authentication → registration | Peer state machine + bus authority | Accept protocol transitions only from their valid states; normal operations require completed Hello. |
| Validated frame → authority | Bounded ingress channel | Only structurally validated, identity-stamped input; no arbitrary in-VM peer impersonation API exposed externally. |
| Authority → destination | Policy + routing + bounded egress | Resolve recipient and check permissions before an effect is committed; preserve per-connection order. |
| Config files → policy generation | Loader/compiler | Validate complete candidate off the hot path; atomically publish immutable rules. |
| Name activation → service manager/helper | Activation supervisor | Authorized, bounded, asynchronous work with a reliable bootstrap path. |
| Bus → diagnostics | Bounded observer interface | Default metadata only; no full payload feed that bypasses authorization. |

`gao_config` becomes an ordinary client service, not a bootstrap dependency. A future monitoring UI should use a privileged, explicitly authorized interface, preferably from a separate OS process. During this program, disabling the optional UI in the headless release is sufficient; redesigning the UI is not required.

## 2. Pure state transitions with explicit effects

Separate validation and decision logic from effects. Authentication parsing, bus-method argument validation, name queue transitions, match-rule parsing, policy evaluation, and routing decisions should return explicit success/error results and intended effects.

Processes own state and apply effects; they do not rely on exceptions for expected hostile input. A match on an untrusted body is permitted only after a validator has established the method contract. Broad `rescue` around the Router is not a substitute for correct validation or consistent state mutation.

Keep a single logical authority for ownership/registration ordering until evidence justifies further partitioning. Do not add sharded routers or distributed consensus to solve an unmeasured performance concern. Avoid synchronous cycles among Router, Peer, NameRegistry, and cleanup callbacks. Peer input must never make the authority wait for that same peer's socket writer.

Registration is an atomic externally observable transition: credentials, policy context, unique name, and peer index become usable together. Ensure Hello's reply and the relevant bus signals cannot be reordered by self-casts or races with subsequent calls. Maintain a connection incarnation identifier independent of a recycled OS PID.

## 3. Peer identity and authentication

Use separate phases corresponding to accepted socket, authentication exchange, authenticated negotiation, binary protocol awaiting Hello, registered connection, and closing. This is a conceptual model; implement the exact legal authentication transitions from the protocol rather than substituting these labels for the specification's state machine.

At acceptance, construct an immutable credential record from supported kernel facilities. Preserve identity provenance and distinguish unavailable data from numeric zero. For Linux system mode, inability to obtain the required credentials rejects the connection. Never fall back to an asserted UID or a permissive test identity.

If supplementary groups or process metadata are needed, distinguish account-database membership from the connected process's group state. Prefer appropriate kernel facilities; when process inspection is unavoidable, defend against process exit/PID reuse and document the snapshot semantics. Do not assume a later `/proc/<pid>` read describes the original peer. Missing required information must not produce an allow decision.

Authentication text is checked against this identity. Parsing failure, unsupported mechanisms, cancellation, premature BEGIN, and early FD negotiation follow a tested transition table. Retain valid fragmented/pipelined exchanges. Bound total authentication bytes, individual lines, unsuccessful exchanges, and absolute/idle deadlines. Production system mode does not expose ANONYMOUS.

After authentication, binary messages are still subject to registration restrictions. Enforce sender identity at ingress from the registered connection; sanitize untrusted sender/extension headers according to the supported protocol behavior. Do not globally reject unknown flags or headers where the specification requires ignoring/filtering them. [S1]

## 4. Validation and framing

Create a framing/validation boundary that distinguishes three outcomes: a complete valid message, an incomplete message needing more input, and a terminal protocol violation. The result must include exactly consumed bytes and a resource-safe continuation state.

Inspect fixed lengths before allocating or recursively decoding. Validate the advertised protocol version, field types, required fields, serial constraints, signatures, alignment/padding, string encodings, container bounds, and complete body consumption. Use finite depth/size/work budgets. A valid D-Bus method call with incorrect arguments is different from a corrupt frame: return a method error for the former and terminate the offending connection for the latter as appropriate. Revalidate details against [S1], not merely encode/decode symmetry.

Do not retain an invalid prefix forever or decode a corrupt body into an empty successful body. Tests must exercise mixed valid and invalid frames, multiple frames in a read, and one-byte fragmentation. Malformed signatures/containers must not cause core process exceptions or unbounded atom creation.

An initial M1 frame validator may precede the full M2 codec cleanup, but it cannot pass input to core handlers without the checks needed to contain all known crash paths.

## 5. Policy architecture

Replace direct dependency on one permissive capability module with an explicit policy boundary. Both compatibility configuration and future native policy can use common evaluation context, but **compatibility mode must preserve ordered reference semantics**, not flatten XML into an unordered set of grants.

A policy context includes trusted source identity, connection incarnation, message metadata, resolved destination identity and owned names, policy generation, and requested-reply context where applicable. Resolve aliases and evaluate ownership-based policy in the same ordering domain as routing, so a name change cannot redirect a previously authorized operation to a different service without revalidation.

Authorization surfaces are admission; RequestName; send; receive; privileged bus methods; service activation; monitor admission; and monitor delivery. An implementation may centralize these surfaces, but every path needs a regression test. Protect bus-generated/control messages through explicit semantics, not a blanket exemption for any client message addressed to the bus.

Compatibility policy is authoritative. A new native-capability layer must not silently broaden its allow set. Keep it disabled in the initial compatibility profile or explicitly make it an additional restriction, with documented behavior. Avoid hard-coded all-powerful root and `uid < 1000` grants; privileges originate in the loaded policy. Legitimate broad permissions in a reference session policy remain possible in the explicitly selected session mode.

Policy loading has two outcomes: a complete valid generation, or a descriptive error with file/element/rule provenance. Parse XML without fetching network entities or expanding uncontrolled external entities. Accept normal D-Bus documents with their known DOCTYPE without needing an external DTD fetch. Honor supported includes/search ordering with bounded recursion. Unsupported security/activation directives fail validation; recognized harmless unsupported settings may be handled only through an explicit documented compatibility decision, never a silent catch-all.

Publish candidate policy generations atomically. Failed reload leaves the previous valid generation active. Failure with no valid initial policy prevents readiness. Reads must never observe a half-populated ETS table. Any cache is keyed by relevant identity/ownership/policy generations and invalidated on changes. Decide and test revocation semantics for pending activation and outgoing work; messages not yet authorized for delivery must not use a stale broad allow cache. [S2]

## 6. Name, subscription, and reply authority

Treat name ownership as a pure queue transition plus ordered effects. Preserve current-owner and queued-requester flag updates; prevent duplicate queue entries; release queued requests; handle replacement and disconnect consistently; validate reserved/malformed names before any mutation. The exact transition table is defined by [S1] and differential tests.

Maintain a single registry view for resolution, credential queries, routing, and signal sender matching. A well-known name is not a fixed literal sender identity. Subscription parsing requires a real grammar with quoting/escaping and typed argument matching, not comma splitting and unguarded string operations. Preserve duplicate-subscription semantics and quota accounting. Remove the “no rules means all broadcasts” fallback. Keep unicast and privileged monitoring behavior distinct.

Requested replies need bounded causal state, not an unconditional allow for every error/return. Bind a forwarded request to the caller incarnation, request serial, and actual callee incarnation. A new owner of the same well-known name cannot inherit authorization to answer an earlier call. Apply configured send/receive reply policy; do not impose a new blanket rejection on modes that explicitly permit unsolicited traffic. Retire state on accepted replies, timeout, failed delivery, and disconnect. Respect no-reply and no-auto-start behavior without manufacturing extra replies. [S1, S2]

## 7. FD ownership and Unix I/O

### Mandatory feasibility decision

Before implementing the full descriptor path, prove how the pinned OTP/Linux runtime receives, owns, duplicates where needed, sets close-on-exec, forwards, and closes **arbitrary** SCM_RIGHTS descriptors. Test a pipe, regular file/memfd, and Unix socket. Raw descriptors are not interchangeable with OTP socket handles. Neither a serialized integer nor garbage collection of an Elixir list is an ownership strategy.

Use supported public OTP facilities when they meet the contract. Otherwise isolate the missing operations in a minimal reviewed native resource adapter or helper; document the actual FD-owning process and the IPC/ownership transfer. A port cannot close a BEAM-process FD merely by receiving its integer value. Keep native glue out of pure marshalling code; avoid arbitrary shell commands, runtime-wide privilege escalation, and undocumented runtime internals.

### Ownership lifecycle

| Stage | Owner and required action |
| --- | --- |
| Received but incomplete | Transport owns descriptors and buffers their stream/frame association across reads. |
| Complete validated frame | Message resource owner holds a bounded descriptor bundle; indices/counts are validated before use. |
| Authorized queued delivery | Egress holds an explicit ownership reference/reservation until the final send or cancellation. |
| Multiple recipients | A defined shared-resource lease or duplication strategy protects each delivery; dropping one recipient cannot invalidate another. |
| Partial send | Continuation records remaining bytes and whether ancillary data has already been committed. Never resend rights accidentally. |
| Rejected/dropped/failed | Release every daemon-owned reference; descriptor reclamation must survive process failure. |
| Completed | Release the daemon's local reference after all required delivery ownership is retired. |

Persist FD associations with partial byte buffers; do not assume one `recvmsg` equals one D-Bus message. Detect control truncation and invalid counts/indices; reject resource-bearing authentication traffic safely. Do not forward a message claiming FDs to a peer that never negotiated that feature.

Descriptors and ownership must survive source disconnect while an authorized delivery is pending, or cancellation must deterministically release them. Do not rely solely on `terminate/2`: supervisor kills and other abnormal paths require monitored resource owners or native resource cleanup. Prevent FD reuse from turning a double-close into closure of an unrelated resource.

Use bounded nonblocking I/O or explicit finite deadlines. Implement the exact pinned OTP send/receive continuation forms, cancellation, and error results. Never assume that send success means all bytes were consumed without checking the API contract. [S3]

## 8. Resource accounting and failure domains

Define finite per-connection, per-UID, and global budgets for: admitted/authenticating connections; authentication/frame buffers; message bytes; pending rights; names and match rules; pending replies; ingress/egress bytes and counts; activation requests/queues; diagnostics; and work per scheduling turn.

Apply budgets **before** enqueueing. Moving traffic into another GenServer mailbox is not backpressure. Prefer explicit ingress/egress credits or another race-safe reservation model. Limit per-peer decode batches and signal fan-out work so one producer cannot monopolize the authority. Every denial, send failure, timeout, or disconnect returns its reserved credits exactly once.

Document overload actions and distinguish protocol-visible errors from disconnect policies. Avoid error amplification: non-calls/no-reply traffic must not create unnecessary replies. Bound metric cardinality and rate-limit repetitive logs. Stress tests exercise resource limits under a concurrent healthy probe.

Keep the existing supervision approach unless tests demonstrate a better failure boundary. An authoritative registry/router failure may require a coherent bus-epoch reset and reconnect; blindly changing `rest_for_one` to `one_for_one` can leave live sockets with invalid names and stale permissions. A single malformed client, however, must never reach that failure domain. Core restart recovery and malicious-client containment are separate tests.

Cleanup should be owned by monitors and idempotent authoritative transitions. Do not depend on synchronous work in a dying peer's `terminate/2` to clean names, capabilities, match rules, replies, or FDs. A core reset must not pretend that the old identity/ownership universe survived; define bus-instance ID/GUID and machine-ID behavior explicitly.

## 9. Activation and service-manager integration

Activation is an asynchronous, supervised coordinator keyed by destination and bounded across callers. Load `.service` files and relevant daemon configuration with verified precedence. Authorize before launch, coalesce concurrent requests, track request deadlines, correlate name acquisition with the launch, and release all queued work on failure. Revalidate delivery against the actual owner and current policy when activation completes.

Support the declared profile's systemd-backed services and its traditional `Exec`/identity entries, or mark the profile blocked. Never turn a service file's Exec field into an unrestricted shell command. An unprivileged bus cannot pretend to launch another UID; use the selected service-manager or narrowly scoped launcher design and document the trust boundary. Configured activation must not require the bus service to acquire its own readiness name.

Treat listener socket activation, D-Bus service activation, and `Type=dbus` application readiness as different lifecycle mechanisms. Prove the bootstrap path without a circular wait on the not-yet-ready system bus. The packaged bus daemon must not require owning `org.freedesktop.DBus` through an external connection to itself in order to become ready.

For inherited listeners, validate the expected process/environment and descriptor type, consume the handoff once, account for shell/BEAM launcher PID changes, and preserve FD lifetime through the actual release launcher. Close the daemon's copy on shutdown without unlinking or shutting down a manager-owned listener. Runtime proof is required; setting environment variables alone is not integration. [S4]

## 10. ADRs and documentation changes

Write focused ADRs for: compatibility-first ordered policy evaluation; Unix credentials/FD resource ownership; bus authority and failure domains; minimal release and service activation/bootstrap; and supported-profile boundaries. Update the existing capability ADR rather than leaving contradictory accepted decisions.

The root `AGENTS.md` currently begins with Phoenix-oriented guidance in the reviewed baseline [R12]. Add accurate bus-core guidance and scope web instructions appropriately without deleting useful generated rules. Do not let web-application defaults become bus-security requirements. Align README claims with executed evidence; supervision is not proof of safety, zero-copy transport, or seamless hot replacement.
