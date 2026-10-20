# ADR-005: Ordered authority and contained peer failures

Status: initial authentication/policy/input boundary implemented; resource gates
and complete name/reply semantics remain in progress.

The Router remains a single ordered authority. Peer authentication is bound to
kernel credentials; the Peer caches those credentials with Router before sending
Hello. A unique name is assigned only during validated Hello. Router updates its
peer index in that same turn, sends the Hello reply, and subsequently processes
ownership signals. Peer defers buffered follow-up calls until its Hello reply has
been written. Sender headers from clients are replaced with trusted connection
identity.

Wire validation is pure and precedes authority dispatch. The bus-method schema
checks object path, interface, signature, argument count and values before handler
body patterns run. Incomplete input is distinct from terminal invalid input;
unknown valid wire extensions retain the required ignoring behavior. Malformed
clients cannot obtain correctness by triggering a broad Router rescue/restart.

Policy precedes effects. Recipient resolution returns the actual peer and its
owned name set together, and routing uses that resolved peer rather than resolving
again after authorization. One immutable generation covers related policy checks.
The core uses one_for_all supervision: losing policy, accounting, routing, or
registry state disconnects every peer and resets the complete authority epoch.
The old rest_for_one strategy left names/queues behind after Router failure and
retained a policy generation after registry failure. Supervised Ids creates new
independent authentication GUID and bus instance ID values for each epoch;
GetId is not the machine ID. Preserving sockets across this reset is not claimed.

Peers are temporary children. Router monitors authenticated peers and owns
idempotent authority cleanup; dying peers must not synchronously call back into an
authority that can be waiting on registration. Connection, frame, ingress and
egress credits are reserved before their corresponding reads or enqueueing.

## Bounded Peer ingress and asynchronous completion

Each real Peer promotes at most one frame into Router work before completion.
`Router.route_frame/3` returns the promoted ingress token and sends a distinct
internal frame-routing cast. Router performs the existing ordered routing turn,
then closes the original FD bundle and requests ingress release in its cleanup.
Only after routing and cleanup both succeed does it send
`{:route_complete, token}` to the source. Failed routing or cleanup sends no
success acknowledgement. Ordinary denial or missing-recipient processing still
completes the callback; the acknowledgement is not a delivery receipt. Legacy
`Router.route/3` calls do not request one.

Peer matches the exact outstanding token; stale or duplicate completions are
ignored. While that token is outstanding, guards stop socket reads, message
processing and read arming. Read/select readiness, message continuations,
ingress-capacity notifications and Hello's output-completion path all pass
through those guards. Unknown valid message types retain the existing bounded
ignore/continuation path. Authentication behavior and numeric resource limits
are unchanged.

The Peer remains available for authority calls, output messages, Writer ticks
and existing expiry messages. It never synchronously waits for Router: Hello
routing calls back into Peer to assign identity. Hello remains registering until
its actual reply has been written; routing completion alone does not register it.
Self-directed output uses the same independent nonblocking Writer path.

Completion ends Router's ownership of the original received FD bundle, not
recipient ownership. Each egress delivery retains its independent copies. With
XML queues, source ingress may remain charged through output references after
Router requests release. Completion therefore re-enters the existing
`Limits.ingress_ready` check and may pause input until those references retire;
it does not wait unconditionally for the source's own output queue to drain.
Peer death leaves admitted ingress cleanup with Router/Limits. Core failure
retains the existing coherent epoch teardown; outstanding tokens are not replayed
into a replacement Router.

This window bounds each Peer's admitted Router backlog while preserving the
current single-turn policy/context and delivery ordering. It does not bound the
CPU cost of one fanout independently, prove native mutex contention, or qualify
the full workload deadline. The controlled red/green and affected-slice evidence
are recorded in the foundation ledger; original traced RES-04 remains required.

Filesystem listeners refuse existing paths, symlinks, and unsafe containing
directories. Clean shutdown compares socket device/inode/owner before unlinking;
a replacement path is preserved. A root-owned sticky ancestor such as /tmp is
allowed only above a private, non-writable-by-others containing directory. Stale
endpoints after SIGKILL require explicit operator/VM cleanup; startup does not
infer permission to delete them. The native boundary exposes getpid/geteuid/getegid
for filesystem ownership checks without shell tools; peer identity continues to
come from SO_PEERCRED.

All tests operate on private endpoints. Socket regressions kill Router,
NameRegistry, and Policy, verify every old peer closes, all authority and quota
state resets, identifiers rotate, and reconnecting clients can reclaim names.
Per-UID/global resource stress and inherited release-listener lifecycle remain
separately gated. Optional UI diagnostics are disabled outside the explicit
session profile, even if a Phoenix.PubSub server is present in the VM.
