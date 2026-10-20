# P02 SEC01: persistent independent client identity and valid stream exchanges

Prepare fresh `environment/m1-sec01-complete1/source1/**` only, using current
candidate18 and the existing backend/actor/oracle and finite-VM machinery.
The read-only `m1-auth-next-assessment1/ASSESSMENT1.md` describes the missing
invariant. Do not rebind historical short-lived CLI results to current identity
evidence. Preserve all production, candidates, prior failures, maps and ledgers.

The complete core workload must run reference and GaoBus on separate private
sockets inside one marked disposable Linux VM. Establish a persistent,
Hello-complete independent observer first. Run real persistent GLib and
sd-bus/libdbus clients under known non-root UIDs1100/1101, each completing Hello.
Use small fixture-only native clients if needed; compile against actual pinned
guest libraries with strict compiler warnings. Hold each client alive through
the observation and retire it gracefully with an explicit bounded command.
Do not add a production dependency or client authentication seam.

For each library client, join its returned unique name to independently queried
GetConnectionUnixUser, GetConnectionUnixProcessID and GetConnectionCredentials,
and independent live kernel PID/starttime/status/socket-FD/inode/executable data.
The observer must have a distinct identity. Self-reported UID/PID or the
observer's own credentials cannot substitute for the live client. Preserve
actual GIDs and optional metadata distinctions; do not fabricate missing fields.

Alongside the library clients, reuse the raw independent actor to execute valid
EXTERNAL exchanges split at every byte boundary of the bounded canonical auth
sequence, plus coalesced AUTH/BEGIN/Hello/followup frames with exact successful
reply/serial order. Retain the raw actor's kernel/public identity correlation,
exact byte writes/reads and actual outcomes. Do not claim the libraries emitted
chosen fragments. AUTH OK alone is not Hello completion. No malformed-input,
negotiation, authorization or reference expectation changes belong to this scope.

Preserve daemon and already-registered observer incarnation, unique name and
sentinel ownership, full public authority and native FD/resource recovery, with
positive observer serviceability probes before/during/after. Bound the entire
two-backend workload by one360s authority deadline, guest480s and host900s;
request/health/settle1s, startup10s and cleanup5s. Prove natural actor/daemon
retirement, exact owned endpoint cleanup, export on failure and VMoff. If the
reference controller must remove its exact owned endpoint, record that action
explicitly and do not describe it as natural daemon unlink.

Prepare meaningful failure controls for identity substitution, stale PID or
socket identity, missing library/Hello/fragment cases, byte/serial mismatches,
missing observer continuity and incomplete resource recovery. Preserve actual
catalogue labels, config-first bindings, source-scenario versus assertion-source
references, backend commands/exits and raw witness joins. Use the unchanged
evidence consumer contract. Selected/executed/passed/failed/blocked/skipped counts
must come from actual observations; collector success cannot normalize a failed
backend or missing library. No complete-row promotion occurs during preparation.

Preparation is stdlib/file-data/AST only. Native source, unit/control tests,
guarded imports, public parsers, compilation/builds, brokers/VMs and consumers
remain NOT RUN until root SPEC and distinct QUALITY. Root owns serialized
execution and ledger; distinct saved-raw review precedes receipts/adoption.
The worker owns only fresh source1/** and must preserve others' edits. Stop on
the first new substantive defect; retain routine reader errors if corrected.
No host bus/account changes, Git mutation, remote writes, publication or memory
writes. L0/product_qualified=false until mandatory product gates actually pass.
