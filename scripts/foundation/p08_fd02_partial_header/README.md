# Independent FD02/core partial-header fixture

This fixture prepares exactly offset15 and two ancillary positions against two
serialized independent backends: Gao and pinned dbus-daemon. Each backend runs
prefix-right (15bytes plus one PIPE reader right) and last-byte-right (14plain
bytes, then the final prefix byte with that right), with complete close/recovery
between modes. Two selected backend combinations produce four mode observations.
Warmup remains complete-frame context, never FD02 coverage. Runtime is NOT RUN
at offline implementation handoff; full qualification is false/L0.

The actor has explicit prefix, retained and finish commands. The suffix stays
unsent until the root controller observes one actual broker FIFO matching the
original reader and Gao source buffer15/frame_bytes15/frame_fds1 at global,
UID1100 and source-peer levels. All other scalar authorities/credits/peer state
and numeric broker inventory must match the connected baseline. Reference
uses actual kernel FD inventory, with no invented internal state. The target
executes strict health112 while held; no Resource/rights may precede that reply
or remain readable afterward. The source sends no health into its partial frame.
The controller checks retention again after target health before finish.

Finish writes the exact remaining suffix with zero new rights. The first target
resource receive is strictly Resource100, flags0, h/index0/header9=1/right1 and
actual sender/destination. Both source prefix chunks and suffix retain individual
wire bytes/counts/digests; their assembled complete frame is decoded independently.
Distinct send positions do not imply controlled broker recvmsg coalescing. The
received FIFO consumes exactly PIPE and EOF, matches original dev/inode/mode/
target, and both actual readers remain held through external checked sampling.
The writer closes with actual fstat EBADF before transfer; numeric FD reuse
is permitted but the writer cannot equal the held original reader. No broker
pipe endpoint remains after forwarding. Four actual reader/connection EBADF
closures, full warmed numeric actor/broker recovery and Gao normalized scalar
recovery precede the next mode and EOF/owned-group/socket teardown.

All seven accepted singleton-pipe files, wire actor, channel, quota daemon and
collector are imported or packaged read-only. The accepted run_backend function
has no workload callback, so lifecycle() checks the complete accepted source
SHA256 and exact20-node active-range AST digest, replacing only that range with
run_modes. Startup, complete warmup, sampling, scalar configuration, deadlines,
error containment and teardown remain unchanged. Source-shape drift fails closed.
Both original and executed new source inputs are recorded in the report.
Every actual mode open response must retain op=open and source/target aliases
equal to its first/second connections, including the mode not exposed to the
facade. The complete accepted oracle receives the final complete-mode data
shape through a private validation facade, while the new oracle validates actual selected modes,
raw prefix/retained/finish commands, phase order, extra held-health frame and
all observations. The facade is never exported as execution evidence; no
original oracle expectations or on-disk files are patched.

The Nix fixture takes explicit frozen candidatePath and reviewed scopePath.
It packages new and reused seven-file roots separately and sets the bound
FD02_PIPE_FIXTURES path before Python import, with --reuse-fixtures matching it.
Candidate16 remains80artifacts/71sources with original modes and immutable Nix
copy modes &~0222. New19inputs and seven reused inputs retain before/after
hashes. Runtime executable aliases must later resolve through the actual guest
closure. Reference833B XML is real generated execution output; generator/bytes/
hash/startup must be bound without a fictitious pre-execution XML hash.

UID/global egress-FD2/3, writer5000/health1000/cleanup1000/resource3000/startup10000ms,
guest120s and parent host900s are unchanged. Offline tests use native local
socketpair/pipe/SCM_RIGHTS unit relays and synthetic oracle reports; they start
no broker, application or VM and provide no runtime PASS. Scope excludes
partial-body, each-relevant-boundary, FD03, network, activation, packaged
workload, replacement/rollback and canonical map promotion. Independent
specification then quality acceptance and parent freeze precede any VM run.
