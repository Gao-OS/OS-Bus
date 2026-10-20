# ADR-004: Linux kernel identity and ancillary resource ownership

Status: implemented runtime adapter; full bus integration and qualification pending.

## Evidence and decision

The pinned development runtime is OTP 27.3.4.6 / Elixir 1.17.3. On Linux,
`:socket.getopt(socket, {:socket, :peercred})` returns an unsupported option.
The supported public `:socket.getopt_native(socket, {:socket, 17}, 12)` retrieves
Linux SO_PEERCRED. Parse the exact native `struct ucred` (signed PID, unsigned
UID/GID), reject unavailable/invalid data, and never substitute authentication
text. This is Linux-specific; other platforms are unsupported until verified.

The installed OTP `socket.erl` documents `socket.open(FD, Options)` as requiring
a **socket** descriptor. Its public sendmsg/recvmsg APIs expose SCM_RIGHTS as
raw integers; they provide no general pipe/file descriptor resource owner or
close operation. A helper in another OS process cannot close those BEAM-process
integers. Consequently a small Linux C NIF in `gao_bus/c_src/gao_unix.c` owns
ancillary resources; `ex_d_bus` remains pure and has no native dependency.

Receive performs nonblocking recvmsg with MSG_CMSG_CLOEXEC and immediately wraps
every received descriptor in a native resource in the same call. The backing
control buffer accommodates Linux SCM_MAX_FD (253), but each receive exposes only
`CMSG_LEN(max_fds * sizeof(int))` bytes, or no control buffer for zero credit.
Using CMSG_SPACE for that ceiling would admit an extra descriptor in its padding.
The kernel closes rights omitted by control truncation before returning, so even
the temporary installed descriptor count respects the caller's credit.
Truncated, unexpected, and
excess ancillary data is rejected with all received descriptors closed. Each
resource has an idempotent explicit close and a destructor when its last reference
is destroyed, including abnormal exit of its sole holder. If another process holds
a reference, creator exit alone does not close it; explicit queue/fan-out ownership
is required in P08. Allocation failures close all rights before returning, including
those awaiting wrapper allocation. No integer descriptor is exposed to routing code.

Send duplicates resource references under their mutex with F_DUPFD_CLOEXEC,
performs one nonblocking MSG_NOSIGNAL sendmsg, closes those temporary copies,
and reports exactly the number of accepted bytes. A positive partial result
means the rights were committed; a continuation must send only the byte tail
without rights. EAGAIN commits neither. Queue ownership, per-frame association,
and recipient policy remain P08 responsibilities; passing these adapter probes
does not establish full bus FD support.

Each syscall is bounded to 64 KiB of data and at most 253 rights. Native socket
capture uses the public `:otp, :fd` option and F_DUPFD_CLOEXEC in a short ordinary
NIF; it must not run on a dirty scheduler. An ordinary NIF prevents its owning
caller from finishing exit and releasing the borrowed descriptor during capture.
The owner check, descriptor lookup, and duplication require exclusive bootstrap:
trusted BEAM code must not concurrently close or transfer that OTP socket. They
are not atomic against an explicit close by another process.

Every dirty recv/send/poll uses the captured resource under its mutex, never a
borrowed descriptor integer. Native close uses the same mutex, marks the resource
closed, and releases its private copy once. An already executing operation may
finish on the original connection; subsequent operations return `closed`. OTP
owner exit may release the original descriptor without redirecting a dirty call
onto its replacement. The NIF argument retains the private copy until native
completion, and its destructor closes it when the last reference disappears.
All I/O remains nonblocking; no blocking reader or owner-DOWN callback is added.
Linux close is
never retried after EINTR because the descriptor may already have been reused.
Explicit cleanup errors are returned; destructor cleanup errors are reported.
The BEAM process is a trusted boundary; this NIF does not sandbox hostile code
loaded into that process. C memory safety remains a review obligation.

## P08 delivery copies and nonblocking output

`Resources.duplicate/1` creates separate CLOEXEC native resources for a delivery.
It holds each source mutex while duplicating, constructs no Erlang resource terms
until every copy succeeds, and destroys all provisional copies on any failure.
Closing the input bundle or another recipient's copies cannot invalidate this
delivery. Copies share the underlying open file description (including file
offsets), as required by SCM_RIGHTS; they are independent descriptor lifetimes,
not independent underlying files. Router/Peer integration must reserve descriptor
and egress credits before duplicating/enqueueing and explicitly close each owned
bundle on its terminal path. No owner may close a shared fan-out handle on behalf
of only one recipient.

`Unix.Writer` stores immutable bytes/handles, accepted byte offset, rights-commit
state, and an absolute deadline including queue wait. Each step makes at most one
nonblocking send of at most 64 KiB. Positive sends commit ancillary data once;
EAGAIN commits neither bytes nor rights. The writer does not close resources: its
delivery owner closes on completion/error, with native destruction as the abnormal
sole-holder-exit fallback.

Pinned OTP 27 supports ordinary byte-tail continuation using
`socket.send(Socket, Tail, SelectInfo, nowait)` and `socket.cancel/2`. However, a
zero-byte send on a full socket immediately returns `ok`, so it cannot arm write
readiness for an initial native SCM_RIGHTS send returning EAGAIN. The minimal
native `poll(POLLOUT, timeout=0)` primitive therefore checks readiness without
blocking and surfaces HUP/ERR/NVAL. The caller schedules at most one tokenized
retry tick per blocked peer and enforces the absolute deadline; there is no native
busy loop or infinite wait. Output uses native sends throughout, avoiding mixed
OTP/native outstanding write operations.

Private Linux probes also show that a wide recvmsg can combine preceding ordinary
bytes with a subsequent rights-bearing send without exposing the ancillary byte
offset. Peer input therefore keeps authentication reads separate from binary input
and FD-negotiated reads bounded by the current frame, retaining rights across
partial reads. The specification allows rights anywhere within their frame, not
just on its first byte.

After validating the current frame's 16-byte fixed prefix, FD-free input may read
ahead by at most 65,536 bytes per receive, within the existing maximum input-buffer
size and reserved frame credits. Retained successors remain charged, including
after an unknown frame is discarded. If speculative byte credit is denied at the
peer, UID or global ceiling, Peer retries the current-frame extent; other reservation
errors keep their existing failure path. Unexpected rights on an unnegotiated
connection are explicitly closed and rejected before decoding or routing any
coalesced messages. Authentication and negotiated descriptor boundaries remain
unchanged; these implementation decisions do not establish runtime qualification.

Peer captures one native socket after admission and authentication-state creation,
then retains it for receives, authentication/error output, and writer continuations.
The OTP handle remains responsible for credentials and readiness. Normal Peer
termination explicitly closes both handles; a killed Peer releases its sole
native reference after any dirty call completes. This costs one extra descriptor
per admitted connection. Other processes retaining a native handle intentionally
extend its destructor lifetime; production observers must not retain it.

`socket_lifetime_test.exs` compiles a test-only copy of this NIF with deterministic
syscall barriers and forced reuse of closed descriptor numbers. Its original five
cases reproduced diverted bytes/rights, consumed unrelated input, and excess
temporary received descriptors. Added cases verify native close against in-flight
read/write, repeated close after descriptor reuse, full native completion, and
terminal FD counts. `peer_socket_lifetime_test.exs` verifies explicit closure with
a retained observer reference and final descriptor recovery after Peer kill.
These focused cases do not certify the complete P08/M2 transport gate.

## Bounded local directory enumeration

`Native.list_dir_bounded/3` adds a Linux/glibc public `getdents64` primitive to
the same native boundary. It opens one owned O_DIRECTORY/O_CLOEXEC descriptor
on dirty I/O, uses a fixed32KiB scratch buffer and bounded filename bookkeeping,
and returns a complete result or an error. Hard maxima are1024 non-dot entries,
262144 filename bytes,255 bytes/name and4096 bytes/path. Count every non-dot
entry before filename allocation; suffixes, hidden names and entry types do not
bypass the budget. Bound raw records to entry_budget+3 and getdents attempts,
including EINTR/EOF, to entry_budget+4. Validate record lengths and in-record NUL
before copying. Close once on terminal paths, surface close errors and never
retry Linux close after EINTR.

Before/after fstat and final pathname stat compare device/inode/mode/size and
mtime/ctime. This detects observed change; it does not provide an atomic
snapshot, ancestor confinement or an anchor for a subsequent file open. Native
names remain binary bytes. `Unix.Directory.list/3` validates bounded arguments,
rejects invalid UTF-8 names and sorts the complete result without allocating
atoms. No service parser, runtime consumer or new process is introduced.
A hung filesystem syscall can retain its dirty scheduler and descriptor; hard
timeouts and caller-kill cancellation are not part of this primitive.

Candidate11's scoped evidence is RED13/13 to GREEN13/0, affected44/0, strict
compile/format, independent static reviews and frozen-artifact smoke. Actual
UID1000/GID100 EACCES checks recover FD count18 to18. Existing socket/rights
functions are mechanically unchanged. These are local primitive results on
the pinned Linux/glibc/OTP platform, not full native or bus qualification.
Candidate11's separate security refresh is FAIL20/1 at RES-03 connection usage
equality; its13 owned processes exit0 and VM poweroff is verified. The failure,
guest export and unresolved cleanup-observation boundary remain recorded in
`continuation-20261010-bounded-directory/` and `candidate11-security-refresh/`.

## Bounded anchored regular-file reading

Pinned OTP27 public file.open/2 accepts a filename and modes, with no public
descriptor-relative openat or O_NONBLOCK mode. Config's joined-path reading and
Accounts' pathname stat followed by open cannot supply this primitive. The
installed profile also requires trusted absolute cross-store leaf symlinks;
blanket O_NOFOLLOW or beneath-only resolution would exclude required inputs.

`Native.read_file_at_bounded/4` opens an owned O_DIRECTORY/O_NONBLOCK/O_CLOEXEC
directory, compares its fstat against `Directory.list/3.identity.after` before
opening a leaf with openat, O_NONBLOCK and O_CLOEXEC. It follows trusted links,
then requires an actual regular opened file before body allocation or reading.
Paths are1..4096bytes; one leaf is1..255bytes without slash/NUL/dot/dot-dot.
`Unix.FileReader.read/4` checks UTF-8 leaf names and adds joined-path provenance;
contents remain bytes. No consumer, parser or process is introduced here.

The byte budget is0..1048576. Refuse initial file size above it; allocate one
budget+1 buffer, read at most that many bytes in requests of at most4096, and
charge every read/EINTR/EOF attempt against floor(budget/4096)+4. The returned
binary can retain that bounded backing allocation. Refusals never expose partial
contents. Opened-file before/after and final fstatat leaf identity must agree;
the captured byte count must equal the unchanged file size. Opened-directory
after and final configured pathname stat must both match the expected identity.
Files/directories share exactly device,inode,mode,size,mtime,ctime with nanosecond
timestamps. Expected unsigned64 device/inode, unsigned32 directory mode,
nonnegative signed64 size, signed64 seconds and0..999999999 nanoseconds are
validated before opening. All six fields participate in comparisons.

Every terminal branch closes at most two owned descriptors once, never retrying
Linux close; close errors take precedence. Filesystem errors retain numeric
errno. Metadata checks detect observed changes, without promising an atomic
snapshot, ancestor confinement, invisible/ABA mutation detection, a hard syscall
timeout or cancellation on caller exit. Consumers still need aggregate budgets,
parsing, file trust and coherent generation publication. Other platforms remain
unsupported until separately verified. Current scope and saved evidence are in
`P10_ANCHORED_READING_SCOPE.md` and `continuation-20261010-anchored-reading/`.

Candidate12's local reader evidence is unchanged-production RED17/17 to
identical-test GREEN17/0, affected Unix/Peer61/0, strict compile/format and
independent static reviews. Frozen actual UID1000/GID100 directory/leaf EACCES128
and33 installed-profile file occurrences (30 leafsymlinks) pass with FD18 to18
and exact byte/module/native hashes. Fresh same-candidate native security VM
passes21/0 plus fixture28/0 with13 EOF exits0 and VMoff. That refresh exercises
existing native security paths; it does not test reader consumers, Config/Accounts
migration, activation or an atomic generation. Full qualification stays at L0.

## Packaging and proof

`elixir_make` (already in the lockfile) builds the NIF into the gao_bus build
artifact using the pinned compiler/ERTS headers and warnings-as-errors. There
is no runtime shell invocation, privilege change, downloaded native binary,
or dependency on Phoenix/config/cluster in the adapter.

`apps/gao_bus/test/unix/resources_test.exs` uses an independent Python actor
with generated pipe/file/socket resources. It tests actual returned-resource
use, CLOEXEC, exact FD counts, excessive-rights cleanup, partial sends, and
abnormal owner exit. Logs live in `test/reports/foundation/p01-*` and results
are tracked in the foundation ledger; unexecuted cases remain unverified.

`python3 scripts/foundation/probe_listener.py` exercises descriptor inheritance
through the actual elixir/erl/BEAM launcher into the public socket.open API,
checks LISTEN_PID, local stream/listening state, and verifies closing the
candidate copy neither removes the pathname nor disables the manager's copy.
This is a prototype; P11 must repeat it with the packaged headless release.
