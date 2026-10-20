# Bounded anchored regular-file reading prerequisite

Status: in progress under the full P00–P12 Foundation goal. Previous RES-03 turn
made concrete progress and completed its independent checks; no runtime handle
remains. Worktree `.trees/os-bus-foundation`, branch `codex/os-bus-foundation`,
base `7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4`; readiness remains L0.

## Purpose and evidence

ADR006 section3 requires bounded service/configuration discovery, provenance and
one coherent generation. Directory.list/3 closes its descriptor before returning;
current Config reads joined pathnames and Accounts opens after a pathname stat.
Neither provides a public descriptor-relative nonblocking open of the later file.
Pinned OTP27 file.erl1463–1491 exposes open/2 by filename and modes, with no public
openat or O_NONBLOCK mode. Its opened-descriptor read_file_info is useful but does
not anchor the open. Use the existing minimal native boundary; no undocumented
OTP API, subprocess/NSS lookup, new process or general command executor.

The installed profile requires trusted leaf symlinks to other Nix store roots;
blanket O_NOFOLLOW or beneath-only resolution would exclude required service and
policy files. Preserve those links. This primitive reads bytes without parsing
or executing them and anchors the leaf lookup to the verified opened directory.

## Contract

Add Native.read_file_at_bounded(directory, name, expected_directory, byte_budget)
on dirty I/O and checked FileReader.read(directory,name,expected,bytes=1048576).
Directory/name are binaries: nonempty directory up to4096bytes/no NUL; a single
leaf name up to255bytes/no slash/NUL, neither dot nor dot-dot. Checked names must
be UTF-8; bytes remain raw for the consumer to validate. Byte budget is an integer
0..1048576. Expected directory identity is exactly the six-field metadata map
returned by Directory.list/3.identity.after: device,inode,mode,size,mtime,ctime;
device/inode are unsigned64, mode is unsigned32, size is nonnegative signed64,
timestamp seconds are signed64 and nanoseconds are0..999999999. Expected mode
must be a directory. File metadata uses exactly the same six fields, numeric
ranges and nanosecond timestamp tuples; all six fields participate in equality.

Open directory O_RDONLY|O_DIRECTORY|O_NONBLOCK|O_CLOEXEC, verify opened fstat
against expected identity before opening any leaf. Open the leaf using openat
with O_RDONLY|O_NONBLOCK|O_CLOEXEC (follow trusted symlinks), require regular file
before allocating/reading. Refuse initial size above the budget; read at most
budget+1 bytes in <=4096byte requests, accepting only EOF within budget. Every
read attempt including EINTR consumes the fixed attempt budget floor(bytes/4096)
+4; exhaustion fails. Check opened-file fstat before/after and final fstatat leaf
identity, plus directory fstat after and final pathname stat against expected.
Success additionally requires bytes_read to equal the unchanged opened-file
before.size (and therefore after.size and final leaf path.size); mismatch refuses
:file_changed, including early EOF. An empty regular file remains valid.
Do not expose partial bytes on any refusal. At most two owned descriptors and
one bounded byte allocation exist per call. Every post-open path closes each
owned descriptor exactly once; Linux close is not retried, close errors take
precedence over successful/failed reads.

Success is {:ok,%{bytes:binary,bytes_read:integer,syscall_attempts:integer,
identity:%{before:file,after:file,path:file},
directory:%{before:dir,after:dir,path:dir}}}. Checked wrapper adds path joined only
for provenance. Error reasons are :invalid_path/:invalid_name/:invalid_identity/
:invalid_budget/:not_regular_file/:file_byte_limit/:file_work_limit/
:directory_changed/:file_changed/:enomem or {:errno,number}. Wrapper errors are
{:error,%{reason:reason,path:bounded_original_path_or_nil}}. Invalid directory/
name inputs use nil rather than retaining oversized or invalid strings.

Metadata comparisons detect observed changes, not an atomic inventory snapshot,
ancestor confinement or invisible mutation. The directory is reopened and checked
against its enumeration metadata; no long-lived directory resource is added.
Trusted symlink targets may leave that directory. O_NONBLOCK prevents FIFO-open
waiting but does not impose a hard wall-clock bound on arbitrary filesystem calls.
Dirty-call cancellation, hung network filesystems and other architectures/libcs
are not qualified. Consumers must handle aggregate budgets, parsing/UTF8/provenance,
complete generation consistency and existing-file changes independently.

## Ownership, scope and verification

Production scope exactly:

- apps/gao_bus/c_src/gao_unix.c: additive reader/helpers/registration only.
- apps/gao_bus/lib/gao_bus/unix/native.ex: additive matching stub only.
- apps/gao_bus/lib/gao_bus/unix/file_reader.ex: checked function wrapper.

Worker first owns only new apps/gao_bus/test/unix/file_reader_test.exs. Parent
owns all builds/tests/runtime/VM, candidate capture and documentation. Preserve
before images; run meaningful unchanged-production RED, implement, then identical
GREEN. Cover empty/exact/overflow/raw bytes, invalid arguments/full identity,
FIFO/directory/nonregular refusal, missing/non-directory/trusted symlink paths,
stale same-count directory replacement/leaf mutations and actual FD recovery.
Use deterministic before/after changes rather than timing races; real UID1000
permission evidence must remain distinct from root chmod. Independent source
specification and quality reviews follow GREEN. Run strict compile/scoped format,
new file tests and affected existing Unix/Peer lifetime/writer selections.

Preserve original-main209 files, prior3717 evidence files, all frozen candidates
and every unrelated workspace file. Capture NEW candidate12, never overwrite11,
verify source-to-BEAM/artifact binding and frozen local/profile smoke, then run the
existing disposable security VM on that exact candidate in a NEW report directory.
No VM result or full P08/P09/P10/M1 acceptance is inferred from local tests.
Any outside-scope production/qualification failure remains FAIL and stops this
scope; do not fix it here or weaken any required gate.

Parent docs: this scope, ADR004, STATUS and COMPATIBILITY. Reports:
`test/reports/foundation/continuation-20261010-anchored-reading/`.
Do not change Directory, Config/Accounts consumers, parser, policy publication,
activation, helper/release or fixtures in this prerequisite scope. They remain
next tasks toward the intact full goal. No commits/merges/pushes/remote writes,
releases/deployments/host live-bus traffic, memory updates or redispatch of the
previously rejected registered-Peer FD04 audit.
