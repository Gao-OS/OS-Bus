# Shared bounded input capture and immutable discovery generation

This continues the intact P00–P12/M0–M4 goal and accepted ADR006 section3/slice1.
It integrates candidate12's primitives into real file consumers and publishes
policy, service discovery and account data together. It does not qualify service
launch, asynchronous wire reload scheduling, installed policy equivalence or the
full Foundation. Readiness remains L0. Previous turn made concrete progress:
anchored-reader completion, independent final audit and preservation all passed.

Worktree `.trees/os-bus-foundation`, branch `codex/os-bus-foundation`, base
`7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4`. Preserve original-main209 files,
current394 workspace files,3812 prior evidence files and all twelve candidates.
Record new attempts exclusively under
`test/reports/foundation/continuation-20261010-coherent-discovery/`.

## Input capture and consumers

Add a plain `Config.Capture` value, with no new process or native operation.
`new/0` returns the capture value. `list(capture,directory)` and
`read(capture,path,bytes=1048576)` return `{:ok,record,capture}` or
`{:error,reason_map,capture}`. Normalize absolute paths;
retain at most4096bytes/path. Successful and missing/failed directory/file
attempts are cached by normalized path, so repeated occurrences use one captured
byte/metadata result and do not issue a second read. A cached file still must fit
the current caller's byte limit. Invalid unbounded paths are not retained.

Fixed shared ceilings:64 distinct directory attempts,8192 actual non-dot names,
2097152 filename bytes,1024 distinct file attempts and16777216 captured bytes.
Directory calls receive min(per-call ceiling,shared remaining credit) for both
entries and filename bytes, before allocation/enumeration. Their per-call ceilings
are1024 entries/262144 filename bytes; file calls remain bounded to1048576bytes
and the shared remaining byte credit. These are
candidate safety ceilings, not reference-daemon constants. Count ignored siblings
before suffix filtering and count missing directories against the directory cap.
All errors retain bounded path, operation and native reason; map known Linux
ENOENT/ENOTDIR/EACCES values to existing consumer errno atoms without creating
atoms. No successful partial input is exposed.

Thread this capture through Accounts→XML Config→service discovery. Add
`Accounts.load_captured(options,capture)` returning
`{:ok,snapshot,capture}` or the existing provenance error; `load/1` delegates and
retains its public two-tuple result. Supplied trusted account snapshots remain
supported and are validated once. Files use Directory/FileReader, not path stat
followed by an independent open. Account source identity becomes the reader's
six-field opened-file metadata; source directory identities, bytes/hash and read
attempts are retained. Do not fabricate uid/gid/link metadata or infer file-owner
trust from these six fields. Account named UID/primaryGID/groups/provenance and
policy UID-membership union remain compatible.

Config retains existing XML limits:1MiB/file,8MiB expanded bytes,1024 file
occurrences,32 include depth and10000 rules. Cache hits still debit expansion
budgets and retain distinct file/include occurrences. Cycles use captured
device/inode. Included directories use the captured full listing's identity for
leaf open, lexical `.conf` order, and existing missing/ignore_missing behavior.
Retain complete source identity/directory/hash/read provenance. Raw contents must
be valid UTF-8 at their respective XML/account/service parser boundary.

Add `captures` and `services` to Config. Load services after XML with exactly the
same accounts and capture value; loading has no runtime publication/launch effect.
`Capture.summary/1` strips raw file bytes for publication and retains observed
identities, hashes, work/count/byte accounting and directory inventories.

## Service contract

Add pure `Config.Services.parse(bytes,path,origin,accounts)` and
`discover(config,capture)`. The latter returns `{:ok,inventory,capture}` or a
provenance error. Inventory has ordered `directories`, ordered `occurrences` and
`selected` keyed by validated well-known name. Each occurrence retains effective
or shadowed disposition, directory index/origin, file hash/identity/directory
read evidence and parsed fields. First configured directory wins; conflicting
definitions of one Name in the same directory are refused per ADR006. Retain
missing directories and absent systemd targets; never probe or start a unit.

Bound discovery to64 configured directory occurrences,8192 traversed non-dot
entries and1024 service-file occurrences including cached/repeated paths.
Files are at most131072bytes, matching the pinned reference service-file ceiling;
read credit is reserved before allocating. Limit line length to4096bytes, key and
field strings to4096bytes, Exec to4096bytes and argv to256 words/4096 total bytes.
Each parse has at most4096 physical lines,64 sections and64 key declarations;
unknown, duplicate and locale declarations still debit work/retention budgets.
These additional string/work ceilings are explicit supported-profile limits.

Use pinned dbus1.14.10 desktop-file/argv behavior for LF/CRLF, comments/groups,
duplicate keys/groups, locale-key skipping and string escapes; preserve unknown
keys/groups according to that parser. The D-BUS Service group requires Name and
Exec; system services require User. Use the existing requestable-name predicate.
This supported system profile requires canonical `Name.service` filenames and
eager complete named account/primaryGID binding. The reference explicit servicedir
mode can warn and retain a filename mismatch and defer some validation; those
cases are deliberately refused here, not claimed equivalent. Keep optional
SystemdService as bounded nonempty metadata without requiring target existence.
Store both Exec text and actual parsed argv using the pinned D-Bus argv quoting,
escaping, comment and trailing-whitespace behavior. No shell, environment expansion,
command execution, filesystem executable probe or invented root fallback.
Retain present empty Exec as argv[""], and retain relative argv0 literally,
including installed Exec=false. Neither presence nor parsing proves launchability.

Every field and decision has full `{file,line,element,occurrence,include_chain}`
provenance, including the configured directory origin and account binding errors.
Installed16 file occurrences/15 names and their shadowed entry remain discoverable
without rewriting inputs; Exec=false and missing targets are retained.

## Compilation, publication and listing

Keep Policy.snapshot's existing `{:ok,generation,policy}` shape and native/list
policy compatibility. XML successful blocks/rules retain provenance; update exact
compiled-key validators only for the intended optional provenance field. Compiler
errors retain full valid provenance while preserving existing malformed-provenance
fallback behavior. Successful provenance must be bounded: paths4096bytes,
line1..1048577,occurrence1..1024,element255bytes and include_chain at most32
nonrecursive bounded origins. Preserve absent provenance and legacy file/line
origins, without retaining arbitrary unknown fields. Authorization decisions/rule
order remain unchanged.

For Config candidates, XML.configuration contains immutable settings/limits,
daemon UID, accounts, service inventory, source/directive provenance and capture
summary. It excludes the raw byte cache. Publish this complete value in the
existing single protected ETS generation row. Failed reload retains the entire
old row; captured old generations remain usable. Expose
`Policy.configuration(snapshot=Policy.snapshot())` and
`Policy.activatable_names(snapshot=Policy.snapshot())` for same-snapshot reads.
ListActivatableNames uses Router's already-captured policy snapshot. List policies
retain their empty service-list behavior. Existing restart-required runtime
settings and all Config.Runtime activation refusals remain enforced.

The existing wire ReloadConfig path commits while Router is serially handling the
request. Its synchronous preparation/scheduling remains a separately documented
gap: this scope establishes the coherent generation data and commit, not healthy
traffic during arbitrary filesystem stalls or asynchronous reload admission.

## Ownership and verification

Production scope exactly Config,Config.Accounts,Policy.XML,Policy,BusInterface
and new Config.Capture/Config.Services. No Directory/FileReader/native/Runtime,
Router,activation/helper/release or existing fixture changes. New regressions:
config/capture_integration_test.exs,config/service_discovery_test.exs and
policy/coherent_discovery_test.exs. Existing tests remain unchanged.

Workers first own disjoint test files only. Parent owns all runtime/build/VM,
before images and docs. Observe unchanged-production RED, then implement and run
identical GREEN, affected Config/Policy/API and Unix/Peer selections, strict
compile/format and independent specification then quality reviews. Cover real
file reads/budgets/ignored-entry overflow/repeated includes/trusted links/FIFO
refusal, complete provenance, account coherence, service parser/precedence/listing,
invalid reload retention and concurrent same-generation reads.

Capture a NEW immutable candidate13, verify sources→BEAM/native/artifacts and run
the existing disposable security VM in a NEW report directory. The VM refresh
does not exercise newly added service consumers or prove activation. Preserve all
earlier FAILs and three mandatory reference/spec discrepancies. An outside-scope
failure remains FAIL and stops that scope; never weaken a gate or fix it here.
No commits/merges/pushes/remote writes/releases/deployment/host live-bus traffic,
memory updates or rejected registered-Peer FD04 audit redispatch.

Neither shared captures nor immutable publication provide an atomic cross-file
filesystem snapshot, invisible/ABA mutation detection, ancestor confinement,
hard syscall timeout or caller-kill cancellation. Other platforms remain unqualified.
Full P08/P09,activation/release/inheritance/packaged600s/real-service rollback and
asynchronous reload scheduling remain unfinished toward the unchanged full goal.
