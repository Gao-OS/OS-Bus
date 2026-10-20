# P10 bounded directory prerequisite

Status: primitive implemented and locally verified; candidate11's broader
security refresh FAIL is retained. Full P08/P09/P10/M1 qualification is open.
Worktree: `.trees/os-bus-foundation`, branch `codex/os-bus-foundation`,
base `7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4`. Readiness remains L0.
Candidate10 and all preceding sources, artifacts and failed evidence are frozen.

## Contract

Public OTP27 directory APIs materialize the complete list before callers can
enforce an entry limit. Use the existing Linux/glibc native boundary and public
`getdents64`, not an OTP internal API or a post-enumeration `File.ls` limit.
The static basis and selected parent decisions are retained in
`continuation-20261010-p10-discovery/bounded-discovery-primitive-review.json`
and `bounded-reader-parent-decisions.json`.

`Native.list_dir_bounded(path, entry_budget, name_byte_budget)` runs on dirty I/O,
opens one owned directory descriptor with `O_DIRECTORY | O_CLOEXEC`, and reads
through one fixed 32 KiB scratch buffer. Hard maxima: 1,024 non-dot entries,
262,144 total filename bytes, 255 bytes/name and 4,096 bytes/path. Caller budgets
are integers from zero through their respective maxima. A zero budget permits
only an empty directory. Charge all non-dot entries before filtering or filename
allocation, including hidden files, unrelated suffixes, links and subdirectories.
Process at most `entry_budget + 3` raw records and attempt at most
`entry_budget + 4` getdents calls, including interrupted calls and terminal EOF.

Validate every record's length, positive progress and in-record NUL before
reading or copying fields. Reject oversized names, malformed records, budget
overflow, read/allocation failures and observed directory/path identity changes.
No successful truncated prefix. Never create filename atoms. Close exactly once
on every terminal path; surface close failures and never retry Linux close after
EINTR. Preserve existing socket/resource code, ABI and ownership unchanged.

Success returns `{:ok, %{names: raw_binary_names, examined: count,
name_bytes: count, raw_records: count, syscall_attempts: count,
identity: %{before: metadata, after: metadata, path: metadata}}}`. Metadata
contains device, inode, mode, size and mtime/ctime as `{seconds, nanoseconds}`.
Native names retain raw bytes. Static native refusal reasons include
`invalid_path`, `invalid_budget`, `entry_limit`, `name_byte_limit`,
`invalid_directory_entry`, `directory_changed` and `enomem`; ordinary filesystem
errors preserve the errno via the existing native error representation.

`GaoBus.Unix.Directory.list(path, entries \\ 1024, name_bytes \\ 262144)` checks
the arguments, refuses invalid UTF-8 names explicitly, sorts a complete result
and returns the same success map. Errors are `{:error, %{reason: reason,
path: bounded_original_path}}`; an invalid/nonbinary/oversized path uses `nil`
instead of retaining unbounded input. Invalid filename encoding reports
`{:invalid_name_encoding, raw_name}`. This module is a function boundary, with
no new process, registry, dependency or runtime consumer.

## Ownership and validation

Production write scope is exactly:

* `apps/gao_bus/c_src/gao_unix.c`: additive enumeration helpers/registration only.
* `apps/gao_bus/lib/gao_bus/unix/native.ex`: matching stub only.
* `apps/gao_bus/lib/gao_bus/unix/directory.ex`: checked wrapper.

Worker first owns only new `apps/gao_bus/test/unix/directory_test.exs`. Parent
preserves the before images and runs meaningful unchanged-source RED before
authorizing the three production files. Parent owns all builds, tests, runtime,
candidate capture, documentation and preservation. Independent specification
and quality reviews follow GREEN; do not proceed with material open findings.

Verify real empty/exact/overflow cases, bytes/examined-entry accounting before
filtering, invalid arguments, native raw-name/wrapper UTF-8 behavior, missing and
non-directory paths, trusted directory symlinks, metadata and repeated terminal
FD recovery. Use actual unprivileged execution for permission-denied evidence;
root chmod is not such evidence. Do not add timing races or weaken a negative.
Run strict scoped compile/format, the new tests and affected existing Unix,
Peer-lifetime/writer and resource tests. Native changes require a new immutable
candidate; never overwrite10. Preserve failed attempts and report exact results.

Parent documentation scope: this file, ADR004, STATUS and COMPATIBILITY.
Evidence: `test/reports/foundation/continuation-20261010-bounded-directory/`.
No commits, merges, remote writes, releases, host live-bus traffic, deployments,
memory updates or redispatch of the rejected registered-Peer FD04 audit.

## Evidence boundary

Configured local trusted directory paths may contain the required symlinks;
enumeration never follows entry targets. Metadata before/after and final pathname
comparison detect observed changes only. No atomic directory snapshot, ancestor
confinement, invisible-mutation detection, subsequent file-open anchoring, hard
wall-clock timeout or dirty-NIF caller-kill cancellation is claimed. A hung
filesystem syscall can retain its dirty scheduler and descriptor.

These fixed bounds are candidate support/safety limits, not dbus-daemon limits.
Permission checks and flags are qualified only by the recorded static/runtime
evidence. Pinned Linux/glibc/OTP is the supported platform; other libc/architecture
qualification is absent. Service parsing, anchored file reading, aggregate
consumer budgets, precedence, publication, activation, release and rollback are
separate later scopes. Full P08/P09/P10/M1 acceptance remains open.

## Completed primitive checks and retained failure

The three production files and new directory test implement this contract.
Saved parent execution uses OTP27.3.4.6/Elixir1.17.3, explicit private sockets,
MIX_ENV=test and ERL_FLAGS=+S4:4. These overlapping selections are not summed.

- [x] Unchanged-source RED13/13 (exit2), with all58 candidate10 sources unchanged.
- [x] The unchanged test then passes13/0; affected Unix/Peer selection passes44/0.
- [x] Native/Elixir warnings-as-errors compile and final scoped format checks pass.
- [x] Independent specification and quality reviews pass with no source findings.
- [x] Mechanical projection preserves existing socket/rights functions and stubs.
- [x] Immutable candidate11 binds59 sources,69 artifacts and47 source/BEAM mappings.
- [x] Frozen-artifact UID1000/GID100 permission refusals are EACCES13;32 measured
  refusals preserve the process FD count18 to18. Profile enumeration is recorded.
- [x] Earlier candidates and failed evidence are preserved; final accounting,
  documentation and saved-evidence review are recorded in this scope's reports.

The separate candidate11 security refresh failed at RES-03:21 selected/executed,
20 passed,1 failed,0 skipped/blocked. Its burst completes32 operations of each
kind, but the resource snapshot has connections5 to6 and one extra registered
UID1100 Peer belonging to the burst actor. FD count30 to30, reservations0 and
all other resource counters0 do not resolve that mismatch. All13 owned process
exits are0 and VM poweroff is observed. The snapshot alone cannot distinguish
incomplete cleanup observation from persistent state retention.

`candidate11-security-failure-triage.json` preserves17 exact guest export files
under `candidate11-security-refresh/security-vm-failed-evidence/` and verifies
their candidate/source/fixture binding. The broad gate remains FAIL; prior
candidate10's21/0 is historical evidence. Per the user's scope rule, no RES-03
source/fixture repair or further runtime qualification is part of this primitive
completion. No full candidate security/native-platform acceptance is inferred.

Completion records: `directory-completion.json`,
`directory-final-preservation.json`, and
`directory-saved-evidence-takeover-review.json`. Readiness stays L0; the full
Foundation goal remains active.
