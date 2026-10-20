# Current-artifact SEC09–12 functional adapter

This recipe reuses the historical `m1-sec09-sec12-complete1/source1/fixture1`
collector, 23 cases per backend, actors, diagnostics, deadlines, independent
requirement gates and cleanup. It adds no production code or qualification gate.
Historical files remain untouched. The copied `contract.py` candidate/source
digest assignment, 98 existing `rules.conf` bus-method rules, two UID1102 reply
denies and `run.py` native serial-count/deadline/persistence/daemon-channel code, collector persistence, launcher
logger/provenance, copied XML daemon safety setup and expected provenance change;
the other 22 fixtures are checked for
identical bytes, modes and hashes, and all 80 runnable product files are preserved.
One daemon-only file-channel helper is added to the copied fixture directory.
The original corpus manifest pins all 29 input fixture files.

`normalize.py` verifies XML artifact manifest `b77d142e…`, frozen runtime `6077a50d…`
and corpus manifest `992aa6de…`, then emits the legacy candidate metadata schema
and records the input hashes/modes, normalized hashes, all seven patched fixture
hashes with before/after reversible-change provenance, and the added helper hash
in `bindings.json` (adapter revision10).
It never imports the corpus or starts a bus. Current immutable
artifact pins replace historical candidate18 and `_build/test` assumptions.

Authorization VM1 failed before the first actor: reference `dbus-daemon` reported
`On element <allow>, if you specify a member you must specify an interface or a path`.
The source1 XML omits both on bus-method rules. Revision2 adds only
`send_path="/org/freedesktop/DBus"` to the 90 existing allow and 8 existing deny
rules with destination `org.freedesktop.DBus`, type `method_call`, a member, and
no interface/path. That is the actual bus-method path used by the fixture; it
narrows both grants and denials consistently without adding a rule, case or
changing an expected result. Both backends consume the same corrected XML bytes.
The adapter asserts the exact counts and proves that removing those inserted
attributes restores the original XML bytes. Historical XML and VM1 raw failure
remain unchanged; the fresh XML hash is recorded explicitly.

Authorization VM2 started the reference daemon with the corrected XML, then
stopped with `AssertionError()` after one operation and before collecting any
case; all eight requirement gates were blocked. Its saved first operation
contains daemon serial 7 on two outgoing connections: an `AccessDenied` error
to ordinary peer `:1.1` and a successful `GetId` reply to receive-denied peer
`:1.4`, both replying to serial 6. The strict historical `bus_serial_count()`
deduplicates daemon serials across destinations and rejects that collision.
This is a fixture-accounting failure; the observed denial had no service
delivery, and VM2 provides no completed conformance result.

Revision3 changes exactly one assignment in copied `run.py` to call
`bus_serial_count(value['window'])` only when `backend=='gao_bus'`, recording
`'UNSUPPORTED'` for the reference backend. Only GaoBus uses that native count
for `serial_advance()` recovery. The strict historical counter, ordered windows,
connection identities, health checks, denial/no-delivery checks and requirement
gates remain unchanged. The adapter asserts one original assignment match and
exact reversal, and records `run.py` input/output hashes, sizes, modes and both
assignments in `bindings.json`. Historical runner bytes and VM2 raw reports
remain unchanged; fresh collection and all eight gates still require execution.

Build4 passed, but VM4 exhausted its 1536 MiB guest before exporting evidence.
The 16 GiB evidence disk mounted successfully. The kernel task table identifies
the reference Python evidence worker at 1235 MiB RSS and dbus-daemon at 260 KiB;
the collector's cumulative checkpoint copies and JSON serialization need more
RAM. The recipe now provisions 8192 MiB for these retained evidence graphs and
the collector's coexistence with later workers. This changes only disposable
VM capacity: the product, actor corpus, assertions, daemon resource bounds,
disk, two cores and fixed deadlines remain unchanged. VM4 remains a failed
environment attempt; sufficiency of the new capacity requires a fresh run.

VM5's larger guest exported evidence without OOM, then stopped before any gate:
15 cases and 20 operations completed. Its failed checkpoint response took
11.921627 ms and was successful; all 1899 journaled responses were successful,
with maximum recorded network time 85.408341 ms. The assertion checked the
one-second response deadline after writing its diagnostic journal. Revision4
evaluates that unchanged assertion before disk I/O and writes the same row in
`finally`, including on assertion failure. Journal latency and scheduler delay
were not separately measured in VM5. Four deterministic controls reproduce the
old failure and check timely, late and error responses with journal retention.

Only the copied backend and qualification persistence calls switch to compact
JSON. They preserve decoded values, sorted keys, newline and atomic replacement;
candidate/source hash serializers are unchanged. The adapter records exact
reversible changes for both files. All one-second request, health and settle
checks and the 360/480/490/900-second whole-run bounds are retained. VM5 remains
failed with all eight requirement gates blocked; revision4 needs fresh execution.

VM6 collected all 23 reference cases and its first independent SEC-09 gate exited
0 naturally. That gate finished at monotonic 378.333546605 with the unchanged
shared deadline 381.849285098; collection subsequently stopped with
`AssertionError()` and seven gates blocked. The saved backend checkpoint was
633,496,065 bytes and the qualification report was 633,572,271 bytes. These
results do not qualify the unexecuted gates or the GaoBus backend.

Revision5 removes only four accumulating full-graph checkpoint calls in the
copied scripts: after operation/case append in `run.py`, and after backend append
or each gate result in `collect.py`. All graph mutations remain in memory.
Backend initial, exception, cleanup-finally and final checkpoints remain; the
collector retains initial, final and exception checkpoints. Per-request JSONL
journals still write synchronously, including on response-boundary failure.
Compact encoding and atomic replacement remain unchanged. This reduces repeated
serialization inside the shared budget; runtime sufficiency still requires a
fresh root-owned execution. No bound, identity, expectation, validator, gate
process, corpus or production source changes.

Seven pure controls cover the existing response/journal boundary, decoded
success/failure checkpoints and failed-gate counts. AST comparison verifies that
the copied guest programs differ from VM6 by only those four calls, preserving
all deadline expressions and result mutations. The controls compile only the
isolated persistence functions and synthetic control flow; they never import
the guest corpus or start daemons or gates. Run them from the repository root:

```sh
python3 -B scripts/foundation/authorization_current/test_normalize.py -v
```

Before images, exact reversible patches and control results are retained under
`test/reports/foundation/resume-20261019/authorization-persistence-repair1/`.

VM7 collected all 23 reference cases and ran its four actual requirement gates.
GaoBus then failed at copied `launcher.exs:12`: `logger_std_h` rejected the binary
`SEC09_SEC12_LOG` file path with `{:invalid_config, :logger_std_h, %{file: ...}}`.
VM7 remains failed; collection and gate execution do not imply passing gates.

Revision6 converts only that environment value with `String.to_charlist/1`.
The installed pinned OTP 27.3.4.6 `logger_std_h.erl` documents `file:filename/0`
and checks `is_list(File)`. The handler identity, `:ok` assertion, level, file
type and formatter remain unchanged, as do every XML rule, case, oracle, bound
and all production bytes. The launcher original SHA is pinned to
`e7836b4136a37adca89e1ef5d9ba97ebb6bb5bd4d79e22963aa0e59985d11ae6`;
the adapter asserts one substitution, exact reversal and records its before/after
pins and expressions in `bindings.json`.

The file-only control `test_logger.exs` evaluates only the launcher handler
statement in a separate pinned Elixir 1.17.3/OTP 27 BEAM and temporary directory.
Original binary-path RED reproduces the rejection; corrected charlist GREEN
adds the handler, preserves its settings, writes a marker, syncs and reads the
file. It starts no bus, security actor, gate or VM. Before-images, the OTP contract,
exact patch, command results and source checks are retained under
`test/reports/foundation/resume-20261019/authorization-logger-repair1/`.
Runtime collection and requirement results still need root-owned execution.

VM9 used the frozen XML candidate (revision7) and completed 23 reference cases.
Its SEC09/10/11/12 gates exited 0/1/0/0; the failed SEC10 correlated-return/error
observations remain failed. GaoBus then rejected startup with
`{:inconsistent_safety_limit, :global, :frame_bytes}` before any actor or case.
The XML fixture inherited a pre-XML `GaoBus.Limits.defaults()` application
override: its global frame budget was 16,777,216 bytes while omitted XML limits
allow a 33,554,432-byte message. The uid/peer frame and ingress/egress budgets
also conflict. Small XML limits cannot retain the legacy egress budgets because
generated output reserves the protocol maximum of 134,217,728 bytes.

Revision8 clears only that legacy `:resource_limits` override in the copied
same-XML daemon. Production derives finite safety budgets from the unchanged XML
and continues to reject inconsistent explicit overrides. Ready evidence reads
`GaoBus.Limits.snapshot()` and reports its actual `limits` map. The copied
transformed daemon SHA changes from `24aa74ef…` to `3c27c3e2…`; both launcher hash
checks and its emitted provenance, plus `PROVENANCE_EXPECTED1.json`, follow the
effective bytes. Historical fixtures and the inherited non-XML daemon stay intact.

The changed capacity derivation is explicit: peer/uid/global frame budgets are
33,554,432/67,108,864/134,217,728 bytes; ingress budgets are
166,723,584/333,447,168/666,894,336; egress budgets are
267,386,880/534,773,760/1,069,547,520. All other safety metrics use the existing
XML-aware runtime derivation, including connection ceilings. VM9's invalid
legacy overrides never reached a running Gao authority. No XML, policy, corpus,
oracle, validator, request deadline or whole-run bound changes. Ten pure adapter
controls cover the existing seven cases plus exact XML-only substitution,
unexpected-input rejection and effective provenance. These controls do not start
a bus or establish runtime qualification. Before-images, RED/GREEN results and
the frozen input/output pins are retained under
`test/reports/foundation/resume-20261019/authorization-xml-safety-repair1/`.

From the repository root, build the disposable VM driver:

```sh
nix-build scripts/foundation/authorization_current/test.nix -A driver \
  --argstr artifactPath "$PWD/test/reports/foundation/resume-20261019/xml-doctype-candidate" \
  --argstr runtimeManifestPath "$PWD/test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec16-complete1/candidate1/candidate.json" \
  --no-out-link
```

Run the resulting `bin/nixos-test-driver --no-interactive -o OUTPUT
--junit-xml JUNIT`, with fresh output locations and the existing root lifecycle
recorder. Runtime remains root-owned. Evidence exports to
`authorization-current-evidence/`, including `current-bindings.json`, collector
output, raw backend observations and exact eight requirement gate exits.
`authorization-current-vmoff.json` records endpoint removal and VM shutdown.

Successful collection can preserve failed requirement gates. VM exit 0 or green
JUnit means collection/cleanup succeeded; inspect `qualification.json` counts
and `backends[].gate_commands` for actual conformance outcomes. The unchanged
collector requires 46 case observations, eight executed gates and zero skips;
failed rows remain failed. This adapter claims no product qualification.

Revision8 passes all ten pure controls and file-only normalization using pinned
immutable inputs. The earlier revision6 isolated logger control remains saved
evidence. No build, daemon, actual security fixture, gate or VM was run by this
implementation worker. Root owns runtime checks and saved-raw review.

VM10 reached Gao ready/handshake, then missed the one-second common settle
deadline on the second snapshot before the first case action. Its first complete
snapshot was 367849 bytes; the final raw log contains a 64746-byte unterminated
second snapshot. The inherited daemon channel only drained stdout during reads
and after shutdown waits/signals. The daemon failed natural retirement and
required SIGKILL. That wait-before-drain coupling can prevent the synchronous
snapshot emitter from consuming quit/EOF. The saved evidence does not isolate
the initial one-second miss between generation, serialization, scheduling, I/O
and parsing; revision9 does not claim to fix that primary latency.

Revision9 captures only the Gao daemon's stdout/stderr directly into its regular
raw evidence file. `daemon_channel.py` tails that file with the inherited
LF/FIXTURE JSON protocol and 4 MiB line bound; raw bytes are written once by the
child, including incomplete output. Its fixed read deadlines and stop
EOF/TERM/KILL sequence remain unchanged. The copied runner changes only its
daemon import/construction beyond the previous reversible adaptations. Actor
channels and `cleanup.py` remain byte-identical. The helper source is embedded
in the adapter so the existing single-file Nix entrypoint includes it, and its
exact output hash is recorded in `added_helpers`.

The sealed SEC10 reference diagnosis found that UID1102's default-false reply
denies match unsolicited replies only; they do not express the fixture's
correlated-reply denial expectation. Revision9 adds
`receive_requested_reply="true"` only to its existing method_return and error
deny rules. The two insertions are exactly reversible and recorded separately
from the 98 bus-path attributes. All original negative, AccessDenied,
correlation/pending, third-party/repeated-reply and positive-control assertions
remain unchanged. Both backends will consume the same corrected policy; no
corrected-policy runtime result is claimed.

The first offline construction attempt failed because copying immutable fixtures
preserved directory mode `0555`. Round2 temporarily adds owner-write only to
that copied output directory while creating the helper, then restores the exact
original mode in `finally`, including on creation failure. Original fixture
modes never change; bindings record the copied directory's before/after modes.

Twenty-two offline controls pass: the original ten, two exact reply-policy
controls, eight transport/cleanup controls with harmless Python stdout stubs,
and two copied-directory construction controls. Saved large snapshot bytes
reproduce the old pipe's failed five-second natural retirement; direct-file
capture preserves their exact bytes and retires naturally. A genuinely stalled
stub still fails natural retirement and requires containment. Other controls
cover frame order/remainder, partial timeout/resume, EOF, zero deadline, line
limit and the unchanged stop sequence. They import no guest program and start
no bus, actor, requirement gate or VM. Before-images, both RED phases, GREEN
results, original construction failure, normalized output and bindings checks
are retained under
`test/reports/foundation/resume-20261019/authorization-channel-policy-repair1/`.
VM1–10 evidence remains unchanged; fresh root-owned execution and raw review
are still required for runtime conformance.

Revision10 preserves VM11's full-state observations and fixed deadlines while
removing the copied daemon's explicit JSON flatten/prefix binary allocations.
The emitter passes the existing OTP JSON iodata directly to Unicode-safe
`IO.puts`. It uses the same encoder, complete fields, prefix and newline; no
deduplication, cache, transport references or custom JSON encoding is used.
Launcher checks and provenance bind the exact resulting copied daemon.

Fixture-only timings prepare a later root-owned run to allocate the unexplained
VM11 latency. Requested snapshots record `capture_ns`, `encode_ns` and `write_ns`.
Capture includes the unchanged full-state reads/conversion and the nested native
FD-readback event emission. Records stay in the command-loop accumulator and
flush in order as separate `FIXTURE_TIMING ` lines only at EOF, with a zero-based
`snapshot_index`. The existing finite workload and 128-read settle limit bound
their number; there is no sampling or additional target operation. Abnormal
termination before EOF can lose buffered daemon timings.

The daemon channel buffers `read_ns`, `decode_ns`, `total_ns`, decoded status
and event name for each read, including failures. Read time includes polling,
frame assembly and ignored log lines. Decode time covers the selected line's
UTF-8/JSON conversion and small result bookkeeping; it is null when decoding
was never reached. Controller timers wrap the existing external-FD observation
(including its snapshot hash) and state-key computation, preserving their
return values and exceptions. Existing initial/failure/final persistence points
write these small lists to separate `phase-timings.json`. Snapshots, state keys
and `backend.json` receive no timing fields. No instrumentation time is
subtracted from the unchanged1000ms/128reads or other deadlines. Durations are
local clock differences, not comparable cross-process absolute timestamps.

New offline controls execute only extracted emitter/timing closures with saved
events, Unicode/escapes/nested values, and a pure snapshot stub. They compare
exact output bytes and decoded values, check syntax of the full copied daemon,
and exercise unchanged failure/deadline behavior with deterministic clocks.
They do not establish a runtime speedup or qualify SEC09–12. Evidence for this
round is under `test/reports/foundation/resume-20261019/authorization-snapshot-repair1/`;
fresh build/VM execution remains a separate root decision.
