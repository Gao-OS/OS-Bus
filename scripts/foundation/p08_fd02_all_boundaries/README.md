# FD02/core each-relevant-boundary static fixture

Static preparation only. No new capture, Python execution, syntax check, tests,
build, broker or VM has run. Runtime/index qualification remains NOT RUN and
full P08/M1-M4 remain unqualified/readiness L0. This is not a release.

Every invocation derives the incomplete offsets from the actual fresh Resource100
frame: 1..frame_bytes-1. Both arrival modes run on fresh isolated Gao/reference
core backends. Each offset has two backend invocations and four mode observations;
the overall selection still has two logical backend combinations. At offset1 both
ancillary arrangements use its single nonempty byte, with no empty plain send.
Geometry must match across the two modes, both backends, and every accepted batch.

The actor uses real SCM_RIGHTS and the unchanged singleton PIPE/EOF and EBADF
helpers. The controller samples a matching retained broker FIFO before and after
strict target health112, while the suffix remains withheld. No source or target
output may precede that probe. Finish sends only the remaining bytes with no new
rights, then validates full wire, sender/destination/body/index/right and warmed
numeric recovery; Gao additionally requires exact buffered-byte/FD credits,
configuration and scalar recovery. Reference uses kernel inventories.

The unchanged singleton lifecycle's pinned 20-node active range is replaced by
the explicit two-mode barrier sequence. Its full report oracle is replayed with
the private socket expectation. Only the reference XML listen address and native
configuration socket differ; all accepted policy and limit bytes are retained.
Private addresses are `/run/osbus-fd02-all-boundaries/case-<offset>/bus`.

`batch.py` packs at most eight fresh controller/backend invocations in one
physical guest. Its absolute deadline is 120 seconds for the entire batch;
remaining time is passed to each child wait. Standard input is DEVNULL, the
current pinned guest Python runs with `-B`, DBUS variables are stripped, child
groups are owned, and per-case stdout/stderr/reports survive failure. A timed-out
controller is killed/reaped; independently grouped broker containment requires
the disposable VM shutdown. No cleanup success is invented. Nix exports all
non-socket evidence and requests VM shutdown in nested finally blocks. The parent
retains its 900-second host bound and verifies actual shutdown.

Static proposed deadline repair1 (NOT RUN): case oracle completion and full-batch
replay completion now check the same absolute deadline. The saved report remains
running while a separate in-memory passed candidate undergoes complete replay.
Final passed serialization, persistence, persisted readback, summary serialization
and return each check elapsed time; late completion rewrites failure evidence and
raises. Deterministic mocked-clock controls exercise the real batch flow crossing
120 during final case validation, full replay and final serialization, plus late
persistence/readback/summary controls and an inside-bound positive. These controls
mock child transcripts, do not start a broker, and do not replace full-oracle tests.

Parent execution API, after review and execution reservation:

- Nix arguments: `candidatePath`, `scopePath`, `freezePath`, `first`, `count`.
  Starts are 1,9,17,...; each count is `min(8,N-first+1)` and the final count is
  explicit. The first successful actual report establishes N. No current value
  of N is claimed by this unexecuted fixture.
- Controller: existing shared `--candidate`, `--fixtures`, `--wire-dir`,
  `--helpers`, `--quota-daemon`, `--collector`, `--reference-executable`,
  `--scope`, `--reuse-fixtures`, plus required `--freeze` and `--boundary`.
  `--evidence` must equal that boundary's private case directory.
- Batch: the same input arguments, with `--first` and `--count` instead of
  `--boundary`/`--evidence`. Writes `/run/osbus-fd02-all-boundaries/batch.json`.
- `plan.batches(actual_geometry)` provides the complete explicit batch plan.
  `plan.assert_batch(batch,case_reports,qualify.assert_report)` replays every
  full oracle; `plan.assert_coverage(entries,qualify.assert_report,host_receipts)`
  requires exact unique `(boundary,backend,mode)` coverage, matching geometry and
  freeze, and fresh process instances within each guest. Nothing is inferred
  from a claimed count alone.

Freeze JSON uses schema1 and scope `FD02/all-boundaries/core`, candidate manifest
digest, `guest_inputs` (the unchanged 19 captured roles plus `batch` and `plan`),
seven `reused_inputs` filenames, and `broadcast_actor_sha256`. Every input/reused
role has exact `sha256` and integer permission `mode`; paths are recorded by the
controller. The freeze file is separately hashed and does not hash itself.
Pinned inputs, modes and candidate inventory must pass preflight before launching
either backend, and before/after captures must remain equal at completion.

Offline controls API: `python3 -B actor_test.py` uses socketpairs only;
`python3 -B oracle_test.py --inputs <19-role-map.json> --freeze <freeze.json>`
replays complete deliberately synthetic reports against real pinned files.
Prepare the role map in the offline environment; its bytes/modes must match the
parent freeze. No synthetic report is eligible as runtime evidence. Offline
children remain bounded to 60 seconds by the parent. Tests include every split,
both real ancillary positions, offset1, changed destination geometry, actual
last-send mutation, invalid offsets, complete-report coherent FIFO/body/ancillary
faults, health/order/provenance/configuration/closure/recovery/teardown faults,
batch completeness/counts and process/receipt controls. These checks are NOT RUN.

Host receipt API: one parent-sealed receipt per accepted batch, containing unique
`vm_id`, `sealed: true`, `shutdown_confirmed: true`, `host_seconds: 900`, measured
positive `elapsed_seconds` at most900, `batch_first`, and the exact exported
`batch_sha256`. Guest `physical_vm_count` is null. Only receipt-backed coverage
returns a physical VM count; absence of host receipts leaves that count null.
Receipt authenticity/adoption belongs to the parent evidence seal.

Eight invocations were chosen from the parent's accepted partial-body timing
10.05s each: 8*10.05=80.4s, nominal margin39.6s. This is an engineering estimate,
not a timing result for these new sources. If the fixed bound fails, preserve the
failure and request a bounded review; never increase a timeout or skip coverage.
Independent ordered specification then quality review, final parent freeze and
serialized disposable VMs remain required. Existing historical and release
blockers are unchanged. Header/body index evidence and ledgers are parent-owned.
