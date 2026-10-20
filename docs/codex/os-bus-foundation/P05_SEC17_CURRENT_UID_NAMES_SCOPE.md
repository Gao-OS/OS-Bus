# Current-candidate UID-name cleanup preparation

Task: `sec17-current-uid-names1` (direct static preparation).
Worktree: `/data/development/Gao-OS/OS-Bus/.trees/os-bus-foundation`.
Branch/baseline: `codex/os-bus-foundation` / `7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4`.

## Exact scope

The new `scripts/foundation/uid_names_current/test.nix` only imports the unchanged
`scripts/foundation/m1_uid_abrupt_peer/test.nix` with explicit `selection = "uid_names"`
and the exact candidate bindings below. It selects only `owner_down_promotes` and
`queued_down_reclaims`. There is no new guest fixture, policy, helper, workload,
assertion, API traffic or rights/fault case. The existing runner, contract, launcher,
inherited inputs and private guest socket remain authoritative.

This is ordinary process-cleanup testing on the current code with the legacy private
fixture. The launcher clears `config_file`, `inherited_listener` and `lifecycle`, then
uses the existing private policy overlay and limits. It does not qualify installed
XML policy parity, complete SEC17, FD coverage, milestones, H01, precommit or product
acceptance. Readiness remains L0/product false.

## Frozen binding

The initially requested `resume-20261019/xml-doctype-candidate/candidate.json` does
not exist. Parent explicitly corrected the path to the unchanged existing directory
`test/reports/foundation/resume-20261019/sec17-xml-preparation1/normalized/candidate`.
This is a preparation path correction, not a source/runtime retry or regenerated
candidate. The original fixture's `fetchTree` and inherited lock provenance are
unchanged; future resolution must use the offline cache or stop.

- Artifact: `b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1`.
- Candidate manifest: `fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82`.
- Source aggregate: `f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c`.
- Runtime origin manifest: `6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5`.
- 71 current production sources; 57 source-to-BEAM mappings covering 61 BEAMs;
  80 runnable files. All actual source and artifact bytes are checked in static pins.

The authority/guest/host bounds remain 60/120/900 seconds. The original 1000 ms
request, settle, health, kill-readback and DOWN bounds and shutdown 5 seconds /
absence 1 second are unchanged. The reviewed owned-descendant host lifecycle
implementation is reused with timeout 900 seconds and cleanup 5 seconds; it does
not enumerate unrelated host processes.

## Reviews and parent-only next steps

Evidence directory `E` is
`test/reports/foundation/resume-20261019/sec17-current-uid-names1`.
Only parent may execute the prepared entrypoints. Before preflight, require fresh
spec and independent quality reviews of this exact preparation. Each creates
`E/spec-review/VERDICT.json` or `E/quality-review/VERDICT.json` with
`verdict: "PASS"` and `preparation_sha256` equal to the actual `E/PREPARATION.json`
SHA256. A changed preparation requires fresh reviews. Reviews are not provided by
this worker.

1. `python3 E/preflight.py` (replace `E` with the directory above).
   This creates `preflight1` once, dry-runs only, inspects every scheduled derivation,
   its selected outputs, sources and builders, and queries cached requisite closures.
   No realization. Offline, empty substituters, sandbox true and no IFD apply to the
   driver plan. Unexpected derivations, missing inputs, downloads or uncached
   toolchains stop the stage. Do not retry or rewrite provenance to proceed.
2. Parent reviews the actual plan and writes `E/PARENT_PLAN_REVIEW.json` with
   `verdict: "PASS_PARENT_PLAN_REVIEW"`, actual `preflight_sha256`, exact
   `scheduled_derivations`, `missing_selected_outputs: []`, and
   `no_uncached_toolchain_or_download: true`.
3. `python3 E/run_build.py build1`. One offline, sandboxed, no-IFD build with empty
   substituters (600 seconds), bound to that parent-reviewed plan. Pins the driver
   files and symlinks; executes no guest or VM.
4. `python3 E/run_vm.py vm1 build1`. One isolated VM only, with input and driver
   pins checked before and after; uses the unchanged reviewed owned lifecycle.

No alternate selector, `all`, `uid_matches`, new build/VM attempt, retry, fourth
attempt or broader authority is granted. Prior denials and no-retry boundaries
remain closed. SEC17 counters are separate: no SEC17 exhausted counter was received;
this static preparation consumes no repair or runtime attempt. H01 VM Sol2 and
source-builder Sol2, closed authorization/P10 counters and all other counters are
unchanged.

## Static acceptance and verification boundary

Create only the wrapper directory, this scope file and `E`. Verify Python syntax
by AST parsing, Nix syntax by `nix-instantiate --parse`, exact bindings and source,
fixture and runnable-file hash/mode readbacks. Record frozen source pins, static
receipts and `PREPARATION.json`. Do not run preflight/evaluation, realization,
Git, Mix, compilers, tests, helpers, actors, VMs or network operations in this task.
The repository precommit requirement is unrun/BLOCKED_SCOPE for this explicitly
static worker task; parent owns later required validation. No commit, publication,
host-bus, account/configuration or memory edits.
