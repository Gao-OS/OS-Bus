# Current SEC04 authentication-state adapter

XML-candidate source preparation, adapter revision4. File-only
normalization and original pure contract controls are recorded in
`test/reports/foundation/resume-20261019/xml-functional-rebind1/`.
Nix evaluation/build, native compilation and fresh daemon/client/VM execution
for this XML candidate are NOT RUN. Earlier retained runtime used the
pre-XML candidate and does not qualify these new pins. Root owns builds,
serialized VMs, raw-runtime review and adoption. Readiness remains L0 and
product_qualified=false. Existing fixture repairs and all functional
assertions, policies, corpora and numerical bounds are preserved.

The donor is the complete fixture actually accepted by
`test/reports/foundation/continuation-20261011-full-goal/environment/m1-res01-measurement1/ROOT_SEC04_COMPLETE_ACCEPTANCE1.json`,
SHA256 `8314c808d0e29f0ec8500615d63c069bb72372ff1086f6009b4081ec90e3ee86`.
That record has status `ADOPTED_COMPLETE_CURRENT_SEC04_CORE`, independently
reviewed, two selected/executed/passed combinations, zero failed/blocked/skipped.
It binds `m1-sec04-complete1/source1`, not the later source2/source3 preparations
whose manifests say `all_targets: NOT RUN`. No source4 directory was present.

The donor directory is
`test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec04-complete1/source1/fixture1`.
Its 20 files match the accepted source1 `SOURCE_MANIFEST1.json`, SHA256
`d574c6b62b7c6fa3005b1170286bbc2d0dd619457c22f7a50eb131cf6757c206`.
The original donor `run.py` has SHA256
`a61cdc9721d307fe64c998b6ff9b2ea951171d60bdf7db2642025b13e80e6c53`;
the original `contract.py` has SHA256
`04f3291fa4b5d54203ba00ec6de74acc91c02810c691f006f6c7ac4c0084745e`.
Saved-file metadata inspection confirmed all 20 donor files against the manifest;
this was not fixture execution. The accepted historical runtime covered candidate18;
it does not qualify the current candidate.

`test.nix` accepts `candidatePath`, `artifactPath` and `runtimeManifestPath`.
Root supplies the existing normalized candidate at
`/nix/store/9v44l2apb02b7c478dfia5ml7ak8crvn-osbus-authorization-current-inputs/candidate`.
Exact current pins are:

- Candidate manifest: `fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82`.
- Candidate source map: `f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c`.
- Artifact manifest: `b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1`.
- Origin/runtime manifest: `6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5`.

The adapter checks the 71 source-map entries, 57 source mappings/61 BEAMs,
80 runnable files, modes, runtime anchors and byte equality to the current
artifact. It uses the candidate without changing its product bytes. It verifies
all 20 immutable donor files before copying them. The copied contract's two
manifest/source digest assignments are rebound to this XML candidate. The
preserved revision3 repair changes one exact request block in copied `run.py`: retain revision2's captured
read-completion time, unchanged inclusive deadline and response `ok` assertions,
and append the original receipt schema in `finally`, removing only revision2's
per-request `persist()` call. Receipt elapsed time uses captured read completion.
This avoids a full-graph write inside every snapshot request's shared one-second
settle clock. All initial, settle-finally, case, positive, exception, teardown
and final persistence calls remain byte-identical at their original boundaries.
The complete in-memory receipt graph, including returned late or `ok=false`
responses, is saved by those success/failure boundaries. No journal or new
persistence mechanism is added. This does not promise per-request durability if
the entire controller is forcibly killed before an existing persistence boundary.
All numerical bounds and other source bytes remain unchanged. Full byte
reversal is checked separately for both copied files; the other 18 files retain
exact bytes and read-only modes. All 20 original donor files remain untouched.
The copied old `test.nix` remains provenance. The adapter records revision4,
input pins and both exact reversible before/after changes in `bindings.json`,
and rejects optimized Python or invocation without `-B`.

The finite corpus remains five cases per backend: `direct_begin`, `wrong_uid`,
`anonymous`, `challenge_cancel` and `unsupported`. Each sends premature `BEGIN`
followed by the original five-operation tail: Hello, service ownership,
privileged ownership, a forbidden delivery and ReloadConfig. The contract still
requires actual closure without normal bus entry, no ownership/delivery effects
and no fabricated credentials. Both backends retain two positive EXTERNAL
controls (`plain`, `discovery`), real UID/GID1101 clients, the persistent
UID/GID1100 observer, and eight actors per backend (16 total). Observer
identity/incarnation, names, bus ID and full external FD projections, native
resource recovery, natural retirement and private-endpoint cleanup are unchanged.
Router serial and SEC13 whole-authority state remain outside this corpus's
observation claims. The inherited launcher still receives `SEC04_ORIGINAL`
from `run.py`.

The reference is pristine pinned dbus1.14.10, with no patches or separate
embedded upstream-test prerequisite. The disposable guest retains root
ownership, two real UID/GID accounts, a regular mode0444 isolation marker,
private `/run/osbus-security/sec04-complete/{reference,gao_bus}/bus` endpoints,
1536MiB RAM and two cores. A size-checked 16GiB empty guest disk at `/dev/vdb`
holds evidence under `/run/osbus-security`. Direct export preserves basename
`sec04-complete` beneath `auth-bypass-current-evidence`, avoiding an extra
in-memory evidence copy. No host configuration changes are involved.

All original bounds remain: authority60s, guest120s, host900s, cleanup5s,
startup10s, ordinary request1000ms, attack2000ms, authentication1500ms/idle500ms,
settle1000ms/128reads, poll50ms and observer30s. Guest transport waits130s for
the original120s command timeout and3s termination grace. The wrapper exports
runner output/status, full original evidence, current bindings and
`auth-bypass-current-vmoff.json` with VMoff/socket-removal observations.

VM1's reference backend failed at the post-persistence deadline assertion during
a shared settle window: 2 selected / 1 executed / 0 passed / 1 failed / 1 blocked
/ 0 skipped, with Gao unrun. Its final returned `GetNameOwner` response was
`ok=true` with receipt elapsed1.727314ms; shutdown had no errors and VMoff/socket
removal were true. The saved report does not contain the absolute caller deadline
or read-completion timestamp, so it cannot independently prove remaining shared
settle budget at that read. Source order and deterministic controls establish
the measurement defect; a fresh VM run must establish current runtime behavior.
The original inclusive deadline and response assertions are both preserved,
and request `finally` appends receipts for either assertion failure; existing
enclosing persistence saves them.

VM2 revision2 again failed reference after four of five cases, with seven
actors retired, at `remaining(limit)` during settle's `GetId` snapshot request
before its read. Root reported 37.672978 seconds and the same raw counts:
2 selected / 1 executed / 0 passed / 1 failed / 1 blocked. This demonstrates
that protecting one response's verdict alone did not remove per-request
full-graph writes from the unchanged shared recovery window. These VM2 facts
are supplied by root; this source repair did not execute or re-review the VM.

Run the focused controls with
`python3 -B scripts/foundation/auth_bypass_current/test_normalize.py`.
They execute extracted donor request/call/snapshot/settle functions and the
original enclosing exception/teardown blocks with fake clock, channel and
absent processes. No native clients, sockets or daemons are started.
`SEC04_TEST_UNPATCHED=1` deliberately selects the original pinned controller;
its expected failing results do not supply backend evidence. Before-images,
revision2 red controls, revision3 green controls and exact single-call removal
proof remain in the scoped repair evidence directory.

Root must use fresh output directories and preserve every failure.
Current expected selection is two complete SEC04/core
combinations and ten case/backend pairs; execution/passing remain unmeasured
until root runs and reviews them. This does not adopt an index row or qualify
network, installed-system, M1 or the product: readinessL0,
product_qualified=false. Actual denied SEC06/FD04 actions remain blocked and
are not part of this adapter.
