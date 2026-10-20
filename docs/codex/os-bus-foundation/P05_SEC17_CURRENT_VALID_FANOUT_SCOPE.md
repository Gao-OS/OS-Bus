# Current-candidate valid negotiated memfd fanout: static preparation

Task `SEC17-CURRENT-VALID-FANOUT1` prepares one existing valid negotiated memfd fanout workload against the current frozen development artifact. This assignment authorizes static preparation only. Readiness remains L0 and product qualification is false.

## Frozen behavior and identity

The original `scripts/foundation/p08_fd_fanout/{actor.py,qualify.py,oracle_test.py}` bytes, assertions, private policy, helper implementations, and workload behavior remain unchanged. The new `scripts/foundation/fd_fanout_current/workload.json` changes exactly `candidate` and `candidate_manifest_sha256`; all other parsed values remain identical. A small Nix metadata adapter copies the original actor, qualifier and oracle unchanged into an immutable fixture with this workload. It retains the original guest qualifier command and existing helper/runtime closure. It adds reviewed graceful VM-off/socket-removal evidence and a 900-second global timeout.

The candidate is `test/reports/foundation/resume-20261019/sec17-xml-preparation1/normalized/candidate`:

- Manifest SHA256: `fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82`.
- Production source aggregate: `f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c`.
- Artifact manifest SHA256: `b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1`.
- Runtime-origin manifest SHA256: `6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5`.

The pins cover 71 production sources, 57 source-to-BEAM mappings representing 61 BEAMs, all 80 runnable files and their actual read-only modes, original declared modes, native `.so`, root `devenv.lock`, the complete copied original helper directories, reviewed runner donors and lifecycle helper. Directory inventories reject added or removed copied files. Shared status/compatibility/evidence ledgers are not runtime inputs.

## Selected valid workload

Four independent actors use the original roles: source and observer UID0, fast UID1100, slow UID1101. Three valid directed warmups precede one 196608-byte `Hold` broadcast carrying one negotiated memfd; exactly fast and slow match. The fast recipient receives the complete frame and retains its memfd; slow uses the original 1024-byte send buffer and stalls with one admitted pending output. Original source-then-slow cleanup is observed by acknowledged BEAM `DOWN` monitoring before the original 5000ms writer deadline. Fast rereads the same retained resource after both cleanups, then releases it. The original complete-frame, exact-prefix/right/EOF, resource identity, global/UID/Peer accounting, health/final fences, authority continuity, actor/daemon inventory and normal owned-child cleanup assertions remain intact.

Original bounds remain: healthy/cleanup 1000ms; three warmups, one broadcast, two admissions, one full/one partial disposition, two kill events, two retained reads and three health checks. Existing limits and trace bounds remain exact. No new malformed, authorization, negative, count-mismatch, truncation or resource-limit traffic is introduced. Synthetic oracle mutations never produce traffic.

## Required gates and stop rule

The parent continuation allocates ONE first current-artifact VM and ZERO runtime repair/retry rounds. Any operational failure stops this lane; no automatic rerun, local runtime repair, counter reset or borrowed budget is permitted.

1. Independent spec and quality reviews must each report `PASS` and the exact frozen `PREPARATION.json` SHA256 in `spec-review/VERDICT.json` and `quality-review/VERDICT.json`.
2. Run `preflight.py` once: offline, empty substituters, sandbox enabled, IFD disabled, full scheduled derivation/source/builder/selected-output and cached closure checks. It realizes nothing. Unknown or uncached planned work stops. Parent must approve the actual complete plan in `PARENT_PLAN_REVIEW.json`, bound to `preflight1/RESULT.json` and its exact scheduled derivations.
3. Run one `build1`, offline with the approved plan only, maximum two jobs and 600-second timeout. No VM or oracle executes during build.
4. Run one `oracle1`: actual pinned cached Python, `-B`, unchanged original immutable `oracle_test.py`, immutable helper path, minimal environment without `DBUS_*` or Python optimization, DEVNULL stdin, 60-second timeout. All 38 original tests operate on pure synthetic evidence. Import reads only sibling workload metadata; no runtime class is instantiated, no saved report is read, and no real FD/socket/process workload executes. Require exit0 and matching before/after input pins.
5. Parent serializes one `vm1` with all other VM work. Host observation/cleanup remains the reviewed owned-descendant lifecycle, 900-second host limit and five-second cleanup, with exact `owned_snapshot()` and `save()` AST identity to H01 donor. Require oracle success/pins before launch and unchanged inputs throughout. Original guest qualifier has its existing120-second bound. Require graceful VM shutdown and socket removal.

The prepared commands are listed in the report. Each stage exclusively creates its fixed directory, preventing a second invocation from reusing it. Review failure or drift requires a separately reviewed preparation, never an operational retry under this receipt.

## Historical counters and evidence boundary

The eligibility receipt `m1-valid-rights-fanout-eligibility1/VERDICT.json` SHA256 is `cd54259a6f1f97a22253665cf3e9ea05427854f6e3df46e532a548b82afef6e3`. Its full stage-specific counter vector is preserved in `PREPARATION.json`/`SOURCE_PINS.json`: candidate07 successful review3 with no lane-wide numerical receipt; candidate15 Sol1/Astra0 successful fixture correction and one recorder correction; candidate16 audit Sol2/Astra unknown, round2 PASS with no runtime/fixture repair or retest; pre-VM review repair label2 PASS. No lane-wide cumulative total is inferred. This direct static assignment consumes zero Sol repair rounds, zero runtime attempts and zero VM attempts; received Astra repair counter is unknown. The parent's one-VM/zero-repair continuation limit is separate and does not reset historical counters.

No installed XML-policy parity, full SEC17, FD08, FD09, P08, release/product acceptance or precommit result is claimed. SEC03/06/08/FD04, authorization and P10 remain closed. There is no new guest launcher or guest workload. No original sources, ledgers, test assertions, private policy or excluded scope may be changed. This assignment does not execute prepared stages, tests/imports, Mix/compiler, Git, network, Nix evaluation/build/realization, VM, actors/helpers or probes. Nix syntax parse, Python AST, JSON, hashes and file readbacks are the only validation here.
