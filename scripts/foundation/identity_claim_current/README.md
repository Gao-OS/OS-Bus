# Current SEC02 complete-corpus adapter

XML-candidate source preparation, adapter revision4. File-only normalization,
eight deterministic settle/patch controls and28 original pure contract controls
are recorded in
`test/reports/foundation/resume-20261019/identity-claim-settle-repair1/`.
VM3 failed the GaoBus final settle deadline; its saved output remains failed.
Execution of this revised runner is NOT RUN. Earlier retained runtime used the
pre-XML candidate and does not qualify these new pins. Root owns builds,
serialized VMs, raw-runtime review and adoption. Readiness remains L0 and
product_qualified=false. Existing fixture repairs and all functional
assertions, policies, corpora and numerical bounds are preserved.

The accepted donor is
`test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec02-complete1/source3/fixture1`.
Its 23 fixture files are bound by `source3/SOURCE_MANIFEST1.json`, SHA256
`d6e57fd6b5bddab06058142c2b85dad752d895c2f8a6cfab214246d9cee381f8`.
Both current retained SEC02 complete/core receipts point to
`source3/receipt_adapter1/receipts1/COMPLETE_ROW_RECEIPT3-{reference,gao_bus}.json`.
`index3/ROOT_ADOPTION_RECHECK1.json`, SHA256
`7f610a010ca1dcbd42beb64325764409b0edcccdae11d57701187fac8737db3e`,
records `ADOPTED_EXACTLY_TWO_CURRENT_CANDIDATE19_SEC02_CORE_ROWS`.
The independent saved-runtime review is `source3/RAW_RUNTIME_REVIEW3.md`, SHA256
`6e27090f0c5239f2696cfe8d9990d202bce68a40b22f2ee1d36d5bc38a2b348c`.
This historical acceptance does not qualify the current changed candidate.
The evidence directory records the exact retained-reference, accepted-index,
receipt, source, witness, review and fixture-pin joins; earlier failed donors
are preserved and are not selected.

The immutable XML candidate is
`/nix/store/9v44l2apb02b7c478dfia5ml7ak8crvn-osbus-authorization-current-inputs/candidate`.

`test.nix` takes `candidatePath`, `artifactPath` and `runtimeManifestPath`, like
`credentials_current`. Candidate manifest SHA256 is
`fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82`,
source-map SHA256 is
`f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c`,
artifact manifest SHA256 is
`b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1`,
and artifact-origin/runtime manifest SHA256 is
`6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5`.
The adapter checks 71 source hashes, 57 source-to-BEAM keys/61 mappings and
80 runnable files, their read-only modes, equality to the immutable artifact
and exact runtime anchors. It copies the donor fixture and replaces the two
copied `contract.py` manifest/source assignments. The existing runner repair
removes one per-request `persist()` after appending the original receipt and
one snapshot `persist()` in `control(limit)` before returning the snapshot.
The snapshot/receipt appends and all other persistence calls remain, including
the settle `finally` and original enclosing success/failure boundaries.
All substitutions have exact whole-byte inverses; the other 21 fixture
files retain exact bytes, modes and hashes. Bindings record original inputs,
contract and runner before/after pins and both reversible patches. Historical
`test.nix` is retained as provenance and is not run.

The runner retains four cases per backend: real kernel UID/GID1100
claims UID0 or UID1101 using inline EXTERNAL or DATA. It checks rejection,
same-stream or explicit terminal recovery, actual retry credentials, protected
ownership/call denial, forged-effect non-delivery and independent observer
health. Genuine UID0 and UID1101 positive controls and discovery/inline/empty-DATA
canonical controls remain. Both reference and GaoBus core backends retain their
private `reference/bus` and `gao_bus/bus` endpoints, original controller/snapshot,
whole-state and external FD recovery, natural actor retirement and daemon cleanup.
No assertion, UID, policy, oracle, case, actor or production byte is changed.

VM3 finished in57.346686539 seconds with no host timeout, matching input pins
and absent PID/process group. Reference passed four cases with115 receipts.
GaoBus reached its fourth case's final `settle(serial_advance(before,count))`,
where two complete snapshots and complete external-FD views were retained, but
the unchanged elapsed assertion failed:1720.842454ms exceeded1000ms. Four case
rows had been appended; final case validation and full-backend acceptance were
not reached. The whole snapshot graph was synchronously serialized before each
`control(limit)` return. Its actual write duration was **unmeasured**; saved
elapsed time alone does not prove how much time persistence consumed.

Revision4 removes only that redundant snapshot write from the copied runner;
the prior request-only correction is retained. Two complete consecutive views,
external-FD completeness, expected whole-state equality, the shared1-second
budget,128-read bound and all original oracles remain. The original settle
`finally` writes the full retained graph on both success and failure. Bindings
record the two exact donor-to-copy substitutions and the new runner digest.

Deterministic controls execute only the actual runner's extracted
`remaining`/`control`/`settle` AST plus original exception/teardown blocks, with
synthetic snapshots and a fake clock. A modeled0.55-second diagnostic write
makes the VM3 code fail; two0.01-second snapshot reads finish before persistence
in the corrected code. These are synthetic costs, not measurements of VM3.
Genuinely late snapshots, incomplete snapshot/FD views and mismatched expected
state still fail and retain the original persistence/read limits. Exact byte
and AST comparisons prove no other VM3 runner change. Run pure controls with:

```sh
python3 -B scripts/foundation/identity_claim_current/test_normalize.py -v
```

This is the second bounded timing-repair slice, following the earlier
request-only repair. It has zero failed source-control repair attempts and no
Astra repair. Root owns any serialized runtime rerun; source controls do not
establish runtime sufficiency or qualification.

Original bounds remain 60 seconds authority, 120 seconds guest, 900 seconds host,
request/health/settle 1 second, 128 settle reads, startup 10 seconds, observer
30 seconds and cleanup 5 seconds. The wrapper uses an additional 10-second guest
command collection allowance, matching existing wrappers without changing the
runner's deadline. The reference is pinned pristine dbus 1.14.10 with no patches.
The disposable guest has UID/GID1100 and1101 accounts and a mode-0444 regular
isolation marker. A size-checked 16 GiB `/dev/vdb` disk at `/run/osbus-security`
retains evidence outside RAM-backed `/run`, following `credentials_current`.

Direct export retains the `sec02-complete` basename under
`identity-claim-current-evidence`, including current bindings, original raw
qualification, runner log and exit status. `EXPORT_ACTIONS1.json` records observed
socket entries and no deliberate omissions; it makes no cleanup claim. The
separate `identity-claim-current-vmoff.json` records VMoff and actual endpoint
absence checks. Fresh host output paths are required; failed attempts remain
failed. The existing persistence repair and original fixed clocks require fresh runtime execution.
