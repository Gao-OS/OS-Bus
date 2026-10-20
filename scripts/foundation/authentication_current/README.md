# Current SEC03 complete-corpus adapter

XML-candidate source preparation only. File-only metadata checks and existing
pure controls are recorded in `test/reports/foundation/resume-20261019/xml-remaining-rebind1/`.
Nix evaluation/build, native tests and daemon/client/VM execution for these
XML-bound adapters are NOT RUN. Earlier runtime observations are pre-XML
evidence and cannot qualify these pins. Existing fixture repairs, assertions,
policies, vectors and bounds remain unchanged. Root owns builds, serialized
VMs, independent runtime review and adoption; L0/product_qualified=false remain.

`test.nix` accepts `candidatePath`, `artifactPath` and `runtimeManifestPath`.
The candidate is the existing read-only normalized candidate with manifest
`fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82` and source
`f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c`.
The current artifact manifest is pinned to `b77d142e…` and the origin/runtime
manifest to `6077a50d…`; complete digests are enforced in both source files.
The adapter verifies all 71 source hashes, 57 source mappings/61 BEAMs, 80
runnable files, modes, runtime anchors and byte equality to the current artifact.
It uses that candidate directly without modifying or recopying its product bytes.

The existing source7 fixture is copied from
`test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec03-complete1/source7/fixture1`.
Its 27 files are checked against source7 `SOURCE_MANIFEST1.json`, SHA256
`092fb09ada4d49e4cc5644b64562fd45b8a19097e0a6d60b8fdda304b4c679b9`.
Only the copied `contract.py` manifest/source assignments change. Whole-byte
reversal is asserted; all other 26 files retain exact bytes and read-only modes.
The original 51-case corpus, actors, policies, collector, snapshots, recovery
predicates, assessment and backend gate assertions are unchanged.

The existing collector runs both backends: 51 cases each, 102 pairs. The reference
is pristine pinned `${pkgs.dbus}/bin/dbus-daemon` (dbus 1.14.10), without the
separate embedded upstream/OOM test derivation, a parser patch or disabled tests.
Historical pristine-reference 12 decimal/base0 conformance failures remain
failed evidence. Collection exit 0 means complete validated collection; actual
reference gate exit 1 and failed conformance remain visible in the exported raw
report. No passing reference result or product qualification is inferred.

The disposable guest retains root ownership, the isolation marker, UID/GID 1100
and 1101 accounts, 360-second authority/480-second guest/900-second host bounds,
original request/settle/cleanup limits and private endpoints. It exports the
complete existing evidence tree, both gate command receipts/logs, collector
exit status, current candidate/fixture bindings and VMoff/socket-removal result.
A size-checked 16 GiB empty guest disk at `/dev/vdb` holds the evidence under
the original `/run/osbus-security` path. This follows the parent's diagnosed
authorization VM3 ENOSPC correction without changing workload or timing bounds.
Direct export retains basename `sec03-complete` beneath
`authentication-current-evidence`, avoiding a duplicate `/run` evidence tree.
No new controller or evidence framework is introduced. Use a fresh host output
directory for each root-owned execution and preserve all historical failures.
