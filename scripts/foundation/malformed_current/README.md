# Current SEC15 complete-corpus adapter

XML-candidate source preparation, adapter revision2. File-only
normalization and original pure contract controls are recorded in
`test/reports/foundation/resume-20261019/xml-functional-rebind1/`.
Nix evaluation/build, native compilation and fresh daemon/client/VM execution
for this XML candidate are NOT RUN. Earlier retained runtime used the
pre-XML candidate and does not qualify these new pins. Root owns builds,
serialized VMs, raw-runtime review and adoption. Readiness remains L0 and
product_qualified=false. Existing fixture repairs and all functional
assertions, policies, corpora and numerical bounds are preserved.

The immutable XML candidate is
`/nix/store/9v44l2apb02b7c478dfia5ml7ak8crvn-osbus-authorization-current-inputs/candidate`.

`test.nix` accepts `candidatePath`, `artifactPath` and `runtimeManifestPath`.
The existing read-only normalized candidate has manifest
`fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82` and source
`f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c`.
The current artifact manifest is pinned to `b77d142e…` and the origin/runtime
manifest to `6077a50d…`; complete digests are enforced in both source files.
The adapter verifies all 71 source hashes, 57 source mappings/61 BEAMs, 80
runnable files, modes, runtime anchors and byte equality to the current artifact.
It uses that candidate directly without modifying or recopying its product bytes.

The existing source1 fixture is copied from
`test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec15-complete1/source1/fixture1`.
Its 20 files are checked against source1 `SOURCE_MANIFEST1.json`, SHA256
`a06264853f5732f5a33c274d66e17ed1fc76282c79a8f2e132e400ab6109ff28`.
Only the copied `contract.py` manifest/source assignments change. Whole-byte
reversal is asserted; all other 19 files retain exact bytes and read-only modes.
The original copied `test.nix` is retained as corpus provenance; this new wrapper
supplies the current bindings and runs the unchanged `run.py`.

Both backends retain the exact two original complete malformed RequestName `su`
vectors: missing final uint32 with adjusted advertised body size, and corrupt
string terminator. Each backend retains its plain/discovery EXTERNAL positive
controls, actual UID/GID 1101 clients, persistent UID/GID 1100 observer, complete
observer-stream checks for transient ownership effects, zero terminal bytes and
actual EOF/reset proof. Policies, actors, independent wire replay, identity/epoch,
state/resource recovery, natural retirement and endpoint-cleanup assertions are
unchanged. The inherited launcher still receives `SEC04_ORIGINAL` from unchanged
`run.py`. The reference is pristine pinned dbus 1.14.10, with no patches or separate
embedded upstream-test prerequisite.

The disposable guest retains root ownership, the regular mode 0444 isolation
marker, both real UID/GID accounts, 60-second authority/120-second guest/900-second
host bounds and all original request/settle/cleanup limits and private endpoints.
The guest transport waits up to 130s for the unchanged 120s command timeout and its
existing 3s termination grace. A size-checked 16 GiB empty guest disk at `/dev/vdb`
holds evidence under the original `/run/osbus-security` path. Direct export keeps
basename `sec15-complete` beneath `malformed-current-evidence` without duplicating
the evidence tree in `/run` memory. No host configuration is changed.

The wrapper exports the complete original evidence tree, runner output/status,
current bindings and VMoff/socket-removal record. Root must use a fresh host
output directory and preserve failures. Successful execution alone remains scoped
SEC15 core evidence pending review/adoption; it does not establish full M1,
network, installed-system or product qualification.
