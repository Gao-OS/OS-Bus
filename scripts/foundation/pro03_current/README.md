# Current PRO03 complete core corpus

This wrapper runs the existing eight-vector PRO03 source1 corpus against the
frozen installed XML-corrected artifact, using the existing independent raw
actors, reference daemon, observer and validators. All identities, policies,
wire bytes, assertions and numerical deadlines are unchanged. Copied fixture
changes are two contract manifest/source digest assignments and removal of the
two full-report writes inside `request` and `settle`, each with an exact reversal
check;20other fixture files are unchanged.

Timed operations retain every receipt, snapshot and settle record in memory.
Existing case/backend success, exception and finally boundaries flush the full
report; raw actor logs are unchanged. A report rewrite therefore cannot consume
the caller/settle budget after a successful reply. Actual request overruns still
fail under the original absolute deadlines and their evidence is flushed.
The correction is confined to copied fixture scheduling, without product changes.

`test.nix` accepts `candidatePath`, `artifactPath`, `runtimeManifestPath`.
Candidate manifest SHA256 is fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82;
artifact is b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1;
runtime is6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5.
The normalizer verifies71sources,57mappings/61own BEAMs and80runnable files,
including immutable mode and exact artifact/candidate byte equality.

The eight existing malformed/valid counterpart pairs cover duplicate member,
wrong-typed path, missing final uint32, trailing body byte, invalid UTF8 string,
invalid object path, nonzero header padding and an array element crossing its
boundary. Each backend retains11actors,2positive controls, real UID1101 sources
and UID1100 healthy observer. No PRO04/PRO05/endian/depth coverage is inferred.
Original60s authority/120s guest/900s host and request/settle/retirement bounds
remain. Export uses the same regular read-only guest marker and isolated
16GiB evidence disk as the existing current SEC15 wrapper. These storage and
export choices preserve corpus behavior and avoid duplicate transcript copies.

Offline normalization/controls and exact source pin checks are recorded under
`test/reports/foundation/resume-20261019/pro03-xml-preparation1/`.
Current VM1 failed on the reference backend after a valid sub2ms reply because
the request checked its deadline after a synchronous full-report write. That
failure remains immutable. The scheduling correction's offline RED/GREEN and
source-preservation evidence is under
`test/reports/foundation/resume-20261019/pro03-persistence-repair1/`.
Build and fresh runtime of this correction are NOT RUN; root owns serialized VM
execution and saved evidence acceptance. Previous execution remains historical.
L0/product_qualified=false; this source preparation does not pass a gate.
