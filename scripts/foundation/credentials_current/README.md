# Current SEC01 complete-corpus adapter

XML-candidate source preparation, adapter revision2. File-only
normalization and original pure contract controls are recorded in
`test/reports/foundation/resume-20261019/xml-functional-rebind1/`.
Nix evaluation/build, native compilation and fresh daemon/client/VM execution
for this XML candidate are NOT RUN. Earlier retained runtime used the
pre-XML candidate and does not qualify these new pins. Root owns builds,
serialized VMs, raw-runtime review and adoption. Readiness remains L0 and
product_qualified=false. Existing fixture repairs and all functional
assertions, policies, corpora and numerical bounds are preserved.

The donor is the accepted complete source4 fixture under
`test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec01-complete1/source4/fixture1`.
Its `SOURCE_MANIFEST1.json` SHA256 is
`cf838a3ab091824ab3b748bc14c5079bee5107400e04af5a52f86807a77e929e`.
The donor was identified through the current retained SEC01 receipt references,
then `m1-sec01-complete1/index2/ROOT_ADOPTION_RECHECK1.json`, SHA256
`f93f06c106b0240ee39bd2b43065b5fc08790345dc15dbce63982ddfc0b32b5f`,
status `ADOPTED_EXACTLY_TWO_CURRENT_CANDIDATE19_SEC01_CORE_ROWS`.
Source4 raw review marker is
`ACCEPT_COMPLETE_CORE_SEC01_SOURCE4_RAW_RUNTIME_V1`; its review SHA256 is
`0b69612a50d0c9360776f0edeabf826b91c8302b7666c93a7ff2d837ce3a84eb`.
Source3 and source4 contain the same 30 fixture files. Only old candidate digest
strings in `contract.py` and historical `test.nix` differ; the other 28 files,
including native client sources, runner, collector and workload, are identical.

`test.nix` accepts `candidatePath`, `artifactPath` and `runtimeManifestPath`.
Use the existing immutable normalized candidate directly:
`/nix/store/9v44l2apb02b7c478dfia5ml7ak8crvn-osbus-authorization-current-inputs/candidate`.
Its manifest SHA256 is
`fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82`
and source-map SHA256 is
`f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c`.
The current artifact manifest is pinned to `b77d142e…` and origin/runtime
manifest to `6077a50d…`; both complete hashes are enforced in the adapter and
wrapper. The adapter verifies 71 source hashes, 57 mappings/61 BEAMs, 80 runnable
files, read-only modes, byte equality to the artifact and unchanged runtime
anchors. It copies only the donor fixture and changes only the copied
`contract.py` manifest/source assignments. Whole-byte reversal is asserted;
all other 29 files retain exact bytes and read-only modes. Historical
`test.nix` is retained as provenance and is not executed by the wrapper.

The unchanged donor compiler builds the existing persistent GLib and sd-bus
clients with the pinned `glib`, `systemd`, compiler and pkg-config inputs. Its
`build.json` retains compiler commands, source/header hashes, binary metadata,
library versions and store dependencies. No replacement client is introduced.
Each backend runs 28 cases: GLib as actual UID/GID 1100, sd-bus as 1101, and
raw UID 1101 clients at all 24 internal canonical-auth byte boundaries plus
coalesced and pipelined flows. Both backends yield 56 case pairs and 58 actors.
Kernel PID/starttime/status, socket FD/inode, executable and actual mapped
libraries remain joined to public credential/UID/PID replies. Existing observer,
wire ordering, authority recovery, full process FD recovery, natural retirement
and backend exit predicates are unchanged. Historical internal native FD
records remain incomplete; independent external inventories provided the
accepted complete recovery evidence. No internal completeness is inferred.

The reference is pristine pinned dbus 1.14.10 with no patches. The disposable
root guest has a regular mode-0444 isolation marker, UID/GID 1100 and 1101
accounts and private endpoints. Original bounds remain 360 seconds authority,
480 seconds guest and 900 seconds host, with request/health/settle 1 second,
128 settle reads, startup 10 seconds, observer 30 seconds and cleanup 5 seconds.
A size-checked 16 GiB `/dev/vdb` disk mounted at `/run/osbus-security` retains
evidence without a duplicate RAM export tree. Direct export places the original
`sec01-complete` basename beneath `credentials-current-evidence`, including
the unchanged collector/gate records, native build metadata, current bindings,
collector log and exit status. `EXPORT_ACTIONS1.json` records observed socket
entries and no deliberate omissions; it makes no endpoint cleanup claim.
The separate `credentials-current-vmoff.json` records VMoff and socket removal.
Use a fresh host output directory for every execution and preserve failures.
