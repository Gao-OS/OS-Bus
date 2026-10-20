# Current SEC17 native pending-cleanup adapter

Source preparation only. This entrypoint selects exactly `pending_cleanup`:
`killed_callee`, then `killed_caller`, on GaoBus. Root owns a fresh serialized
build/VM run and independent runtime reconciliation. Current runtime is NOT RUN;
full SEC17/FAIL01, reference/network/FD/resource qualification remain incomplete.
Readiness stays L0 and all qualification/index flags remain false.

From the repository root:

```sh
nix build --file scripts/foundation/peer_cleanup_current/test.nix driver \
  --argstr artifactPath "$PWD/test/reports/foundation/resume-20261019/xml-doctype-candidate" \
  --argstr runtimeManifestPath "$PWD/test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec16-complete1/candidate1/candidate.json" \
  --no-link --print-out-paths
```

Use the existing parent host lifecycle wrapper and a fresh output directory.
This command was not executed during preparation. The entrypoint accepts only
`artifactPath` and `runtimeManifestPath`; selection is fixed to the two cases
actually independently reconciled in the latest donor run.

The donor is `m1-sec17-pending-cleanup1/source1/fixture1`, authenticated by source
manifest SHA256 `a96cbae0d5e7a58894770502874e80134dff2910c0483b5adc8d42087779737a`.
Its execution3 VM1 passed both cases; the saved corrected reconciliation2
invocation also passed. That receipt qualifies only its original candidate and
native pending/capability/retained non-FD ingress subset. Earlier preflight and
saved-checker failures remain untouched. The predecessor
`scripts/foundation/m1_uid_abrupt_peer` contains UID name/match cases; these are
retained in the copied closure but are not selected or claimed by this adapter.

The normalizer copies all 24 donor leaves and changes only the two hardcoded
candidate identity literals in `run.py`. Its exact inverse recovers the original
runner. All remaining AST nodes/assertions and all other 23 files, including the
contract, launcher, actors, independent wire encoder, Channel, state/identity
validators, policies, workload and original controls, remain byte-identical.
The Nix node and driver retain their original behavior, with only a new test
name, fixture load path and export of binding provenance.

Pinned inputs and derived identities:

| Input | SHA256 |
| --- | --- |
| artifact.json | `b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1` |
| runtime manifest | `6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5` |
| normalized candidate.json | `fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82` |
| hash-only source aggregate | `f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c` |

The adapter verifies 71 source hashes, 57 mappings covering 61 BEAMs, all 80
runnable artifact files and their exact bytes/hashes/read-only modes. It derives
the established candidate schema without compiling or changing production.

The actual owning Peer is resolved through the accepted identity, monitored,
killed with `Process.exit(peer, :kill)` and matched to `DOWN :killed`. There is
no explicit cleanup in that arm. Exact pending caller/callee/serial/trusted UID,
capability removal and survivor grants, retained 128-byte fixture-owned non-FD
ingress, ledger/admission credit, full identity/authority state, and wire
NoReply/no-unwanted-reply effects remain required before explicit consumer
release. External actors remain alive for automatic-cleanup readback, then must
observe closure and retire naturally. This is a BEAM Peer kill, not external
actor OS SIGKILL, and introduces no additional fault campaign or FD audit.

All original limits and bounds remain: 1536 MiB/two CPUs, UID/GID1100/1101 and
root, authority60s/guest120s/host900s, combined kill/readback1000ms, daemon
DOWN1000ms, health/request/settled1000ms, pending25000ms, authentication1500ms/
idle500ms, shutdown5s/absence1s and existing inner poll/read bounds. Natural
actor/daemon retirement, no fallback, socket removal, guest VMoff and independent
host driver/VLAN/QEMU retirement remain mandatory. Guest evidence stays at
`/run/osbus-security/uid-abrupt-peer`, exported as `uid-abrupt-peer-evidence`,
with `uid-abrupt-peer-vmoff.json` separately recording shutdown/socket removal.

Offline preparation passed 33 unchanged existing controls and three new binding
controls, exact normalization and candidate equality, 13 Python syntax parses,
Nix parse-only and exact node/driver preservation. Existing source-mode package
controls ran against a separate copy with original manifest modes restored;
all its bytes match the read-only normalized fixture tree. No checker assertion
was skipped or weakened. Evidence is in
`test/reports/foundation/resume-20261019/sec17-xml-preparation1/`.

Nix evaluation/build, VM, broker/actor/socket execution, runtime reconciliation
and `mix precommit` are NOT RUN under the offline assignment. No production,
shared helper, ledger or index changes, commit/push, SEC06 interposition or FD04
audit are included.
