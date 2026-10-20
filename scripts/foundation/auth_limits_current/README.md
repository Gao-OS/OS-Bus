# Current complete SEC-07 core adapter

Source preparation only. Root must build and run a fresh disposable guest before
reviewing runtime evidence. No current SEC-07 pass, index adoption or product
qualification is claimed; readiness remains L0. Preparation evidence and offline
command receipts are in
`test/reports/foundation/resume-20261019/sec07-xml-preparation1/`.

`test.nix` accepts exactly `artifactPath` and `runtimeManifestPath`. Supply the
current `resume-20261019/xml-doctype-candidate` artifact with artifact.json SHA256
`b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1`
and `m1-sec16-complete1/candidate1/candidate.json` runtime manifest SHA256
`6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5`.
For example, from the repository root:

```sh
nix build --file scripts/foundation/auth_limits_current/test.nix driver \
  --argstr artifactPath "$PWD/test/reports/foundation/resume-20261019/xml-doctype-candidate" \
  --argstr runtimeManifestPath "$PWD/test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec16-complete1/candidate1/candidate.json" \
  --no-link --print-out-paths
```

Use the existing parent host lifecycle wrapper, a fresh host output directory
and serialized VM execution. This example is a build instruction; it was not
executed during preparation.

The donor is the latest passing complete corpus,
`m1-sec07-complete1/source5/fixture1`, with source manifest SHA256
`391bf23fa14ec2cd1595fd9913618bd179d2f5fd3a8b6675b0564cd1a9034641`.
Its historical runtime acceptance remains evidence for its original candidate.
The adapter preserves all 34 fixture leaves and changes only two exact
assignments in the copied contract: candidate manifest and source identities.
All other contract bytes, predicates and assertions are unchanged. The runner,
collector, policies, actors, admission-overlap and consumed-byte validators,
kernel primitive, workload and thresholds remain byte-identical. Historical
sources and saved failures are preserved.

The normalizer derives the existing candidate schema from the supplied artifact
and runtime metadata, producing manifest SHA256
`fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82`
and hash-only source aggregate
`f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c`.
This hash-only aggregate differs from PRO05's full source-metadata aggregate.
The recipe checks all 71 current source hashes. The normalizer verifies the
exact 80 runnable files, bytes, hashes and read-only modes, 57 source mappings
covering 61 BEAMs, original fixture inventory and reversible contract changes.
No production source is compiled or rewritten by the adapter.

The unchanged collector runs both pristine dbus 1.14.10 and GaoBus against all
17 cases each. It retains the mandatory kernel-queue primitive, independent
UID/GID1100 observer and negative actors, permitted root/UID1101 controls,
per-case AccessDenied effects, no protected delivery, fresh admission, exact
resource recovery and natural teardown. Native line/total/failure/turn limits
remain 4096/8192/8/32, authentication absolute/idle/Hello deadlines
1500/500/1500ms, and UID/global authenticating quotas 2/3. The finite
nonterminal processed observation deadline remains 700ms. Original request,
health, settle, timer, holder-overlap, cleanup and CPU/memory bounds remain.
Reference internal accounting remains UNSUPPORTED; connected backlog is not
admission. External peer continuation is not established.

The VM preserves 1536 MiB, two CPUs, the original isolation marker, UID/GID1100
and1101, shared 360-second authority deadline, 480-second guest command and
900-second host bound. Evidence remains at `/run/osbus-security/sec07-complete`,
exported directly as `auth-limits-current-evidence`, including collector output,
exit status, current-bindings.json and original raw backend/qualification files.
`auth-limits-current-vmoff.json` separately records VM shutdown and both socket
removals. Backend gate exits and unchanged complete validation remain mandatory.

Offline preparation passed 119 existing source5 controls and three binding
controls, exact normalization, 20 Python syntax parses and Nix parse-only.
Nix evaluation/build, VM, broker/actor/socket execution and mix precommit were
NOT RUN under the file-only assignment. All qualification/index flags remain
false. This adapter prepares core coverage only; it does not promote network,
catalogue, milestone or product status.
