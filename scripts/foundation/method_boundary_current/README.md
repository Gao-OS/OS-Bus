# Current-artifact SEC14 complete-core adapter

Reuses the latest previously executed donor
`test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec14-complete1/source5/fixture1`
and manifest `SOURCE_MANIFEST1.json` SHA-256
`8fe87a9f8bfbb182f095f243f32cae01f48d0b04b7f61b22d5ec7af5736ba590`. All 22 donor fixture files are pinned.
This remains the two-backend method-boundary corpus: ten invalid-signature/path/interface cases per backend, independent wire correlation, healthy followups, complete measured native state and cleanup. The existing XML and pure materializer remain exact source5 bytes.

`normalize.py` verifies candidate manifest `fdcb882f…`, source set `f1f945ac…`,
XML artifact `b77d142e…`, runtime manifest `6077a50d…`, all 80 runnable files,
71 source pins, 57 mapping keys/61 mapped BEAMs and the complete donor fixture
manifest. It copies the fixture and replaces only two digest literals in each
of `contract.py` and `test.nix`, with exact input SHA/count/reversal guards.
The other 20 files retain identical bytes, hashes and immutable modes.
No runtime assertion, identity, policy, workload, actor, cleanup or deadline
changes. Both donor runners already load `candidate/lib/*/ebin`; no load-path
repair is needed. Output `bindings.json` records all original and patched pins
and reversible substitutions; it must be retained with root's build/runtime
bindings. The original guest export protocol stays unchanged and does not add
a new bindings export step.

The real `test.nix` entrypoint accepts `candidatePath`, `artifactPath` and
`runtimeManifestPath`, normalizes the exact pinned inputs, then imports the
copied donor Nix test with `complete_core` and the new candidate/source hashes.
This uses import-from-derivation during root evaluation. It retains the donor's
1536 MiB/two-core VM, account UID/GIDs 1100/1101, authority 60 s, guest 120 s,
host 900 s and all inner fixed bounds. The pinned reference package is pristine
D-Bus 1.14.10. No new runtime capacity, capture or policy workaround is added.

From the repository root, offline controls:

```sh
python3 -B scripts/foundation/method_boundary_current/test_normalize.py -v
nix-instantiate --parse scripts/foundation/method_boundary_current/test.nix
```

The controls read the retained frozen fixtures under
`test/reports/foundation/resume-20261019/sec13-sec14-xml-preparation1/inputs/`
and the explicitly pinned local Nix store inputs. Four adapter controls pass;
all 10 unchanged copied donor synthetic contract controls pass. Full
offline normalization and wrapper/copied-donor Nix parse-only checks pass.
The controls do not execute a guest runner, actor, daemon, socket or VM.

Root-only future build (not executed by this preparation):

```sh
nix-build scripts/foundation/method_boundary_current/test.nix -A driver \
  --argstr candidatePath /nix/store/9v44l2apb02b7c478dfia5ml7ak8crvn-osbus-authorization-current-inputs/candidate \
  --argstr artifactPath "$PWD/test/reports/foundation/resume-20261019/xml-doctype-candidate" \
  --argstr runtimeManifestPath "$PWD/test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec16-complete1/candidate1/candidate.json" \
  --no-out-link
```

Build/evaluation, guest/runtime behavior, exact current-artifact outcomes and
fresh independent raw review remain unrun and root-owned. Parse-only success is
syntax evidence; it does not establish derivation evaluation or a successful VM.
Evidence, command logs, source/input pins, exact diffs and seal are under
`test/reports/foundation/resume-20261019/sec13-sec14-xml-preparation1/`.
No historical result, accepted consumer/index/shared ledger or production source
is changed. Product qualification remains false.
