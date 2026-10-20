# Current-candidate UID-match cleanup preparation

Task `sec17-current-uid-matches1`: direct static preparation in
`/data/development/Gao-OS/OS-Bus/.trees/os-bus-foundation`, branch
`codex/os-bus-foundation`, baseline `7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4`.

## Exact scope

The new `scripts/foundation/uid_matches_current/test.nix` only imports the unchanged
`scripts/foundation/m1_uid_abrupt_peer/test.nix`, with `selection = "uid_matches"`.
The sole selected existing cleanup event is `match_down_reclaims`. This separate
ordinary match-subscription cleanup slice does not alter the frozen `uid_names`
preparation. No new guest, extra workload, policy, helper, assertion, deadline,
rights/fault case, security/API probe or traffic is introduced. Existing fixture
traffic and assertions remain unchanged.

The launcher clears `config_file`, `inherited_listener` and `lifecycle` and uses the
existing legacy private policy overlay/limits and guest socket. This is not installed
XML policy parity, complete SEC17, FD coverage, milestone, H01, precommit or product
acceptance. Readiness remains L0/product false. Closed SEC03/06/08/FD04, native
authorization/P10, counters and accepted ledgers/index are untouched.

## Frozen candidate and lifecycle

Use the parent-confirmed unchanged normalized candidate directory:
`test/reports/foundation/resume-20261019/sec17-xml-preparation1/normalized/candidate`.

- Candidate manifest: `fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82`.
- Source aggregate: `f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c`.
- Artifact: `b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1`.
- Runtime origin: `6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5`.
- 71 production sources, 57 mappings covering 61 BEAMs and 80 runnable files.

The wrapper retains the original `fetchTree` and inherited lock provenance.
Resolve only through the offline cache; stop if unavailable. Source and runnable
bytes, inherited fixture pins and read-only candidate file modes are statically
verified. No candidate or source regeneration occurs.

Parent runners are minimally adapted from the preceding source-only preparation;
the reviewed H01 `owned_snapshot` and `save` lifecycle ASTs remain identical.
The authority/guest/host bounds remain 60/120/900 seconds; host cleanup 5 seconds,
request/settle/health/kill-readback/DOWN bounds 1000 ms, fixture shutdown 5 seconds
and absence 1 second. The host observer inspects only its owned descendants and
retained identities; there is no global host process enumeration.

## Reviews and parent-only execution

Let `E` be `test/reports/foundation/resume-20261019/sec17-current-uid-matches1`.
Fresh spec and independent quality reviews must each approve this exact
`E/PREPARATION.json` SHA256. Their separate `E/spec-review/VERDICT.json` and
`E/quality-review/VERDICT.json` require `verdict: "PASS"` and the actual
`preparation_sha256`. Any preparation change requires fresh reviews.

1. Parent runs `python3 E/preflight.py`, once. It dry-runs the complete driver plan
   offline with empty substituters, sandbox true and no IFD. It inspects every
   scheduled derivation, selected input outputs, sources, builders and cached
   requisite closures, realizing nothing. Unexpected derivations, missing inputs,
   download requirements or uncached toolchains stop the stage without retry.
2. Parent reviews the actual plan, then writes `E/PARENT_PLAN_REVIEW.json` with
   `verdict: "PASS_PARENT_PLAN_REVIEW"`, actual `preflight_sha256`, exact
   `scheduled_derivations`, `missing_selected_outputs: []` and
   `no_uncached_toolchain_or_download: true`.
3. `python3 E/run_build.py build1`: one offline/sandbox/no-IFD/empty-substituter
   build (600 seconds), bound to the approved plan; captures driver file and
   symlink pins. No VM or guest execution.
4. Only after `uid_names` finishes, parent runs
   `python3 E/run_vm.py vm1 build1`, once. Input/driver pins are checked before and
   after using the unchanged reviewed owned-descendant lifecycle implementation.

Only `build1` and `vm1` are prepared. No broad selector, alternate slice, new attempt,
retry, fourth attempt or reopening of a closed route is authorized. This worker
performs static preparation only: file reads/copies/hashes, Python AST parsing and
Nix syntax parsing. No operational preflight, evaluation, build, VM, tests, actors,
helpers, network, Git, Mix or compiler execution. Required precommit is unrun /
BLOCKED_SCOPE for this static task; parent owns later required checks. No source
fix, commit, publication, account/configuration, host-bus or memory changes.

## Static deliverable boundary

Only this scope file, `scripts/foundation/uid_matches_current/` and `E` are created.
`SOURCE_PINS.json`, `STATIC_STRUCTURE.json`, `NIX_SYNTAX.json` and
`PREPARATION.json` preserve the static evidence. Sol repairs: 0; no Astra counter
received. No exhausted SEC17 counter was supplied. All other counters remain
unchanged. Static preparation is reviewable; runtime behavior and cache availability
remain unverified until the parent completes the gated stages.
