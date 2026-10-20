# Current RES02 slow-egress metadata preparation

`materialize.py` uses only Python's standard library to make a distinct candidate
descriptor and a donor-derived fixture. It adds the baseline authenticated by
the original runtime, changes only six identity literals across three fixture
files, proves exact inverses, and preserves every runnable byte and mode.
Its six positional arguments are: existing candidate directory, original runtime
manifest, artifact directory, donor source manifest, donor fixture directory,
and a nonexistent output directory. Run with Python `-B`, without optimization.
The prepared output already exists; do not overwrite it or retry materialization.

`test.nix` imports the derived original recipe with the frozen candidate identity.
No alternative harness, policy, assertion, threshold, or VM recipe is introduced.
Preparation and source pins are frozen under
`test/reports/foundation/resume-20261019/res02-current-slow-egress1/`.

After fresh sequential specification and independent quality PASS reviews, the
parent owns `preflight.py`, full offline plan and cached closure inspection, and
the manual `PARENT_PLAN_REVIEW.json` receipt. Unknown scheduled derivation names
stop preflight. There is no assumed derivation count. The parent may then run
`run_build.py build1` once and `run_vm.py vm1 build1` once, sequentially, within
the existing 600-second build and 900-second VM bounds. All stage directories
are create-only. Unexpected failure stops the sequence; no runtime repair or
retry is allocated. Successful capture alone is not functional acceptance.

This preparation runs no preflight evaluation, realization, fixture import,
compiler, Mix, tests, actors, probes, VM, lifecycle helper, or network operation.
The earlier donor's partial acceptance remains historical evidence. Current
RES02 functional qualification is unrun; full RES02, M1, installed XML/reference/
network parity and product qualification remain incomplete at readiness L0.
The exact scope is `docs/codex/os-bus-foundation/P05_RES02_CURRENT_SLOW_EGRESS_SCOPE.md`.
