# H01 six-command dependency probe with exact cached Git

This new create-only preparation supersedes the stopped, unfrozen
`h01-git-environment2` preparation for future dependency-probe execution only.
That preparation and all previous results remain unchanged. It is not eligible
for execution: root `mix precommit` can load dependencies, compile and dispatch
the web child precommit alias/tests even without a root alias. Actual precommit
remains BLOCKED_SCOPE/ENV. Neither `mix help precommit` nor `mix precommit` is
selected here. No alias, check bypass or production source repair is allowed.

Own only this scope, `scripts/foundation/h01_dependency_git/`, and
`resume-20261019/h01-git-dependency3/`. Copy the original reviewed guest and
remove only its final two precommit commands and their false no-test comment.
Preserve every helper body, normal dependency/runtime/SCM check, command argv
and limit. The selected commands are exactly the first six original commands:
`elixir --version`, Hex discovery using the original Elixir expression,
`mix help deps`, `mix help deps.loadpaths`, `mix deps`, and
`mix deps.loadpaths --no-compile --no-path-loading`. This is dependency evidence
capture, not compilation, baseline, H01, precommit or product qualification.

Derive the recipe from reviewed `h01_environment_otp27/test2.nix`. Select the
same locked-tree `gitMinimal`, assert the exact acquired Git2.52.0 output, add
it to explicit closure anchors and the private PATH, use a fresh fixture name
and reference the new six-command guest. Retain all inherited provenance,
Hex, runtime and source assertions and the immutable original 4,148-file
snapshot. Pin the completed `h01-git-cache1/verification/RESULT.json`, exact Git
path, derivation and NAR metadata. Original recipes, snapshots, guest and
reports remain immutable.

Worker preparation permits file reads/copies/hashes, Python AST and Nix syntax
checks and offline cached closure inspection only. No preflight, realization,
build, compiler, Mix, Git, test, application, helper, VM or network execution.
Fresh parent/spec and independent quality review receipts must approve this
exact preparation before parent preflight. One create-only preflight1 inspects
every scheduled derivation, selected output, source, builder and complete
cached closure without realization. Stop on missing outputs, downloads or
uncached toolchains. Parent must manually review the exact resulting plan and
bind its hash and scheduled derivation set before build1. The build must use
--offline, no substitution, sandbox=true and no import-from-derivation.
Only one build1 and one serialized parent-owned vm1 are prepared; no automatic
retry or broad task selection is allowed.

Preserve the 60-second per-command/preflight, 600-second build, 650-second guest
and 900-second host limits, UID/GID1101, private HOME/MIX_HOME/HEX_HOME, separate
disconnected workload network namespace, original bounded owned-descendant
host lifecycle functions, input readback before/after, exact process/output/
exit evidence, reaping and VMoff. A successful capture does not imply that any
captured command passes; actual errors and statuses must remain visible.
No product tests or bus application may start.

H01 integration Sol2 and source-builder Sol2 remain separate and unchanged;
no Astra repair counter was received. The earlier missing-input preparation
was an environment blocker, not a runtime/source failure. SEC03 no-retry,
SEC06/FD04 denials, SEC08 no-fourth and native authorization/P10 terminal
Sol2/Astra2 remain closed. No optional audit, penetration test, broad fuzzing,
API probe, live host bus/system/account change, commit/merge/push/publication/
release/deployment or memory write. H01 and full goal remain incomplete;
M1/P02 earliest unfinished; readiness L0; product_qualified=false.
