# H01 environment integration with exact cached Git

This is a new ordinary integration revision following the completed official-cache
acquisition. The earlier Git preparation stopped because the exact tool was not
cached; its scope, REPORT and CORRECTION1 remain historical and unchanged.
The cached-input condition is now resolved by the parent acquisition and its
completed `h01-git-cache1/verification/RESULT.json` receipt. This is not a retry
of a denial or a new source-builder repair.

Own only this new scope, `scripts/foundation/h01_environment_git_cache/`, and
`resume-20261019/h01-git-environment2/`. Derive the recipe from reviewed
`h01_environment_otp27/test2.nix`: select `gitMinimal` from the same locked
Nixpkgs tree, assert its exact Git2.52.0 output, add it to closure anchors and
the private command PATH, and use a fresh fixture name. Preserve every other
provenance, Hex, runtime, dependency and SCM check. Reuse the original immutable
4,148-file snapshot, exact guest.py and eight commands. Do not alter the
snapshot or heroicons metadata, add an alias, or bypass any check.

Preparation permits static reads, copies, hashes, Python AST/Nix syntax checks
and offline evaluation/cache inspection only. No worker preflight, build,
compiler, Mix, tests, selected Git, VM, helper or network execution. Freeze
only after pinning the actual completed acquisition verification receipt.

Future execution is parent-owned and serialized. First run one fresh preflight
with no realization, inspecting all scheduled derivations, selected outputs,
sources and builders plus complete cached closures. Stop for missing inputs,
downloads or uncached toolchains. Require fresh spec/quality reviews and a
manual `PARENT_PLAN_REVIEW.json` binding the exact preflight hash and scheduled
derivation set before build1. The driver build uses offline mode, no
substitution, sandbox=true and no import-from-derivation. Preserve the
60-second command/preflight, 600-second build, 650-second guest and 900-second
host limits, UID/GID1101, private HOME/MIX_HOME/HEX_HOME, disconnected workload
network namespace, original owned-descendant lifecycle helper, evidence capture,
input readback, reaping and VM shutdown. Only build1 and vm1 are prepared;
no automatic retry is permitted.

Successful capture and successful commands are separate predicates. Preserve
actual errors and exit statuses. The saved prior dependency/loadpaths/precommit
Git `:enoent` failures and missing root `precommit` task remain evidence. The
new probe must capture actual command results, including `mix help precommit`
and `mix precommit`, without adding an alias or starting product tests. H01 and
precommit remain blocked until their full predicates actually pass.

H01 integration Sol repair2 follows provenance parse repair1; the stopped
missing-input preparation was an environment condition, not a runtime/source
failure. Source-builder Sol repairs2 remain separate; no Astra repair counter
was received or reset. SEC03 no-retry, SEC06/FD04 denials, SEC08 no-fourth and
native authorization/P10 terminal Sol2/Astra2 remain closed. No optional audit,
penetration test, broad fuzzing, API probe, host live bus/system/account change,
commit/merge/push/publication/release/deployment or memory write. Goal incomplete;
M1/P02 earliest unfinished; readiness L0; product_qualified=false.
