# H01 environment probe with source-built Hex on OTP27

This continues the ordinary H01 dependency prerequisite. The earlier cached
OTP28 Hex package failed on pinned OTP27 with `corrupt atom table`; its eight
command results and VM evidence remain unchanged. The failed original source
fetch and its toolchain timeout also remain. This scope neither retries a
denied test nor certifies H01.

After the cached-builder source recipe has been reviewed, fetched with the
unchanged official URL/hash, and compiled offline successfully, use its exact
output in one new revision of the environment-only VM. Preserve the original
snapshot, guest program, eight commands, 60s command limits, 600s build limit,
900s host limit and owned-descendant lifecycle helper. Use the independently
identified cached Nixpkgs tree at the inherited lock revision/NAR hash. The new
recipe changes only that import, the source-built Hex identity/provenance
assertions, and the fixture name. It starts no bus application or test suite.

Before realization, inspect the entire build plan and required output closures;
stop if any uncached toolchain or downloaded dependency is required. Disable
substitution and networking for the driver build. Run the probe as UID/GID1101
in a disposable Linux VM, a separate network namespace with no usable routes,
and private HOME/MIX_HOME/HEX_HOME. Preserve ordinary dependency and runtime
checks and the original source bytes. Capture exact argv/environment, process
identities, outputs, exit statuses, input hashes, reaping and VM shutdown.

The guest captures errors as evidence. A successful capture does not imply
that its commands pass. `mix deps` and checking-only dependency load paths do
not establish compilation or baseline qualification. The root has no precommit
alias: record `mix help precommit` and `mix precommit` results without adding
an alias, bypassing checks, or starting broad tests. H01/precommit remain
blocked until their full predicates are actually satisfied.

Own only this new scope, new `scripts/foundation/h01_environment_otp27/`,
new `resume-20261019/h01-otp27-environment1/`, and precise parent-owned ledger
additions. Do not change the original probe/build recipe, snapshot, guest,
production sources, tests, policies, accepted index or index consumers.

VMs remain serialized. SEC03 no-retry, SEC06/FD04 denials, SEC08 source9
no-fourth and authorization/P10 terminal Sol2/Astra2 boundaries persist.
No optional audit, penetration test, broad fuzzing, API probe, live host bus
or system/account change, commit, merge, push, release/deployment or memory
write. Goal incomplete; M1/P02 earliest unfinished; L0/productfalse.
