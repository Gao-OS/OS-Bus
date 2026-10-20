# H01 partial normal Mix baseline: ex_d_bus wire regressions

Prepare one finite normal Mix regression VM for current ex_d_bus source/test
bytes. This is partial P00/P04/P06 baseline evidence; scoped success cannot
qualify H01/precommit, accept a row or raise L0. Parent owns review, full
preflight, all executions, serialized VMs, ledger updates and evidence sealing.
Preparation allows file copies/hashes/static syntax only: no Mix/compiler/test,
full Nix preflight, realization/build/VM, source retrieval or network execution.

Own only this scope, new scripts/foundation/h01_wire_mix/ and new
resume-20261019/h01-wire-mix1/. Preserve all existing sources, tests, helpers,
recipes, policies, evidence, indexes and consumers. Snapshot root/application
Mix/lock/config/formatter/README/LICENSE inputs, cached dependency source/SCM
metadata, full ex_d_bus lib, test_helper and only test/wire plus independent
corpus fixtures. Materialize file symlinks with resolution/mode/hash records.
Never copy or construct compiled manifests, _build, ebin or BEAM artifacts.
Start with a clean build directory. No fetch/install/dependency/runtime/archive/
SCM check bypass; missing genuine dependencies remain BLOCKED_ENV.

Run as UID/GID1101 in one disposable Linux VM with a disconnected net namespace,
private HOME/MIX_HOME/HEX_HOME/XDG/TMP and original normal ERL_LIBS integration.
Use exact source-built Hex p3gy...2.5.1, pinned Elixir1.17.3/OTP27.3.4.6 and cached
locked Nixpkgs identity. Retain every working test2 provenance assertion and
explicit Hex dependency. Import immutable h01_environment/guest.py helpers for
identity/network/readback/command lifecycle and reuse original owned host
lifecycle wrapper; do not fork competing helpers.

From project/apps/ex_d_bus run only: elixir --version; ordinary Hex discovery;
mix help compile; mix help test; mix help format; mix compile --warnings-as-errors;
mix format --check-formatted with explicit changed wire/message/introspection
source and test/wire paths; mix test --no-start --seed 4321 test/wire. Each command
has60s, driver build600s, guest invocation650s, host VM900s and original cleanup
bounds. Stop dependent commands on the first nonzero exit. Retain output/inputs,
then verify readback/isolation and classify check failure separately from
containment/evidence failure. Successful evidence capture is not check success.

Before any realization, parent executes/reviews the full offline/substituters-
disabled/no-IFD dry-run and all selected-output/store-source/builder closure
inventory. Parent manually approves only required VM/text builds; uncached
external dependencies/toolchain requirements block. No auth/transport/connection
or gao_bus/E2E test selection. SEC03/SEC06/FD04/SEC08 and authorization/P10
terminal boundaries remain closed. No optional audit/fuzz campaign/API probe,
host bus/system/account change, commit/publication or memory write. Current
accepted index,71 production source/80 artifact bytes and readiness stay unchanged.
