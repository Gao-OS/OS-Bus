# H01 offline Mix/Hex environment feasibility

Continue the authorized P00/P01 baseline prerequisite in the existing foundation
worktree. This scope tests the genuine cached Hex library on pinned Elixir
1.17.3 / OTP 27.3.4.6. It is environment evidence, not a replacement baseline or
an H01 row acceptance.

1. Verify HEAD, the current accepted H04 checkpoint and source pins. Snapshot
   the unchanged root/application Mix files, configuration, cached dependencies
   and test build artifacts. Record source bytes, modes and symlink resolution.
2. Build one NixOS test driver offline, with substituters disabled. Use the
   existing pinned Linux/runtime inputs and the normal cached Hex package
   through ERL_LIBS. No archive fabrication, manifest fabrication, installation,
   fetching, devenv enterShell or dependency-check bypass is permitted.
3. Run the finite probe as UID/GID1101 inside a fresh disposable VM and a network
   namespace with no active interfaces or usable routes. Private HOME, MIX_HOME and
   HEX_HOME and HEX_OFFLINE=1 accompany enforced networking isolation. Preserve
   ordinary archive, runtime and dependency checks. Normal package-manager
   startup is allowed; no bus/web application or test suite is started.
4. Record versions, loaded Hex paths, normal `mix help deps`,
   `mix help deps.loadpaths`, `mix deps`, and
   `mix deps.loadpaths --no-compile --no-path-loading` results. The last command
   still permits dependencies needing compilation; neither its exit0 nor
   `mix deps` exit0 certifies baseline usability. Inspect all printed statuses.
   Run root `mix help precommit` and `mix precommit` only with the unchanged
   root project, which has no precommit alias. Preserve their actual errors.
5. Retain exact argv/cwd/environment, process identity, hashes, stdout/stderr,
   exit status, deadlines, cleanup and VM shutdown evidence. Use the reviewed
   host lifecycle wrapper with owned-descendant-only monitoring. No host Mix
   runtime fallback or VM concurrency. Per-command ceiling60s, host900s.

Only new `scripts/foundation/h01_environment/`, this scope, a fresh
`test/reports/foundation/resume-20261019/h01-offline-environment1/`, and precise
ledger updates are in scope. No production/test/policy/consumer/index changes.
Any follow-on baseline selection must explicitly avoid denied/terminal paths;
this probe never uses a broad test selection. Required checks that do not run
remain blocked. H01 stays blocked until its full evidence predicates pass.

SEC06/FD04 denials are never retried, delegated or rerouted. SEC03 no-retry,
SEC08 source9 no-fourth and authorization/P10 terminal Sol2/Astra2 boundaries
remain in force. No optional audit, penetration test, broad fuzzing, external
API probe, live host bus or system/account change, commit, merge, push, release,
deployment or memory write is authorized here. Goal remains incomplete and L0.
