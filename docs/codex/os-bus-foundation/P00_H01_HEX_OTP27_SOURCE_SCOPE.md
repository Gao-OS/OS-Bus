# H01 prerequisite: build official Hex with the pinned compiler

The approved cached-library experiment actually ran in a disposable VM. OTP27
rejected Hex2.5.1 compiled with OTP28 with `corrupt atom table`. H01 and precommit
remain blocked; all failed commands and clean containment evidence are retained
under `resume-20261019/h01-offline-environment1/`. This is an environment error,
not a tool/policy denial. No denied test is reopened by this scope.

Normal dependency environment preparation is necessary for the existing goal.
Build the genuine official Hex source with Elixir1.17.3 / OTP27.3.4.6 rather than
altering BEAM files, fabricating an SCM/archive or skipping checks. The source is
already pinned by the cached package's source derivation:

- `hexpm/hex`, `v2.5.1`, normal source archive
  `https://github.com/hexpm/hex/archive/v2.5.1.tar.gz`.
- Recursive hash `sha256-1xiv8FWX8fk9WBoJXCUfgFN9lo7ClMVUBYb1mmr6u9U=`.
- Existing source derivation
  `/nix/store/4lbxxj3slqd8hzb4s2z4ms1b2gsv2nzg-source.drv`.

1. Prepare a small Nix derivation using the same old nixpkgs pin and exact
   compiler store paths. A single ordinary hash-checked source-fetch command is
   in scope. Do not probe APIs, use alternative targets after a denial, change
   certificate settings, run `devenv enterShell`, or install anything on the
   host. If access is denied, record target/error and stop this blocked step.
2. Compile/install the normal source package in a Nix sandbox with networking
   disabled after the source is cached. Use standard production `mix compile`
   and private state. No dependency-check/runtime-version/archive bypasses,
   handcrafted dependency manifests, BEAM transformations or source patches.
   Retain the original package recipe's normal ERL_LIBS integration.
3. On successful build, repeat the prior finite offline VM experiment with the
   newly compiled package, same runtime, source snapshot, commands, limits and
   private state. Freeze the new package identity before execution. Keep the
   original probe's files/results unchanged. Never interpret inventory or
   checking-only dependency-task exit0 as full baseline/test qualification.
4. Record exact commands, sources/hashes, runtimes, stdout/stderr, exits,
   deadlines and cleanup. Update ledgers precisely. No current required row or
   readiness level changes solely because this environment works.

Own only new `scripts/foundation/h01_hex_source/`, fresh
`resume-20261019/h01-hex-otp27-build1/`, this scope and precise ledger additions.
VMs remain serialized and disposable. Build command ceiling600s, source-fetch
ceiling300s; offline probe ceilings unchanged60s per command and900s host.
No production, tests, policies, consumers or accepted-index changes. Any later
baseline selection must explicitly avoid denied/terminal tests.

SEC06/FD04 denials, SEC03 no-retry, SEC08 source9 no-fourth and native
authorization/P10 terminal Sol2/Astra2 boundaries persist. No optional audit,
penetration test, broad fuzzing, external API probe, live host bus/system/account
change, commit, merge, push, release, deployment or memory write. Goal remains
incomplete; M1/P02 earliest unfinished; L0/productfalse.
