# H01 cached source builder prerequisite

Parent selected the ordinary cached fetchzip candidate from
`resume-20261019/h01-source-builder-preflight2/RESULT.json`. The earlier failed
82-derivation source-fetch attempt and original `h01_hex_source` recipe remain
unchanged. That failure was a SourceForge libisl timeout, not a policy denial.

Own only new `scripts/foundation/h01_hex_cached/default.nix`, this scope, and
`resume-20261019/h01-cached-source-build1/`. Preparation permits offline Nix
evaluation, derivation inspection, dry-run and static syntax checks only.
No retrieval, realization, compilation, VM or test is authorized in preparation.
The parent must independently review the candidate before executing either
create-only phase. Do not alter existing sources, tests, policies, consumers,
accepted indexes, ledgers or evidence.

The new recipe retains the genuine official Hex2.5.1 source URL
`https://github.com/hexpm/hex/archive/v2.5.1.tar.gz`, recursive hash
`sha256-1xiv8FWX8fk9WBoJXCUfgFN9lo7ClMVUBYb1mmr6u9U=`, stripRoot=true and expected
`/nix/store/4cxbmdd32vsqcw8gd9i0z0h0hxzijiya-source`. Use only the cached locked
Nixpkgs rev207d15 tree, fetchurl with its cached curl.bin and fetchzip
withUnzip=false for this tar.gz. Pin/assert inherited lock bytes, Nixpkgs
revision/NAR/content address/store identity and runtime manifest bytes. Fresh
local store registration checks precede each future phase. Any uncached builder
input, hidden download or toolchain derivation blocks execution. The allowable
build plan contains only source, Hex, provenance and the unchanged small
setup-hook text derivation. These text builds are distinct from toolchain builds.

The future fetch1 command is a single bounded ordinary hash-checked source
retrieval with a 300s host deadline and substitutes disabled. The future
compile1 command requires successful fetch1 evidence and the exact realized
source output, uses the pinned Elixir1.17.3/OTP27.3.4.6 stores, normal production
`mix compile`, private state, HEX_OFFLINE=1, Nix --offline and sandbox=true, with
substitutes disabled and a 600s host deadline. No checks/assertions, dependency
checks, SCM/archive or BEAM/runtime-version behavior may be bypassed. Keep the
normal ERL_LIBS setup hook. No new VM, Mix dependency task or consumer run is in
this slice. Each phase creates a fresh exclusive directory and records argv,
input hashes, output, status, elapsed time and owned command cleanup. A failed
phase is terminal here; do not retry or select another retrieval route.

H01/precommit remain BLOCKED_ENV pending actual usable-runtime evidence. This
preparation cannot accept any required row, raise readiness or qualify product.
All SEC03 no-retry, SEC06/FD04 denials, SEC08 source9 no-fourth and authorization/
P10 terminal boundaries stay closed. No optional security audit/test, API probe,
host live-bus/system/account change, publication, commit or memory write.
