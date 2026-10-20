# H01 exact Git prerequisite: official cache metadata and acquisition

The earlier preparation-only Git scope stopped correctly: neither ordinary Git
output from the locked Nixpkgs tree is locally cached. That result and its
correction record remain preserved. Missing cached tooling is an environment
condition, not a tool/policy denial. The existing foundation goal authorizes
ordinary dependency preparation; no new user approval is required for this
bounded prerequisite step.

Own only this scope and new
`test/reports/foundation/resume-20261019/h01-git-cache1/`. First inspect official
`https://cache.nixos.org` metadata for the exact already-derived Git 2.52.0
minimal output `/nix/store/a8mapvrhrzw6ahgb7iv72h3jbm5ghwdy-git-minimal-2.52.0`.
Preserve exact argv, exits, stdout/stderr and hashes. Use a 60-second ceiling.
This is ordinary package-cache metadata, not a product test or external API
security probe. If absent, invalid or unavailable, record the result and stop.
Do not try other caches, versions, source pins, or alternative download routes.

If metadata is present, review the entire substitution plan and closure before
any acquisition. Only signature-verified official-cache substitutes are in
scope; retain normal Nix trust checks and prohibit source/toolchain builds with
zero build jobs and no fallback. A separate create-only receipt must prove the
realized exact package and closure. Do not register the package as a live host
profile or change host configuration. A later environment integration requires
its own frozen recipe, full cached-output preflight, reviews and serialized VM.
No existing recipe, snapshot, guest, test, assertion, policy or index changes.

No Mix/compiler/test/VM/application execution belongs to this acquisition
scope. Root precommit and H01 remain blocked until actually verified. All
SEC03/SEC06/FD04/SEC08 and authorization/P10 denied/no-retry/terminal boundaries
remain closed. No audit, penetration test, fuzzing campaign, host live-bus or
account/system change, commit/merge/push/publication/release or memory write.
Readiness remains L0, product_qualified=false.
