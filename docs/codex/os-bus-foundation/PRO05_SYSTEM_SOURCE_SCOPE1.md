# PRO05 system scenario source, first integration slice

This slice implements reusable source components for the four existing
`PRO-05/complete-requirement` cells (reference/GaoBus × core/network). It does
not add catalogue cells, vectors, product gates or a second backend/actor
harness. The immediate donor is the accepted `m1-pro03-complete1` fixture.

The input set is the six accepted native subsets in
`environment/m1-res01-measurement1/pro05-finite-native-bundle1/BUNDLE.json`
(SHA256 `1a4c9bddb9e1cb3b0b59c4698a4db86a7a5a76d5d45f1ec9604fb74eec982928`):
variants64/65, arrays32/33, structs32/33, ordered string/uint32 `arg0path`,
the materialized1MiB byte array, and32 identical invalid prefixes. No new
native input or arbitrary size is warranted. Terminal depth inputs retain
serial6, following legal serial3 and source health4/5; prefix retains serial3.

Owned changes are `scripts/foundation/pro05_complete/{vectors.py,vectors.json,
test_vectors.py,actor_overlay.py,test_actor.py,wire_replay.py,test_replay.py}`,
this scope and the four existing evidence ledgers. Vector and actor encoders
are independent. The actor reuses the inherited independent `Client`; replay
adapts the accepted finite PRO03 transcript decoder. Production, shared
helpers, the generic evidence mapper and original E2E selection stay outside
this slice.

The guest actor requires the disposable-guest marker and an explicit endpoint
under `/run/osbus-security/pro05-complete/`. Source and observer are separate
UID1101/1100 processes. It retains the native3s source operation,1s observer
health and1500ms DOWN bounds. Compact actual-write size/SHA256 receipts keep
the inherited4194304-byte control ceiling; the1MiB input is never copied into
JSON as full hex. Terminal send and EOF are separate commands: the future
controller must establish actual source DOWN and authority restoration before
authorizing the still-open-socket read. A token alone proves neither fact.

Verification here is offline: independent encoders against saved input pins,
finite synthetic transcript controls and mutation rejection. These execute no
bus, socket, network request, native target or VM. Synthetic controls cannot
supply runtime observations or assertion witnesses. The complete source
runner, fixture-local resource sampler, backend/profile policies, current
candidate/runtime binding, VM realization, independent execution acceptance
and receipt adoption remain unfinished. Network cells cannot inherit core
receipts. Endpoint measurements cannot establish transient peaks, scaling,
decoded-heap budgets, leak/soak/overload or concurrent health.

Updated `AGENTS.md` and the user's policy apply: no optional audits,
penetration/exploit work, broad fuzzing or external API probes. Do not rerun
accepted native cases, paused/excluded cases, or the retained Nix/VM blocker.
Required unavailable runtime stays blocked; all four full PRO05 cells remain
unmapped, M1 unpassed, readinessL0 and `product_qualified=false`.
