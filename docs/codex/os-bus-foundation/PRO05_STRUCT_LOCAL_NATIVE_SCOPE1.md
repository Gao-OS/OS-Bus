# P04/PRO05 native static struct-depth boundary subset

Verify the existing independent static struct-depth limit through a real Peer,
not just the parser. This is the declared PRO-05/R-05/R-06 finite container
boundary, not an optional audit. Current Types caps static struct nesting at32;
the completed pure32/33 target stays completed. No production defect presumed;
native pre-fix RED remains UNOBSERVED and full PRO05 unmapped.

Worker owns only apps/gao_bus/test/peer_struct_depth_test.exs and
apps/gao_bus/test/fixtures/peer_struct_depth_actor.py. Adapt the accepted static
array fixture's independent packet construction/lifecycle/resource assertions
without editing accepted fixtures or shared helpers. One registered source and
independent observer, actual-UID EXTERNAL, no FD negotiation. Sentinel:
org.foundation.StructDepthObserver. Explicit actual-UID scoped policy permits
only admission, observer ownership, setup/health and normal bus receipts/errors.

Exactly two complete GetId target frames: serial3 at depth32 has signature
'(' repeated32 then 'y' then ')' repeated32; serial6 at33 uses33 of each.
Both contain exactly body byte42 (hex2a), all nested struct starts coincide at
the aligned body start. Header183 padded184/body1/frame201 at32;
header185 padded192/body1/frame209 at33. Independently compare Elixir/Python
exact packets and fixed prefixes:
6c0100010100000003000000b7000000 and
6c0100010100000006000000b9000000. No production encoder for construction.

Depth32 is legal wire input with incorrect GetId arguments: exact InvalidArgs,
source health4/5 and observer10/11, unchanged source/observer identities,
authority/accounting. Depth33 violates static signature limit: actual normal
source DOWN must precede actor exact EOF on its still-open socket. No local
source close or negative read timeout as rejection evidence. Exact observer-only
restoration, continuing observer health12/13, same sentinel/bus ID and core/
Listener identities. Full actor0/observer normal DOWN/empty authority and
accounting, monitored supervised shutdown and socket removal mandatory.

Retain six resource endpoints: before32, after32_quiescent, before33,
source_departed_restored, after_observer_health, final_empty_cleanup. Initialize
constant instrumentation before baseline, no target warmup or logging change.
Total sampled BEAM memory<=268435456bytes, atom growth<=16. Raw process/VM
metrics and deltas retained; departed metrics absent, never invented0. Endpoint
samples establish no transient peak, leak/overload/soak or full-PRO05 bounds.

State/DOWN1500ms, socket/reply/exit3s, health1000ms, actor30s, ExUnit60s,
host900s/cleanup5s unchanged. Predicate deadlines checked even if true. Private
0700 parent/0600 socket, pinned separate nonroot Linux/headless process/current
artifact; start_supervised! named core. Success child0/graceful_success=true.
Root owns formatter/checks/runtime after SPEC then independent QUALITY PASS.
Preserve failures, diagnose before a changed numbered retry, no unchanged retry
or increased limits/deadlines. Production/shared helper changes require a
concrete failing regression and separate bounded correction, never presumed.

Completed fragmentation, PRO03, SEC13-16, missing signature, XML deadline/size,
variant64/65, array32/33 and typed-match targets must not run again. Ordinary
complete setup/health for this distinct case is permitted. SEC03 no retry,
SEC06 no redispatch, SEC08 no fourth run/scratch, SEC09-12 pause and FD04
exclusion persist. No optional audit, penetration/exploit work, broad fuzzing,
external API/network probes, Nix build/fetch, VM, host live-bus/system/account
change, push/publication or memory write. All preserve others' edits. Mandatory
VM/profile gates stay blocked, frozen index unchanged, M1 unpassed,
readinessL0/product_qualified=false.
