# P04/PRO05 native materialized-collection subset

Execute one existing-native-frame-ceiling byte-array case for PRO-05/R-05/R-06,
with the established resource envelope from R-09. This covers a materialized
collection rather than a large string or advertised array extent. No production
defect is identified: decoder accumulation/reversal and descriptor traversal
are linear, but wire-byte accounting is not decoded-heap accounting. No new
production limit or correction is justified without failing evidence. Native
pre-fix RED remains UNOBSERVED; full PRO05 unmapped/readinessL0.

Worker owns only apps/gao_bus/test/peer_collection_test.exs and
apps/gao_bus/test/fixtures/peer_collection_actor.py. Reuse unchanged independent
transport/Hello helpers and supervised lifecycle, authority, credential and
resource sampling patterns. Never edit accepted tests/helpers or production.
One registered source and independent registered observer. Actual-UID EXTERNAL,
no FD negotiation; explicit actual-UID policy admits required bus setup/health,
normal receipts/errors and org.foundation.CollectionObserver ownership only.

Exactly one complete target: GetId serial3/signature ay containing1,048,436
byte42 elements. Native default frame ceiling1,048,576 minus fixed16/header120/
array-length4 derives that cardinality; no size sweep or malformed companion.
Body1,048,440 bytes, header/padded120/120, total1,048,576. Independently build
every byte in Elixir and Python without the production encoder. Pin the fixed
prefix, all136 fixed/header bytes, array-length prefix, payload/body/packet
lengths and SHA256. Explicitly assert effective native frame ceiling in the
actual Limits/Peer configuration. Raw target bytes must not be placed on the
actor control line. Use compact {bytes,sha256} receipts for every actual write;
target descriptor adds header_hex, payload count/byte/hash, body length/hash and
packet length/hash. No fabricated writes: derive receipts from actual unchanged
NormalClient.writes, comparing them independently against exact Elixir packets.
Retain actor line limit16,384; locally enforce encoded output fits that bound.

Controller protocol:

- Initial ready: observer registration/ownership, exact identities and target
  descriptor. open -> opened: source registered, same bus ID and kernel actor PID.
- collection -> collected: send target once, read exact InvalidArgs3, complete
  source health4/5; observer probes not sent yet. Require full operation elapsed
  <=3000ms, derived from the established3s socket/reply bound, with raw elapsed
  retained. Source exact write list includes only registration, one target and
  health4/5. This elapsed bound does not establish reductions scaling.
- ExUnit checks unchanged source/observer authority/accounting and records the
  after-collection endpoint before observe -> observed: observer10/11 health,
  exact receipts, empty bytes/FDs. Source remains registered and healthy.
- close-source -> closed is explicit controller-close; require normal source
  DOWN within1500ms and exact observer-only restoration. settled -> settled:
  observer12/13 health, same sentinel/unique name/bus ID.
- stop -> result: actor0, observer normal DOWN, empty peers/authority/accounting,
  monitored supervised core/Listener shutdown and socket removal mandatory.

All11 core identities remain unchanged throughout until explicit shutdown.
Six resource stages: before_collection, after_collection_source_health,
after_observer_health, source_departed_restored, after_final_observer_health,
final_empty_cleanup. Initialize constant instrumentation before baseline without
target warmup or changed logging level. Sampled total BEAM memory<=268435456,
atom growth<=16; preserve raw VM/process metrics and deltas, including reductions.
Departed metrics absent, never invented0. These endpoints prove no transient
peak, scaling, leak/soak/overload/concurrent-health or full-PRO05 bound. Controlled
InvalidArgs under the source-bound materializing decoder does not establish a
payload round trip or an independent element-by-element delivery check.

Keep state/DOWN1500ms, socket/reply/exit3s, observer health1000ms, actor30s,
ExUnit60s and host900s/cleanup5s. Check predicate deadlines even when true.
Private0700 parent/0600 socket, pinned nonroot separate Linux/headless process,
current source-bound artifact and start_supervised! named core. Success requires
child0/graceful_success=true. Root owns formatting/checks/runtime after SPEC
then independent QUALITY PASS. Preserve failures, diagnose before changed
numbered attempts; no unchanged retry or relaxed deadline/threshold.

Completed fragmentation, PRO03, SEC13-16, missing signature, XML deadline/size,
variant64/65, static array/struct32/33 and typed-match targets stay completed.
Ordinary complete setup/health for this distinct case is permitted. SEC03 no
retry, SEC06 no redispatch, SEC08 no fourth run/scratch, SEC09-12 pause and FD04
exclusion persist. No optional audit, penetration/exploit work, broad fuzzing,
external API/network probe, Nix build/fetch, VM, host live-bus/system/account
change, push/publication or memory write. All preserve others' edits. Required
VM/profile gates stay blocked, frozen index unchanged, M1 unpassed/productfalse.
