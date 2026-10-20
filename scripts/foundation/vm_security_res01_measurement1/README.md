# Bounded RES01 timing experiment overlay

SOURCE_ONLY_NOT_EXECUTED. This directory instruments the exact corrected
vm_security_res01 fixture in memory. It diagnoses the retained held400ms failure;
it cannot qualify RES01, M1, the accepted index or product replacement.

BASE_BINDINGS1.json pins corrected run/launcher, actor/workload/cleanup and the
original Channel/daemon. actor.py, workload.json and cleanup.py are byte-exact
copies. Original vm_security wire transports and all base files stay unchanged.
recipe1.json contains exact-hash/count-guarded source replacements, rather than
a copied runtime harness. The wrapper checks candidate18 manifest/source hashes
and preserves the base's artifact/mode and root/marked-guest/private-socket guards.
test.nix reuses the pinned Nix lock, manifest Elixir/OTP/native runtime and original
guest transport, adding only the frozen corrected base and measurement overlay.

Python spans retain same-clock monotonic before/after boundaries in finally for
request/call begin/read/receipt append/persist, settle write/flush/read/validation/
state-key comparison, and Channel select/os.read/synchronous line-log/JSON parse.
Records include dimension/trial/phase/attempt/snapshot ordinal where applicable,
operation/member, actor or channel PID and absolute deadlines. Raw-line and
os.read byte counts are recorded without duplicating payloads. The original
synchronous open/write/close logging and complete returned snapshots remain exact.

The daemon times original snapshot, original/extension Limits snapshots,
authority/each-peer reads, JSON-safe mapping, completed snapshots, JSON encoding
and the existing synchronous IO.puts write/flush interval. No new transport flush
or stdout measurement line is added. Records and ordinals live only in the
launcher process dictionary, outside compared snapshots. try/after retains
failed calls/reads/encoding/writes. A separate daemon-measurement.json is written
only after the original eval loop terminates; runner checkpoint/finally drains
that file after the original persistence-deferral guard and teardown.

Python records are bounded100000; daemon records200000. Exhaustion fails visibly.
Each timing read/metadata append adds overhead inside the unchanged wall-clock
bounds; no time is subtracted or deadline reset. Daemon records use local elapsed
nanoseconds. They must never be subtracted from Python guest monotonic timestamps.
recipe/base/instrumented source and runtime-transformed daemon hashes disclose
the instrumentation. All eight dimensions/trials, order, operations, policy,
denials, predicates, snapshots and clocks remain the original experiment contract.
Bounds remain held400ms/auth1500ms/idle500ms/health-settle-reallocate1s,
authority60s/guest120s/host900s/cleanup5s. The separate reference checker remains
unchanged, including its #Ref< predicate; genuine match-table failure is retained.

Root prerequisites and entries:

1. Fresh ordered SPEC then independent QUALITY review of this source closure,
   transformations, static evidence and scope. No review is supplied here.
2. Root records controls1.py through unchanged FD07 record-preflight6.py .record(),
   using its exact source hash. Eight inert focused methods must run with
   failures0/errors0/skipped0. These exercise actual timed function bodies with
   inert clocks/transports: return identity, exception finally, context restore,
   exact raw logging, failed parse retention, original Channel deadline failure,
   failed request boundaries and unchanged held/authority deadline enforcement.
   They do not import a target runner/actor, operate sockets, or provide VM evidence.
3. Root records parse1.py through the same recorder60s/cleanup5s. It runs pinned
   Elixir parse-only and Nix --parse, each timeout20s. The Elixir probe parses the
   overlay, guarded launcher and daemon drafts; extracts the actual observer
   binary from AST without macro expansion/evaluation; reassembles and parses
   the actual inner transformed daemon, recording its exact hash/length. No
   inspected launcher/daemon/Nix execution or broker/VM occurs in that entry.
4. Root prepares fresh source/candidate/runtime approval using existing host
   lifecycle primitives, builds only the driver, verifies exact realized inputs,
   then exclusively schedules one diagnostic disposable VM with an independent
   driver/VLAN/QEMU witness and natural-retirement reconciliation. This source
   preparation supplies no alternative generic host harness or runtime receipt.
5. Root preserves the first failed original assertion, all raw logs/receipts/
   snapshots, timing/error attempts, measurement files, cleanup and VMoff facts.
   Missing instrumentation remains failed/blocked. Analyze the retained breakdown
   before selecting any separate scheduling repair; no blind repeat or waiver.

Evidence preparation is at environment/m1-res01-measurement1: preserved bindings,
four guarded-source diffs/drafts, static receipt, source binding and handoff.
Actual control/parsing/build/VM outcomes remain NOT_RUN. Original VM4 remains
selected8/executed3/passed2/failed1/blocked5/skipped0. ReadinessL0,
product_qualified=false, full foundation incomplete.
