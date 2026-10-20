# P04/PRO05 native typed match-argument regression

Verify the existing fix for the historical uint32(42)+arg0path Router crash
through a real Peer and independent observer. This is the adversarial match
argument functional requirement in PRO-05/R-05, not an optional audit or new
policy test. The historical unit regression is already completed; do not rerun
it or reopen accepted SEC15. Current match_args/argument_path? contain type/
binary guards; no production defect is identified. Native pre-fix RED remains
UNOBSERVED. Full PRO05 stays unmapped.

Worker owns only apps/gao_bus/test/peer_match_argument_test.exs and
apps/gao_bus/test/fixtures/peer_match_argument_actor.py. Reuse unchanged
independent Hello/transport helpers and current finite array fixture lifecycle/
resource sampling pattern. No production/shared-helper/accepted-test edits.
One registered source and one independent registered observer, actual UID-
derived EXTERNAL, no FD negotiation. Sentinel:
org.foundation.MatchArgumentObserver. Observer installs exactly one rule using
AddMatch4 before source opens: type='signal',arg0path='/probe'.

Send exactly two destination-less target signals at path /probe, interface
org.foundation.Probe, member Changed, without incoming sender/FD headers:
positive serial3 signature s, body string('/probe'), header71 padded72/body11/
frame99; then typed nonmatch serial6 signature u, body u32(42), header71/body4/
frame92. Independently compare exact packets. Both are legal wire signals.
The positive control must deliver exactly one signal with authenticated source
sender and original serial3; it proves the installed match/receive path works.
The uint32 signal must be a nonmatch without an exception or other mutation.

After positive send, source completes GetNameOwner/GetId4/5 before observer
health is sent. Observer exact reader requires ordered signal3 then replies
10/11 and empty bytes/FDs. After typed send, source completes health7/8 and
emits a typed-source barrier. ExUnit observes unchanged source/authority state
and records its endpoint sample, then instructs observer to issue health12/13.
Observer exact reader must receive only those two replies and be empty.
Router enqueues matching signal delivery before source route completion, so
wrong typed delivery must precede those observer replies. Do not use a helper
which skips unexpected signals, sleeps, negative read timeouts or a fabricated
receipt as absence evidence.

Require exact source writes and ordered receipts, same source/observer unique
names, observer sentinel/bus ID, actual UID/GID/kernel actor PID and stable core/
Listener identities. Explicit actual-UID policy scopes admission, sentinel,
required bus methods and this signal's send/receive; no policy bypass. Quiescent
authority/accounting and match entries equal connected baseline after each
phase. On explicit source-close require normal source DOWN, exact observer-only
restoration and continuing observer health. Final actor0, observer normal DOWN,
empty peers/matches/authority/accounting, monitored core/Listener shutdown and
socket removal are mandatory.

Record six unchanged-envelope endpoint resource samples: before-positive,
after-positive-quiescent, before-uint32, after-uint32-source-health,
after-observer-health, final-empty-cleanup. Total sampled BEAM bytes<=268435456,
atom growth<=16; initialize constant instrumentation before baseline with no
target warmup, changed logging level or relaxed thresholds. Record raw metrics/
deltas; departed metrics absent, never zero. These endpoints do not establish
transient peaks, leak/overload/soak or full-PRO05 bounds.

Retain state/DOWN1500ms, socket/reply/exit3s, observer health1000ms, actor alarm
30s, ExUnit60s, host_lifecycle outer900s/cleanup5s. Check predicate deadlines
even when true. Separate pinned nonroot headless Linux process/current artifact,
start_supervised! core, explicit private0700 parent/0600 socket. Success requires
child0/graceful_success=true. Root owns formatting/checks/runtime after SPEC
then independent QUALITY. Preserve failures; diagnose before a changed retry,
no unchanged retry or increased deadline.

Completed targets remain completed; ordinary complete setup/health for this
distinct regression is allowed. SEC03 no retry, SEC06 no redispatch, SEC08 no
fourth run/scratch, SEC09-12 pause and FD04 exclusion persist. No optional
audit, penetration/exploit work, broad fuzzing, API/network probe, Nix build/
fetch, VM, host live-bus/system/account change, push/publication or memory write.
All preserve others' edits. Required VM/profile gates stay blocked, frozen
index unchanged, M1 unpassed/readinessL0/product_qualified=false.
