# PRO02 live valid unknown header

Requirement: TEST_PLAN.md PRO-02 requires valid unknown extension cases to
remain usable. Existing input_containment_test.exs covers header42 in the pure
decoder; peer_coalesced_read_test.exs covers unknown message type42. This scope
adds one missing live-bus observation, not another unknown-type test.

On an explicit private socket, register an independent FD-free source and
observer. Send one otherwise ordinary GetId call with a well-formed unknown
string header42. Require the exact correlated successful bus-ID response, an
ordinary follow-up GetId, observer identity/health, no extra data or rights,
normal closure and owned-socket cleanup. Reuse the existing independent wire
reader/builder and supervised Gao test setup. No product defect or RED is
assumed. This does not resolve the separate reply-interface disagreement or
qualify the complete PRO02 row.

Source ownership: a worker owns only the new actor, ExUnit regression,
proportional data-only checks and explicit private-reference launcher under
apps/gao_bus/test/{fixtures/peer_unknown_header_actor.py,
peer_unknown_header_test.exs} and scripts/foundation/pro02_unknown_header/.
Root owns scope, preparation, pins, selected execution and ledgers under
resume-20261019/pro02-unknown-header1/. Existing helpers and sealed evidence
remain unchanged. Review source before selecting one reference execution.
Gao runtime remains BLOCKED_ENV until its actual prerequisites are established;
no new VM target or product change is selected by source preparation alone.

Use current real UID and EXTERNAL, explicit no-FD negotiation, a restrictive
DBus-only policy, socket/reply3s, actor30s, ExUnit60s, reference startup10s,
actor wait45s and cleanup5s. Reuse the existing identity-bound outer lifecycle
helper with its900s limit. Save exact inputs, commands, streams, backend PID,
socket identity, selection/execution counts and cleanup result. Run only new
data checks and syntax/format checks needed for these sources. No unchanged
failed runtime retry or unrelated test expansion.

All closed routes and protected98 missing RES02 paths remain closed. No probes,
restoration, substitution, reconstruction or rebuilding of those filesystem
paths. No optional audit, exploit, fuzzing, external API test, host live-bus or
system change, commit, merge, push, publication, release or memory write.
The required evidence index is not promoted by this one observation. Full
P00-P12/M0-M4 remains incomplete; M1/P02 first unfinished; L0 and
product_qualified=false; precommit remains BLOCKED_SCOPE_AND_ENV.
