# PRO04 configured XML message-size local native boundary

Close the current-artifact native gap for the max_message_size4096/4097
boundary required by PRO-04/P04 and the implemented XML limit contract. This
boundary has historical native passes in p09-frames13/0 and p09-integration
actors-current-green22/0; the Peer hash differs. Preserve those results as
historical evidence. No production defect is identified and native pre-fix
RED remains UNOBSERVED. Do not rerun completed pure or native targets.

Add only apps/gao_bus/test/peer_xml_message_size_test.exs and
apps/gao_bus/test/fixtures/peer_xml_message_size_actor.py. One selected case,
one registered source, one independent registered observer, two target sends:
the complete4096-byte GetId call with string argument (controlled InvalidArgs),
then only the16-byte fixed prefix of the equivalent4097-byte call. The latter
must cause actual automatic normal Peer DOWN before the actor observes exact
EOF while its source socket is still open. Do not send its advertised body.
Use unchanged independent Hello/transport helpers, actual UID-derived EXTERNAL,
ordinary complete registration/setup/health, no FD negotiation. Sentinel:
org.foundation.XmlMessageSizeObserver.

Use actual Config.load->Runtime.compile->Application->Listener->real Peer
propagation from the private system-type XML file, following the existing
peer_xml_frame_deadline_test fixture. Assert complete compiled configuration
and exact admission/frame_options projections rather than manually forwarding
XML maps. max_message_size4096 must reach both Peers, with the existing protocol
output bound. Allow only actual test UID admission, scoped bus setup/health
methods and observer name; include ordinary error and method_return receipts.
Do not weaken policy or add a blanket identity exemption.

Require exact target bytes/lengths/serials and ordered InvalidArgs/source-health
receipts, no buffered client bytes/FDs, and continuing same-source identity at
4096. Observer unique name/sentinel/bus ID and core/listener identities survive
both boundaries. Require exact authority/accounting equality after the legal
call at quiescence and restoration to the observer-only baseline after the
oversized prefix. Record source normal DOWN and exact open-socket EOF, final
observer health, actor0, empty peer/authority/accounting cleanup, core/listener
shutdown and socket removal. This is a finite frame-boundary check, not a
peak-memory, leak, overload, full PRO04/05 or system-profile qualification.

Reuse existing state/DOWN1500ms, actor socket/reply/exit3s, observer health1000ms,
actor alarm30s, ExUnit60s and unchanged host_lifecycle.py outer900s/cleanup5s
bounds. All waits check deadlines even when their predicate becomes true.
Separate pinned headless Linux process; actual nonroot real/effective UID/GID
and kernel actor PID; current source-bound artifact/native adapter. Core fixture
uses start_supervised!, private mode0700 parent/mode0600 socket and explicit
address only. Success requires child0 and graceful_success=true. Retain failures
and diagnose before a changed retry; no unchanged retry or increased deadline.
Root alone owns formatting/checks/runtime after SPEC then independent QUALITY.

Worker owns only the two new source files; reviewers read only. Root owns the
driver, scope, evidence and ledger. All preserve others' edits. Do not select
historical large input/output, FD cases, accepted Gao/reference fragmentation,
variant64/65, missing-signature or frame-deadline targets. Complete ordinary
setup/health for this distinct requirement is permitted. SEC03 no retry, SEC06
no redispatch, SEC08 no fourth run/scratch, SEC09-12 pause and FD04 exclusion
persist. No optional audit, penetration/exploit work, broad fuzzing, external
API/network probe, Nix build/fetch, VM, host live-bus/system/account change,
publication or memory write. Required VM/profile gates stay blocked; frozen
index unchanged, M1 unpassed, readinessL0/product_qualified=false.
