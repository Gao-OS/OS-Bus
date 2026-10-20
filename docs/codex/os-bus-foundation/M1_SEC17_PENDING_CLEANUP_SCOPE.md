# SEC17 pending-call cleanup regression

Required P05 / TEST_PLAN SEC-17 and FAIL-01: abrupt actual Peer death must reclaim
authority and pending calls while preserving the healthy observer. This scope
extends the existing foundation_security_test.exs SEC17 scenario, which already
covers owned/queued names, match rules and capabilities. Add actual outstanding
requests for killed callee and killed caller, using existing local native Peer
connections. Check NoReply where required, pending reservation retirement and
healthy identity/ownership. Preserve existing assertions and resource semantics;
source-death ingress work must still be explicitly retired by its owner.

Worker owns only apps/gao_bus/test/foundation_security_test.exs test additions and
necessary private helpers; tag these cases foundation_peer_cleanup. Root alone
runs the exact tag selection (never the whole security file), pinned formatter
and relevant compiler checks. No production defect is assumed. If a new scoped
regression fails, retain it and diagnose before authorizing a minimal production
change. Preserve every pre-existing test and all unrelated workspace changes.

No VM or external API test is included. Native sockets must use the existing
private temporary directory and complete cleanup. Use supervised processes,
monitors and absolute bounded polling; no sleep/retry inflation. This is local
functional regression coverage; complete SEC17/M1 remains blocked without its
mandatory independent/VM evidence. Registered-Peer FD04, original SEC03/06/08
restrictions, paused SEC09–12 and all earlier failures remain untouched. No
optional audit, broad fuzzing, extra acceptance criteria, host live system/bus
access, Git commit/merge/push/release/publication or memory writes.
