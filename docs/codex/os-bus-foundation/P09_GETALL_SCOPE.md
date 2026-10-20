# API-02 paired Properties.GetAll qualification

Continue the full Foundation P00-P12/M0-M4 objective in .trees/os-bus-foundation
on codex/os-bus-foundation at base7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4.
Previous turn made concrete progress: scoped Set implementation, paired VM and
candidate08 security refresh all passed. Complete readiness remains L0.

Current immutable candidate08 manifest
735f8127e3caec8d52523a234145810cc30bc6bfac08cc9bb329b4a136433b3c, source
1d826eaa9aa34ffad535d9a94e2942c8de4f7dfb648e272220a29e23b331cec1.
Reuse the existing reload/alias/Set actor and disposable VM harness. Preserve
all four existing tests, six actors, old artifacts, failures and user changes.
Add exactly one paired GetAll test; freeze five tests and eight named actor
reports. New getall-candidate/reference scope is properties-get-all.

Prepare root-owned bus.conf -> policy.conf -> rules.conf once using unchanged
prepare-properties. Candidate and pinned reference consume identical bytes and
socket path. Candidate core/listener monitored normal shutdown and socket
removal precede reference startup without rewriting XML. Independent caller
UID/GID1101 clears groups and connects before root observer; root queries live
UID/PID for both and proofs precede API calls. Preserve ordinary trusted-file
EACCES, identities, complete wire frames and zero-rights/reply-envelope checks.

Caller sequence is Get Features; Get Interfaces; GetAll(org.freedesktop.DBus);
GetAll(org.freedesktop.DBus.Peer); GetAll(org.foundation.UnknownInterface);
then stable GetId. Require outer a{sv}, exactly Features/Interfaces with as
variants matching each backend's own prior Get arrays, empty Peer dictionary,
and exact org.freedesktop.DBus.Error.UnknownInterface for the unknown interface.
Decode physical dictionary/string/variant/array alignment and bounded ranges,
NUL/UTF8/zero padding/duplicate keys/full consumption independently of product
code. Save actual errors and continue following operations/health/normal cleanup;
retain both reports before final assertions so a candidate delta cannot suppress
reference execution. Do not require equal arrays between backends.

Reuse existing operation12s and normal cleanup/startup deadlines. New six-call
coordinator bound is77s (6*12+5), old Set65s is unchanged. Existing test120s,
runner150s and guest180s deadlines remain unchanged. Forced cleanup cannot pass.
All policy/authority/config and immutable source/build hashes must stay stable.
No production defect is established: production changes require retained actual
failing evidence first. Focused missing GetAll error/empty-interface regression
is parent-owned; meaningful external oracle vectors must reject malformed data.

Ownership: p09_alias_quality edits only reload_actor.py. p09_alias_spec edits
only file_reload_socket_test.exs and p09_reload/run.py/test.nix. They coordinate
report schema; parent owns unit tests, preservation, all runtime/VMs/captures,
reviews and docs. Parent snapshot is takeover-20261010-p09-getall/preservation-
before.json. No commits/merges/pushes/remote writes/releases/deployment/host live-
bus traffic/memory updates. Do not redispatch rejected registered-Peer FD04 audit.

This row contributes to full API-02/P09 without closing them. Inventory17/39/500,
mandatory P07 queued-repeat/P09 optional-INTERFACE FAILs remain selected and
unchanged. P10 activation, P11 release/inheritance/packaged600s soak, P12 real
services/rollback and all required dependent gates remain unfinished. Goal stays
active until requirement-by-requirement completion proves the full objective.

Execution boundary 2026-10-10: bounded GetAll slice complete. Focused68/0,
fresh candidate08 paired VM5/0 with8/8 actors and zero skips/blocks; independent
saved-wire976-frame replay,24 external vectors,61 accounting probes and both
static/saved-evidence reviews PASS. Original four tests/six actors,58 sources,
68 artifacts and prior evidence preserved. See STATUS.md and
p09-reload-wire/candidate08-getall-run1/. Full goal remains active at L0.
