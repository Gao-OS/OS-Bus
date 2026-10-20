# PRO01 ordinary reference AUTH24 and BEGIN6 splits

Complete the remaining ordinary reference authentication-fragmentation subset
required by TEST_PLAN PRO-01/P02. The full goal authorizes these finite positive
protocol cases. Existing Gao AUTH/BEGIN/Hello/GetId targets and reference
Hello127 are completed and must not run again. Ordinary complete Hello/GetId
exchanges used to complete the new AUTH/BEGIN cases are permitted setup/health.
Do not select any bypass, invalid identity, denial or paused security target.

Add only scripts/foundation/pro01_reference_auth_begin/{actor.py,run.py,
test_fixture.py}. Reuse the unchanged reference-Hello predicates, tracing,
socket-queue sampling, kernel control, lifecycle and independent wire helpers.
Do not import a donor run() or monkeypatch its globals. Existing files remain
unchanged. One new run contains exactly AUTH offsets1..24 followed by BEGIN
offsets1..6 (30 ordered cases,31 connections including the observer). Derive
AUTH from the actual nonroot UID and require exactly25 bytes; a different
census is a blocker, not silent reselection. AUTH source opener must not send
the complete AUTH automatically. Trace the socket before its first send.

AUTH: hold AUTH[:split], prove the barrier, send its suffix, require exact OK,
then send complete BEGIN+Hello+GetId. BEGIN: send complete AUTH and receive OK,
hold BEGIN[:split], prove the barrier, then send its suffix+Hello+GetId. For
each held prefix require live same-socket TIOCOUTQ0, observer GetNameOwner/GetId
health and a second live queue0 with an unchanged send trace, all within1s of
the prefix's last send completion. No source reply or EOF may appear during
the hold. Preserve the existing finite socketpair0/positive/positive/0 control.
Roles include family and split; no family role collisions.

Require ordered successful replies1,2, exact NameAcquired, stable bus ID,
source/observer unique-name separation, actual kernel UID/PID queries, empty
pending byte/FD state, source ownership disappearance and continuing observer
sentinel health. Census validation rejects missing, duplicate, reordered,
wrong-family or failed cases. Add proportionate offline validator regressions
for these acceptance boundaries, without executing sockets or targets in them.

Run an existing pinned reference dbus-daemon with system-type EXTERNAL-only
test configuration, actual nonroot real/effective identities and explicit
mode0700 private socket parent/mode0600 socket. Independent actor uses explicit
address only. Preserve source/config/actor/runtime pins, raw wire receipts and
finite cleanup. startup10s, socket/reply3s, actor45s, barrier1s, cleanup5s and
unchanged host_lifecycle.py outer900s bounds apply. Success requires child0 and
graceful_success=true. Preserve failures; diagnose before a changed retry; no
unchanged retry or deadline increase. Root alone owns checks and runtime.

Kernel queue-drain observations prove the recorded consumption boundary only.
Reference parser internals, authority/accounting, server receive extents and
multiple frames in one native read remain UNSUPPORTED/UNPROVED. No native
frame-association design change, frozen-index promotion, full-PRO01 mapping or
paired current Gao qualification is implied.

Workers own only the three new source files; reviewers read only. Root owns
scope/evidence/ledger. Preserve all other edits and paused/excluded/restricted
targets. No optional audit, penetration/exploit work, broad fuzzing, external
API probe, network, Nix build/fetch, VM, host live-bus/system/account change,
publication or memory write. Required VM/profile gates remain blocked. M1
remains unpassed; readinessL0/product_qualified=false.
