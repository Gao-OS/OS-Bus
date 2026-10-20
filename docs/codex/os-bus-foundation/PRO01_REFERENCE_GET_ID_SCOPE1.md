# PRO01 ordinary reference GetId127 splits

Complete the remaining ordinary reference GetId fragmentation subset required
by TEST_PLAN PRO-01/P02/P04. This finite positive protocol case is authorized
by the full goal. Accepted Gao AUTH/BEGIN/Hello/GetId, reference Hello127 and
reference AUTH24/BEGIN6 targets must not run again. Ordinary complete setup/
health exchanges needed by this distinct case are permitted. No bypass,
invalid identity, denial, paused or excluded security target is selected.

Add only scripts/foundation/pro01_reference_get_id/{actor.py,run.py,
test_fixture.py}. Reuse unchanged reference-Hello tracing, queue/barrier/kernel
control and lifecycle; independent GetId/Hello/transport wire helpers. Do not
import a donor run() or patch its globals. Avoid ambiguous donor runner
imports through unqualified from actor. Existing source stays unchanged.

One new run contains exactly127 ordered offsets1..127 of the existing128-byte
GetId (SHA256 f55d450521f6041ef2085a7e893bc6b8c80210feea6d97fb3485d101fe9af575),
128 bus connections including one persistent observer. Every fresh source
uses actual nonroot UID-derived EXTERNAL with exact OK, complete BEGIN+Hello,
ordered reply1 and exact NameAcquired. Trace before the first send. Hold only
GET_ID[:split] on the registered source, prove live same-socket queue0,
observer health, second live queue0 within1s of the prefix's last completed
send, with unchanged source sends and no source reply/EOF. Observe registered
source ownership during the hold. Then release GET_ID[split:] plus unchanged
GET_ID_SUCCESSOR (serial3). Require exactly two ordered successful replies,
serial2 then3, both returning the stable observer bus ID. Retain exact bytes,
source/observer unique-name separation, actual kernel UID/PID queries, empty
pending bytes/FDs, source ownership disappearance after close and continuing
observer sentinel/unique-name/bus-ID health. Sentinel:
org.foundation.GetIdSplitObserver. No FD negotiation.

Require raw receive records bound one-for-one to ordinary parsed receipts,
including exact AUTH OK before binary protocol sends, source registration,
target replies, observer ownership/health/identity/disappearance/final health.
Use the existing unchanged frame encoder with actual flags/header ordering;
do not create a generic decoder. Reuse the prior finite socketpair kernel
control. Census rejects missing, duplicate, reordered, out-of-range or failed
cases. Add proportionate offline regressions for census, barrier identity/
deadline, reply order/body and missing/corrupt receive evidence. Offline tests
must not execute sockets, actors or daemon targets.

Use existing pinned reference dbus-daemon1.14.10 and actual real/effective
nonroot UID/GID with system-type EXTERNAL-only scoped configuration, explicit
private0700 socket parent/0600 socket and worktree fixtures directory. No host
configuration includes, service directories or default/live bus discovery.
Preserve exact argv/environment/source/config/runtime pins and raw receipts.
Existing bounds: startup10s, socket/reply3s, actor45s, barrier1s, cleanup5s,
unchanged host_lifecycle.py outer900s. Success requires child0 and
graceful_success=true, removed socket/parent and no observed owned processes.
Preserve failures; diagnose before any changed retry; no unchanged retry or
deadline increase. Root alone owns checks and runtime after SPEC then QUALITY.

Queue evidence proves its recorded kernel consumption boundary. Reference
parser buffers, authority/accounting, native server receive extents and
multiple frames in one native read stay UNSUPPORTED/UNPROVED. No frame-boundary
FD design change, paired current Gao qualification, frozen-index promotion,
full PRO01 mapping or readiness promotion is implied.

Worker owns only the three new source files; reviewers read only. Root owns
scope/evidence/ledger. All preserve others' edits. No optional audit,
penetration/exploit work, broad fuzzing, external API/network probe, Nix build/
fetch, VM, host live-bus/system/account change, Git publication or memory write.
SEC03 no retry, SEC06 no redispatch, SEC08 no fourth run/scratch, SEC09-12 pause,
FD04 exclusion and all completed-target restrictions persist. Required VM/
profile gates remain blocked; M1 unpassed, readinessL0/product_qualified=false.
