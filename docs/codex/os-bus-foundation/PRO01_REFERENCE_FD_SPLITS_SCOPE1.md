# PRO01 positive reference FD split coverage

Implement the remaining normal positive reference D family required by TEST_PLAN
PRO-01 and the reviewed PRO01_COVERAGE1.md FD02 integration contract. The full
goal authorizes this distinct protocol work. The previous goal turn made
progress by preserving the RES02 failure and establishing the exact missing-input
blocker; it did not complete the foundation or establish a whole-goal impasse.
RES02 remains closed with no runtime repair/retry. Its 98 missing store paths
must not be restored, substituted or rebuilt as part of this work.

Own only scripts/foundation/pro01_reference_fd_splits/{actor.py,run.py,
test_fixture.py}, this scope, resume-20261019/pro01-reference-fd-splits1/ evidence
and precise leading entries in STATUS.md, COMPATIBILITY.md and EVIDENCE.md.
Worker owns the three new source files; root owns scope/evidence/ledgers and
execution. Reviewers read only. All preserve others' changes. No product,
donor/helper, existing test, assertion, policy, threshold, sealed evidence or
accepted-index modification is included.

Reuse unchanged reference Hello/GetId/AUTH tracing, kernel queue/identity/barrier,
wire-frame and host_lifecycle helpers, and transport_actor's independent framing,
SCM_RIGHTS and FD receiver. Reuse positive FD donor bundle/receipt/validate/
reclaimed/inventory mechanisms. Do not import a donor run() or patch its globals.
Do not call the donor's negative_controls or select a malformed/denied FD case.
Use qualified imports; no generic replacement decoder or second test framework.

One initial reference run selects exactly286 ordered cases: modes
rights_with_prefix then rights_at_split, each offsets1..143. First frame is the
same saved144-byte Resource signal, serial10, destination :1.2, signature hh,
body [1,0], two rights, SHA256
aece49fad72a9746c85ca850925e3081960904ba870160162c6c940fc853e521.
Register observer first, initial source second and recipient third; require
actual names :1.0/:1.1/:1.2. Keep observer/recipient persistent, use first source
for case0, then a fresh independent source process and connection per case.
The absent sender field means changing source names cannot change the literal.
Use serial11 with a disjoint two-pipe bundle/body [0,1], then serial12 with
no rights, empty signature/body. Freeze all three exact byte vectors before
runtime; require lengths144/144/128, total416 bytes per case. No serial reuse on
one source or dynamic destination-length substitution. Total288 bus connections.

Observer, recipient and each source have independent processes and fresh sockets.
Never fork or pass an already-connected socket to a role. Record actual PID,
starttime, real/effective UID/GID, source/recipient/observer unique names, kernel
peer credentials and bus credential-query correlation. All actors use their
actual nonroot UID through exact EXTERNAL OK; source/recipient complete allowed
FD negotiation before BEGIN and Hello. Account for exact Hello reply and
NameAcquired and all setup/query/health frames. Observer owns
org.foundation.FdSplitObserver and retains its unique name and stable bus ID.

Use the donor's two positive placements exactly. rights_with_prefix sends the
whole frame[:split] with both rights. rights_at_split sends frame[:split-1] as
ordinary bytes when nonempty, then the single byte frame[split-1:split] with
both rights. Close sender readers after transfer; withhold the suffix until
the held-prefix proof completes. No arbitrary sleep replaces synchronization.

Reuse the live source socket TIOCOUTQ zero -> observer health/source ownership ->
second zero barrier within1s of last completed prefix send, with the same PID/
starttime/fd/inode and unchanged complete send signature. Include sendmsg in
tracing: actual completed bytes/count, rights and pipe identities, and ordinary
continuation after any short send. A send through __getattr__ is not evidence.
Record recipient nonconsuming readiness fences proving no pending output at
the sampled held boundary; do not peek/discard unaccounted rights.

Take a quiescent external daemon FD baseline after source registration in each
case. While held, require baseline+2 descriptors, each actual first-bundle pipe
identity exactly once, and CLOEXEC evidence from owned daemon /proc fdinfo.
These observations and both zero samples must fit the unchanged1s barrier.
Do not relabel them as exact reference parser bytes, credits or internal queues.

After release require three ordered exact Resource receipts: serial10/[1,0],
serial11/[0,1], serial12/empty. Validate type/path/interface/member/source/
destination/signature/count/body, ordered FD-array pipe IDs and actual payloads,
disjoint bundles and the FD-free tail. Close received rights. All four writers
must observe BrokenPipe after transferred readers retire. Require empty pending
bytes/rights, exact daemon FD restoration with live connections, then source
exit/name disappearance and persistent recipient/observer health. Census:
286 cases,572 FD-bearing frames,1144 usable pipe resources,286 no-FD tails.

Bind all raw receives one-for-one to parsed receipts and raw ancillary controls/
actual identities, including AUTH/AGREE, registration, target triplets and
observer queries/health. Extend the existing tracing/oracle specifically for
valid SCM_RIGHTS; FD-free GetId controls==[] cannot validate these receipts.
Retain exact partial-send reconstruction, per-role byte streams, no unexplained
frame/FD bytes, process identities, per-case baselines and bounded cleanup.

Add proportionate offline tests for ordered exhaustive census, literal/placement
reconstruction, barrier identity/time/sends, exact ordered receipt fields and
resource identities/payloads, missing/corrupt raw/control evidence and cleanup
acceptance. These tests operate on saved/synthetic data only; they must not open
sockets, pipes, launch actors/daemons or probe the host. Missing/duplicate/
reordered/out-of-range cases and failed cases must reject qualification.

Use the still-available pinned dbus-daemon1.14.10
/nix/store/pb9dhpk6qxjybb8p7prvs18ls2vxk51a-dbus-1.14.10/bin/dbus-daemon
(SHA e98a7397e16b01a3cae65f14e6d38195fc73b313887174d6e5e0bd98de418a9a)
and Python3.13.15
/nix/store/xqnbm0vgqcq9b1b54c80qj9s0qhbwa08-python3-3.13.15/bin/python3.13
(SHA56f78bdc0ad95ef4c2723243bbffb99a64fbef8b190916eecf8b1660137adfca).
Use explicit private0700 parent/0600 socket, system-type EXTERNAL-only standalone
test XML, no host includes/service directories/default bus discovery. Extend the
reference GetId fixture's scoped ordinary-UID policy only for this observer name
and directed /foundation/org.foundation.Transport/Resource signals to :1.2;
preserve normal bus calls/signals needed for setup and health. No broad root or
system-UID exemption and no product-policy change.

Existing bounds remain startup10s, socket/reply3s, actor45s, barrier1s, settle/
Peer-disappearance1.5s, cleanup5s and host_lifecycle outer900s. Offline tests60s.
Do not increase a bound to obtain green status. Freeze source/config/runtime/
helper/input hashes and all vectors, then specification review, independent
quality review, root-only static/offline checks and one initial isolated
reference runtime. Preserve any failure and diagnose before proposing a changed
retry; no unchanged retry or automatic new allowance follows. New-scope source
and runtime counters begin0 and remain separate from every historical counter.
Success requires child0, graceful_success=true, no containment, owned descendants
reaped/absent and socket/private-parent removed through normal bounded cleanup.

This is ordinary private reference development evidence using separate daemon
and actor processes. It does not execute or qualify mandatory disposable-VM/
installed-profile gates. No VM/Nix build/fetch is part of this local reference
scope. Reference parser/accounting/native receive extents and several frames
per native receive remain UNSUPPORTED/UNPROVED by this fixture. Earlier design
documents' universal native-read blocker is historical: current Gao coalescing
evidence exists and is not rerun or superseded here. No full PRO01, FD row,
paired current Gao/reference, network, index, milestone or readiness promotion.

Completed Gao/reference AUTH/BEGIN/Hello/GetId targets must not rerun. Ordinary
complete setup/health required for D is permitted. SEC03 no retry, SEC06/FD04
automatic denials, SEC08 no-fourth, native authorization/P10 terminalSol2/Astra2,
frame-cleanup VMremaining0 and RES02 VMremaining0 remain closed. No optional
audit/penetration/exploit work, broad fuzzing, external API/network probe, host
live-bus/account/profile/configuration change, commit/merge/push/release/
deployment or memory write. Actual precommit remains BLOCKED_SCOPE_AND_ENV.
Full P00–P12/M0–M4 incomplete; M0 historical; M1/P02 earliest unfinished;
L0/product_qualified=false until mandatory gates actually pass.
