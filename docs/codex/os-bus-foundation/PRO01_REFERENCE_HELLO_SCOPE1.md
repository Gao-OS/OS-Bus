# PRO01 normal reference Hello fragmentation subset

Implement and run the missing reference-side normal Hello split sequence under
R-02/R-06/R-15, P02 preliminary PRO01 and P06, TEST_PLAN.md's PRO-01 row.
The full goal already authorizes this work. The earlier source-design1 contract's
requirement for another owner approval was our workflow, not an additional user
condition. This document supersedes that prerequisite for this subset only.
Preserve the historical contract and all completed Gao AUTH/BEGIN/Hello/GetId
evidence. No completed target is rerun or relabeled.

The stream reader must handle legal fragmented and adjacent frames. The current
native adapter deliberately stops at frame boundaries because recvmsg supplies
no ancillary byte offsets (ADR-004). Keep that design. Adjacent client writes,
sender-queue consumption, parser-buffer state and frames in one native recvmsg
are different observations. This subset proves normal reference continuation
after a consumed prefix. It cannot prove reference internal parser state,
reference accounting or several complete frames in one native receive.
Those observations remain unsupported/unproved; full PRO01 stays unmapped.

Use exactly 127 Hello cases, offsets 1..127 of the existing 128-byte literal.
Reuse the unchanged independent Hello/transport actors. Source and observer
perform ordinary EXTERNAL with their actual nonroot UID; no FD negotiation.
One observer retains its unique name, owned sentinel and bus ID across all cases.
For each source withhold the suffix after BEGIN plus the exact Hello prefix.
Record actual write bytes/timestamps and live same-socket PID/starttime/fd/inode.
Within the existing one-second barrier prove sender TIOCOUTQ zero, unrelated
observer GetNameOwner/GetId success, then another live zero with unchanged sends.
Queue drain demonstrates kernel consumption; it must not be called parser state.
No source bytes or EOF may be available before releasing the suffix.

Complete the exact Hello suffix plus GetId. Require successful replies serials
1 then 2, exactly one correctly addressed NameAcquired, consistent unique name,
stable bus ID, no errors/extra replies/pending bytes/FDs. Close each source and
prove its unique ownership disappears while observer health remains intact.
Retain all 127 offsets and reject missing/duplicate/failed cases. Save raw logs,
receipts, queue samples and exact literals/hashes even on failure.

Reuse the SEC07 sender-queue observation contract and socketpair control as
functional synchronization primitives, without rerunning its security cases.
Control: empty zero, unread positive, partial-read positive, exact-full-read zero
within one second. No arbitrary sleep substitutes for the prefix proof. Keep
startup10s, socket/reply3s, actor45s, barrier1s, cleanup5s and existing lifecycle
outer900s. Preserve failure without automatic unchanged retry or deadline growth.

Root verified the existing reference executable
`/nix/store/pb9dhpk6qxjybb8p7prvs18ls2vxk51a-dbus-1.14.10/bin/dbus-daemon`,
SHA256 `e98a7397e16b01a3cae65f14e6d38195fc73b313887174d6e5e0bd98de418a9a`.
Use the existing pinned Python3.13 and host_lifecycle.py, record all hashes and
the actual version/kernel/identity. Generate an EXTERNAL-only system-type
configuration for these normal operations and actual UID only. Start a dedicated
reference process on an explicit socket inside an owned mode0700 directory;
never use default bus addresses or host bus environment. No live system/session
bus, privileged operation, account change, Nix build/fetch or network is needed.
Success requires the worker's exit0 and lifecycle.graceful_success=true.

Ownership: worker edits only scripts/foundation/pro01_reference_hello/actor.py,
run.py and test_fixture.py; reviewer performs source-only spec then quality review;
root owns scope, static/validator checks, execution, raw reconciliation and ledgers.
All preserve existing work. Required checks are direct functional validator
tests and these normal streams only, with no optional audit, penetration/exploit
work, broad fuzzing or external API probe. No publication or memory updates.

Local reference success is partial new evidence. It does not update the frozen
required index, pair this run with a current Gao artifact, complete M1 or restore
the blocked VM closure. All paused/excluded target restrictions persist.
M0 accepted, M1 unpassed, readiness L0, product_qualified=false until mandatory
gates actually pass. Missing dependencies and unexecuted cases remain blocked.
