# Candidate07 development FD09 qualification slice

This implements existing R08/FD09 evidence only. No production change, release,
activation, live bus, remote write or qualification expansion. Parent owns runtime,
freeze and reviews; workers own disjoint new files in scripts/foundation/p08_fd_fanout/.
Reuse the unchanged quota daemon (not a second daemon/observer implementation),
its bounded scalar watcher and snapshots, sustained transport/Channel, and fairness
collector. Its fixed /run/osbus-fd-quotas/bus stays private inside this disposable VM.
All these shared source files, the candidate and previous evidence stay immutable.

Frozen candidate07 manifest:819dcc23793c34d3f5b2fd08ddfa0307f7326ec255ec502050bf66df4acb83b7.
Runtime limits remain the quota daemon's UIDFD2/globalFD3/peerFD16, writer5000ms,
health1000ms and cleanup1000ms. New workload does not saturate those ceilings.

Four independent actor processes/connections: root source, root unmatched observer,
fast UID1100 and slow UID1101. Warm each recipient/observer with actual directed
memfd traffic, close all, record warmed daemon/actor FD/memfd/authority/budget baseline,
then reconnect. Source creates and closes one named CLOEXEC memfd per send. Only
fast/slow add the same specific Hold signal match. No destinations on the broadcast;
body hay with index0 and deterministic196608-byte payload. Use broadcast serial101;
warm serials901/902/903. No product client encoder is used.

Fast receives the entire exact frame and one usable memfd, retaining that FD.
Slow sndbuf1024 and unread receive side force actual blocked partial output with
0<offset<bytes and rights_sent. Watch source/slow before the broadcast and record
scalar independent DOWN receipts. Source on-wire ListNames fence precedes trace
and Router/Peer/sys snapshots. Collector must show exactly the3 warmup targets
and exactly the2 broadcast targets, no source/observer/extra admission/rejection.
Collector singleton hay bytes/hash are not payload evidence. Reconstructed frames,
Peer scalar full-frame hash/size, fast actual frame/body/resource and slow actual
prefix/resource validate the data independently.

Full-capacity health is not claimed here. Run concurrent source/observer zero-FD
health under one original1000ms deadline while slow holds its pending output.
Kill source using slow's original writer deadline guard, verify exact bounded
cleanup and unchanged blocked slow resource. Re-read fast's retained FD after
source cleanup. Then kill slow with the same guard, verify bounded exact cleanup,
then re-read fast FD again. It must remain held and usable across both events.
Drain slow through real daemon EOF and require exact expected wire prefix,
exactly1 usable named memfd, correct full-frame/prefix hashes, no duplicate/extra
rights/messages; close it. Observer remains unmatched and registered.

Each stabilized phase must prove exact external daemon FD/memfd inventory:
warmed_empty_FDs +2*live_Peers + pending_output_FDs. Before slow kill exactly
its one pending memfd remains; afterward none. Limits credit/UID/Peer maps,
names/matches/pending and authority identities match the actual survivor state.
Actor FD inventories equal baseline+own_socket+held_received_FDs; never retain
actual native handles in evidence/controller. Close fast retained FD only after
both kills/reads; real on-wire final fence rejects extra Hold/resources. Close all
connections and prove exact warmed external actor/daemon FD recovery, zero budget,
UID/Peer/match/capability/pending maps, bus-only name and unchanged authority PIDs.
Four actors+daemon must all EOF/exit0; watcher/collector normal monitor joins; VMoff.

Actor.py interface: WORKLOAD, payload(serial,size), resource(serial),
packet(serial,target=None,size=None,sender=None), validate_partial(...) and
Workload commands connect/close/fds/send(target optional,size optional), warm,
subscribe, receive_hold, verify_held, release_held, partial, barrier/health.
Quota Workload may be reused for genericconnect/close/fds/barrier/health only;
new actor retains its own resource/payload checks. Controller uses existing Actor
channel begin/finish/request. Controller CLI args are candidate,evidence,helpers,
quotaDir,collector, with evidence /run/osbus-fd-quotas. Actor argv path,role,quotaDir.
Each public command response is {ok,result}; bootstrap emits actual PID/UID/GID.
Report complete scenario and per-phase details; counts planned warmup3,broadcast1,
admitted2,full1,partial1,killed2,retained_reads2,health3 (two load,one recovery).
Standalone assert_report must reject malformed counts, targets, stale PIDs,
wrong data/resource hashes, premature retained-FD close, early/late kill receipts,
wrong inventory/credits, duplicate/extra rights and unsuccessful child cleanup.
Offline oracle regressions precede guest qualification; parent executes them.

Ownership: p08_sustained_probe actor.py/workload.json/README.md;
p09_queue_review qualify.py/oracle_test.py/test.nix. Both may coordinate schema
messages. No shared-source edits. Use existing fixture code; do not add an extra
BEAM process, tracing implementation or product configuration switch.


Prequalification review correction: tie all external PID/UID/GID rows to the
ready daemon and original actor process identities, and require chronological
phase/registration/kill/receipt/consumption/cleanup ordering in the persisted
report. Sender records actual memfd device/inode identity before sending and
closing it; fast full, slow partial and both retained reads must identify that
same kernel resource. This strengthens the existing intended-resource evidence
without changing workload, caps, deadline or production code. Negative evidence
regressions precede the validator correction and guest qualification.
