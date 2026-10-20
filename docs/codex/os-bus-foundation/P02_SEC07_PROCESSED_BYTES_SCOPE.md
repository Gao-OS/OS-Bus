# P02 SEC07: consumed-byte barriers and native retained-state evidence

Root inspected stopped source1, actual production Auth/Peer and pinned
dbus1.14.10. The draft can retire incomplete-N/retained-N after sendall before
the server reads their bytes. Preserve all83source1 files and its stopped
failure/readback. Prepare only fresh environment/m1-sec07-complete1/source2/**;
all prior evidence, candidate18 and production remain unchanged.

Use the same client-owned Linux AF_UNIX stream socket to sample SIOCOUTQ
(Python fcntl.ioctl with the platform TIOCOUTQ constant). This value is transmit
allocation accounting, NOT a payload-byte count. A successful zero observation
after the final successful send, while the same connection is live, establishes
that its queued data was consumed. Pin socket fd/inode, actor PID/starttime,
send trace and monotonic ordering. Record errors/unavailable values explicitly;
they cannot satisfy the barrier. Never substitute successful sendall or a fixed
sleep for observation. No other writer/duplicated connection may contaminate it.

Root's read-only source data are in m1-sec07-complete1/processed-observation1:
Linux6.12.68 af_unix.c3119–3124/3168–3172 maps SIOCOUTQ to sk_wmem_alloc_get;
sock.h2265–2273 subtracts the initial reference. Non-PEEK stream reads consume
the complete skb only after copying its remaining bytes (af_unix.c2909–2934);
unix_destruct_scm1883–1897 releases it with sock_wfree. This is corresponding
stable source, not a claim of bit-identical Nix kernel build provenance. The
actual guest's kernel/version and runtime primitive must also be validated.

Add a mandatory marked-guest kernel control on its own socketpair: send an
exact pattern, show a positive queue with no read, read one byte/show positive
queue, read and compare all remaining bytes/show zero. Finite deadlines, exact
socket identity, no extraneous writer, successful actual ioctl calls and full
cleanup are required. Missing support blocks execution; no fallback claim.

For each nonoffending byte boundary, do not end at the minimum response count.
Require an actual post-send zero queue observation, then a healthy request on
the established observer, then another live zero observation with the same
unchanged send trace/socket. Keep both raw observations and the intervening
health result. For native also require a complete, unambiguous Auth snapshot
selected by trusted actor credentials/incarnation. Derive exact buffer contents,
total_bytes, failures and phase from the pinned production state transitions
and actual sent transcript. Preserve all during snapshots; do not accept an
earlier prefix reply or incomplete/raced snapshot as processed-N evidence.
Full native buffer/total counter equality is mandatory for incomplete/retained
and cumulative N, not only an arbitrary minimum. Keep total_bytes (completed
lines plus initial NUL) distinct from retained buffer bytes. Closed N+1 paths
must retain their actual terminal disposition and must not require a live queue
barrier after closure. No phantom proof that every offered byte was consumed
before a correct threshold disconnect.

Reference observations remain wire/kernel results, with internal accounting
explicitly UNSUPPORTED. Pinned transport-socket.c244–268 reads directly into
the Auth incoming DBusString; auth.c2250–2265 retains input without CRLF and
2313–2324 deletes complete commands. do_authentication400–502 processes read
auth work before returning to normal event dispatch. The post-drain healthy
round trip and second live sample supply the causal barrier. Label source-
derived retained-input reasoning separately from actual native snapshots; do
not fabricate a reference Auth.buffer or total counter. Preserve the16KiB
strict-greater buffered limit, six-failure budget and accept-to-Hello timeout;
never replace them with native4096/8192/eight-failure constants.

Keep all17declared cases/34pairs, N/N+1, failures, timing, admission, negative
effects/positive controls, same-daemon observer and PID/socket/public epoch/
authority/FD/resource/accounting recovery requirements from the original scope.
Native external33-command pipeline cannot reach Auth.feed's32-line continuation
because Peer reads one byte. Keep that fact and the separately labeled direct
production-Auth supplement; do not claim external continuation coverage.
Reuse the proven directed idle timer relation from the SEC03 scope consistently,
with exact consecutive actual samples and every other normalized field intact.
No production seam, selected skip, omitted case, threshold/deadline increase or
reference expectation change. Caller/health/settle1s,startup10s,cleanup5s,
authority360s,guest480s,host900s and all original workload limits remain fixed.

Complete the originally missing source-derived controls, staged root dispatcher,
approval/realization/witness/replay/receipt adapters, whole-file reverse proofs
and final manifest before handoff. Add meaningful negative controls for an
undrained/stale/wrong-connection observation, a prefix-only native snapshot,
wrong buffer/total/phase/counter, incomplete identity and barrier ordering.
Source-derived REDs must fail the original defective predicates; GREEN controls
exercise the actual corrected predicates and the saved evidence contracts.
Tests must not import hand-authored stand-ins for the implementation.

Ordinary self-review edits to fresh unexecuted source2 within this design are
authorized before sealing. Stop for contradictory requirements, evidenced
impasse or first unexpected executed target failure. Preserve source/runtime
repair-validation0/Astra0 and original stopped defect history. Preparation is
file-data/AST only; no target import/test/public parser/compiler/build/VM/client/
broker/consumer. Root SPEC/distinct QUALITY/full pin check precede serialized
actual stages and one paired VM/observer. Distinct actual raw review precedes
receipt/adoption. Other workers are active; preserve their edits. Root owns
execution/ledger. No host bus/account/Git/remote/publication/memory mutation.
SEC07 stays blocked until actual complete evidence; L0/product_qualified=false.
