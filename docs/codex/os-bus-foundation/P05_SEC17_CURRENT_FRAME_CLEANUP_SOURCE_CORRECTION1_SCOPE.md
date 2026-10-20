# P05 / SEC17 current-frame cleanup static SOURCE_CORRECTION1

Direct correction task SEC17-CURRENT-FRAME-CLEANUP-SOURCE-CORRECTION1 owns only
`scripts/foundation/sec17_frame_cleanup_current_correction1/`, this scope, and
`test/reports/foundation/resume-20261019/sec17-current-frame-cleanup-source-correction1/`.
Other workers and parent are active. Preserve every original fixture/preparation/
review/helper/candidate/production/policy/input byte, shared ledger and other lane.
No original frozen file is overwritten. Shared live STATUS.md, COMPATIBILITY.md
and EVIDENCE.md remain excluded from runtime pins.

The preserved original PREPARATION SHA is
3a14e2744117841dcf0d5dba2b0a44660288d2c51024122503f56daec455c21b.
Original spec-review FAIL finding SEC17-FRAME-SPEC-01 identified a real required
observation gap: first strict GetNameOwner reply consumption does not prove no
extra bytes/messages are queued at the existing observer health fence. The
unchanged transport reads exactly the current frame and has no internal buffer.
Original oracle's extra-frame-named test only mutated reply rights. Parent
accepted this finding and authorized this single separate static correction.

Copy the original eight fixture files because they are immutable. Change only
actor health, saved-data contract and pure synthetic oracle as needed, and recipe
fixture/driver metadata names. Four stage runners target the new fixture/driver;
all stage helper/lifecycle functions remain unchanged. qualify.py, daemon.exs,
workload.json and README.md are byte-identical to the original. No shared helper,
private policy, candidate, production or original FD02 contract changes.

After consuming and checking the exact health reply, set the actor socket to
nonblocking (Python timeout-mode sockets may otherwise select/wait even with
MSG_DONTWAIT). Perform exactly one explicit recvmsg(1, CMSG_SPACE(253*4),
MSG_DONTWAIT). Accept only BlockingIOError with EAGAIN/EWOULDBLOCK and save
result=would_block, errno, nonblocking=true, recv_calls=1, extra_bytes=0,
extra_rights=0, flags=0 and eof=false. Any returned data/control/flags/EOF fails.
Collect any returned SCM_RIGHTS descriptors and close them in finally before
propagating rejection; the existing outer finally restores the socket timeout
and reader and closes reply FDs. Include the observation in the original
absolute1000ms health measurement. No new traffic, waiting interval, retry,
deadline extension, permission grant or competing lifecycle. This proves one
point-in-time reply fence, with no claim about data arriving later.

The contract requires the exact saved fence receipt. Add pure dictionary
mutations rejecting an extra byte, full-frame byte count, extra rights and
invalid EOF/flags/errno/nonblocking/attempt outcomes. Preserve all original
24 oracle methods and every original requirement; new total28. Do not import,
execute or discover the tests/factory during author preparation.

Retain exactly one full valid warmup, one held valid prefix, one actual Peer kill
and one strict same-UID1101/name/Peer unique-name GetNameOwner health. No well-known
ownership/denial traffic, grants or manual unregister/credit/resource release.
Frame5000ms, health1000ms, cleanup1000ms, guest120s, host900s, cleanup5s and all
existing automatic cleanup/FD inventory/authority/normal child joins/VMoff
requirements and actor roles remain unchanged.

Only scoped static file/hash/mode/JSON/Python AST work and the explicitly allowed
`nix-instantiate --parse scripts/foundation/sec17_frame_cleanup_current_correction1/test.nix`
are authorized. No Nix evaluation/build/realization, reviewed script/module import,
compiler/Mix/tests/oracle/VM/probes/network/Git or operational execution. Fresh
spec then independent quality source reviews must bind the correction PREPARATION
SHA; later offline plan/cache/full selected-output and actual parent-plan approval,
build/pure-oracle and one serialized first new-case VM remain parent-owned.
Unknown scheduled derivation names still stop; no fixed plan size assumption.

Original operational counts remain0; this is new static source repair Sol1,
received Astra counter unknown. One first frame-cleanup VM remains unconsumed;
ZERO runtime repairs/retries. Preserve prior fanout consumedVM1/remaining0,
static guardSol1/runtime repairs0/retries0 and all other historical counters,
unknown totals, no-reset/no-borrow restrictions. SEC03 no-retry, SEC06/FD04 denied,
SEC08 no-fourth, terminal native authorization/P10 and all closed/paused routes
stay closed without retry/rerouting. No FD04 ancillary-audit or broader campaign.

Stop after frozen static correction/readback. No operational authorization is
created by these files. ReadinessL0/product_qualified=false; actual precommit
BLOCKED_SCOPE_AND_ENV. No full SEC17/FD08/FD09/P08/installed XML parity, milestone,
release/product acceptance, publication or memory update is claimed.
