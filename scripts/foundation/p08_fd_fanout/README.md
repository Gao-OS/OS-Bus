This bounded fixture proves selected development R08/FD09 against frozen
candidate07. It uses four independent processes: root source and unmatched
observer, UID1100 fast recipient, and UID1101 stalled recipient. All traffic
uses the unchanged quota daemon's private `/run/osbus-fd-quotas/bus` in a
disposable guest. The quota daemon, scalar watcher/snapshots, sustained
transport/channel, and fairness collector remain unchanged.

Actual directed memfd traffic warms fast, slow and observer with serials
901/902/903. The received rights are used and closed; all connections close
before exact warmed daemon and actor baselines are captured. After reconnect,
only fast and slow install the same specific Hold match. Source sends one
broadcast signal, serial101, with no destination, signature `hay`, FD index0,
and deterministic 196608-byte data. Source closes its named CLOEXEC memfd
after sending. The collector must show exactly three warm targets and two
broadcast targets, with no extra admissions or rejections. Its singleton-body
hash is not `hay` payload evidence.

Fast validates the complete actual wire frame and one usable named memfd,
then retains that FD across monitored source and slow Peer kills. Each kill
uses slow's original 5000ms writer deadline as guard and requires bounded
cleanup. Fast rereads the same retained resource after each event, in order;
the actor rejects premature release or close. Slow remains unread until its
kill, then drains through real EOF, requiring the exact frozen wire prefix
and exactly one usable named memfd. Raw bytes and resource contents are
validated independently of the collector and scalar Peer hashes.

Source and observer issue concurrent zero-FD health requests under one
original 1000ms deadline while slow holds its partial output. Observer also
checks recovery health. This does not claim full-capacity health. Each
stabilized checkpoint requires exact daemon FD/memfd inventories and credits
for the actual survivors; external actor inventories equal their warmed
baseline plus their socket and retained received FD. Fast closes its retained
FD only after both rereads, then fast and observer perform strict on-wire
fences that reject extra messages or resources. Closing all connections must
recover the exact warmed inventories, zero budgets/maps and unchanged
authority PIDs. All four actors and daemon must stop via EOF/exit0; watcher
and collector must join normally and the guest must shut down.

`actor.py` takes `path role quotaDir`. It reuses quota Workload only for
connect/close/FD inventories. The command protocol is one JSON request per
line and `{ok,result}` responses; bootstrap records actual PID/UID/GID.
`receive_hold` returns full wire/body/resource hashes and a retained
`fd_identity` scalar (`device:inode`, never the FD number). `verify_held`
accepts stages `after_source`, then `after_slow`; `release_held` requires
both. `partial` accepts the frozen byte offset and reports exact prefix,
resource and EOF disposition. Offline validation helpers do not close
caller-owned descriptors; actor commands always own their cleanup.

Parent executes offline oracle regressions before guest qualification:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=scripts/foundation/p08_sustained python3 -B scripts/foundation/p08_fd_fanout/oracle_test.py
nix-build scripts/foundation/p08_fd_fanout/test.nix --argstr candidatePath /tmp/os-bus-security-candidate-20261010-07 --no-out-link
```

The frozen workload plans warmup3/broadcast1/admitted2/full1/partial1/killed2/
retained_reads2/health3. The controller exports the complete report and child
logs on failure too. This slice does not qualify full P08, FD10 activation,
RES-06, or a packaged release. Scope is fixed by
`docs/codex/os-bus-foundation/P08_FD_FANOUT_SCOPE.md`.
