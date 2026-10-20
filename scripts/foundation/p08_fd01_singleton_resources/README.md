# Independent FD-01 singleton-pipe fixture

Offline preparation selects only FD-01/core/pipe for sequential private Gao
and reference brokers in a disposable Linux VM. At the offline implementation
handoff, runtime is **NOT RUN**.
Candidate16 is an unchanged development capture, not a release or installed
policy qualification. Independent specification and quality review, an exact
input freeze and parent-owned serialized runtime must precede any VM launch.

One fixed four-byte `PIPE` payload is written once to a fresh pipe. The writer
closes with an actual EBADF check before delivery. One reader right is sent to
one negotiated target using exactly two authenticated actor connections. Only
the received reader consumes the shared stream, under the original absolute
3000ms resource bound. Original and received readers stay open until the root
observer's checked sample: S_ISFIFO, matching dev/inode/target and exact content
are mandatory. The broker must retain no pipe endpoint. After checked, both
readers and both connections close with actual EBADF checks; exact numeric
actor/broker warmed baselines and scalar Gao state/credits must recover.

The Python Linux socket/SCM_RIGHTS actor has one actual PID shared by its two
connections. The root controller independently records actor, launcher, broker
and observer identities. Setup/complete ListNames, strict wire/index/count,
active health, config bytes/startup, all attempts/deadlines and owned groups/
socket/EOF shutdown are preserved from the accepted socket fixture. Guest
poweroff never substitutes for workload recovery. UID egress-FD2/global3,
writer5000/health1000/cleanup1000/resource3000/startup10000ms and guest120s/
host900s bounds are unchanged. Host900s is enforced by the parent runtime
recorder; test.nix retains guest120s and owned export/poweroff.

Scoped offline controls use the pinned Python3.13.15 executable with `-B`,
DBUS_* removed, DEVNULL stdin and a finite60s recorder. They use native local
pipe/SCM_RIGHTS operations and explicit unit-test relays, never a broker,
authenticated runtime stand-in or VM. Synthetic controller reports are labelled
offline controls and never selected runtime evidence.

After reviewed preparation and separate parent runtime authorization, the
existing test.nix accepts explicit frozen `candidatePath` and reviewed
`scopePath`; no default mutable candidate is allowed. Its export names are
`/run/osbus-fd01-pipe-export` and `fd01-pipe-evidence`. This worker runs neither
evaluation nor build. Missing inputs, failed assertions, zero executions and
reference disagreements remain failed or blocked. Memfd/socket/network,
fullFD01/P08/M1-M4, installed policy, packaging and activation stay separate;
full qualification is false and readiness stays L0.
