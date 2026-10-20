# Inactive standalone real-UID authority VM draft

Source preparation only. No imports, syntax checks, hashing, tests, builds or
VM execution have been performed on these sources. Root owns independent
reviews, final candidate capture, source binding and all execution. This
directory is separate from the unchanged eight-case RES01 fixtures and P12.

`test.nix` supports exactly one fresh disposable invocation selecting `all`
(both cases), `uid_names`, or `uid_matches`. It requires a final root-frozen
`candidatePath` from the existing capture.py contract; the old candidate16 is
not assumed to contain the UID implementation. It reads the same worktree
devenv.lock pin, carries the candidate's OTP/Elixir/native store roots, creates
real users UID/GID1100 and1101, and retains guest120s/global900s. Root must
add its existing fixed host900s invocation/receipt/owned-group containment.

The runner requires root, the disposable-guest marker, a fresh root-owned0755
`/run/osbus-security/uid-authorities` directory and absent private socket/report.
It uses the unchanged original Channel, Actor, actor.py, daemon.exs, state.ex
and policy.exs, verifies their retained pins, and verifies candidate artifacts
and read-only Nix modes. There is no new wire encoder, actor, backend, oracle
service or production API. The fixture-only policy overlay permits both trial
UIDs to own `org.foundation.Uid*`; original policy bytes remain unchanged.

The launcher verifies the exact original daemon hash and two default-profile /
one snapshot anchors, then adapts that source only in memory. It sets native
UID name/match caps2, peer caps4/global caps16, and the existing ordinary finite
Limits profile (global connections6/authenticating3; UID connections4/
authenticating2). Other Limits defaults and auth1500/idle500ms remain unchanged.
Its provenance truthfully records the original and transformed hashes, profile,
controls and embedded lifecycle. The sole snapshot extension reads tables and
admission/local monitors; it does not call mutation or cleanup APIs.

A root-UID observer owns `org.foundation.Root.Observer` and watches bus name
signals. Its separate finite UID budget leaves both target UID budgets free.
The same actor, accepted peer, kernel identity, unique name, admission monitor,
authority processes and bus ID must survive every trial. Actual actor
UID/GID/PID plus live `/proc` status join daemon accepted credentials, Router,
supervised children, Limits admissions and the authority caches. Retained
owner/queue associations and match entries independently reconcile UID counts,
per-peer counts, distinct local monitors and pinned admission incarnations.

`uid_names` uses three UID1100 peers and one UID1101 peer. Owner+queued
association exhaust the shared UID budget while peer/global headroom remains.
New ownership and a third queue association are denied with identical settled
state and no name signals. Repeats do not charge again. UID1101 owns a separate
name. Release promotes without recharging; owner death promotes, queued death
preserves the owner, and each reclaimed credit is reused exactly once before
another denial. Final trial actors retire to the unchanged observer baseline.

`uid_matches` fills two credits across UID1100 peers and denies allocation both
on a retained peer and an uncharged peer, with positive peer/global headroom.
UID1101 independently subscribes/delivers the denied signal; UID1100 does not
receive it. Two canonically equal entries on one peer have distinct references
and consume two credits, with deduplicated delivery. Removing exactly one leaves
the surviving stored entry delivering and permits exactly one reuse. Actual
peer death reclaims the remaining credit, a new same-UID peer reuses it, later
N+1 remains denied, and surviving UID1100/UID1101 subscriptions still deliver.

Death means actor stdin EOF, socket close and actual actor process exit followed
by daemon peer death. Every actor must finish EOF/exit0 with its kernel PID,
wrapper PID and owned group absent. This draft does not inject abrupt SIGKILL
or prove cleanup with Router absent; those unit cases remain separate. No
synthetic daemon cleanup command or authority mutation is used to obtain credit.

All selected outcomes begin blocked. Raw commands, replies, polls, snapshots,
kernel joins, denied-state comparisons, phased counts and healthy probes remain
in the report/logs. Requests, settled phases and healthy probes have1000ms
bounds with at most128 settle attempts; all share a fixed authority60s deadline.
Teardown is in finally: all actors stop, daemon quit is flushed, original
Channel.stop retires it, and socket removal/process absence are recorded.
Successful completion also requires all selected outcomes and graceful cleanup,
and the complete authority duration including teardown <=60s. Nix exports
failure evidence and independently records VMoff/socket removal in finally.

Unfinished: independent source reviews, meaningful runner/checker regressions,
syntax/import checks, final production activation/GREEN/capture and a real
disposable execution with exact host receipts and output/cleanup readback.
The draft has no executed timing evidence; snapshot/serialization and signal
ordering must be qualified under the fixed bounds. Partial results must remain
failed/blocked, never promoted. Full replacement/flag/XML and abrupt-death
matrices are outside this two-case draft. Productfalse/readinessL0 and all
historical blockers remain; a successful selected run cannot certify the full
RES01, M1, P12 or foundation goal.
