This narrow fixture qualifies real recipient UID and global egress-FD rejection
against the frozen development candidate named and hashed in `workload.json`.
The current binding is candidate16; candidate07/candidate15 runs remain separate
historical evidence. It does not qualify a release or close
the full P08/readiness gate. All guest traffic uses `/run/osbus-fd-quotas/bus`;
the guest has actual UIDs 1100 and 1101 and five independent actor processes.

`workload.json` freezes capacities, message sizes, serials, timing and cleanup.
The `Hold` member is an approved unrun fixture choice that allows reuse of the
existing immutable fairness collector. Its accepted-row body bytes/hash are
not evidence for `hay`: Peer scalar full-frame hashes and sizes are compared
with independently reconstructed wire frames, and each partial frame is
validated through EOF with exactly one usable named memfd.

The actor performs an on-wire ListNames fence before each daemon trace fence.
Health checks validate the actual zero-rights replies and share an absolute
1000ms deadline while global FD credit remains 3 and original blocked-writer
deadlines remain unchanged. Source and A1 are killed before the original A1
deadline; A2 and B1 remain unread and expire naturally. No expiry is injected.
Scalar inspections never retain a killed Peer's native socket resource.

One fixture-local independent monitor observer starts before the warmed
baseline. It registers synchronously for only source, A1, A2 and B1 before
workload writes, retains four scalar DOWN records and accepts at most 32
queries. Each record uses BEAM monotonic time when that observer receives
DOWN; the main controller's later consume time is recorded separately and
cannot replace it. This proves bounded monitor receipt timing, rather than
the kernel's exact instant of death. EOF stops and joins the observer under
a monitor with normal reason. The existing fairness collector remains the
only trace process.

Actual FD warmup precedes an empty baseline. All five clients are reconnected
for the workload and closed afterward; daemon and actor FD counts must return
exactly to that warmed baseline, with empty memfd lists and zero credits,
UID maps, peers, matches, capabilities and pending entries. The original bus
name and authority PIDs must recover unchanged.

Every stabilized quota, health and after-kill checkpoint must also have exactly
`warmed_empty_FDs + 2 * present_peers + active_outputs` daemon FDs and precisely
the active accepted memfd names. Denied resources 201/202 must never remain in
that inventory; each denial leaves the external inventory unchanged.

Offline checks (no bus or VM):

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=scripts/foundation/p08_sustained python3 -B scripts/foundation/p08_fd_quotas/oracle_test.py
env PATH="$PWD/.devenv/profile/bin:$PATH" ERL_FLAGS='+S 4:4' MIX_ENV=test mix run --no-compile --no-start scripts/foundation/p08_fd_quotas/serializer_test.exs
```

The serializer regression compiles only the fixture module and tests its actual
output without starting a bus. Its recursive OTP27 encoder preserves Elixir nil
as JSON null, including nested nullable snapshot fields.

Parent-owned guest qualification, using the explicitly frozen capture:

```sh
nix-build scripts/foundation/p08_fd_quotas/test.nix --argstr candidatePath FROZEN_CANDIDATE_DIRECTORY --no-out-link
```

The report and child logs are exported even on failure. Every child must stop
via EOF with exit 0; the Nix test always shuts down its disposable guest.
