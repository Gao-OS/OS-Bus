# P08 resource workload

This scope runs only in a disposable Linux VM on an explicit private socket.
The numeric `workload.json` must be frozen before qualification. Changing a
threshold requires a recorded capacity rationale and a fresh affected run.

Development command (no Mix or live `_build` access):

```
nix-build scripts/foundation/p08_sustained/test.nix \
  --argstr candidatePath /absolute/path/to/frozen-candidate04 \
  --no-out-link --keep-failed --max-jobs 2 --cores 4
```

The guest verifies every candidate artifact before and after execution. Its
Python SCM_RIGHTS actor reuses the existing independent native transport actor.
Three post-warm-up batches each complete exactly1,000 operations, cycling
three-rights pipe/file/socket transfers, named/matched peer disconnect, malformed
FD-index rejection, policy denial, real pending timeout, caller cancellation,
and monitored abrupt Peer kill. The independent UID1100 observer owns a name
and checks its exact owner and latency throughout UID1101 traffic. Every operation
uses bounded authoritative quiescence; cleanup does not rely on sleeps. Healthy
workload pacing uses a bounded event wait. Batch artifacts include identity/data
checks, completion counts, authority PIDs, monitored kills, native FD targets,
RSS/BEAM memory, atom counts, names, matches, pending requests, resource credit,
queues and subprocess shutdown results. Quiescent FD/authority/resource/name/
match/reply growth fails. Runtime GC precedes the retained memory samples.

This is development evidence for RES-05/FAIL-01 and selected actual transfers.
It does not replace FD-01 through FD-10, fairness/backpressure/queue boundary
coverage, full M2 acceptance or any packaged-release requirement.

The current package6/frozen8 release is available. The separately adopted
packaged-local-console fixture uses its supported nondistributed `start_iex`
command and a hash-bound test inspector loaded after normal startup. It also
requires independent public and policy checks under plain `start`. The original
native/XML parity comparison remains FAIL3/1 (8/400); universal parity is
BLOCKED_DESIGN. The new `packaged_wire_policy.xml` is a standard-policy fixture
with the documented UID1101 interface-less method_call receive delta. It grants
no new production mode or installed-activation acceptance.

Freeze new schema2 inputs only after the offline checks pass. The capture binds
the complete release, current source/BEAM identities, fixture bytes, standard XML,
actual compiled capacities and every original workload threshold. The short VM
must pass all14 independent policy rows on the private reference daemon and both
packaged modes, whole accounting, actual monitored kills, health coverage and
owned cgroup cleanup. Its10s sustained phase remains nonqualifying for RES-06.
Only that preflight can admit a fresh soak capture with100warmup operations,
3x1000verified batches and>=600additional seconds. Failed attempts are retained.
Python caches are excluded from the guest inputs; raw logs and receipts reside
on the guest disk and are exported even after controller failure.

The packaged inventory regression requires `OSBUS_P08_INVENTORY_STORE` to name
an immutable Nix import of the frozen package. Missing input fails the selected
test. The real IEx shutdown regression requires `OSBUS_P08_IEX` to name the
pinned `.devenv/profile/bin/iex` executable; missing input fails BLOCKED_ENV.
Its FIFO barrier proves input stays open until orderly application cleanup
completes. The guest checks Nix's exact read-only modes before copying, restores the
recorded safe modes only in its private copy, and verifies the original complete
inventory. Frozen inputs and the Nix store remain unchanged.

Commands for the implemented packaged entrypoint (use new destinations):

```sh
python3 -B scripts/foundation/p08_sustained/packaged_capture.py /absolute/path/to/frozen8 /absolute/path/to/new-preflight --mode preflight
nix-build scripts/foundation/p08_sustained/packaged_test.nix --argstr packagedPath /absolute/path/to/new-preflight --no-out-link --keep-failed --max-jobs 2 --cores 4
```

After successful preflight, repeat with a new destination and `--mode soak`.
The qualifying report must identify the artifact/capture hashes and the local-
console mode. Neither this fixture nor its600s result qualifies uninstrumented
plain-start600s, the installed helper/activation or system-bus replacement.
See `docs/codex/os-bus-foundation/P08_PACKAGED_SOAK_SCOPE.md` and the current
execution ledger for actual results and blockers.
