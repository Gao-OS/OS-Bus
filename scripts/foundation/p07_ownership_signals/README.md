# Supplementary P07 ownership observations

This implements the previously missing independent observation path for the
fourteen actions in `apps/gao_bus/test/name_reference_test.exs`. It supports
R-07/R-15 and the Hello/ownership observations of SEM-01/SEM-02/SEM-05. It does not complete
those requirements or replace the original comparisons or their gate consumers.

The original comparison SHA256 is
`57d95a42205808db0a0d554f23b2750e1b3b23be7a125bf99ead277da09c62c5`.
The collector measures that file and checks the unchanged action list. It never
modifies candidate/reference policies, configurations, queues or expectations.
The three reference dispositions and historical FAIL/BLOCKED_DESIGN records
remain in `docs/codex/os-bus-foundation/P07_REFERENCE_DISPOSITIONS.md`.

## What is implemented

`actor.py` reuses only the independent framing/client primitives from
`apps/gao_bus/test/fixtures/transport_actor.py`. It does not invoke that file's
FD or other workload modes. The ordinary EXTERNAL connection does not negotiate
UNIX_FD. A separately spawned observer W connects and subscribes independently
before four controller connections A/B/C/D register and execute the original
requests. W subscribes to NameOwnerChanged; A/B/C/D subscribe to that signal for
the target name. Directed NameAcquired and NameLost are retained on their
receiving connection.

Every receive is recorded before reply filtering, including its physical serial,
reply correlation header, all decoded headers, body bytes and descriptor count.
Every explicit call records its serial, signature, body and exact attempted wire
bytes. Hello and the constructor's ListNames barrier replies are retained during
setup; these two constructor calls are not repeated in the explicit call list.
AddMatch and each GetId barrier are recorded. Schema2 additionally requires the
properly directed unique-name NameAcquired after each connection's Hello reply.
This reply-first check implements the task's SEM-05/candidate causal contract;
the public specification describes the methods/signals without explicitly
stating that order. Pristine-reference agreement remains unexecuted.
Receive indices remain contiguous across snapshots. Only the reused
little-endian reader is supported here.

W acknowledges its subscription/GetId setup before A registers. After each
participant completes setup, W captures that unique name's NameOwnerChanged
through its own GetId reply. Four registration snapshots precede the original
fourteen actions. W uses serials 5-8 for these barriers, then serial 9 for its
first action barrier. These observations are ordered on W's connection; no
ordering between a participant's receive and W's receive is inferred.

After each mutation, the acting connection queries ListQueuedOwners. All five
connections then capture through their own correlated GetId reply. The collector
records all fourteen actions before validating normative results; reference queue
divergence therefore preserves the full raw run and returns FAIL. Missing or
late observations also fail validation rather than being inferred or filled in.
The observer journals snapshots before acknowledging them; failure reports retain
partial controller records and observer journals, including incomplete raw bytes.
Collection has finite time and trace bounds and cleans up its owned connections
and observer. Existing output files are never overwritten.

`oracle.py` is pure: it checks the complete five-connection setup, four observer
registration snapshots, fourteen-action transcript, results, queues, required
ownership events, correlation and barriers. Schema1 transcripts lack the
registration evidence and are rejected by the current oracle; their historical
receipts remain unchanged.
`compare()` preserves each connection's ownership-signal-to-signal order while
normalizing run-specific unique names. It compares directed/broadcast signal
interleaving, each connection's Hello/setup reply/acquisition interleaving, and
W's registration signal/barrier stream. Setup comparison omits arbitrary
ListNames/GetId body values after validating them. During the fourteen ownership
actions, reply placement relative to signals remains raw-only. A total order
across connections is not asserted. Full SEM-05 runtime/reference qualification
remains unaccepted.

Comparison requires reference/candidate labels and identical source bindings,
profile and evidence kind. Runtime comparisons also require successful collector
status and observer cleanup. Neither labels, supplied process IDs nor a runtime
kind string establish authentic runtime evidence or pristine backend provenance.
Synthetic fixtures, including in-memory runtime-labelled completion fixtures,
prove only these offline functions.

Every comparison result carries `qualifies_original_gate=false`. A supplementary
match does not accept the original comparison, SEM gate, milestone or product.

## Checks executed in this slice

Only these ordinary offline tests run; imports do not open sockets or start an
observer. Fixtures use in-memory messages and disposable regular journal files.

```sh
python3 -B -m unittest discover \
  -s scripts/foundation/p07_ownership_signals -p '*_test.py' -v
```

`actor_test.py` covers recording before filtering, physical/correlation serials,
detached snapshots, original source binding, a full fourteen-action memory replay
through the independent decoder and pure oracle, distinct participant/observer
subscriptions, and interrupted journal preservation. `oracle_test.py` covers
Hello causal order, independent observer registration snapshots, complete synthetic traces, correlation,
missing/duplicate/incorrect observations, barriers, unique-name normalization,
different valid signal interleavings, comparison provenance and completion status.

Exact current RED/GREEN commands, outputs, source hashes and review records are
under `test/reports/foundation/p07-hello-order-20261021/`. The prior schema1
checkpoint remains under `test/reports/foundation/p07-ownership-signals-20261021/`.
Python results are
separate from the existing ExUnit totals. Actual collection and interoperability
remain **UNRUN**. No security test, bus/native/FD workload or VM acceptance ran.

## Inputs for later collection

Actual collection is deferred. A later authorized run needs already running,
isolated candidate/reference backends, a shared declared compatibility profile,
their exact binaries/configuration/source provenance and explicit private socket
paths. This tool never launches a backend, discovers a default bus or changes an
installed service. The socket must be user-owned, have no symlink components,
and reside in a user-owned 0700 directory. Canonical host system/session paths
and environment-declared live bus paths are refused. This does not supply VM
isolation or authorize host-bus operations.

Source-only invocation examples; **not executed**:

```sh
python3 -B scripts/foundation/p07_ownership_signals/actor.py collect \
  --socket /private/reference/bus --backend reference \
  --profile '<exact-shared-profile>' --output reference.json
python3 -B scripts/foundation/p07_ownership_signals/actor.py collect \
  --socket /private/candidate/bus --backend candidate \
  --profile '<exact-shared-profile>' --output candidate.json
python3 -B scripts/foundation/p07_ownership_signals/actor.py compare \
  --reference reference.json --candidate candidate.json --output comparison.json
```

An incomplete/failed collection or normative reference disagreement is not a
passing comparison. The unchanged original comparison still needs its own
required pristine-reference evidence. Highest verified readiness remains L0,
`product_qualified=false`; the full foundation goal remains incomplete.
