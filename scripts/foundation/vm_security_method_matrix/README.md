# Independent SEC-14 method matrix

This source-only P04 extension selects the ten ordered cases in `workload.json`.
It preserves the original21 selection separately and reuses the unchanged
`vm_security` independent packet/client, Channel/Actor, daemon, restrictive native
policy and exported snapshot channel. It adds no production test API.

The actor records complete raw request/reply frames and decodes the actual
Properties.Get Features string-array variant. The controller requires each
controlled error, matching request/reply serials, unchanged whole exported
Router/peer/name/queue/match/capability/credit/policy snapshots after bounded
quiescence, and root `/proc` PID/UID/GID observations matching trusted Router
credentials. The observer owns `org.foundation.Observer`; actual UID1100 and
UID1101 actors use only `/run/osbus-security/method-matrix/bus` in a disposable VM.

Every rejection has a 1000ms observer probe and valid affected-method follow-ups.
Name ownership and match effects are observed live, then fully retired. Canonical
Properties.Get Features and ordinary off-path ListNames must succeed. Raw boolean
scalars must be exactly uint32 0 or 1 before shared decoding. Both ListNames
replies must contain exactly the complete settled baseline name set, allowing
array order variation and rejecting duplicate names. Acceptance
requires exactly10 selected/executed/passed, zero failed/blocked/skipped, exact
execution order, complete per-case evidence and all three owned process groups
reaped by EOF with exit0, absent actor PIDs and a removed socket. The VM driver
exports regular evidence files and powers off in `finally`.

The controller starts the original `daemon.exs` with the socket and policy file
as its two positional arguments, using the frozen candidate ebin paths. Its
stdin accepts newline-delimited text commands; `metrics` returns `FIXTURE ` JSON
on stdout. Original `quit` calls `Application.stop` and emits no FIXTURE reply;
EOF alone only ends the input command loop. After stopping the actors, cleanup
sends and flushes `quit\n` directly to the owned daemon without waiting for JSON,
then uses unchanged `Channel.stop` to close stdin and perform bounded EOF/group
reaping. A quit write failure is recorded while reaping is still attempted.

`test_fixture.py` retains the original aggregate-only rejection and selection
regressions. Added fixtures cover fixed endian/frame/variant vectors, malformed
frames, canonical boolean values, raw reply correlation, wrong errors/requests,
ListNames extra/missing/duplicate names and order variation, missing/duplicate/reordered/
unexecuted rows, integer accounting, whole-state/credential/effect/probe drift and
owned teardown. Synthetic fixture reports do not constitute bus or VM evidence.

Root owns execution, ordered specification and independent quality reviews,
source approval, complete current candidate/source/artifact/runtime verification
and VM scheduling. After that authorization, fixture execution is:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/foundation/vm_security_method_matrix/test_fixture.py
```

The VM expression requires explicit `candidatePath`; null fails. It freezes the
candidate and both fixture inputs, reads runtime closure anchors from the
candidate manifest, and pins nixpkgs through `devenv.lock`. Candidate validation
checks every manifest file byte-for-byte and requires regular files through real
directory components. Nix normalizes trusted source0644 data to0444 and source0755
executables to0555; the source executable bit selects the exact readonly mode.
Writable modes, executable mismatches, incompatible source modes, symlinks,
non-regular files and changed bytes reject. The report retains the original
manifest and source modes, alongside observed frozen modes and hashes. Candidate
fixtures use copied temporary readonly data and executables; they do not alter
store files. An authorized root invocation has this form:

```sh
nix-build scripts/foundation/vm_security_method_matrix/test.nix --argstr candidatePath /absolute/path/to/verified/frozen/candidate
```

Authority60, guest120 and host900 seconds remain fixed. The authority deadline is
owned by the outer root runner; this workload records it without widening it.
Whole-state comparison is limited to the unchanged daemon's exported snapshot;
this extension makes no claim about unexported production state. This is scoped
P04/SEC-14 evidence only. Product qualification is false, readiness remains L0,
and the full P00–P12 goal, reference/FD/resource/helper/package/600s/P12 blockers
remain incomplete. No activation, full-system, FD04, resource, soak or release
qualification is included.
