# Disposable system-policy qualification fixture

This fixture runs only in the pinned disposable NixOS VM. It never replaces a
guest or host bus. The guest root-owned `/run/osbus-security` directory is 0755;
the candidate's explicit system listener is 0666 so real UID 1100/1101 clients
can reach policy admission. The daemon loads restrictive explicit rules and
only `gao_bus`, `ex_d_bus`, and the currently required `phoenix_pubsub` runtime
dependency. This capture is not a packaged P11 headless release.

## Capture contract

1. Parent freezes production sources and completes pinned compilation/native
   build, including `GaoBus.Limits`. No capture is made from a moving build.
2. `python3 scripts/foundation/vm_security/capture.py <new-empty-directory>`
   copies only the required application `ebin`/native artifacts, records their
   hashes, exact runtime store roots, baseline/ref, and source hashes, and
   rejects changed inputs or stale build artifacts. Each source must have
   compiled modules identified by BEAM compile-info, each newer than its source.
3. `nix-build nix/tests/security.nix --argstr candidatePath <capture-directory>
   --no-out-link --keep-failed --max-jobs 2 --cores 4` imports the frozen capture. The Nix
   expression never imports the live `_build` directory.
4. Guest qualification verifies each copied artifact hash before starting the
   daemon, records actual configuration bytes/hash, tools, actors and outcomes,
   and exports evidence even when an assertion fails.

## Actor and inspection contract

Raw Python actors implement only the D-Bus types needed by these tests, with
independent wire construction; no ExDBus encoder/decoder is used by an actor.
Workers run through `runuser` as root/UID 1100/UID 1101 and report their actual
PID/UID/GID. The root observer compares `/proc/<pid>/status` with actual trusted
Router credential records while connections remain live. GLib `gdbus` and
sd-bus `busctl` additionally run ordinary EXTERNAL calls under each identity.

The daemon's stdin inspection/fault channel is accessible only to the root
fixture controller. It is not a production D-Bus API or a credential-query
compatibility claim. No UID is synthesized or substituted in production state.
Policy stop/restart is real supervisor fault injection, not a mocked evaluator.

The expanded security selection covers SEC-01 through SEC-17. Root-only fault
commands run the real credential adapter and Peer admission path on a closed
OTP socket, and kill a real authenticated peer after it acquires names, a queued
request, match rules, an explicit stored capability and an ingress reservation.
Monitored cleanup is inspected twice for idempotence while the observer remains
live. Raw actors also send complete malformed frames, pre-Hello operations,
coalesced registration calls, duplicate Hello and an explicitly forged sender.
These probes retain the report's precise limits for broader PRO/POL/FD suites.

Each selected requirement records passed/failed/blocked evidence and a healthy
observer retains its owned name after malformed/denied traffic. Cases requiring
unimplemented production APIs, adapter-failure injection or broader XML/FD/
activation/runtime conformance remain explicitly unverified. No known gap is
converted to a passing result.

Run the fixture-only checks without bus traffic:
`PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/foundation/vm_security -p test_fixture.py -v`.

## Composite invocation and coverage boundary

After preparing the pinned devenv profile, run
`scripts/security-qualify <new-report-directory>`. The invocation serially
compiles, builds the C fixture, runs explicit scoped M1/harness tests, runs the
existing strict original E2E manifest against both backends, freezes the
candidate, and runs this VM. Missing tools/backends, zero execution, exclusions,
skips, incomplete row/actor counts, hash mismatch or unsuccessful cleanup fail
the invocation. Existing strict E2E accounting remains authoritative.

`scripts/security-qualify --frozen-candidate <capture-directory> <new-report-directory>`
runs only the frozen VM scope, without Mix or live-build access. Its report
labels this mode explicitly. Every invocation preserves commands, logs,
selection/counts and configuration; use a fresh report directory for each run.

`workload.json` freezes the numeric M1 PR workload: 200ms authentication trickle
against a 1500ms absolute/500ms idle deadline, 96 malformed/auth/ownership
operations, a concurrent 1000ms health deadline, no post-quiescence FD growth,
128MiB daemon RSS ceiling and at most 16 additional atoms. External `/proc`
samples corroborate process FD/RSS use. The start-peer failure fills the real
supervisor's 256 slots with root-owned waiting fixtures, observes actual accepted
socket rejection at N+1, then retires every injected child. It does not claim
the distinct controlling-process-transfer failure branch was injected.

The required PR check is `security (Linux, frozen system fixture)`. Hosted
execution and branch-protection settings require separate evidence/operator
action. The job is wired locally; a workflow definition is not a passing run.

M1 audit: SEC coverage, H fail-closed accounting, initial connection/ingress/name/
match limits and local core recovery have evidence, but historical results must
be refreshed after source changes. The earlier 17-row VM did not qualify real
paced deadlines, supervisor startup failure or a measured diagnostic burst;
the current manifest requires these procedures. Full fast-producer/slow-reader
egress and pending requests, 1000-operation leak batches, sustained soak,
reference XML equivalence, complete PRO/POL/FD and packaged-release gates remain
unqualified. Neither invocation marks M1 complete or upgrades the acceptance
level; report the exact manifest and complementary evidence.
