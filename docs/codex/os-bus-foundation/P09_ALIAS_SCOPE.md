# Candidate07 same-file destination-alias policy comparison

This executes the existing POL-02/SEC-09 destination-alias requirement using
the current reload fixture and independent wire actor. Production, the frozen
candidate, the complete installed inventory (17 XML occurrences, 39 policy
blocks, 500 rules), transport_actor.py, and prior evidence remain unchanged.
No commit, remote write, release, deployment, or host live-bus traffic.

Candidate07 manifest SHA256:
`819dcc23793c34d3f5b2fd08ddfa0307f7326ec255ec502050bf66df4acb83b7`.
Pinned runtime: OTP 27.3.4.6 / Elixir 1.17.3; seed 1703. Parent owns all runtime
execution, freezes, preservation checks, evidence and documentation.

Prepare bus.conf → policy.conf → rules.conf once. Retain existing fixture
permissions and add a caller-UID-specific deny for method_call AliasProbe,
interface org.foundation.Reload, destination org.foundation.Reload.Protected.
Candidate and pinned reference must use identical bytes and socket path;
reference alias mode must not prepare or rewrite any XML. Verify all three file
hashes before/after each backend and the name release. Stop the supervised
candidate normally and observe listener shutdown/socket removal before reference
startup. Do not manually unlink the socket.

Independent service UID1100 and caller UID1101 processes use the existing
multiprocessing Pipe/Client patterns. Spawn them before opening root coordinator
or observer sockets. Drop supplementary groups and record actual PID/UID/GID/
groups; observer independently queries each connection's kernel UID/PID. Both
ordinary identities must be unable to write the three trusted files.

Service acquires Protected and Alternate (org.foundation.Reload prefix), each
RequestName=1. Observer verifies both resolve to the service's unique name.

| Phase | Addressed destination | Required outcome |
| --- | --- | --- |
| Protected owned | Protected | Exact AccessDenied, zero service delivery |
| Protected owned | Service unique name | Exact AccessDenied, zero service delivery |
| Protected owned | Alternate | Exact AccessDenied, zero service delivery |
| Protected released | Same service unique name | Exactly one call and matching echo |
| Protected released | Same Alternate | Exactly one call and matching echo |

ReleaseName(Protected)=1; observer gets exact NameHasNoOwner for Protected and
unchanged Alternate owner. XML remains unchanged. Keep service pumping through
a second GetId fence issued after the caller's actual response; the first fence
must not end pumping. Every call/echo checks raw headers/body, actual sender,
addressed destination, serial/reply serial, signature, marker and zero rights.
Compare exact error names and decisions while retaining explanatory error bodies.

Require stable per-backend bus ID, socket-closed receipts and normal worker
exit0. Bounded termination/kill are failure cleanup, never passing evidence.
The reference daemon must be reaped and the VM powered off; export failed
evidence too. This fixture does not establish complete FD/leak qualification.

Ownership: p09_alias_actor owns reload_actor.py; p09_alias_test_runner owns
file_reload_socket_test.exs and p09_reload/run.py/test.nix. They coordinate their
result schema. Preserve the existing two reload tests; add one paired alias test
and freeze selected/executed test count at three, with four actor reports (two
reload, two alias). Parent reviews specification and quality before running the
frozen disposable VM. If the real regression exposes a production defect, retain
the failure before any narrowly scoped repair.

P07 queued-repeat and P09 optional-INTERFACE mandatory failures remain selected.
Full P08/P09, P10 activation, P11 packaged release/inheritance/600s soak and P12
real-service rollback remain open; highest verified readiness is L0.
