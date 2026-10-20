# API-02 read-only Properties.Set regression

Continue the existing Foundation goal with one bounded API-02 subcase. Work in
`.trees/os-bus-foundation` on `codex/os-bus-foundation`, base
`7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4`. Preserve previous work and evidence.
No commits, remote writes, deployment or host live-bus traffic.

The current introspection advertises Properties.Set(ssv), but BusMethod and
BusInterface only recognize Get/GetAll. Before any production repair, execute
the independent wire case on frozen candidate07 and the pinned reference.
Both actual responses must be saved before asserting PropertyReadOnly.

Use the existing reload actor/ExUnit/disposable VM harness. Preserve its three
tests; add one paired property test, freezing four tests and six actor reports.
Prepare root-owned bus.conf -> policy.conf -> rules.conf once. Both backends
consume identical bytes and socket path; reference must not rewrite XML.
Stop the supervised candidate normally, monitor core/listener shutdown and
require socket removal before starting reference.

An independent UID/GID1101 caller clears supplementary groups and connects
before the root observer. Root independently queries its live UID/PID. Retain
actual identity, trusted-file EACCES and complete raw messages with correct
serial/reply serial, sender/destination and zero rights. The caller waits for
identity proof before exercising the property sequence:

1. Actual introspection advertises Set with input signature ssv.
2. Get Features and retain the backend's original variant-as value.
3. Set Features with variant-as [foundation-property-set-sentinel].
4. Require exact org.freedesktop.DBus.Error.PropertyReadOnly.
5. Get Features unchanged and complete GetId health with stable bus ID.

Different backends can advertise different feature arrays. Compare each to its
own initial value. An unexpected Set error must not suppress the subsequent
Get, health, normal cleanup or reference run. Failures keep their actual error
headers/bodies and truthful test/actor accounting. Use existing bounded operation
and cleanup deadlines; forced cleanup cannot qualify a passing run.

Only after retained RED evidence implement the smallest schema/dispatch/read-only
handler correction. Preserve UnknownInterface/UnknownProperty and InvalidArgs
distinctions with focused regressions. Compile using pinned OTP27.3.4.6 /
Elixir1.17.3, capture a new immutable candidate and rerun the frozen VM selection.
Review the scoped change and refresh affected product evidence before completion.

Ownership: p09_alias_quality owns reload_actor.py; p09_alias_spec owns the ExUnit
fixture and p09_reload/run.py/test.nix. Parent owns production, focused unit tests,
preservation, all runtime/captures/VMs and documentation. They share the actor
report contract and preserve concurrent edits. Parent snapshot:
`test/reports/foundation/takeover-20261010-p09-properties/preservation-before.json`.

This subcase cannot close full API-02/P09. Complete inventory17/39/500 and both
mandatory P07 queued-repeat/P09 optional-INTERFACE FAILs remain intact. P10/P11
activation/release/inheritance/packaged600s soak and P12 real-service rollback
remain dependent/unfinished. Highest verified readiness stays L0.
