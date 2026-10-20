# FD-07/core/missing-destination corrected source

Exactly Gao and reference missing-destination rows, sequentially in one disposable
NixOS VM. Highest verified readiness remains L0. This is a development candidate
fixture, not a release or full FD07/P08/P00-P12 qualification.

The predecessor seven-file fixture and its VM1 remain immutable FAIL evidence:
flags2/reference returned NameHasNoOwner while the fixture expected ServiceUnknown.
Gao's former pass is unadopted. Pinned dbus1.14.10 dispatch and the preserved raw
receipt justify this exact correction; this fixture requires NameHasNoOwner on
BOTH backends. ServiceUnknown is rejected, never accepted as an alternative.

The actor is byte-identical to the predecessor and reads the corrected workload.
It reuses frozen FD05 and singleton actors; the controller retains the same frozen
FD05, singleton, mixed and different-bundle predicates, channel, wire, daemon and
collector. No competing harness, wire encoder or execution recorder is introduced.
The inherited raw flags2 predicate and all inherited negative controls remain.

Source serial100/NO_AUTO_START targets org.foundation.Absent with a real named
CLOEXEC memfd. The first error must have exact reply_serial100, source destination,
bus sender, no header9 and zero rights/installed descriptors. Six strict health
receives110/111/112/210/211/212 follow. No receive search or silent draining occurs.
Original/installed warmup identity, content/EOF, owned close+EBADF, numeric FD
inventories, actual UID1100/PID/GID/starttime/executable/process/credential/config
joins, settled authorities/credits/queues/buffers/pending and unchanged baselines
remain required. Fallback cleanup never certifies graceful teardown.

Startup10000/writer5000/health1000/cleanup1000/resource3000ms, globalFD3/UIDFD2,
authority60s, guest120s and host900s are unchanged. Failure logging preserves the
base controller's primary actor error and marks unfinished executed cases failed
before post-run predicates inspect a partial report. Success still requires every
original predicate and complete teardown. Remaining selected rows become blocked
on preceding disagreement; actual selected/executed/passed/failed/blocked/skipped
counts remain the inherited strict accounting.

No future candidate hash is guessed. workload.json has null candidate pins until
controller main binds REQUIRED root-supplied --candidate-manifest-sha256 and
--candidate-source-sha256. It checks candidate.json bytes against the first value
and its source_sha256 against the second, records both in report.workload, and
revalidates at final input capture and report validation. Candidate17 manifest
SHA256 a27888106012b209b8941a4c7e5b9611764c7ceaa3ff2e27ebe9c753783a6c77 and
source f5dfe03ced34c9b24e69b780588156330a74d2ee025a07dcf2dd0e5d395eab92
are explicitly rejected. Synthetic b/c/d hash literals in controls are labelled
synthetic-only and cannot supply real candidate evidence.

Nix requires repoPath, candidatePath, scopePath, candidateManifestSha256 and
candidateSourceSha256. The two exact root-supplied values are checked during
realization and passed explicitly to the controller. `test.nix -A driver` remains
separately buildable by root; realizing that derivation does not run the VM. The
package explicitly includes this seven-file root, four retained seven-file roots,
and the original explicit wire/channel/daemon/collector/runtime inputs.

Tests were authored before implementation and are NOT RUN. Parent-owned ordered
specification/quality reviews must precede executable imports/tests. Root then
uses its bounded60s offline recorder (inherited HOME, scrubbed DBUS selectors,
DEVNULL stdin) for actor_test.py and oracle_test.py, all inherited controls plus
new exact-error/binding/partial-failure controls. Prior --predecessor wire control
remains available, with the same ordinary AssertionError-not-raised expected RED;
this is retained-source replay, not a claim of historical test-first execution.
Only stdlib source AST/compile, JSON/hash/readback checks ran during preparation.
Nix syntax/evaluation, target imports, tests, native/Mix/compiler, candidate build,
closure review and runtime are NOT RUN here.

Root owns review, executable validation, exact corrected candidate capture,
freeze/modes/71-source/57-mapping/80-artifact reconciliation, driver-only build,
independent realized-input/closure review, separately authorized VM invocation,
and host PID/group/socket/VMoff reconciliation. Reports export even on failure
under fd07-missing-corrected-evidence, with fd07-missing-corrected-vmoff.json.
No host live bus/accounts, accepted-index/ledger change, Git mutation, publication,
release, remote operation, dependency workaround or memory write is authorized.
