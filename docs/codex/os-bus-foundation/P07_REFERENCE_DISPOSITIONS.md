# P07 reference comparison dispositions

Recorded on 2026-10-21 for `codex/os-bus-build-compat`, HEAD
`0493680ba7dc216baa5d3a1a8d6e6831f76ebc61`, with existing uncommitted work.
The source bindings below describe that actual worktree, not a clean HEAD build.

This records the three dispositions requested by the user. The unchanged
[P07 reference contract](P07_REFERENCE_CONTRACT.md) supplies the implementation
obligations. Each disposition is recorded; each original comparison remains
**BLOCKED_DESIGN**, with its historical **FAIL** preserved. No comparison,
security test, VM acceptance or original archived trace was executed or reopened
for this document. Readiness remains **L0**, `product_qualified=false`.

| Obligation | Classification | Recorded decision | Original comparison |
| --- | --- | --- | --- |
| `P07_UPSTREAM_QUEUE_ORDER` | Normative/reference queue-order disagreement | Keep queued repeats in place when replacement fails; update their flags | BLOCKED_DESIGN; historical FAIL retained |
| `P07_UPSTREAM_REPLY_INTERFACE_POLICY` | Wire applicability/reference-policy disagreement | Validate the header, then ignore an inapplicable reply INTERFACE; keep the corrected XML oracle separate from comparison acceptance | BLOCKED_DESIGN; historical FAIL retained |
| `P07_REFERENCE_NO_REPLY_PROFILE` | Project requirement stronger than the specification's SHOULD | Keep zero physical replies for the existing AbsentMember case; classify the discrepancy without calling it a MUST violation | BLOCKED_DESIGN; historical FAIL retained |

## Evidence and decision authority

The official [D-Bus specification](https://dbus.freedesktop.org/doc/dbus-specification.html)
was retrieved for this record and identifies **version 0.43**. The captured HTML
SHA256 is `623a8a947f820a521d12b5706ef603f5bf443cf312695bb756c4e4efd258e75a`.
It states that RFC 2119 meanings apply and that its keywords are not capitalized.
The public-document capture is a normative reference, not a pinned daemon build
or runtime qualification artifact.

Fresh evidence is under `test/reports/foundation/p07-reference-disposition-20261021/`:
`BEFORE.json`, `PRIMARY_SOURCE.json`, the original HTML and extracted clauses,
source bindings, document reviews and the final verification receipt. The earlier
bounded diagnosis is
`test/reports/foundation/ordinary-activation-zero-20261020/06-reference-disposition.json`;
it records the three retained blockers and no executed comparison. Historical
runtime outcomes below are retained ledger findings, not fresh observations or
an independent revalidation of protected original logs.

These decisions retain [R-07/R-15](REQUIREMENTS.md) and
[SEM-01/SEM-02/SEM-10/SEM-11](TEST_PLAN.md). They authorize documentation of the
existing contract. They do not authorize a reference patch, a different profile,
changed selections, changed evidence consumers, skipped cases or an upstream
message. No upstream issue or PR was created in this slice.

## P07_UPSTREAM_QUEUE_ORDER

The specification's [RequestName algorithm](https://dbus.freedesktop.org/doc/dbus-specification.html#bus-messages-request-name)
states: “If replacement is not possible, and the method caller is currently in
the queue but not the primary owner, its flags are updated with the values from
the new RequestName call.” Appending applies to a caller currently outside the
queue. A queued caller with DO_NOT_QUEUE is removed under the subsequent rule.

**Decision:** preserve the candidate's in-place flag update. Do not emulate a
historical reference reorder to make a differential test pass. This is a recorded
normative/reference disagreement; no new upstream root-cause proof is claimed.

Current [NameRegistry](../../../apps/gao_bus/lib/gao_bus/name_registry.ex#L421)
handles owner repeats, replacement, queued DO_NOT_QUEUE removal and in-place
queued repeats. The unchanged
[reference comparison](../../../apps/gao_bus/test/name_reference_test.exs#L54)
contains the following prefix. A/B/C/D denote its peer indices 0/1/2/3; these are
**source-derived candidate expectations**, not newly observed daemon output.

| Action | Return code | Owner followed by waiters |
| --- | ---: | --- |
| A requests flags 0 | 1, PRIMARY_OWNER | A |
| A repeats flags 1, ALLOW_REPLACEMENT | 4, ALREADY_OWNER | A |
| B requests flags 0 | 2, IN_QUEUE | A, B |
| C requests flags 0 | 2, IN_QUEUE | A, B, C |
| B repeats flags 1 | 2, IN_QUEUE | A, B, C |
| D requests flags 2, REPLACE_EXISTING | 1, PRIMARY_OWNER | D, A, B, C |
| B repeats flags 2; D does not allow replacement | 2, IN_QUEUE | D, A, B, C |

The historical reference comparison disagreed with the retained queue behavior.
The checked-in source comment identifies a dbus-daemon 1.14.10 reorder; this
record does not assert a newly tested version or reconstruct the original trace.

**Closure evidence:** the unchanged comparison must actually pass against the
declared pristine reference, with its exact configuration and binary/source
provenance, independent actors, every request flag, return code and queue state.
Required ownership signals, including their required ordering, must also have
independent observation evidence.
The current comparison's
[reply helper](../../../apps/gao_bus/test/name_reference_test.exs#L171)
discards intervening messages while waiting for a reply; it does not assert
signal ordering. Candidate
[signal tests](../../../apps/gao_bus/test/name_signal_test.exs#L20) and
[FIFO tests](../../../apps/gao_bus/test/name_registry_test.exs#L211) are source
anchors, not substitutes for that independent evidence. Reordering by the
declared pristine reference keeps the comparison blocked.

## P07_UPSTREAM_REPLY_INTERFACE_POLICY

The specification's [header-field rules](https://dbus.freedesktop.org/doc/dbus-specification.html#message-protocol-header-fields)
require accepting and ignoring known fields in unexpected message kinds. They
also state: “implementations must not send or accept known header fields with
the wrong type stored in the field value.” INTERFACE is therefore validated
before its applicability is normalized; ignoring it does not permit UINT32 in
place of the required STRING or remove interface-name validation.

**Decision:** retain the current wire normalization and corrected XML quota
oracle. A well-formed INTERFACE on METHOD_RETURN or ERROR becomes `nil` and
cannot change the effective authorization decision. METHOD_CALL and SIGNAL
retain their applicable interfaces. A forged or malformed header is not granted
an exception by this disposition.

The [decoder](../../../apps/ex_d_bus/lib/ex_dbus/message.ex#L310) validates fields
before [normalizing applicability](../../../apps/ex_d_bus/lib/ex_dbus/message.ex#L403).
The [wire fixtures](../../../apps/ex_d_bus/test/wire/input_containment_test.exs#L125)
cover both endiannesses and reply kinds, absent/Blocked/Accepted INTERFACE,
wrong-type refusal and preserved call/signal semantics.

The corrected [XML causal-quota test](../../../apps/gao_bus/test/policy/xml_quotas_test.exs#L237)
requires the same receive denial for absent, Blocked and Accepted reply
INTERFACE. It preserves policy bytes and one-credit quota, uses fresh correlated
returns, crosses the caller's ordinary GetId barrier, requires empty pending
entries, refuses a stale duplicate and forwards the next fresh call. The
[denial helper](../../../apps/gao_bus/test/policy/xml_quotas_test.exs#L425)
checks AccessDenied against the service's **actual response serial**, not the
original call serial. The strict barrier and adjacent alias-release positive
case remain required.

**Closure evidence:** execution and exact bindings are needed to close that
local oracle correction; its historical Accepted-delivery timeout remains
old-oracle RED. That correction is a different deliverable from the original
pristine-reference comparison. Closing the latter requires the original policy,
identities, aliases, selection and reference to demonstrate the same effective
decision for all three valid inputs, with wrong-type rejection retained.
Current source assertions and another candidate-only unit pass cannot close it.
Security-related execution remains prohibited in the present scope.

## P07_REFERENCE_NO_REPLY_PROFILE

For [NO_REPLY_EXPECTED](https://dbus.freedesktop.org/doc/dbus-specification.html#message-protocol),
the specification says the message expects neither method-return nor error
replies and “the reply should be omitted.” This is **SHOULD**, not MUST, under
the specification's stated keyword convention. It remains a normative
recommendation; this record does not certify an upstream justification for
departing from it.

**Decision:** retain the project's stronger zero-physical-reply requirement for
the existing registered-client AbsentMember error case. The historical reference
error is a failure of that project/profile comparison; that fact alone does not
prove violation of a MUST clause. Do not change the candidate to emit the error,
accept either output as a pass, or remove the reference row.

Current [Router error handling](../../../apps/gao_bus/lib/gao_bus/router.ex#L1466)
suppresses method-call error replies when bit 0 is set. Its
[bus reply path](../../../apps/gao_bus/lib/gao_bus/router.ex#L1352) retains the
existing Hello registration-identity exception. This disposition concerns the
existing AbsentMember row and does not broaden it into a change to Hello.
The [requested-reply regression](../../../apps/gao_bus/test/requested_replies_test.exs#L119)
also covers no pending permission and suppressed failure replies.

The existing independent [API actor](../../../apps/gao_bus/test/fixtures/reload_actor.py#L1218)
records any response to the flagged serial, waits for its ordinary GetId barrier
and requires an empty physical-reply list. Its
[row inventory](../../../apps/gao_bus/test/fixtures/reload_actor.py#L1420)
includes AbsentMember; the
[SEM-11 evidence requirement](../../../apps/gao_bus_test/test/support/e2e/foundation_evidence_index.ex#L671)
still requires both backends, an independent client and an external observer.
These are unexecuted source anchors in this documentation slice.

**Closure evidence:** the unchanged row must actually establish zero physical
replies and the applicable pending-budget/healthy-barrier invariants on the
declared pristine reference and candidate. A synthetic timeout, client-side
discard of an error, patched reference or candidate-only pass is insufficient.
If that reference continues to emit an error, the original row stays blocked.

## Next acceptance boundary

All three implementation dispositions above are recorded. The three original
comparison obligations remain open. A maintainer can close one only with fresh
evidence satisfying its unchanged contract; an upstream fix must first be
present in the declared pristine build. Any alternative reference/profile or
comparison-design resolution requires a separate explicit decision and revised
acceptance design before execution. This document makes no such revision and
cannot retroactively convert a historical FAIL into PASS.

Document checks and reader review qualify this record only. No original test
count, gate, milestone or replacement-readiness claim is promoted. Security,
VM, native/FD, trusted-helper and package blockers retain their existing status.
