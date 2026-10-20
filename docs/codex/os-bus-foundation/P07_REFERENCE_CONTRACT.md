# P07 reference contract and XML test correction

The full foundation goal authorizes the narrow test correction below. It does
not change the production candidate, the declared pristine reference profile,
or any mandatory conformance result. The historical diagnosis and failed logs
remain unchanged. M1 is unpassed; readiness is L0.

Root SPEC `ROOT_P07_REFERENCE_CONTRACT_SPEC1.json` checks 47 saved files.
The accepted architecture is `p07-reference-contract-design1/DESIGN1.md`,
SHA256 `63dd5f915a164ef1f73f4cb1fca81c7113c98387496ab7769c930bb587fa2898`.
Distinct QUALITY `p07-reference-contract-quality1/QUALITY_REVIEW1.md`, SHA256
`8167e85dba97f392a8311fd2e78f1d0ced872028b82512da6d8f5898817a3897`,
reports no blocking design findings. These files are under
`test/reports/foundation/continuation-20261011-full-goal/environment/m1-res01-measurement1/`.
An initial root checker resolved design-relative seal keys against the checkout;
its saved failure and corrected check are retained. No target ran in that check.

## Unchanged acceptance obligations

- Preserve queued requesters' position when replacement fails. Keep the original
  queue comparison, flags, response codes and signal ordering.
- Ignore correctly typed known fields in message kinds where they are
  inapplicable, while retaining field-type validation. A reply INTERFACE cannot
  change the effective authorization decision.
- Preserve the project's stronger zero-physical-reply requirement for the
  existing NO_REPLY_EXPECTED error case. The specification says SHOULD, with
  RFC2119 meanings applying to lowercase words; do not call this a MUST defect.

The original pristine-reference gates remain blocked by
`P07_UPSTREAM_QUEUE_ORDER`, `P07_UPSTREAM_REPLY_INTERFACE_POLICY` and
`P07_REFERENCE_NO_REPLY_PROFILE`. A diagnostic patched reference cannot satisfy
those original rows. No reference patch, different profile, selection change,
upstream message or evidence-consumer change is authorized by this correction.

## Authorized test slice

Only these existing files may receive behavioral edits:

- `apps/gao_bus/test/policy/xml_quotas_test.exs`: correct only the receive-denial
  causal-quota test and a narrowly required local helper. For absent, Blocked
  and Accepted INTERFACE on fresh otherwise identical correlated returns,
  require AccessDenied addressed to the service's actual response serial, no
  caller delivery before its ordinary GetId barrier, empty pending entries,
  stale-duplicate refusal and successful forwarding of the next fresh call.
  Preserve policy bytes, identities, aliases, one-credit limit, deadlines,
  healthy probes and the adjacent alias-release positive test. The existing
  barrier helper must continue rejecting unexpected routed payloads.
- `apps/ex_d_bus/test/wire/input_containment_test.exs`: add independent wire
  fixtures for ignored reply INTERFACE on METHOD_RETURN and ERROR, wrong-type
  refusal, and preserved METHOD_CALL/SIGNAL interface semantics. Do not change
  production codec behavior.

Own fresh evidence under `m1-res01-measurement1/p07-xml-oracle-correction1/`.
Freeze both complete preimages, original failed logs and production bindings
before editing. Other agents are active; preserve source9 and all unrelated
work. Saved authoring and review may proceed in parallel. Root owns all actual
controls, compiler/formatter/tests and ledger/index changes; executions remain
serialized with SEC08. No target may run before root review and explicit GO.

This is an oracle correction, not a newly fixed production vulnerability. The
old Accepted-delivery timeout is retained as old-oracle RED. A fresh preimage
run may reproduce it; no production mutation is permitted to manufacture RED.
Record actual scoped commands, counts and source/artifact bindings. Unexpected
out-of-scope failures stop this slice. Tests start NOT RUN. Historical failures
never become passes merely because the oracle is corrected.
