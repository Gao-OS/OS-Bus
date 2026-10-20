# P07 retained reference discrepancies: bounded source diagnosis

Task: `P07_REFERENCE_DISCREPANCIES_DIAGNOSIS`, direct Sol source-only assignment.
Investigation **DONE**; resolution **BLOCKED_DESIGN**. Three retained mandatory
failures remain failures. No narrow candidate implementation defect is established
by these traces, and no normative expectation correction is justified.

Worktree `/data/development/Gao-OS/OS-Bus/.trees/os-bus-foundation`; assigned
branch `codex/os-bus-foundation`; assigned baseline
`7aba5a476a1a60a899ae3e8d5d288685d6f9f6e4`. Branch/baseline and candidate16 VM4
pending state are root-supplied, not revalidated by Git/runtime commands.
Candidate16 and all production/tests/ledger/evidence remain untouched. This
new diagnosis document is the sole write owned by this assignment.

## Contracts and evidence boundary

`REQUIREMENTS.md` R-07 requires reference-profile observable semantics; R-15
fails qualification for mandatory gate failures. `SOURCES.md` S1 identifies
the official specification, while its final reference guidance explicitly says
reference behavior cannot license contradicting an explicit normative requirement.
`CODEX_GOAL.md` forbids weakening negatives or changing reference expectations to
obtain green. These simultaneous constraints are unresolved for the rows below.

The locally saved official text identifies **D-Bus specification0.43** at
`test/reports/foundation/references/dbus-specification.txt:38`. All specification
citations below refer to that existing saved text, not a new web interpretation.
The saved daemon manual is `references/dbus-daemon.txt`. Archived official
dbus1.14.10 source provenance is
`test/reports/foundation/p09-xml-quotas/reference-source.json`, recording the
official release URL/archive binding. Recorded hashes are not recomputed here.

Historical evidence actually read:

- `test/reports/foundation/continuation-20261011-full-goal/mandatory-reference-after-identity.log`
  and scoped portions of its JSON: saved seed1703, **19 tests/2 failures**,
  queued-repeat action7 and XML second-reply timeout. This selection mixes a
  reference comparison with candidate XML tests; it is not19 reference cases.
- `test/reports/foundation/p07-reference-observations.log` identifies pinned
  dbus-daemon1.14.10 and its isolated custom session-policy fixture;
  `p07-reference-queue-order.log` records the complete14-action reference
  transition sequence. Its observation-test success does not turn the later
  normative equality failure into PASS.
- `test/reports/foundation/continuation-20261010-coherent-discovery/optional-interface-diagnosis.json`
  preserves the prior exact XML timeout/source chain and old failure binding.
- `test/reports/foundation/continuation-20261010-p09-api-completion/reference-no-reply-source-review.json`
  preserves the original no-reply frame/source diagnosis.
- `test/reports/foundation/continuation-20261011-full-goal/environment/p09-corrected15-vm-run2/FINAL_VERIFICATION.md`
  records historical **6 selected/executed,5pass/1fail,0blocked/skipped** and
  **10 actors,9pass/1fail**: candidate234 API rows pass; reference233pass/1fail.
  Bounded plaintext excerpts from that directory's
  `vm-export/osbus-p09-reload/actors/api-{candidate,reference}-actor.json`
  confirm the exact failing no-reply row and passing omitted-interface rows.
  That evidence explicitly predates later Router changes and does not qualify
  current sources or candidate16.

The earlier source-only
`continuation-20261011-full-goal/environment/reference-semantics-audit1.md`
was also read. This diagnosis independently read its decisive specification,
current source and named artifacts; it preserves that audit's contradiction
classification. No recorded run was repeated or historical count reclassified.

## 1. Queued-repeat RequestName reorders the reference queue

**Trigger/expected/actual.** `apps/gao_bus/test/name_reference_test.exs:51`
compares result codes and ListQueuedOwners after14 literal actions. Let initial
peers0/1/2/3 be A/B/C/D. A requests0 and repeats1; B/C queue0; B repeats1;
D replaces with2. Both queues are now **D,A,B,C**. D does not allow replacement.
Action7, `{:request, 1, 2}`, is B's queued REPLACE_EXISTING repeat. Both return
IN_QUEUE2, but candidate stays **D,A,B,C** while reference becomes **D,B,A,C**.
The saved reference probe then releases D and promotes B; normative candidate
promotion is A. The mandatory comparison remains FAIL at this exact action.

**Normative and current path.** Saved specification4310–4350 requires a queued
requester's flags to update when replacement is impossible; new requesters append.
The explicit queued update is4329–4331. REPLACE_EXISTING is evaluated at call
time, not an instruction for automatic future promotion. Current
`BusMethod.resolve/1`/`validate_arguments/1` selects RequestName with signature
`su`; `BusInterface.handle_request_name/3` at361–379 authorizes ownership before
calling the registry. `NameRegistry.request_name_transition/5` at351–414 checks
actual allowed replacement, handles DO_NOT_QUEUE removal, then updates an
existing queued tuple with Enum.map, preserving position and association count.
`list_queued_owners/1` returns owner followed by queue in that order.

**Concrete reference cause.** Archived
`p09-xml-quotas/reference-source/bus/services.c:883-897` unlinks an existing
queued requester and inserts it directly after the primary whenever its new
flags include REPLACE_EXISTING, even when replacing that primary is unavailable.
The adjacent854–877 branch also inserts a new REPLACE_EXISTING requester after
the primary rather than appending.

**Smallest safe correction/regression.** No candidate queue edit is justified.
A standards-directed reference fix updates flags without unlink/reinsert in
this unsuccessful-replacement branch; a new nonreplacing requester appends.
Preserve actual replacement, old-primary second position, DO_NOT_QUEUE,
response codes, quotas and ownership signals. Keep the original measured RED
and `name_queue_conformance_test.exs:54` unchanged. Add a separate differential
case: A0, B0/C0 queued, new D2; require IN_QUEUE2 and A,B,C,D, then B promotion
after A releases. Also repeat B1 before promotion, then replace promoted B with
D2 to prove flags actually update rather than becoming a no-op. Check ordered
queues, no duplicate association/extra charge, and causal ownership signals.
These proposed new cases are NOT RUN; reference reconciliation is outside this
report-only ownership.

## 2. Inapplicable reply INTERFACE changes reference XML authorization

**Disambiguation.** The retained failure is **INTERFACE on METHOD_RETURN**, not
optional INTERFACE on a bus METHOD_CALL. Current `BusMethod.resolve/1:40-55`
infers a known member's interface only when it is absent. Supplied unknown
interface yields UnknownInterface; omitted interface with absent member yields
UnknownMethod. Saved candidate15/reference rows `path-0-omitted-ListNames`,
`path-0-unknown-interface` and `path-0-omitted-unknown-member` all PASS. Archived
`p09-api04-groups/reference-source/bus/driver.c:3055-3067,3136-3140` confirms
the distinction. A patch that treats an explicit unknown interface as omitted
would break the existing reference contract.

**Trigger/expected/actual.** `policy/xml_quotas_test.exs:240-258` denies requested
method returns from alias QuotaA with receive_interface Blocked. The first reply
carries Blocked; the service receives AccessDenied, caller GetId succeeds,
pending entries are empty, and a stale reply is rejected. A fresh call's return
carries Accepted; the test expects caller delivery at258 but times out. The
same retained test and earlier assertions identify a header/policy contradiction,
not a newly demonstrated causal-credit retirement race.

**Normative and current path.** Saved specification1237–1253 requires accepting
and ignoring known fields in unexpected message kinds, while retaining known
field type validation. INTERFACE1308–1325 is optional for calls, required for
signals and has no defined return meaning. The saved manual820–826 warns that
interface-qualified deny rules match no-interface messages.

`send_reply/4:410-422` intentionally encodes the extra field;
`ExDBus.Message.build_header_fields/1:275` writes it. Decode at321/402 retains
INTERFACE only for method_call/signal, producing nil for both Blocked and
Accepted returns. `Peer.decode_frame/1:648` uses that result; no raw-interface
restoration occurs. Router's routing context1352 and recipient authorization1205
preserve the decoded message. `Policy.XML.match_attribute?/3:450` treats nil
interface as matching deny; its requested-reply modifier470 applies to this
correlation. Router252–274 retires the actual callee's XML correlation before
authorization; receive denial emits the bounded diagnostic to that service
instead of forwarding the return to the caller. The second alias ownership and
rule still apply, so its Accepted wire field cannot authorize delivery.

**Concrete reference cause.** Archived
`p09-xml-quotas/reference-source/bus/policy.c:1234-1252` directly reads the
present raw interface and skips this deny when it differs from Blocked. Thus
Accepted can affect reference authorization although the normative decoder
must ignore it for this message kind.

**Smallest safe correction/regression.** There is no candidate correction that
both ignores the field and permits that field to defeat the deny. A normative
reference correction would evaluate method_return/error INTERFACE as absent
for policy while preserving validation. That would still contradict this
original test's Accepted-delivery assertion, now on both backends. **A concrete
contract disposition is necessary; retain the original FAIL meanwhile.** Do not
preserve raw reply interface for policy, remove receive authorization, change
nil-interface deny, or relabel this expectation PASS.

Add a separate differential diagnostic with three otherwise identical real
correlated returns: absent INTERFACE, Blocked and Accepted. Require identical
effective deny and exactly-once credit retirement for all three; candidate is
predicted to deny all, reference's Accepted branch is predicted RED. Add
method_return/error decoder cases for correctly typed unexpected INTERFACE
yielding nil and wrong-typed INTERFACE remaining terminal. Existing
`input_containment_test.exs:99,118` covers general type/applicability invariants,
but its unexpected-field positive example is a signal's reply serial. Preserve
the adjacent XML alias-release test, which already exercises legitimate later
reply delivery after the policy alias ceases to match. No new case ran here.

## 3. AbsentMember produces a physical reply despite NO_REPLY_EXPECTED

**Trigger/expected/actual.** `fixtures/reload_actor.py:1420` selects
`no-reply-AbsentMember`; `api_query():1218-1250` sends flagged request204,
then ordinary GetId barrier205, and records any original-serial reply before
the barrier. The saved reference row FAIL contains UnknownMethod error206,
reply_serial204, flags1, destination:1.0, rights0, followed by barrier return207,
reply_serial205. Its exact assertion is
`NO_REPLY_EXPECTED produced a physical reply`. Candidate's same row PASS has
`suppressed_replies: []`. Row expected signature `s` belongs to GetId's barrier,
not an expected AbsentMember response.

**Normative and current path.** Specification1168–1179 says the reply should be
omitted;1670–1679 explicitly includes both METHOD_RETURN and ERROR, without an
unknown-member exception. This is normative **should**, not a quoted MUST.
The project's SEM-11 retains the stronger no-spurious-reply acceptance.
BusMethod resolves AbsentMember to UnknownMethod; BusInterface constructs its
internal error at660–675. Router `do_route/5:336-365` passes that result to
`deliver_bus_reply/4:1105-1131`, which suppresses delivery using the original
flags bit1 (`reply_expected?/1:1254`). Internal error construction/serial
advancement is not physical emission. The separately documented/tested Hello
identity exception remains selected and is not generalized to unknown methods.

**Concrete reference cause.** Archived
`p09-xml-quotas/reference-source/bus/dispatch.c:385-404,503-527` calls the
driver then routes its DBusError to `bus_transaction_send_error_reply`.
`p09-api04-groups/reference-source/bus/driver.c:3136-3140` sets UnknownMethod.
`connection.c:2682-2709` converts and forwards the error without checking the
original request's no-reply bit. Its driver send path2362–2438 sets flags1 on
the **outgoing** error, performs capture/policy and queues it. That outgoing
bit cannot undo the observed physical response to request204.

**Smallest safe correction/regression.** No candidate suppression change is
justified. The reference request-to-error delivery boundary must suppress
recipient output when the original call has flags1 while preserving transaction
completion, monitor semantics, unflagged errors and healthy barriers. Equivalent
dispatch failures and the separate OOM fallback require explicit qualification;
no dynamic OOM claim is made here. Preserve all234 API operations and the exact
physical-barrier negative. Add focused flagged/unflagged absent-member twins
for known bus/Peer and omitted interface, plus unknown-interface twins. Flagged
cases must produce zero original-serial replies before GetId; unflagged cases
must produce the appropriate UnknownMethod/UnknownInterface. Preserve observer,
authority/admission state and pending budgets. Existing
`requested_replies_test.exs:119` covers forwarded no-reply calls/missing
destinations, not this exact driver error. New regressions are NOT RUN.

## Ownership, verification and required decision

The three behaviors are narrow reference implementation disagreements with
the saved normative text; their required qualification rows remain unresolved.
No reinterpretation of specification wording or correction of negative
expectations is justified by the evidence. The XML row additionally demands
mutually incompatible Accepted delivery and ignored-header authorization.
Resolution remains **BLOCKED_DESIGN** until root supplies the bounded reference
reconciliation/contract disposition. This label does not claim model incapacity
or request Astra. The reference dependency is freedesktop dbus, outside the
listed Gao/gsmlg organizations; no automatic internal-request issue was created.

Only plaintext reads (`cat`, `rg`, `rg --files`, `sed`, `nl -ba`) and creation/readback of
this new report occurred. One initial guessed ExDBus spelling and unmatched
shell glob failed during source lookup, then were corrected. Ignored evidence
filenames needed `rg --files --no-ignore`. Minified JSON initially exceeded
output bounds; decisive actor rows were reread with bounded `rg -o` excerpts.
None of these commands changed source or started runtime processes. No imports,
hashes, syntax checks, tests, Mix, builds, VM, Git, network/account, background
or memory execution occurred. All commands finished; no child runtime persists.

Sol repair-validation rounds for this assignment:0; received Astra counter:none;
astra_gate:none. Report-only diagnosis task **DONE**. Ownership of this new file
is released to root. Root owns any later additive regression assignment,
reference reconciliation, runtime scheduling after the candidate16 freeze,
source/candidate binding and ledger changes. UID draft/persistence work and VM4
are untouched. Full Foundation goal incomplete, productfalse/readinessL0.
