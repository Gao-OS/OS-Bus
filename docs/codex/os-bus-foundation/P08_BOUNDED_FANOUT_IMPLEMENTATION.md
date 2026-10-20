# P08 bounded fan-out implementation

Implementation source only. Compiler, syntax/parser, formatter, ExUnit, native FD,
independent-client, performance, and release qualification checks are **UNRUN**.
This document does not promote the evidence boundary in `STATUS.md` or establish
M2 replacement readiness. Acceptance is deferred by the user's implementation-first
instruction.

## Requirement mapping

| Requirement | Implementation in this slice | Acceptance still required |
| --- | --- | --- |
| P08 / R-09 | Atomic Limits ingress handoff; finite internal control pool; bounded match visits and recipient selection; single FIFO authority-work barrier | Scoped compiler/formatter/tests and resource/fairness gates |
| R-08 | Independently owned ingress FD copies survive producer exit; broadcast retains ingress credit until finish/cancel; egress duplicates retain their existing independent lifetime | Actual FD transfer, process-kill and cleanup evidence with independent actors |
| R-03 / R-04 | Captured sender identity/names and initial peer incarnations; current send/receive policy checked before delayed enqueue; sender revocation cancels remainder | Policy-generation and incarnation scenarios |
| R-05 | Ordinary quota saturation is a typed refusal/drop or guaranteed terminal overload result, without intentionally restarting authority/coordinator | Saturation and recovery scenarios |
| R-07 / R-11 / R-13 | Ordered directed/broadcast emits, activation delivery effects, generated pending failures and reload replies; activation terminal capacity reserved before admission | Ordering, activation and transactional reload scenarios |

## Scheduling and match semantics

`MatchRules` retains its existing per-peer bag and maintains a protected ordered
index with increasing insertion IDs. A cursor captures the concrete ETS table TID,
the initial highest ID, sender names, parsed argument types and a finite seen set.
Each self-message turn visits at most 32 rows, including nonmatches, duplicates and
concurrent deletions, and selects at most 8 distinct recipients. Later insertions
cannot extend the scan. Replacing the named index cannot attach an old cursor to
a new table; loss of its captured table ends the broadcast.

Router has one active broadcast and one FIFO of subsequent authority work. Later
routes, bus emits (including directed name signals), activation effects, pending
failure replies and reload completion wait behind it. Registration, policy commit
and DOWN cleanup remain immediate. The initial peer map and sender-name snapshot
are immutable for this broadcast. Delivery skips changed recipient incarnations
and rechecks current send/receive policy immediately before enqueue. A dead or
revoked source cancels the remainder.

This deliberately allows head-of-line routing delay behind one finite broadcast.
It bounds work per mailbox turn and preserves ordering; it does not promise that
later routes bypass the active broadcast. No parallel broadcast worker is added.

## Ownership and overload

Limits reserves/promotes ingress credit, duplicates the message's input FD bundle,
binds ownership to the concrete monitored Router and sends the owned envelope in
one callback before returning success. The public handoff then closes the
producer's originals. Source death does not retire queued authority work early.
The broadcast retains its ingress token and input copies through its last turn or
cancellation. Router closes/releases that ownership once and sends frame
`route_complete` once. Dead queued sources are discarded only when reaching the
FIFO head. Router DOWN reclaims mailbox/FIFO ingress resources; existing output
pins keep their source accounting until independent output copies retire.

Internal work uses a separate control pool capped at 512 items and 4,194,304 bytes;
it cannot borrow activation message/FD accounting. Reservation precedes mailbox
or FIFO admission, ownership is monitored, and a finite saturation counter records
refusals. NameRegistry notification refusal is a best-effort drop after committed
name mutation, with no rollback or additional error amplification. Generated
pending-disconnect notifications also drop on control saturation.

Essential pending expiry and reload completion retain their existing single-job
slots while queued, rather than competing with best-effort control notifications.
A queued pending expiry keeps the one timer slot occupied and cannot admit a
second timer completion. Reload retains the single reload waiter until ordered
completion, including after caller disconnect; duplicate completion messages cannot
create another FIFO item. Policy
publication itself stays immediate, and delayed reload replies use current policy.

Activation reserves terminal-control capacity before claiming/admitting a waiter.
Its byte reservation covers the validated header/metadata plus an 8192-byte finite
identity/error envelope. Backend error text is copied into a valid UTF-8 prefix of
at most 4096 bytes, and its name is bounded to 255 bytes. Terminal notifications
contain no body or FD handles. Refusal before admission releases the incoming
activation lease and returns a typed admission error.

A terminal reservation monitors both coordinator producer and Router owner. Before
enqueue, producer death/cancel reclaims it. Atomic terminal enqueue transfers it
to Router; subsequent producer death/cancel cannot release its queued credit.
Router consumption or DOWN retires it. Successful delivery cancels the unused
reservation. Nonterminal notification saturation settles the affected work as
overload using the reserved credit, without a coordinator restart. An existing
queued resolution retains its leased body/FDs until Router's finish acknowledgment.
Helper-result saturation applies the actual observed result before settling
remaining nonresolving waiters, preserving uncertain-child charges. Unexpected
missing/mismatched accounting remains an invariant failure.

## Test source and validation boundary

New ordinary test declarations cover bounded scan/recipient work, duplicate and
nonmatching rows, high-water and table identity, FIFO unicast order, frame window
retention, late registration exclusion, current policy, source cancellation,
ingress/control ownership and quotas, terminal producer/authority death, ownership
transfer, cancellation and envelope limits. Coordinator declarations cover
pre-admission refusal, guaranteed overload settlement, bounded backend text and
source/coordinator cleanup. Existing mailbox observers now recognize owned-route
and control envelopes and release observed control tokens.

Only source reads and scoped Git textual checks are authorized in this phase.
`git diff --check` is a whitespace check and cannot prove Elixir syntax or runtime
correctness. Every executable acceptance check above remains **UNRUN**; existing
native/independent actor gates remain required for later qualification.
