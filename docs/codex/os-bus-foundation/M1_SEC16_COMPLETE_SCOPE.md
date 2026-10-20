# SEC16 registration behavior: complete core scope

This scope implements the existing TEST_PLAN.md SEC-16 functional requirement:
pre-Hello operations, repeated Hello, forged sender and reordered registration
input, with no premature privileges, stable registration identity and correct
reply/signal sequencing. Select exactly SEC-16/complete-requirement/core for
reference and GaoBus. M1 remains earliest unpassed; readinessL0 and
product_qualified=false. Full P00–P12 remains active/incomplete.

Reuse the existing scripts/foundation/vm_security/run.py:473–501 scenarios and
independent actor/packet machinery in a fresh finite copy of the completed
m1-sec15-complete1 source1/execution1 fixture. Existing assertions and normative
or pinned reference expectations cannot be weakened. Preserve old sources,
results, receipts and accepted index8df46147. No new general framework, optional
audit, external API probing, exploit work or broad fuzzing is authorized.

Root owns this scope, current ledgers, candidate capture and all execution under
test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec16-complete1.
Source worker owns only source1/ there: finite fixture/contract/test adaptations,
README, provenance and source manifest. Wrapper worker owns only execution1/
there: finite copies of SEC15 private runtime, driver/observer/realization/source
helpers, binding/handoff/manifests. Preserve the inherited lifecycle mechanism;
do not create another VM launcher or copy old observed runtime identities. No
worker may change production, old evidence, catalogue/consumer or current ledgers.
All workers share the checkout and must preserve each other's changes.

Preparation uses saved file/hash/JSON/AST operations only. Root alone runs
contract controls, pinned parsers, build/realization, one paired VM/observer,
runtime replay and consumers. Distinct source review must precede execution.
Production changes require an evidenced directly affected regression and narrow
correction; no production defect is assumed from an unmapped evidence row.

Use real UID1100 persistent observer and UID1101 functional clients with equivalent
frozen system policies, positive EXTERNAL/Hello/ordinary-call controls and existing
private socket guards. Cover pre-Hello RequestName denial/closure without ownership;
duplicate Hello controlled error without identity change; coalesced valid
Hello/RequestName/Hello and an operation-before-Hello ordering; forged sender
replaced by the actual registered unique name at the receiving actor. Keep the
full actual receive streams. Client.reply's serial-filtered return list alone
does not prove wire ordering. Validate actual reply order and required registration
signals against the existing contract/specification and pinned reference behavior;
do not invent a signal ordering that the protocol does not require.

Preserve unrelated observer identity, owned names, truthful credentials, daemon
incarnation, bus ID and endpoint. Save the complete relevant ownership streams
so an unauthorized transient mutation cannot be hidden by final-state recovery.
Use existing full observable Gao native baseline recovery; do not fabricate
reference internals. Require identity-bound natural actor/daemon retirement,
private socket removal and VMoff. Retain all failing/incomplete evidence.

Keep donor bounds: authority60s, guest120s, host900s, cleanup5s, observer30s,
startup10s, request1000ms, case2000ms, authentication1500ms/idle500ms,
settle1000ms/128reads and poll0.05s. Underlying waits stay finite within the
absolute enclosing deadline. No automatic retry or raised threshold follows
a failure. Preserve and diagnose a failure before any explicit in-scope repair.
Unrelated test failures stop the scope; do not rerun or fix unrelated XML tests.

Meaningful contract controls must reject missing cases, changed sent bytes,
incorrect observed reply/signal order, premature ownership, false sender identity,
changed healthy identity and missing/duplicate/wrong-identity retirements; accept
valid harmless record reordering where order has no semantics. These controls
verify only this existing functional requirement. Missing real execution stays
blocked. Only complete raw results, distinct review and root's unchanged receipt
consumers may adopt the two core rows; both network rows remain blocked.

SEC03 original timeout remains causeUNKNOWN: no retry, extended deadline or
dependent dispatch. SEC06 never redispatch; SEC08attempt3 remains failed/no fourth;
SEC09–12 stay paused. /tmp/osb-s9-002da709a82d10fa remains off limits. Preserve all
mandatory comparison and FD/resource/activation/release/real-service blockers.
Never touch host live buses, system, accounts, mounts or devices. No Git
commit/merge/push/publication/release or memory mutation. All sockets/processes
for actual runtime tests are private in a marked disposable Linux guest.
