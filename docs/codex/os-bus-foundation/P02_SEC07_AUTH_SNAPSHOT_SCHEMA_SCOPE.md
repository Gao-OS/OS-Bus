# P02 SEC07: validate the actual credential snapshot schema

Source3 candidate19 execution stays immutable/FAILED. Root failure record
1c430f128b448d9a2f677a8e3064cc9a706b5e94e8a814b675eeb85a8a624403 freezes
the exported raw. Saved-only diagnosis traces five complete matching native
Auth snapshots with actual credentials {pid,uid,gid,groups}. Production adapter
returns kernel pid/uid/gid and validated groups; Peer passes that map to Auth.
The fixture validator requires nonexistent credentials.source, while synthetic
controls fabricate it. Its KeyError is treated as an unsettled snapshot. Saved
queue/reply complete before116ms, first complete snapshot before202ms, followed
by logged auth_idle_timeout and closed635ms. No full performance pass is inferred.
Bind the completed diagnosis report/readback before finalizing new preparation.

Own only fresh environment/m1-sec07-complete1/source4/**. Other agents are
active; preserve edits. Reuse complete source3 fixture/candidate19 and unchanged
17cases/34pairs,700ms criterion, all policies, timer/queue/wire/health/recovery/
resource predicates and absolute bounds. Correct only the credential-schema
expectation to the actual production snapshot. Preserve exact uid/gid/pid/groups
checks and independently bound socket/kernel/actor identity provenance; never
invent a source field, accept asserted UID, fabricate metadata, or erase identity
checks. Correct synthetic controls to the actual schema and replace their
source-only omission with a real required-identity-field omission. Existing
negative identity/credential and Auth state tests must remain effective.

Add meaningful controls using the exact saved native snapshot and expected
identity data. The old source3 validator must fail the new legitimate-snapshot
assertion as a deliberate RED; the corrected validator must accept the complete
actual schema and reject missing/mismatched required kernel identity/state.
Keep raw/source-derived failures distinct from synthetic controls and backend
qualification. No validator/actor/snapshot/timer/corpus redesign. Do not relax
outcomes/deadlines/skips or use this diagnosis as full runtime qualification.

All other changes are fresh output/candidate/provenance/reversal/review bindings.
Preserve every source3 raw file and old source2 performanceRED. Preparation is
own stdlib file-data/hash/AST only; no target imports/control/test/public parser/
compiler/build/VM/broker/actor/consumer. Root SPEC, distinct QUALITY and full pin
check precede serialized controls/import/parsers/approval/build/realization and
one simultaneous VM-driver/observer launch. Raw review precedes receipts. Stop
first unexpected failure; no occupied retry. This is source3 fixture runtime
repair1; production auth runtime repair1 and Astra0 remain separate.
No production/index/ledger/old-output, host live bus/account/mount/device,
Git/remote/release or memory mutation. All targets NOT RUN; L0/productfalse.
