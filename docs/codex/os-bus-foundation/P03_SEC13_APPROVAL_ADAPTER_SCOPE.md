# P03 SEC-13: correct the frozen approval adapter's stage join

Continue the original SEC13 scope and serial-correction addendum. Source2's
serial correction remains sound, but independent review confirmed that
`prepare-approval2.py` joins recorded stage receipts to `stage + '1.py'` while
its actual wrappers are named with suffix2. Preserve rejected source2, its
seals, root SPEC and QUALITY rejection without alteration.

Source preparation owns only new files under
`environment/m1-sec13-complete1/source3/`. Keep the suffix2 filenames, module
stems, fixture/output names and review markers within that new directory.
This avoids another filename migration. Correct the dynamic stage join to
the actual suffix2 wrappers, rebind necessary absolute source-directory
references and the sealer's directory assertion, and freeze complete source2
history in addition to source1. Record every changed callsite and retain the
failed adapter's exact preimage. Distinguish historical authoring scripts
that are copied as inert provenance from current executable entrypoints.

Add a file-data cross-check that independently joins all six actual stage
wrapper paths to the approval adapter's derived paths and rejects the old
suffix1 form. Verify all current import and dynamic filename constructions;
do not rely solely on finding literal filenames in the dispatcher. No target
execution is authorized during preparation. No production, candidate,
fixture policy/scenario/serial/control logic or numeric bound may change.

Root owns SPEC, ledger, serialized execution and adoption; a distinct reviewer
owns QUALITY. Fresh source3 seals and both reviews are required before any
target stage. Preserve occupied paths and first unexpected failures. This is
source repair2; the two earlier preparation failures and root auxiliary reader
preparation incident remain separate. All rejected-source target stages are
NOT RUN. Full M1 and foundation remain incomplete at L0,
product_qualified=false. All original isolation and no-publication constraints
remain in force.
