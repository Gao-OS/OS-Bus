# P02 SEC05: complete the preserved realization inputs

The first source2 realization command failed before any VM invocation because
the unchanged verifier reads `source2/REUSE_ORIGINS1.json`, which preparation
omitted. Preserve that actual failure, all source2 sealed files, its successful
offline controls/build and the failed historical source1 VM.

Add only a new byte-exact copy of the already approved and frozen
`source1/REUSE_ORIGINS1.json` at the verifier's missing source2 path, plus fresh
`source2/realization-input-repair1/**` evidence. The descriptor and reference
binary already have matching pins in source2's BEFORE_BINDINGS and actual
VM_SOURCE_APPROVAL. Do not edit any existing source, assertion, deadline,
approval, fixture, candidate, driver, log, map or receipt. Do not rebuild or
rerun any control or historical VM. The prior missing-input failure is the RED
evidence; do not fabricate another regression by changing a validator.

Root data-only SPEC and distinct QUALITY must check the exact copy, complete
existing approval/build/realization input chain and all prior source2 pins.
After those reviews, root may record one new invocation of the unchanged
realization verifier, with fresh repair-stage outputs. Its original fresh
BUILD_REALIZATION_VERIFICATION output remains required. This is a corrected
input execution, not a change to the verifier or a rewrite of its failed record.
All original realization assertions must execute unchanged. Stop on any further
substantive failure and preserve its exact evidence. Only a successful complete
realization permits the previously authorized one paired VM/observer execution.

Keep the supplement frozen through runtime and raw review. Root owns adoption
and ledger updates. No host bus/account action, Git mutation, remote write,
publication or memory write; L0/product_qualified=false. Other workers are
active; preserve their edits and every occupied output.
