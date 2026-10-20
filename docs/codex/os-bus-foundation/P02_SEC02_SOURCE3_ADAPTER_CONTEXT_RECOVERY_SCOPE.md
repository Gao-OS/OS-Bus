# SEC02 source3 adapter context and attempt routing correction

This separate local correction is authorized by CODEX_GOAL.md's implementation
assignment. It does not alter or reopen any previous failed attempt. M1 remains
unpassed and readiness remains L0 until all required gates pass.

The accepted saved diagnoses are `sec02-source3-adapter-context-diagnosis1`
(seal ba4188b2644ea8dc6d1b2ca9c3f37c2b7662ecdfeb1ffdf359d06a2e0cadc81e)
and `sec02-source3-adapter-receipt-path-diagnosis1`
(seal 541a7afe3511375f217e082e18a1f1a563a0c460bfdd87bd1d6e021531c1ef03).
Root must verify both complete sealed inventories and input bindings before
applying their finite proposals.

Permitted changes are exactly:

1. Preserve original CONTEXT1.json and IMMUTABLE_INPUTS1.json bytes and modes in
   the new `m1-res01-measurement1/sec02-source3-adapter-context-recovery1/before`.
   Add the proposed catalogue_invariant, catalogue_rows and catalogue_map to
   CONTEXT1.json; change only that context's files entry in IMMUTABLE_INPUTS1.json.
   Existing runtime values, original builder, sources, reviews and manifests stay
   frozen. Proposed new context SHA256 is
   9a2ba0f09b425659568d61da542e8185fcfadd2cec4b77bcc00dd81657245fa0;
   new immutable map SHA256 is
   c5a1467e582394b919e3824f61c61d14d438d56c88e337c27125f3df9f8e0470.
2. Author only the exact proposed derived make-receipts1.py (four routing edits)
   and ROOT_STAGE1.py (three routing edits) in that new directory. Verify complete
   byte and location-bearing AST inverses. Keep all assertions, control scripts,
   adapter semantics, old logs, recorder, fixed stages and receipt output paths.
3. Add a finite root guard binding the corrected data, derived files, all original
   immutable inputs and historical failed attempts. Distinct SPEC then QUALITY
   review must pass before any target execution.
4. Run the four RED controls and 45 GREEN cases once each, separately through the
   existing recorder, in the new offline1 namespace. Verify the REDs are intended
   assertion failures, with no ERROR or skip; stop on any unexpected outcome.
   Then run the derived receipt writer once. No VM or runtime replay is needed.

Afterwards, distinct output review, unchanged strict consumers and exact two-row
root adoption remain mandatory; those steps do not waive any other requirement.
Accepted map and all four ledgers remain unchanged until a separate verified
adoption or checkpoint. No production edits, bus traffic, host changes, commits,
pushes, releases, evidence deletion or fourth SEC08 attempt are authorized.
