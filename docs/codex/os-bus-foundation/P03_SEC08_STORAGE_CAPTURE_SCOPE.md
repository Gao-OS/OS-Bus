# P03 SEC08: recognize the reviewed exception capture in storage validation

Source6 actual controls stop at storage-green: 14 tests, 13 pass, one failure
at test_prepared_layout. Root failure recordabcdb991 freezes36outputs. The
pure storage source predicate still requires literal primary = sys.exc_info()
although the reviewed driver now captures (type(error),error,error.__traceback__)
under except BaseException as error. Source6 is immutable. No build or VM ran.

Own only fresh environment/m1-sec08-complete1/source7/**. Reuse exact source6.
Correct only storage_provenance1.validate_storage_source's stale exception-
capture expectation to the actual reviewed equivalent caught tuple. Preserve
all existing storage, rethrow, diagnostic, disk/RAM, lifecycle and failure
predicates. No alternative allow branch, unconditional acceptance or bypass.
The exact source6 storage-green failure is the meaningful regression RED;
the unchanged prepared-layout assertion and all14storage controls must pass
after correction. Preserve all130GREEN/12RED control sources, cases/backend,
two individually bracketed denials, policies, identities, bounds and candidate19.
No new control count or runtime-driver/helper/production change is needed.

All other deltas are fresh bindings/reversals/review/output paths. Bind every
source6 output including the failed control, and keep source5 buildRED/earlier
failures. Preparation is own stdlib saved-file/hash/AST only; no target imports,
controls/parsers/typechecking/build/VM/broker/actor/consumer. Root SPEC, distinct
QUALITY and full pins precede actual serialized execution; runtime raw review
precedes receipts. Stop first unexpected implementation/target failure; do not
retry occupied paths. Own checker schema mistakes may be corrected in fresh
preserved versions without changing targets. This is storage-capture validator
integration repair1, separate from build-type1/primary static2/fixture runtime1/
production auth1/Astra0. No primary-preservation redesign is authorized.
Other agents are active; preserve edits. No production/index/ledger/old output,
host live bus/account/mount/device, Git/remote/release or memory mutation.
All targets NOT RUN, L0/product_qualified=false.
