# P03 SEC08: preserve the diagnostic driver contract through type checking

Source5 controls actually ran: 130 GREEN and 12 intended single-test REDs;
imports, public parsing and approval passed. Its first driver build failed
before any VM execution: NixOS mypy reports 24 errors in the heterogeneous
status dictionary and sys.exc_info() optional exception tuple. Root freezes
74 outputs in source5/ROOT_BUILD_FAILURE_RECORD1.json (4306b75f). All source5
files and outputs remain immutable. No realization, VM, replay or receipt ran.

Own only fresh environment/m1-sec08-complete1/source6/**. Reuse source5 and
correct only the embedded driver typing. Give the heterogeneous diagnostic
status an explicit accurate type; capture the caught BaseException and its
traceback with a type that proves the saved exception is present. Preserve the
saved tuple shape consumed by existing tail code/controls if possible. Never
disable skipTypeCheck, add type ignores, weaken assertions, erase exception
details, change cleanup/export/reporting order or suppress a failure. Keep the
same primary exception object and traceback behavior. Document the exact
runtime equivalence of the old except capture and the new capture.

Keep all 130 GREEN/12 RED controls, including actual reporter/handler/driver-tail
tests, all 32 cases/backend and two individually bracketed denials, all policies,
bounds, candidate19, guest disk/RAM, storage measurements and lifecycle checks.
Only fresh source/provenance/reversal/review/output bindings may otherwise
change. Historical source5 build and earlier ENOSPC/quality failures stay bound.
This is the first driver build-type integration repair, separate from primary
static repair2, fixture runtime repair1 and production auth repair1; Astra0.
No repeated primary-preservation repair is authorized by this typing scope.

Preparation is own stdlib saved-file/hash/AST only; no controls/imports/public
parsers/typechecker/compiler/build/VM/broker/actor/consumer execution. Root SPEC,
distinct QUALITY and full pins precede serialized actual controls/imports/
parsers/approval/build/realization and one paired driver/observer launch. The
existing source5 build is the actual typing RED; a new build must actually pass.
Raw reconciliation and distinct review precede receipts. Stop first unexpected
failure and do not retry occupied outputs. No production/index/ledger/old output,
host live bus/account/mount/device, Git/remote/release or memory mutation.
Other agents are active; preserve their edits. L0/product_qualified=false.
