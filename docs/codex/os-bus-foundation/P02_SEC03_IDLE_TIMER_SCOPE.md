# P02 SEC03: directed idle timer recovery, collector semantics clarified

This supersedes only the erroneous collector-outcome requirement in
P02_SEC03_TIMER_AND_OUTCOME_SCOPE.md. Root inspected source5 collect.py:
main validates complete evidence and returns normally even when backend gates
honestly report failed_conformance. The module does not propagate a backend
exit through sys.exit. test.nix requires that collector success and clean
shutdown. Therefore a complete valid collection has driver0 and clean JUnit;
the original source5 driver1 records its unexpected incomplete GaoBus run.
Preserve these distinct meanings. Do not change collector, vm1 recorder,
testScript, runtime success/JUnit joins, reference expectations or gate exits.
Never derive driver failure from a retained reference conformance failure.
Source6 stopped before implementation because the previous scope contradicted
these facts. Its complete stopped evidence and every earlier failure stay fixed.

Prepare only fresh environment/m1-sec03-complete1/source7/**. Preserve source1..6,
channel-diagnosis1, all root evidence and candidate18 with bytes/modes/file sets.
No production change. Reuse source5 and its original controls unchanged except
the narrow timer relation and necessary path/pin rebinding.

Exact expected-to-observed equality remains accepted. The sole additional
relation permits a valid expected BEAM reference pair to become observed nil
when both complete pending-entry maps are empty and every other originally
normalized field is identical. A new or changed reference, malformed timer,
timer loss with nonempty pending, changed serial/authority/FD/accounting or any
other state mutation must fail. Consecutive observed samples remain exact.
Apply the relation consistently to live settle, recovery validation and saved
replay; preserve raw expected and actual snapshots. Do not ignore timer fields,
raise deadlines or change production. The accepted diagnosis compares all29
saved samples and proves this directed transition in source5.

Add source-derived whole-file reversal RED and new GREEN controls using those
saved samples, exact equality and each prohibited mutation. Retain every old
control and all51cases/102pairs, including all12reference numeric/login-name
failures. A collector success proves complete evidence collection only;
validate_complete must still validate each actual backend status, counts and
gate exit. Failed backend receipts cannot qualify and source5 remains failed.
Add data/AST controls pinning this actual collector/testScript relationship if
useful; do not modify their behavior or broaden runtime joins.

Bounds remain caller/health/settle1s,128reads,startup10s,authority360s,guest480s,
host900s,cleanup5s. Root SPEC, distinct QUALITY and full root pin recheck precede
separately recorded controls/imports/parsers/approval/build/realization and one
paired VM/observer. Distinct actual raw review precedes receipt and unchanged
consumer adoption of any genuinely passing backend. No occupied retry.

Ordinary authoring/self-review corrections to fresh unexecuted source7 within
this scope are authorized before sealing. Stop for contradictory requirements,
evidenced impasse or first unexpected executed target failure. AuthSol2/Astra1,
credential-oracle0/0 and source5 failure remain explicit; no reset of history.
Preparation is data/AST only: no target import/test/parser/build/compiler/VM or
consumer. Other workers are active; preserve their edits. Root owns execution
and ledger. No old evidence/map/consumer/host bus/account/Git/remote/publication/
memory mutation. Readiness L0; product_qualified=false.
