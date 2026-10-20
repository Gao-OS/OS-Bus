# P02 SEC05: diagnose live receipt versus JSON journal equality

Preserve the source2 once-only failed VM and every earlier failed source. Its
reference backend fails at live `replay_requests` before GaoBus executes. The
saved270 journal records and exported report receipts have equal JSON values;
this does not establish that the live in-memory Python values were equal.

Root owns fresh `m1-sec05-complete1/live-journal-diagnosis1/**` preparation.
Extract the exact pinned source2 `request` and `call` ASTs, execute only those
functions against a fake channel/clock and owned temporary files, and use the
unchanged real journal helper. Use actual saved response/identity samples.
Test the default empty-body call against live journal replay, explicit list
bodies, unchanged deadline refusal, drift/incompleteness rejection, and all270
saved records. A Python tuple and its serialized JSON array must be examined
without changing the actual journal validator or an original assertion.

Preparation is stdlib/file-data/AST only. Root SPEC and distinct QUALITY must
precede one separately recorded offline diagnostic execution. Expected old-source
RED is exactly one default empty-body replay failure; any other result stops for
reassessment. No broker/VM, control retry, source correction, receipt/adoption,
map/ledger mutation by a worker or fabricated passing runtime. Diagnosis cannot
make either failed VM pass. Root may use its actual result to define a separate
narrow source repair later. No host bus/account action, Git mutation, remote or
publication action or memory writes. Other workers are active; preserve all
occupied outputs. L0/product_qualified=false.
