# PRO-04 fixed-header length regression and correction

Required scope: REQUIREMENTS R-05/R-06, IMPLEMENTATION_PLAN P04, TEST_PLAN PRO-04.
The current transport waits for a protocol-invalid header array when a supported
XML max_message_size exceeds 64 MiB. Only the fixed 16-byte prefix is needed to
prove the defect; no large body, FD, load campaign, or external API is permitted.

Phase RED: add one dedicated native ExUnit file and independent Python actor.
Use exactly two tests (little and big endian), each with a valid header-array
boundary held incomplete and then a header-array length of 67_108_865 rejected
from its fixed header alone. Configure a finite supported XML message cap large
enough for both prefixes. Register actual clients normally; preserve a healthy
observer, its owned name, actual kernel credentials and exact authority/Limits
snapshots. A valid boundary prefix must remain incomplete until normal close.
The invalid prefix must cause automatic normal Peer DOWN, with no payload sent,
then accounting restoration and a successful observer health request. No FD
negotiation/resources or explicit source-unregister operation is included.

Root alone runs proportionate syntax/format/compiler gates, an offline driver
build and one disposable Linux RED VM using unchanged candidate6077a50d/source
4e334b95. Preserve raw failures and every origin before changing production.
A RED expected-test-failure disposition is not a passing requirement or gate.
No automatic rerun or deadline increase is allowed.

Only after a diagnosed RED, phase GREEN may minimally share the existing pure
Message length validator with Peer so framing and receive budgeting apply the
same protocol header/message limits before more input is requested. Preserve
configured limits, valid incomplete/complete behavior and native frame read caps.
No reinterpretation or redesign of the pending PRO01 read requirement is allowed.
Root records the exact correction, fresh source/build candidate and affected
verification scope before one separate GREEN run. The existing pure input-
containment file is an affected regression; excluded FD suites are not selected.

Source owner A: apps/gao_bus/test/peer_fixed_header_lengths_test.exs,
apps/gao_bus/test/fixtures/peer_fixed_header_lengths_actor.py, plus test.nix,
INPUT_PINS1.json and HANDOFF1.md in environment/m1-pro04-fixed-length1/red1.
Source owner B: that red1 directory's root-execute1.py, EXECUTION_INPUTS1.json
and EXECUTION_HANDOFF1.md. Root owns all other evidence, reviews, execution and
ledger updates. Production source ownership after RED is assigned separately.
Authors/reviewers inspect source/saved metadata only; root executes every check,
build and runtime. Everyone preserves other workers' and unrelated user edits.

Retain socket/reply/exit3s, state/DOWN1500ms, actor alarm30s, ExUnit60s,
host/VM900s and cleanup5s bounds. Reuse unchanged host_lifecycle.py,
lifecycle_adapter.py and PRO03 private_runtime1.py; no new harness or approval
mechanism. Use private sockets, disposable VM accounts and offline Nix builds.
Do not rerun any completed AUTH/BEGIN/Hello/GetId/PRO03/SEC13-16 target. SEC03
no retry, SEC06 no redispatch, SEC08 no fourth run/scratch, paused SEC09-12 and
FD04 exclusions persist. No external API probes, optional security audit,
penetration/exploit work, broad fuzzing, host live-bus/system/account change,
Git mutation/publication or memory write.

This slice cannot complete full PRO04/05, M1 or higher readiness. General XML
frame-deadline behavior and full independent reference coverage remain blocked.
M0 accepted; M1 earliest unpassed; L0/product_qualified=false. Accepted index
and all previous failed/partial evidence remain preserved and source-scoped.
