# PRO01 current whole-stream positive case

Continue P02/PRO-01 with the exact current-C observation missing from the
accepted saved coverage integration. One tested client writes AUTH25 + BEGIN7
+ Hello128 + GetId128 together, then receives OK and ordered successful replies
1,2. Use the existing literals and independent reader. This is one finite
normal-operation case per backend, with observer setup counted separately.

Add a shared Python actor, one supervised Gao ExUnit regression, proportional
data-only fixture checks, an explicit private-reference launcher, and a C-only
frozen-artifact VM runner/Nix entrypoint. Preserve completed fixtures and their
runner/Nix selections. No product changes are expected; a product failure must
be recorded and diagnosed before any repair. Do not invent a product RED when
existing behavior already supports the new regression.

Verify the tested source performs exactly one successful 288-byte write,
correct authentication, Hello name and GetId identity, reply order, no rights,
no extra bytes, and healthy observer behavior. Gao records actual native reads
whose consumed bytes concatenate to the stream; no fixed receive partition is
required. Verify clean Peer parser/auth state and drained authority/resources,
monitor normal closures and remove only the owned private socket. Reference
internal receive extents/parser/accounting remain unsupported.

Bind current product artifact b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1
and runtime metadata 6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5
separately. Retain all71 source/80 artifact hashes and new fixture/runner/config
pins. Host reference UID1000 and Gao VM UID1101 have distinct AUTH/full-stream
hashes and profiles; this work does not establish common-profile qualification.

Bounds remain socket/reply/actor-exit3s, Peer state/DOWN1500ms, actor alarm30s,
ExUnit60s, reference startup10s/actor wait45s/cleanup5s. The VM wrapper retains
guest240s/execute250s/outer900s/cleanup5s. Review source before one new reference
execution and one C-only Gao VM execution. Failed attempts remain failed; no
unchanged retry is selected. Static/data-only checks retain60s bounds.

Root owns this scope, C-only runner/Nix, pins, execution receipts and ledgers in
resume-20261019/pro01-current-whole-stream1/. One worker owns the shared actor,
ExUnit and data-only actor tests; another owns the reference launcher. Workers
coordinate their shared record contract and preserve others' work. Review
source and actual saved output independently before scoped acceptance.

Realization is conditional on available frozen dependencies. No probing,
restoring, substitution, reconstruction or rebuilding of RES02's98 missing
frozen paths is allowed. If this prevents C-only driver realization, record
BLOCKED_ENV and continue the independent reference/static work. Closed SEC03,
SEC06/FD04, SEC08, native authorization/P10, frame-cleanup, RES02 and H01/precommit
routes remain closed. No optional audit, exploit, fuzzing, external API probe,
host live-bus/config/account change, commit, merge, push, release, deployment or
memory write. Existing required index is unchanged. Full goal remains incomplete;
M0 historical, M1/P02 earliest unfinished, L0/product_qualified=false; precommit
remains BLOCKED_SCOPE_AND_ENV.
