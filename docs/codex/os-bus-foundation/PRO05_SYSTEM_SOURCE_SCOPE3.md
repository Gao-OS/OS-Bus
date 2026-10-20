# PRO05 saved-report contract and runtime provenance

Continue the existing PRO05 source with the unchanged catalogue invariant and
core selection. Add a pure saved-report contract and retain the runtime
provenance needed by the existing generic evidence consumer. No new vectors,
native tests, profile cells or alternative runtime/evidence harness are added.

Contract worker owns `scripts/foundation/pro05_complete/contract.py` and
`test_contract.py`. Saved-report worker owns `validate_saved.py` and
`test_saved.py`. Root owns `run.py`, `test_reporting.py`, `README.md` and this
scope document. All other production,
scope1/2 components, shared helpers, generic mapper and E2E selection stay
unchanged. The contract reuses the existing finite replay and controller
checks, retaining exact receipt/actor/event joins, resource endpoints,
restoration, finite work, normal retirement and teardown. It must reject
incomplete reports, claimed booleans without observations, altered order or
limits, and profile/backend/configuration drift. No source test qualifies a
runtime requirement.

The adapter records observed daemon version, configuration bytes/hash/path,
immutable observer identity, current artifact/source identity, fixed bounds,
and a source-bound invariant measurement only after scenario and natural
shutdown checks. Failed teardown cannot yield a passing backend count. The
saved-report validator reads supplied files only, validates their exact input
bindings, and reports validation separately from runtime qualification. It
does not create passing mapper receipts, assertion witnesses or index rows.
Actual receipt construction and adoption depend on authentic runtime evidence
and independent acceptance; neither is available in this source slice.

Only root executes new scoped offline checks under the existing socket/process
audit guard. Workers edit assigned source and conduct read-only reviews only.
SPEC then independent QUALITY precede execution. No completed target or source
test is rerun. New controls use synthetic reports/mocks and temporary local
files; no daemon, VM, socket, network/API or host-system probe. Pinned local
Python is sufficient; no Nix evaluation, realization, fetch or blocker retry.

All previous exclusions and the user's updated AGENTS.md/API restriction
persist. Runtime remains blocked, all four full PRO05 cells remain unmapped,
M1 unpassed, readiness L0 and `product_qualified=false`. Finite endpoint
observations do not establish peaks, scaling, decoded-heap, leak/soak,
overload or concurrent-health bounds. Core cannot qualify network.
