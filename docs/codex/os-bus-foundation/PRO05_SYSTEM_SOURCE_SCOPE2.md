# PRO05 system scenario source, controller integration slice

Continue the accepted scope1 components for the four existing PRO-05 complete
cells. The finite inputs, packet pins, order, 32 prefix incarnations and bounds
stay unchanged. This slice integrates a controller and fixture-local BEAM
resource observation with the existing independent actor/channel/cleanup
machinery. It adds no native vector, catalogue cell or qualification gate.

Owned files under `scripts/foundation/pro05_complete/` are `controller.py`,
`test_controller.py`, `resource_probe.exs`, `daemon.exs`,
`resource_probe_test.exs`, `run.py`, `test_driver.py`, `policy.exs`,
`reference.conf`, `bindings.json` and `README.md`. Root also freezes the exact
accepted PRO03 `cleanup.py`: the current shared RES01 helper differs in its
five-second deadline, so it cannot silently substitute for that donor. Root may prepare a
guest-only `test.nix` from the accepted PRO03 recipe after the source/runtime
bindings are fixed. Scope1 source, production code, shared helpers, the generic
mapper and original E2E selection are outside this slice. Only a demonstrated
integration defect may justify a separately recorded scope1 correction.

The controller must retain a persistent observer, public credential checks,
real normal source DOWN on GaoBus (distinct public disappearance on reference),
exact observer-only authority and FD restoration before authorizing terminal
EOF, natural actor retirement, and unmodified raw endpoint metrics. Reference
must never receive fabricated BEAM metrics or monitor evidence. Tokens join
verified receipts; they are not proof of DOWN. Restoring authority and reading
DOWN share 1500ms; source operations allow 3s and observer health 1s. Endpoint
samples establish no transient peak, decoded-heap budget, scaling, soak,
overload or concurrent-health result.

Root owns verification. Workers only edit their assigned source and perform
read-only reviews. Appropriate new controller/adapter tests use mocks under
an audit guard rejecting sockets and process execution; fixture resource tests
may exercise pure sample/monitor transitions with local test processes only.
No accepted native target is rerun. Elixir parse/compile checks must use the
already available pinned runtime and current artifact, without Nix realization
or fetching. SPEC precedes independent QUALITY and scoped execution.

The updated AGENTS.md and user's API restriction remain in effect. No optional
audit, penetration/exploit work, broad fuzzing or external API/network probe.
No retry/alternative route for the retained invalid VM driver/HTTP503 blocker,
no host live-bus/system/account changes, pushes or publication. Guest source
preparation is not guest execution; unavailable runtime remains blocked.
Core results cannot qualify network rows. Full PRO05 remains unmapped, M1
unpassed, readiness L0 and `product_qualified=false` until authentic required
backend/profile observations and existing-row adoption have passed.
