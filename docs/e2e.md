# OS-Bus E2E Conformance Harness

## Goals

The E2E harness is being refactored from a dbus-daemon-specific integration harness into a backend-agnostic conformance suite. Each scenario should express D-Bus semantics once and later run against both the reference `dbus-daemon` backend and `gao_bus`.

The first batch keeps the existing E2E tests working through `GaoBusTest.E2EHarness` while introducing new backend, actor, command, diagnostics, and oracle layers under `apps/gao_bus_test/test/support/e2e`.

## Concepts

- Backend: an isolated bus implementation with `start/1`, `address/1`, protocol `probe/1`, `diagnostics/1`, and idempotent `stop/1`.
- Actor: a client or service participating in a scenario, such as ExDBus, the GLib fixture, the Elixir service, `busctl`, or `gdbus`.
- Scenario: a tagged ExUnit test with a stable `e2e_id`, group, gate, supported backends, and actor requirements.
- Gate: a run scope selected by `E2E_GATE`. `smoke` runs the minimum protocol checks, `release` runs broader compatibility checks, and `all` includes every migrated scenario.
- Oracle: normalized semantic assertions for method returns, D-Bus errors, and signals. Tool text parsing is centralized here instead of spread across tests.

## Backends

- `reference`: starts a private `dbus-daemon` using an isolated temp directory, generated session config, and private Unix socket. Startup includes an ExDBus protocol probe: connect, `Hello`, and `ListNames`.
- `gao_bus`: ordinary developer runs retain singleton application isolation. Strict runs start a dedicated BEAM containing `:gao_bus` on a private socket with explicit session policy rules. Configuration evidence includes those rule bytes/hash, and startup verifies the child selected the same policy hash. `E2E_GAO_PROCESS=1` also selects this backend for optional developer runs. The separate-process launcher is a test prototype, not a packaged release.

Only selected backends are probed, once per run, before test files load. Results are cached so per-test skip tags never restart global apps or spawn daemon processes during parallel test-file loading.

The original manifest is explicitly a **session** profile. It does not qualify system policy, authentication security, FD support, service activation, or host replacement. No system profile can qualify by relabeling the session fixture.

## Strict qualification

`scripts/e2e-qualify <backend> <gate>` selects the existing E2E-001–E2E-020 conformance tests and sets `E2E_STRICT=1`. The launcher supplies private boot/config addresses, disables automatic config connection and clustering, and runs Mix with `--no-start`. All actors use explicit fixture addresses.

The versioned applicability manifest is `test/support/e2e/selection.ex`. Gate selection remains cumulative: smoke selects 4 IDs, release 16, compat 19, and stress/all 20, per backend. `both` requires each selected combination on both backends. Scenario tags must agree with the manifest.

Strict qualification fails on missing actors, failed startup/probes, selected known gaps, unexpected skips, absent execution, duplicate or unexpected combinations, and missing actor execution evidence. The final report also rejects ExUnit failures, including teardown failures. Optional developer skips remain available when `E2E_STRICT` is unset.

Before execution, the harness writes a selection report under `_build/test/e2e_artifacts/qualification/<run>/qualification.json`. It atomically updates this report as backends/scenarios/actors run, and retains it on successful and failed runs. It contains selected rows, observed execution, normalized outcomes, per-backend counts, required actors and actor evidence, probe results, runtime versions, seeds, and ExUnit totals. A callback returning normally without a required actor is a blocked outcome. Skipped combinations count as blocked and also have an explicit skipped count.

The 27 preserved legacy E2E tests remain reference-only regression tests. Their original numbered names and expectations are unchanged. They do not contribute qualifying E2E IDs; CI runs them separately against the reference backend. The 9 older `:interop` tests also remain a separate suite.

The test-only `process_guard` fixture owns a private child process group. Timeout, actor-owner failure, or closure of the runner's stdin lifeline requests termination and reaping; a bounded TERM period is followed by KILL. The Elixir wrapper waits for the guardian's exit status. This is a Linux test fixture, not the production Unix resource adapter. Backends remove their private directories during normal teardown.

The H-04 regression starts each backend and an independent Python raw actor in a separate BEAM runner, then an external observer sends SIGKILL to that runner. It records the actual descendant tree, verifies guardians reap their own daemon/actor children, and reaps orphan guardians/runtime helpers without signalling them. Interrupted selection/execution evidence, config hashes, logs, and a fixture seed survive; unfinished execution remains blocked. The surviving observer owns and removes the private fixture directory after verifying teardown. This proves the isolated runner fault; abrupt termination of the outer observer itself does not guarantee filesystem cleanup.

`GaoBusTest.E2E.Actor.RawUnix` sends and receives caller-supplied bytes using public OTP Unix socket operations, independently of ExDBus. It does not authenticate or call Hello automatically and rejects addresses outside its explicitly supplied fixture directory. Real separate-UID qualification must run in the disposable Linux environment and verify actual OS identities; the raw actor does not mock a UID or create host accounts.

The H-04 Python actor additionally proves a distinct OS client process sends independently constructed authentication bytes to the private socket, with its actual PID/UID/GID captured in the ledger. It does not substitute for the disposable VM's multiple-UID checks.

## Diagnostics

On failure, or when `E2E_KEEP_ARTIFACTS=1`, diagnostics are written under:

```text
_build/test/e2e_artifacts/<scenario_id>/<backend>/<unique_id>/
```

Scenario artifacts are retained automatically in strict mode, including successful runs. They include:

- `context.json`: scenario/backend metadata, actor history, and backend configuration bytes/hash.
- `backend.log`: backend diagnostics and captured daemon output when available.
- `fixture.log`: GLib fixture output when that actor is used.
- `commands.jsonl`: process-scoped command results emitted by `busctl`/`gdbus` wrappers.

## Known Gaps

Unavailable tools or unsupported backend features must be explicit. Optional developer runs may skip missing tools, fixture binaries, or unavailable backends. Strict runs record a required failure instead.

Scenarios can tag backend-specific known gaps with `known_gap: [:gao_bus]`. When a selected backend is listed in `known_gap`, that backend is omitted for the scenario. If every selected backend is omitted, the scenario is skipped with a known-gap reason pointing to `docs/e2e-matrix.md`. With `E2E_BACKEND=both`, non-gap backends still run normally.

Known-gap tags are constrained:

- `known_gap` must never include `:reference`.
- `gate: :smoke` scenarios must not carry a `known_gap` tag.

Every known-gap matrix entry must include a diagnosis, not just a label.

## How To Run

Run non-E2E tests:

```sh
task_bus_dir=$(mktemp -d /tmp/os-bus-tests.XXXXXX)
trap 'rm -rf "$task_bus_dir"' EXIT
export DBUS_SOCKET_PATH="$task_bus_dir/boot"
export DBUS_SYSTEM_BUS_ADDRESS="unix:path=$task_bus_dir/boot"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$task_bus_dir/boot"
export GAO_CONFIG_STORE_PATH="$task_bus_dir/config" GAO_CONFIG_CONNECT=false
mix test --exclude e2e
```

Use an explicit private `DBUS_SOCKET_PATH` for any Mix command that starts applications: `runtime.exs` overrides the test config. The listener refuses existing endpoints and removes only a socket whose recorded identity it owns. Never use the host bus addresses for tests.

Run migrated smoke scenarios against the reference backend:

```sh
scripts/e2e-qualify reference smoke
```

Run smoke scenarios against the gao_bus backend:

```sh
scripts/e2e-qualify gao_bus smoke
```

Build the GLib fixture when GLib and pkg-config are available:

```sh
make -C apps/gao_bus_test/test/fixture
```

This also builds the Linux process guardian with warnings treated as errors. Required tools are the pinned Elixir/OTP runtime, `dbus-daemon`, GLib/GIO headers and `pkg-config`, a C compiler, `busctl`, and `gdbus`; actors needed by a selected gate must actually be available. Use the pinned `devenv shell` and record its versions, which differ from the ambient host tools.

Keep diagnostics even for passing scenarios:

```sh
scripts/e2e-qualify reference all
```

## CI Policy

Pull requests run the required conformance matrix across:

- backends: `reference`, `gao_bus`
- gates: `smoke`, `release`

All four PR jobs use strict qualification and fail normally. A selected known gap cannot qualify.

Nightly CI runs the `compat` gate for both backends at 03:00 UTC. Manual `workflow_dispatch` runs can select a single gate (`smoke`, `release`, `compat`, `stress`, or `all`) and run it against both backends.

CI uploads the generated `e2e_artifacts` directory after successful and failed runs, including the selection/execution report and scenario diagnostics.
