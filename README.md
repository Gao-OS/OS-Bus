# gao_bus

[![CI](https://github.com/Gao-OS/OS-Bus/actions/workflows/ci.yml/badge.svg)](https://github.com/Gao-OS/OS-Bus/actions/workflows/ci.yml)
[![Test](https://github.com/Gao-OS/OS-Bus/actions/workflows/test.yml/badge.svg)](https://github.com/Gao-OS/OS-Bus/actions/workflows/test.yml)
[![E2E](https://github.com/Gao-OS/OS-Bus/actions/workflows/e2e.yml/badge.svg)](https://github.com/Gao-OS/OS-Bus/actions/workflows/e2e.yml)
[![Release](https://github.com/Gao-OS/OS-Bus/actions/workflows/release.yml/badge.svg)](https://github.com/Gao-OS/OS-Bus/actions/workflows/release.yml)
[![Hex.pm](https://img.shields.io/hexpm/v/ex_d_bus.svg)](https://hex.pm/packages/ex_d_bus)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/ex_d_bus)

A D-Bus implementation in Elixir/OTP for GaoOS, with Linux system-bus
replacement as its qualification target.

The current verified readiness is **L0: baseline and infrastructure established**,
with `product_qualified=false`. The P00–P12 foundation goal remains incomplete;
this checkout is not qualified to replace a live system bus. See the
[execution ledger](docs/codex/os-bus-foundation/STATUS.md),
[implementation matrix](docs/codex/os-bus-foundation/IMPLEMENTATION_MATRIX.md) and
[compatibility matrix](docs/codex/os-bus-foundation/COMPATIBILITY.md) for implemented
source, actual test results and missing gates.

## Overview

gao_bus is an Elixir umbrella project containing:

- **ex_d_bus** — Pure Elixir D-Bus protocol library (client + server)
- **gao_bus** — Unix bus daemon and ordered authority
- **gao_config** — System configuration service (`org.gaoos.Config1`)
- **gao_bus_web** — Phoenix LiveView real-time D-Bus monitor/debugger
- **gao_bus_test** — Integration, compliance, and interop test suite

Part of the [GaoOS](https://github.com/Gao-OS) ecosystem.

## Why

The goal is interoperability with existing D-Bus clients, service identities,
and system policies. Kernel credentials authenticate peers, policy governs bus
operations, and per-peer processes contain malformed input. A core authority
failure resets the bus epoch and disconnects clients; they must reconnect.
Supervision does not establish uninterrupted service or replacement readiness.

The optional web monitor is for an explicitly configured session profile.
System-profile traffic is not published to its internal event feed. Source for
XML policy, descriptor ownership, bounded routing, activation and headless release
has been implemented, with ordinary scoped compile/format and functional evidence
recorded in the ledger. Installed-profile, native/FD, independent-client and VM
qualification remain incomplete; native capabilities cannot broaden compatibility
policy.

## Quick Start

```bash
# Clone
git clone https://github.com/Gao-OS/OS-Bus.git
cd OS-Bus

# Ordinary offline transcript checks (Python 3; no Mix dependencies required)
python3 -B -m unittest discover \
  -s scripts/foundation/p07_ownership_signals -p '*_test.py' -v
```

These checks use in-memory messages and disposable regular files. They do not
start a bus or observer, run native/FD workloads, or establish interoperability.
Actual P07 collection and the three original reference comparisons remain
unaccepted. See the [P07 harness documentation](scripts/foundation/p07_ownership_signals/README.md)
and [reference dispositions](docs/codex/os-bus-foundation/P07_REFERENCE_DISPOSITIONS.md).

For compilation, ordinary functional tests and advanced acceptance, use the
exact scope and prerequisites in the execution ledger. Security tests remain
prohibited and VM acceptance remains deferred in the current work scope.
Independent-client gates are described in [E2E instructions](docs/e2e.md);
disposable VM entrypoints are under `nix/tests`. Always use explicit isolated
socket addresses. Never connect tests to or cut over the host's live system or
session bus.

## Build and release status

[`v0.3.0-alpha.1`](https://github.com/Gao-OS/OS-Bus/releases/tag/v0.3.0-alpha.1)
is a GitHub source prerelease checkpoint at commit `3650933`. Its
[release notes](docs/codex/os-bus-foundation/RELEASE_v0.3.0-alpha.1.md) describe the
implemented scope and remaining blockers. It includes no qualified installation
package or new Hex publication; component package versions are independent.

Automatic push checks run the ordinary offline transcript suite. Mix checks
remain held until the input prerequisites are met; full tests and E2E jobs also
require separate authorization through explicit manual inputs. Green offline
checks, reporting jobs and skipped jobs do not pass the held gates.

Build-input preparation belongs to the project. An immutable source snapshot and
NAR hash pair binds published commit `3650933`; later documentation updates are
outside that snapshot. Main has directory entries for all 44 locked dependencies,
but their contents and SCM metadata remain unvalidated. Complete validated
dependency and Hex input pairs remain unprepared, and source completeness is
UNPROVED. Package assembly, installed-helper behavior, native qualification and
all 11 canonical VM rows remain unrun or blocked. The
[guarded package assembly documentation](scripts/foundation/p10_package/README.md)
describes the required source, dependency and Hex inputs. Follow the ledger's
protected-input restrictions before preparing further materials.

A GitHub release of this checkpoint distributes source with the recorded L0
limitations. Release notes must distinguish executed checks from blocked or
unrun gates. A merge, tag, source archive or release does not establish package
installation, completed milestones or system-bus replacement readiness.

## Architecture

```
ex_d_bus (zero deps, hex-publishable)
    ↑
gao_bus (bus daemon)

gao_config (optional client service)
gao_bus_web (optional Phoenix monitor)
gao_bus_test (independent-client conformance harness)
```

## Development

See [AGENTS.md](AGENTS.md) for contribution and verification boundaries and
[CLAUDE.md](CLAUDE.md) for architecture documentation.

## License

Apache-2.0
