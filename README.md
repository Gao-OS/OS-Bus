# gao_bus

[![CI](https://github.com/Gao-OS/OS-Bus/actions/workflows/ci.yml/badge.svg)](https://github.com/Gao-OS/OS-Bus/actions/workflows/ci.yml)
[![Test](https://github.com/Gao-OS/OS-Bus/actions/workflows/test.yml/badge.svg)](https://github.com/Gao-OS/OS-Bus/actions/workflows/test.yml)
[![E2E](https://github.com/Gao-OS/OS-Bus/actions/workflows/e2e.yml/badge.svg)](https://github.com/Gao-OS/OS-Bus/actions/workflows/e2e.yml)
[![Release](https://github.com/Gao-OS/OS-Bus/actions/workflows/release.yml/badge.svg)](https://github.com/Gao-OS/OS-Bus/actions/workflows/release.yml)
[![Hex.pm](https://img.shields.io/hexpm/v/ex_d_bus.svg)](https://hex.pm/packages/ex_d_bus)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/ex_d_bus)

A D-Bus implementation in Elixir/OTP for GaoOS, with Linux system-bus
replacement as its qualification target.

The current verified readiness is **L0: baseline and infrastructure established**.
Security hardening is in progress; this checkout is not qualified to replace a
live system bus. See the [execution ledger](docs/codex/os-bus-foundation/STATUS.md)
and [compatibility matrix](docs/codex/os-bus-foundation/COMPATIBILITY.md) for actual
test results and missing gates.

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
System-profile traffic is not published to its internal event feed. XML policy,
complete FD forwarding, activation, and headless release qualification remain
unfinished; native capabilities cannot broaden compatibility policy.

## Quick Start

```bash
# Clone
git clone https://github.com/Gao-OS/OS-Bus.git
cd OS-Bus

# Setup (with devenv/nix)
devenv shell

# Dependencies
mix deps.get

# Keep every development endpoint private
task_bus_dir=$(mktemp -d /tmp/osbus-dev.XXXXXX)
export DBUS_SOCKET_PATH="$task_bus_dir/bus"
export DBUS_SYSTEM_BUS_ADDRESS="unix:path=$task_bus_dir/bus"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$task_bus_dir/bus"
export GAO_CONFIG_STORE_PATH="$task_bus_dir/config"
export GAO_CONFIG_CONNECT=false GAO_BUS_CLUSTER=false

# Scoped bus tests; no application starts on a default endpoint
MIX_ENV=test mix test --no-start apps/gao_bus/test/foundation_security_test.exs

# Strict independent-client session gates, with retained artifacts
scripts/e2e-qualify reference all
scripts/e2e-qualify gao_bus all
```

The strict session gate does not certify the system-policy or VM replacement
profile. See [E2E instructions](docs/e2e.md). Disposable VM tests have explicit
entrypoints under `nix/tests`; never apply a test cutover to the host bus.

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

See [CLAUDE.md](./CLAUDE.md) for comprehensive architecture documentation and AI development guide.

## License

Apache-2.0
